//! Downloads the query log as a file, reading it in batches so a long history doesn't sit in memory.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use dns_telemetry::{QueryEvent, QueryFilter, Telemetry};
use futures_util::stream;

use crate::AppState;
use crate::auth::AuthSession;
use crate::dto::{QueryEventDto, QueryExportParams};
use crate::error::ApiError;
use crate::routes::{ApiResult, audit, policy_labels, telemetry};
use crate::util::{from_iso, now_ms, to_iso};

/// An export stops here, so one request can't run for hours. Narrow the filters to get the rest.
const MAX_EXPORT_ROWS: u64 = 1_000_000;

const CSV_HEADER: &str = "time,client_id,client_address,name,type,result,response_code,\
matched_name,rule_id,rule,list_id,list,upstream,duration_ms,policy_revision\r\n";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Csv,
    Json,
}

/// A CSV field, safe to open in a spreadsheet.
///
/// Query names come from anyone on the network, and spreadsheets run cells that start with these
/// characters as formulas, so those cells are marked as text.
fn csv_field(value: &str) -> String {
    let starts_like_a_formula = value.starts_with(['=', '+', '-', '@', '\t', '\r']);
    let text = if starts_like_a_formula {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

fn csv_line(
    event: &QueryEvent,
    rules: &HashMap<String, String>,
    lists: &HashMap<String, String>,
) -> String {
    let label = |id: &Option<String>, labels: &HashMap<String, String>| {
        id.as_ref()
            .and_then(|id| labels.get(id).cloned())
            .unwrap_or_default()
    };
    let text = |value: &Option<String>| value.clone().unwrap_or_default();
    let fields = [
        to_iso(event.occurred_at_ms),
        text(&event.client_id),
        text(&event.client_ip),
        text(&event.qname),
        event.qtype.clone(),
        event.outcome.as_str().to_owned(),
        event.rcode.clone(),
        text(&event.matched_name),
        text(&event.rule_id),
        label(&event.rule_id, rules),
        text(&event.source_list_id),
        label(&event.source_list_id, lists),
        text(&event.upstream),
        format!("{:.3}", event.duration_us as f64 / 1000.0),
        text(&event.revision_id),
    ];
    let mut line = fields
        .iter()
        .map(|field| csv_field(field))
        .collect::<Vec<_>>()
        .join(",");
    line.push_str("\r\n");
    line
}

struct Export {
    telemetry: Arc<Telemetry>,
    filter: QueryFilter,
    rules: HashMap<String, String>,
    lists: HashMap<String, String>,
    format: Format,
    written: u64,
    started: bool,
    finished: bool,
}

impl Export {
    /// The next part of the file, or `None` once it's complete.
    async fn next_chunk(&mut self) -> Option<Bytes> {
        if self.finished {
            return None;
        }
        let page = self.telemetry.query_log_batch(&self.filter).await;
        let mut chunk = String::new();
        if !self.started {
            chunk.push_str(match self.format {
                Format::Csv => CSV_HEADER,
                Format::Json => "[",
            });
        }
        for event in page.events {
            if self.written >= MAX_EXPORT_ROWS {
                break;
            }
            match self.format {
                Format::Csv => chunk.push_str(&csv_line(&event, &self.rules, &self.lists)),
                Format::Json => {
                    if self.written > 0 {
                        chunk.push(',');
                    }
                    let dto = QueryEventDto::new(event, &self.rules, &self.lists);
                    if let Ok(json) = serde_json::to_string(&dto) {
                        chunk.push_str(&json);
                    }
                }
            }
            self.written += 1;
        }
        self.started = true;
        self.filter.before_seq = page.next_before_seq;
        if page.next_before_seq.is_none() || self.written >= MAX_EXPORT_ROWS {
            self.finished = true;
            if self.format == Format::Json {
                chunk.push(']');
            }
        }
        Some(Bytes::from(chunk))
    }
}

/// Downloads the query log, with the same filters as the Query Explorer, newest first. An export
/// stops at 1,000,000 queries, so narrow the filters to get the rest.
#[utoipa::path(get, path = "/api/v1/queries/export", params(QueryExportParams), responses(
    (status = 200, content_type = "text/csv", body = String),
    (status = 401, body = crate::error::ErrorEnvelope),
    (status = 422, body = crate::error::ErrorEnvelope),
    (status = 503, body = crate::error::ErrorEnvelope),
))]
pub async fn export_queries(
    auth: AuthSession,
    State(state): State<AppState>,
    Query(params): Query<QueryExportParams>,
) -> ApiResult<Response> {
    let format = match params.format.as_deref().unwrap_or("csv") {
        "csv" => Format::Csv,
        "json" => Format::Json,
        _ => {
            return Err(ApiError::invalid("FORMAT_INVALID", "Choose csv or json"));
        }
    };
    let time = |value: Option<String>| {
        value
            .filter(|value| !value.is_empty())
            .map(|value| {
                from_iso(&value).ok_or_else(|| {
                    ApiError::invalid(
                        "TIME_INVALID",
                        "Use a UTC time such as 2026-12-01T00:00:00Z",
                    )
                })
            })
            .transpose()
    };
    let not_empty = |value: Option<String>| value.filter(|value| !value.is_empty());
    let filter = QueryFilter {
        before_seq: None,
        limit: u32::MAX,
        qname: not_empty(params.qname).map(|name| name.to_ascii_lowercase()),
        client: not_empty(params.client),
        outcome: not_empty(params.action),
        qtype: not_empty(params.qtype).map(|qtype| qtype.to_ascii_uppercase()),
        from_ms: time(params.from)?,
        to_ms: time(params.to)?,
    };
    let telemetry = Arc::clone(telemetry(&state)?);
    let (rules, lists) = policy_labels(&state.manager.document());

    // Taking a copy of the query history out of the node is worth a record.
    audit(
        &state,
        &auth.session.username,
        "queries.export",
        "queries",
        serde_json::json!({
            "format": if format == Format::Csv { "csv" } else { "json" },
            "qname": filter.qname,
            "client": filter.client,
            "action": filter.outcome,
            "qtype": filter.qtype,
        }),
    )
    .await;

    let export = Export {
        telemetry,
        filter,
        rules,
        lists,
        format,
        written: 0,
        started: false,
        finished: false,
    };
    let chunks = stream::unfold(export, |mut export| async move {
        let chunk = export.next_chunk().await?;
        Some((Ok::<_, Infallible>(chunk), export))
    });
    let (content_type, extension) = match format {
        Format::Csv => ("text/csv; charset=utf-8", "csv"),
        Format::Json => ("application/json", "json"),
    };
    let date = to_iso(now_ms());
    let day = date.split('T').next().unwrap_or("export");
    Ok((
        [
            (CONTENT_TYPE, content_type.to_owned()),
            (
                CONTENT_DISPOSITION,
                format!("attachment; filename=\"ferrixdns-queries-{day}.{extension}\""),
            ),
            (CACHE_CONTROL, "no-store".to_owned()),
        ],
        Body::from_stream(chunks),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_fields_are_quoted_and_cannot_run_as_formulas() {
        assert_eq!(csv_field("example.com"), "example.com");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("line\nbreak"), "\"line\nbreak\"");
        for formula in ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"] {
            assert!(
                csv_field(formula).trim_start_matches('"').starts_with('\''),
                "{formula:?}"
            );
        }
        assert_eq!(csv_field("=1,2"), "\"'=1,2\"");
    }
}
