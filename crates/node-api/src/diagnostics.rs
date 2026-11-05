//! Works out how this node would answer a query right now, and why, step by step.
//!
//! This follows the same order as the DNS path, using the active policy. It asks the upstream
//! servers directly but changes nothing: not the cache, not any counts.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use dns_cache::CacheKey;
use dns_policy::{
    Action, ClientSource, CompiledPolicy, Decision, DecisionSource, DomainName, Filtering,
    LocalAnswer, LocalData, LocalQuery, PolicyDocument, Verdict,
};
use dns_telemetry::QueryFilter;
use dns_upstreams::{EdnsRequest, MAX_UDP_PAYLOAD, Probe, UpstreamRequest};
use hickory_proto::op::{Message, Query as DnsQuery, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::AppState;
use crate::auth::AuthSession;
use crate::dto::{
    DiagnoseRequest, DiagnosticProbe, DiagnosticReport, DiagnosticStatus, DiagnosticStep, Envelope,
    QueryEventDto,
};
use crate::error::ApiError;
use crate::routes::{ApiResult, device_source, policy_labels, scope_name, tier_name};

const RECENT_EVENTS: u32 = 8;

fn step(title: &str, status: DiagnosticStatus, detail: impl Into<String>) -> DiagnosticStep {
    DiagnosticStep {
        title: title.to_owned(),
        status,
        detail: detail.into(),
    }
}

fn local_query(record_type: RecordType) -> LocalQuery {
    match record_type {
        RecordType::A => LocalQuery::A,
        RecordType::AAAA => LocalQuery::Aaaa,
        RecordType::CNAME => LocalQuery::Cname,
        RecordType::PTR => LocalQuery::Ptr,
        RecordType::SOA => LocalQuery::Soa,
        RecordType::NS => LocalQuery::Ns,
        RecordType::ANY => LocalQuery::Any,
        _ => LocalQuery::Other,
    }
}

fn local_answers(answer: &LocalAnswer) -> Vec<String> {
    answer
        .records
        .iter()
        .map(|record| {
            let data = match &record.data {
                LocalData::A(address) => format!("A {address}"),
                LocalData::Aaaa(address) => format!("AAAA {address}"),
                LocalData::Cname(target) => format!("CNAME {}", target.as_str()),
                LocalData::Ptr(target) => format!("PTR {}", target.as_str()),
                LocalData::Soa => "SOA".to_owned(),
                LocalData::Ns => "NS".to_owned(),
            };
            format!("{} {data}", record.name.as_str())
        })
        .collect()
}

fn record_text(record: &Record) -> String {
    format!(
        "{} {} {} {}",
        record.name,
        record.ttl,
        record.record_type(),
        record.data
    )
}

/// A blocking decision in words.
fn why_blocked(decision: &Decision<'_>, document: &PolicyDocument, name: &str) -> String {
    let (rules, lists) = policy_labels(document);
    let scope = decision.scope.map_or("everyone".to_owned(), |scope| {
        format!("{} scope", scope_name(scope))
    });
    match decision.source {
        DecisionSource::Rule(id) => format!(
            "{name} is blocked by {} ({scope}).",
            rules.get(id).map_or_else(
                || format!("rule {id}"),
                |pattern| format!("the rule or service {pattern}")
            ),
        ),
        DecisionSource::List(id) => format!(
            "{name} is blocked by the source {} ({scope}).",
            lists.get(id).map_or(id, String::as_str)
        ),
        DecisionSource::Default => format!("{name} is blocked."),
    }
}

/// Looks through an answer's CNAME targets, and what policy says about them.
fn cname_check(
    policy: &CompiledPolicy,
    filtering: Filtering,
    source: ClientSource<'_>,
    name: &DomainName,
    message: &Message,
    document: &PolicyDocument,
) -> Result<Option<String>, String> {
    let mut targets = Vec::new();
    for record in &message.answers {
        if let RData::CNAME(target) = &record.data {
            targets.push(DomainName::parse(&target.0.to_string()).map_err(|_| {
                format!("The answer points to {}, which can't be checked.", target.0)
            })?);
        }
    }
    match policy.check_answer_with(filtering, source, name, &targets) {
        Verdict::Allow => Ok(None),
        Verdict::Block(decision) => Ok(Some(why_blocked(&decision, document, name.as_str()))),
        Verdict::BlockTarget {
            decision,
            target_index,
        } => {
            let target = targets
                .get(target_index)
                .map_or(name.as_str(), DomainName::as_str);
            Ok(Some(why_blocked(&decision, document, target)))
        }
        Verdict::ChainTooDeep => Err("The answer's CNAME chain is too long to follow.".to_owned()),
    }
}

fn probe_dto(probe: Probe) -> DiagnosticProbe {
    let latency_ms = probe.latency.as_secs_f64() * 1000.0;
    match probe.result {
        Ok(message) => {
            let code = message.metadata.response_code;
            DiagnosticProbe {
                server: probe.server,
                ok: !matches!(code, ResponseCode::ServFail | ResponseCode::Refused),
                rcode: Some(code.to_str().to_owned()),
                latency_ms,
                answers: message.answers.iter().map(record_text).collect(),
                error: None,
            }
        }
        Err(error) => DiagnosticProbe {
            server: probe.server,
            ok: false,
            rcode: None,
            latency_ms,
            answers: Vec::new(),
            error: Some(error),
        },
    }
}

/// Explains how this node would answer a query right now. Nothing is changed, but the upstream
/// servers are asked.
#[utoipa::path(post, path = "/api/v1/diagnostics/lookup", request_body = DiagnoseRequest, responses(
    (status = 200, body = Envelope<DiagnosticReport>),
    (status = 401, body = crate::error::ErrorEnvelope),
    (status = 422, body = crate::error::ErrorEnvelope),
))]
pub async fn diagnose(
    _auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<DiagnoseRequest>,
) -> ApiResult<Json<Envelope<DiagnosticReport>>> {
    let name = DomainName::parse(request.name.trim())
        .map_err(|error| ApiError::invalid("DOMAIN_INVALID", error.to_string()))?;
    let type_text = request
        .record_type
        .as_deref()
        .map_or("A".to_owned(), |value| value.trim().to_ascii_uppercase());
    let record_type = RecordType::from_str(&type_text)
        .ok()
        .filter(|record_type| !matches!(record_type, RecordType::AXFR | RecordType::IXFR))
        .ok_or_else(|| ApiError::invalid("TYPE_INVALID", "Use a record type such as A or AAAA"))?;
    let client_ip: Option<IpAddr> = match request.client_ip.as_deref().map(str::trim) {
        Some("") | None => None,
        Some(value) => Some(
            value
                .parse::<IpAddr>()
                .map_err(|_| ApiError::invalid("ADDRESS_INVALID", "Enter a valid IP address"))?
                .to_canonical(),
        ),
    };

    let mut report = Report {
        result: "forwarded",
        summary: String::new(),
        answers: Vec::new(),
        steps: Vec::new(),
        upstreams: Vec::new(),
    };
    let policy = state.manager.handle().load_full();
    let document = state.manager.document();
    let address = client_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let device = state.services.devices.get(address);
    let source = device_source(address, device.as_deref());
    let identity = policy.identity(source);
    let client_id = identity.map(|identity| identity.id.to_string());

    walk(
        &state,
        &policy,
        &document,
        Question {
            name: &name,
            record_type,
            client_ip,
            source,
        },
        &mut report,
    )
    .await;

    let recent = recent_events(&state, &name, &document).await;
    Ok(Json(Envelope::new(DiagnosticReport {
        name: name.as_str().to_owned(),
        record_type: record_type.to_string(),
        client_ip: client_ip.map(|address| address.to_string()),
        client_id,
        result: report.result.to_owned(),
        summary: report.summary,
        answers: report.answers,
        steps: report.steps,
        upstreams: report.upstreams,
        recent,
        revision: policy.revision().to_owned(),
    })))
}

struct Report {
    result: &'static str,
    summary: String,
    answers: Vec<String>,
    steps: Vec<DiagnosticStep>,
    upstreams: Vec<DiagnosticProbe>,
}

impl Report {
    fn conclude(&mut self, result: &'static str, summary: impl Into<String>) {
        self.result = result;
        self.summary = summary.into();
    }
}

#[derive(Clone, Copy)]
struct Question<'a> {
    name: &'a DomainName,
    record_type: RecordType,
    client_ip: Option<IpAddr>,
    source: ClientSource<'a>,
}

/// Follows the DNS path. Each return is where a real query's handling would end.
async fn walk(
    state: &AppState,
    policy: &Arc<CompiledPolicy>,
    document: &PolicyDocument,
    question: Question<'_>,
    report: &mut Report,
) {
    use DiagnosticStatus::{Info, Ok as Fine, Stopped, Warning};
    let Question {
        name,
        record_type,
        client_ip,
        source,
    } = question;

    match client_ip {
        Some(address) => {
            let allowed = state
                .services
                .allow
                .iter()
                .any(|network| network.contains(&address));
            if !allowed {
                report.steps.push(step(
                    "Allowed networks",
                    Stopped,
                    format!("{address} isn't in the networks allowed to query, so it's refused. Add its network under Settings."),
                ));
                report.conclude(
                    "refused",
                    format!("This node refuses every query from {address}, because that address isn't in its allowed networks."),
                );
                return;
            }
            report.steps.push(step(
                "Allowed networks",
                Fine,
                format!("{address} is allowed to query."),
            ));
            let who = match policy.identity(source) {
                Some(identity) if identity.groups.is_empty() => {
                    format!("This is the client {}, which is in no groups.", identity.id)
                }
                Some(identity) => format!(
                    "This is the client {}, in the groups {}.",
                    identity.id,
                    identity.groups.iter().map(AsRef::as_ref).collect::<Vec<&str>>().join(", ")
                ),
                None => "This address isn't a named client, so only rules for everyone apply.".to_owned(),
            };
            report.steps.push(step("Device", Info, who));
            if let Some(limit) = policy.rate_limit_for(address) {
                report.steps.push(step(
                    "Query limit",
                    Info,
                    format!("Limited to {limit} queries a minute. A device over this is refused for a while."),
                ));
            } else {
                report.steps.push(step("Query limit", Info, "This address has no query limit."));
            }
        }
        None => report.steps.push(step(
            "Device",
            Info,
            "No device was given, so only rules for everyone apply. Give an address to include its own rules, or to check it's allowed.",
        )),
    }

    let filtering = if state.services.pause.is_active() {
        report.steps.push(step(
            "Blocking",
            Warning,
            "Blocking is paused, so only emergency rules apply until it resumes.",
        ));
        Filtering::EmergencyOnly
    } else {
        Filtering::Normal
    };

    // Names this node owns never go upstream.
    if let Some(answer) = policy.local_answer(name, local_query(record_type))
        && (answer.policy_applies || policy.forward_route(name).is_none())
    {
        match policy.check_local_with(filtering, source, &answer) {
            Verdict::Allow | Verdict::ChainTooDeep => {
                let zone = answer
                    .zone
                    .as_ref()
                    .map_or("a name reserved for local use".to_owned(), |zone| {
                        format!("the local zone {}", zone.as_str())
                    });
                report.steps.push(step(
                    "Local DNS",
                    Fine,
                    format!("This node answers this itself, from {zone}. It isn't sent upstream."),
                ));
                report.answers = local_answers(&answer);
                let found = if answer.nxdomain {
                    "that the name doesn't exist"
                } else if answer.records.is_empty() {
                    "that the name has no records of this type"
                } else {
                    "with its local records"
                };
                report.conclude(
                    "local",
                    format!("This node answers {} itself, {found}.", name.as_str()),
                );
            }
            Verdict::Block(decision) | Verdict::BlockTarget { decision, .. } => {
                let why = why_blocked(&decision, document, name.as_str());
                report.steps.push(step("Local DNS", Stopped, why.clone()));
                report.conclude("blocked", why);
            }
        }
        return;
    }
    report.steps.push(step(
        "Local DNS",
        Fine,
        "No local zone or reserved name covers this.",
    ));

    match policy.check_query_with(filtering, source, name) {
        Verdict::Block(decision) => {
            let why = why_blocked(&decision, document, name.as_str());
            report.steps.push(step(
                "Rules and sources",
                Stopped,
                format!("{why} Decided by the {} tier.", tier_name(decision.tier)),
            ));
            report.conclude("blocked", why);
            return;
        }
        _ => {
            let decision = policy.explain(source, name);
            let detail = match (decision.action, decision.source) {
                (Action::Allow, DecisionSource::Default) => {
                    "No rule or source matches, so it's allowed.".to_owned()
                }
                (Action::Allow, _) => {
                    format!(
                        "An allow in the {} tier lets this through.",
                        tier_name(decision.tier)
                    )
                }
                // Only reached while blocking is paused.
                (Action::Deny, _) => format!(
                    "Blocking is paused. Otherwise: {}",
                    why_blocked(&decision, document, name.as_str())
                ),
            };
            report.steps.push(step("Rules and sources", Fine, detail));
        }
    }

    let route = policy.forward_route(name);
    let pool = match route {
        Some(route) => {
            report.steps.push(step(
                "Where it goes",
                Info,
                format!(
                    "A forward zone sends this to {}, and never to the default upstreams.",
                    route.servers.join(", ")
                ),
            ));
            match state
                .services
                .conditional
                .pool(&route.servers, route.load_balance)
            {
                Ok(pool) => pool,
                Err(error) => {
                    report
                        .steps
                        .push(step("Where it goes", Stopped, error.to_string()));
                    report.conclude(
                        "failed",
                        "This node can't reach this forward zone's servers.",
                    );
                    return;
                }
            }
        }
        None => {
            report.steps.push(step(
                "Where it goes",
                Info,
                "This goes to the default upstream servers.",
            ));
            Arc::clone(&state.pool)
        }
    };

    let cached = state.cache.as_ref().and_then(|cache| {
        cache.peek(&CacheKey {
            name: name.as_str().to_owned(),
            record_type,
            dnssec_ok: false,
            checking_disabled: false,
            route: route.map_or(0, |route| route.route),
        })
    });
    let fresh_in_cache = cached.is_some_and(|state| !state.stale);
    report.steps.push(match (&state.cache, cached) {
        (None, _) => step(
            "Cache",
            Info,
            "The cache is off, so every query goes upstream.",
        ),
        (_, None) => step(
            "Cache",
            Info,
            "Nothing is cached for this, so it goes upstream.",
        ),
        (_, Some(entry)) if entry.stale => step(
            "Cache",
            Info,
            "The cached answer has expired. It's only used if upstreams can't answer.",
        ),
        (_, Some(entry)) => step(
            "Cache",
            Fine,
            format!(
                "Answered from the cache for another {} seconds. Rules still apply to it.",
                entry.remaining_seconds
            ),
        ),
    });

    if state.dnssec_validation && route.is_none() {
        report.steps.push(step(
            "DNSSEC",
            Info,
            "Answers are validated on this node, and a failed check gives an error. The servers below are asked without validation.",
        ));
    }

    let Ok(query_name) = Name::from_ascii(format!("{}.", name.as_str())) else {
        report.conclude("failed", "This name can't be sent upstream.");
        return;
    };
    let probes = pool
        .probe(&UpstreamRequest {
            query: DnsQuery::query(query_name, record_type),
            recursion_desired: true,
            checking_disabled: false,
            edns: Some(EdnsRequest {
                max_payload: MAX_UDP_PAYLOAD,
                dnssec_ok: false,
            }),
        })
        .await;
    let answer = probes.iter().find_map(|probe| {
        probe.result.as_ref().ok().filter(|message| {
            !matches!(
                message.metadata.response_code,
                ResponseCode::ServFail | ResponseCode::Refused
            )
        })
    });
    let reachable = probes.iter().filter(|probe| probe.result.is_ok()).count();
    let total = probes.len();

    match answer {
        Some(message) => {
            let check = cname_check(policy, filtering, source, name, message, document);
            report.answers = message.answers.iter().map(record_text).collect();
            report.steps.push(step(
                "Upstream servers",
                if reachable == total { Fine } else { Warning },
                format!("{reachable} of {total} answered directly."),
            ));
            match check {
                Ok(None) => {
                    report.steps.push(step(
                        "Checking the answer",
                        Fine,
                        "Nothing in the answer is blocked.",
                    ));
                    let code = message.metadata.response_code;
                    let source_text = if fresh_in_cache {
                        "from the cache"
                    } else {
                        "from upstream"
                    };
                    let found = match code {
                        ResponseCode::NXDomain => {
                            "that the name doesn't exist. That's the real answer, not a block"
                        }
                        ResponseCode::NoError if message.answers.is_empty() => {
                            "with no records of this type"
                        }
                        _ => "normally",
                    };
                    report.conclude(
                        if fresh_in_cache {
                            "cached"
                        } else {
                            "forwarded"
                        },
                        format!("A device gets an answer {source_text}, {found}."),
                    );
                }
                Ok(Some(why)) => {
                    report
                        .steps
                        .push(step("Checking the answer", Stopped, why.clone()));
                    report.conclude("blocked", why);
                }
                Err(why) => {
                    report
                        .steps
                        .push(step("Checking the answer", Stopped, why.clone()));
                    report.conclude("failed", why);
                }
            }
        }
        None if cached.is_some() => {
            report.steps.push(step(
                "Upstream servers",
                Warning,
                format!("{reachable} of {total} gave a usable answer."),
            ));
            if fresh_in_cache {
                report.conclude("cached", "Upstreams aren't answering, but a device still gets the cached answer for now.");
            } else {
                report.conclude("stale", "Upstreams aren't answering, so a device gets this node's last known answer, which has expired.");
            }
        }
        None => {
            report.steps.push(step(
                "Upstream servers",
                Stopped,
                if total == 0 {
                    "There are no servers to ask.".to_owned()
                } else {
                    format!("{reachable} of {total} responded, and none gave a usable answer.")
                },
            ));
            report.conclude("failed", "A device gets an error, because no upstream server gave a usable answer and nothing is cached.");
        }
    }
    report.upstreams = probes.into_iter().map(probe_dto).collect();
}

/// The most recent queries with this name in them, to show what devices really got.
async fn recent_events(
    state: &AppState,
    name: &DomainName,
    document: &PolicyDocument,
) -> Vec<QueryEventDto> {
    let Some(telemetry) = &state.telemetry else {
        return Vec::new();
    };
    let page = telemetry
        .query_log(&QueryFilter {
            limit: RECENT_EVENTS,
            qname: Some(name.as_str().to_owned()),
            ..QueryFilter::default()
        })
        .await;
    let (rules, lists) = policy_labels(document);
    page.events
        .into_iter()
        .map(|event| QueryEventDto::new(event, &rules, &lists))
        .collect()
}
