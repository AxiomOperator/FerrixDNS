//! Blocking well-known services by name.

use std::collections::HashSet;

use axum::Json;
use axum::extract::{Path, State};
use dns_policy::{BlockedServiceDef, PolicyDocument, SERVICES, Service, find_service};

use crate::AppState;
use crate::auth::AuthSession;
use crate::dto::{BlockedServiceDto, Envelope, SetBlockedService};
use crate::error::ApiError;
use crate::routes::{ApiResult, audit, mutate};

fn service_dto(document: &PolicyDocument, service: &Service) -> BlockedServiceDto {
    let blocked = document
        .blocked_services
        .iter()
        .find(|blocked| blocked.service == service.id);
    BlockedServiceDto {
        id: service.id.to_owned(),
        name: service.name.to_owned(),
        category: service.category.to_owned(),
        domains: service
            .domains
            .iter()
            .map(|domain| (*domain).to_owned())
            .collect(),
        blocked: blocked.is_some(),
        groups: blocked
            .map(|blocked| blocked.groups.clone())
            .unwrap_or_default(),
    }
}

/// Every service that can be blocked in one step, and whether it is.
#[utoipa::path(get, path = "/api/v1/blocked-services", responses(
    (status = 200, body = Envelope<Vec<BlockedServiceDto>>),
    (status = 401, body = crate::error::ErrorEnvelope),
))]
pub async fn list_blocked_services(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<Vec<BlockedServiceDto>>> {
    let document = state.manager.document();
    Json(Envelope::new(
        SERVICES
            .iter()
            .map(|service| service_dto(&document, service))
            .collect(),
    ))
}

/// Blocks or unblocks a service, active as soon as this returns.
#[utoipa::path(put, path = "/api/v1/blocked-services/{id}", params(("id" = String, Path)),
    request_body = SetBlockedService, responses(
    (status = 200, body = Envelope<BlockedServiceDto>),
    (status = 401, body = crate::error::ErrorEnvelope),
    (status = 403, body = crate::error::ErrorEnvelope),
    (status = 404, body = crate::error::ErrorEnvelope),
    (status = 422, body = crate::error::ErrorEnvelope),
))]
pub async fn set_blocked_service(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<SetBlockedService>,
) -> ApiResult<Json<Envelope<BlockedServiceDto>>> {
    let service = find_service(&id).ok_or_else(|| ApiError::not_found("That service"))?;
    let mut seen = HashSet::new();
    let groups: Vec<String> = request
        .groups
        .into_iter()
        .map(|group| group.trim().to_owned())
        .filter(|group| !group.is_empty() && seen.insert(group.clone()))
        .collect();
    let blocked = request.blocked;
    let stored = groups.clone();
    mutate(&state, move |document| {
        let known = |group: &String| {
            document.groups.iter().any(|known| known.id == *group)
                || document
                    .clients
                    .iter()
                    .any(|client| client.groups.contains(group))
        };
        if let Some(unknown) = stored.iter().find(|group| !known(group)) {
            return Err(ApiError::invalid(
                "GROUP_NOT_FOUND",
                format!("There's no group called {unknown}"),
            ));
        }
        document
            .blocked_services
            .retain(|item| item.service != service.id);
        if blocked {
            document.blocked_services.push(BlockedServiceDef {
                service: service.id.to_owned(),
                groups: stored,
            });
        }
        Ok(())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        if blocked {
            "service.block"
        } else {
            "service.unblock"
        },
        service.id,
        serde_json::json!({"service": service.name, "groups": groups}),
    )
    .await;
    Ok(Json(Envelope::new(service_dto(
        &state.manager.document(),
        service,
    ))))
}
