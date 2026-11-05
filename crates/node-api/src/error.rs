use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use dns_runtime::MutationError;
use serde::Serialize;
use tracing::error;
use ulid::Ulid;
use utoipa::ToSchema;

/// The error body shared by every endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

/// What went wrong. `code` is stable; `message` is for people.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: String,
}

/// An API failure, which becomes an [`ErrorEnvelope`] response.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn not_found(what: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            format!("{what} wasn't found"),
        )
    }

    pub fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, message)
    }

    pub fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Please sign in",
        )
    }

    pub fn telemetry_unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "TELEMETRY_UNAVAILABLE",
            "Query data isn't available, but DNS is still being served",
        )
    }

    /// An unexpected failure. The cause is logged and not sent to the client.
    pub fn internal(cause: impl std::fmt::Display) -> Self {
        error!(%cause, "API request failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Something went wrong on the node. Its log has the details.",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = Ulid::generate().to_string();
        if self.status.is_server_error() {
            error!(code = self.code, %request_id, message = %self.message, "API error");
        }
        let body = ErrorEnvelope {
            error: ErrorBody {
                code: self.code.to_owned(),
                message: self.message,
                request_id,
            },
        };
        (self.status, Json(body)).into_response()
    }
}

impl From<MutationError<ApiError>> for ApiError {
    fn from(error: MutationError<ApiError>) -> Self {
        match error {
            MutationError::Rejected(rejected) => rejected,
            MutationError::ReadOnly => Self::new(
                StatusCode::CONFLICT,
                "POLICY_READ_ONLY",
                "This node's policy comes from a file. Edit the file and send SIGHUP, or restart \
                 without --policy to manage it here.",
            ),
            MutationError::Managed => Self::new(
                StatusCode::CONFLICT,
                "POLICY_MANAGED",
                "This node's policy comes from its central controller. Change it there.",
            ),
            MutationError::NoStateDirectory => Self::new(
                StatusCode::CONFLICT,
                "NO_STATE_DIRECTORY",
                "Policy changes need the node to run with --state-dir",
            ),
            MutationError::Invalid(invalid) => Self::invalid("POLICY_INVALID", invalid.to_string()),
            MutationError::Storage(storage) => {
                error!(error = %storage, "cannot store a policy change");
                Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "STORAGE_UNAVAILABLE",
                    "The change couldn't be saved, so it wasn't applied. DNS is still being served.",
                )
            }
        }
    }
}

impl From<dns_storage::ConfigDbError> for ApiError {
    fn from(error: dns_storage::ConfigDbError) -> Self {
        Self::internal(error)
    }
}
