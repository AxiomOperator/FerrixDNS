//! Parses blocklists into normalized artifacts and downloads them safely.

mod fetch;
mod parse;

pub use fetch::{Conditional, FetchError, FetchLimits, FetchOutcome, Fetcher, is_public_ip};
pub use parse::{
    ArtifactError, MAX_LIST_ENTRIES, ParseError, ParsedList, decode_artifact, encode_artifact,
    parse_list,
};
