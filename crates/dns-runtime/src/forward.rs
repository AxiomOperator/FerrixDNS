//! Upstream pools for conditional forwarding, built as policies ask for them.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use dns_policy::{PolicyDocument, PolicyError};
use dns_upstreams::{PoolConfig, PoolConfigError, ServerStats, UpstreamPool, UpstreamServer};

/// Dropped pools are only servers that a policy no longer names, so this just bounds them.
const MAX_POOLS: usize = 64;

/// The pool for a list of servers, and whether it's load balanced.
type PoolKey = (Arc<[String]>, bool);

/// One pool for each list of servers that forward zones name.
pub struct ConditionalPools {
    template: PoolConfig,
    pools: RwLock<HashMap<PoolKey, Arc<UpstreamPool>>>,
}

impl ConditionalPools {
    /// Pools built here use these timeouts. The servers in `template` are ignored.
    pub fn new(template: PoolConfig) -> Self {
        Self {
            template,
            pools: RwLock::new(HashMap::new()),
        }
    }

    /// The pool for a list of servers.
    pub fn pool(
        &self,
        servers: &Arc<[String]>,
        load_balance: bool,
    ) -> Result<Arc<UpstreamPool>, PoolConfigError> {
        let key = (Arc::clone(servers), load_balance);
        if let Some(pool) = self
            .pools
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return Ok(Arc::clone(pool));
        }
        let parsed = servers
            .iter()
            .map(|server| {
                server
                    .parse()
                    .map_err(
                        |error: dns_upstreams::ServerParseError| PoolConfigError::Server {
                            server: server.clone(),
                            reason: error.to_string(),
                        },
                    )
            })
            .collect::<Result<Vec<UpstreamServer>, _>>()?;
        let pool = Arc::new(UpstreamPool::new(PoolConfig {
            servers: parsed,
            load_balance,
            ..self.template.clone()
        })?);
        let mut pools = self.pools.write().unwrap_or_else(PoisonError::into_inner);
        if pools.len() >= MAX_POOLS {
            pools.clear();
        }
        Ok(Arc::clone(pools.entry(key).or_insert(pool)))
    }

    /// What's been seen from a list of servers, if any query has used them.
    pub fn stats(&self, servers: &[String], load_balance: bool) -> Vec<ServerStats> {
        self.pools
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|((listed, balanced), _)| **listed == *servers && *balanced == load_balance)
            .map(|(_, pool)| pool.stats())
            .unwrap_or_default()
    }
}

/// Checks what the policy crate can't, because it doesn't know about upstream servers.
pub fn validate_forward_servers(document: &PolicyDocument) -> Result<(), PolicyError> {
    for zone in &document.forward_zones {
        for server in &zone.servers {
            server.parse::<UpstreamServer>().map_err(|error| {
                PolicyError::Forward(format!("forward zone {}: {error}", zone.id))
            })?;
        }
    }
    Ok(())
}
