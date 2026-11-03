# ADR-003: Scope-first policy precedence, CNAME evaluation and cache partitioning

**Status:** Accepted  
**Date:** 2026-11-03

## Decision

**Precedence**

1. Emergency deny at any applicable scope always wins.
2. Scopes are checked in order: client, group, site, global. The first scope with a match decides.
   A client's groups count as one scope.
3. Within a scope, the first matching tier decides: exact allow, suffix allow, regex allow, exact
   deny, suffix deny, subscribed allow, subscribed deny, regex deny.
4. With no match at any scope, the query is allowed.

Rules have no numeric priority. Each tier has one action, so ties can't change the outcome. The
lowest rule or list ID is recorded as the attribution.

**CNAME targets**

Each target in an answer is evaluated for the same client on every response, including cache hits.
Chains deeper than 16 names return SERVFAIL. If the query name matched an allow rule or a subscribed
allow, subscribed denies on its targets are ignored. Rule and emergency denies on targets still block.

**Local zones**

Subscribed lists don't apply to names in a managed local zone. Rule and emergency denies do.

**Cache**

The cache holds only upstream answers, never policy decisions, so changing policy requires no flush.

## Why

Scope-first makes per-client policy predictable: a client-scoped deny can't be overridden by a broad
global allow. Evaluating targets on each answer closes the gap where a new block on a CNAME target
would be bypassed by a cached answer.

## Consequences

- A global allow can't override a narrower deny. Only removing or changing that deny does.
- Each cache hit pays one policy evaluation per CNAME target.
- **To review:** the tier order lets a broad suffix or regex allow beat a narrower exact deny within
  the same scope (spec section 13).

## Implementation note

Suffix matching probes a hash map once per label rather than walking the reversed-label trie named in
spec section 3.5. The matching behavior is the same and the code is simpler. Revisit this if memory
measurements on large lists favor a trie.
