# Central controller and node-only deployment

A controller manages the policy of many nodes from one dashboard. It serves no DNS. Nodes connect out
to it, so it needs no way into their networks, and nothing a node does for a DNS query waits for it. If
the controller is down, nodes keep enforcing the last policy they applied, including across restarts.

Standalone nodes still work as before. A controller is optional.

| What runs | Deploy with | Has a dashboard | Serves DNS |
|---|---|---|---|
| Standalone node | `scripts/docker-deploy.sh` | Yes, its own | Yes |
| Controller | `scripts/docker-deploy.sh --controller` | Yes, for the fleet | No |
| Node-only | `scripts/docker-deploy.sh --node-only` | No | Yes |

## Setting it up

1. **Start the controller**, on a machine the nodes can reach:

   ```sh
   sudo scripts/docker-deploy.sh --controller --address 10.0.0.2
   ```

   This prints the dashboard address and a setup token. Nodes reach it at `https://10.0.0.2:8444` unless
   you set `FERRIXDNS_PUBLIC_URL`, such as to a name. Set it before creating tokens, because they carry it.

2. **Add a site** under **Sites**. Each site has its own policy, and its nodes all enforce it. **Edit
   policy** opens the same Rules, Sources, Blocked services, Groups, Clients, Local DNS and Conditional
   forwarding pages a node has.

3. **Add a node.** Under **Nodes**, choose **Add node**, then run what it shows on the new server:

   ```sh
   sudo FERRIXDNS_ENROLL_TOKEN=fxn1_... scripts/docker-deploy.sh --node-only --address 10.0.0.5
   ```

   Set `FERRIXDNS_UPSTREAM` the same way to choose its upstream servers. The token works once, and only
   for as long as you chose. It also tells the node how to recognize the controller, so keep it private.

4. **Deploy.** Changes to a site do nothing until you deploy them, from **Sites**. **Deployments** shows
   how far each node has got.

To run a node-only node from a package instead, add these to `/etc/ferrixdns/ferrixdns.env`:

```sh
FERRIXDNS_NO_WEB=true
FERRIXDNS_ENROLL_TOKEN=fxn1_...
```

An existing standalone node can also join by adding the token, and can keep its dashboard. Its policy
becomes read-only there, and its current policy is replaced at the first deployment.

## How a deployment works

Deploying signs the site's policy and lists into a numbered bundle. Each node then:

1. Checks the bundle's signature, that it's for its site, and that its number is higher than what it has.
2. Downloads the files and checks each against the hash in the signed manifest.
3. Validates and compiles the policy. If that fails, the old policy keeps serving and the node reports `Failed`.
4. Makes it active and checks its DNS still answers. If not, it goes back and reports `Went back`.

A node doesn't try a bundle again once it has failed or gone back.

**One node first** sends a deployment to one node. The others follow if it's healthy, and stay where they
are if it isn't. **Send to all nodes now** skips the wait, for example if that node is offline.

**Go back to this** sends a site back to an earlier deployment. It's a new deployment with a higher number,
so nodes accept it. The policy being edited stays as it was, and shows as not deployed.

**List updates:** the controller downloads lists, and nodes never contact list sources. When a download
changes and nothing else has, the update deploys by itself. Turn this off for a site with **Deploy by
themselves** under **Sites**.

## What reaches the controller

Each node reports its version, health, cache and upstream figures, and query counts per minute and result.
Query names and device addresses stay on the node. These appear on the fleet **Overview** and under
**Nodes**. There's no metrics endpoint to scrape, because all of this lives in the dashboard.

A node's own query log isn't visible from the controller. A node-only node keeps it on disk, and it isn't
reachable without a dashboard, so choose a standalone node where you need to look through queries.

## What stays on each node

Listening addresses, allowed networks, upstream servers, DNSSEC and cache settings aren't part of a site's
policy. On a node-only node, change them by deploying again with new values.

## Removing a node

**Remove** under **Nodes** stops the node from reaching the controller. It keeps serving DNS with the last
policy it applied, and it logs that it was removed. To bring it back, delete the `agent` folder in its
state directory and give it a new token.

## Certificates

By default the controller uses a self-signed certificate. Tokens carry its fingerprint, so nodes accept
exactly that certificate. Browsers warn about it, so check the fingerprint in the log. If you delete it, every
node needs a new token.

With `FERRIXDNS_WEB_TLS_CERT` and `FERRIXDNS_WEB_TLS_KEY` on the controller, nodes check the certificate like
a browser would. If a private authority signed it, give nodes that authority's certificate with
`FERRIXDNS_CONTROLLER_CA`.

Nodes refuse plain HTTP, except to a controller on the same machine.

## Backing up

Stop the controller and copy its `ferrixdns-controller-data` volume. It holds the signing key, so treat the
copy like a password: whoever has it can direct every node. Nodes only accept bundles signed by that key, so
losing it means every node needs a new token.

## Current limits

- One administrator role. Roles for different people, and single sign-on, aren't built yet.
- Each site's policy stands alone. A new site can start from a copy, but there's no shared global policy.
- The signing key can't be rotated without giving every node a new token.
- A list update deploys without the size checks the design describes for holding back unusual changes.
- A node reports in every 10 seconds, so changes take up to that long to reach it. Change it with
  `FERRIXDNS_CONTROLLER_SYNC_SECONDS`.
- Packages don't include a service for the controller yet, so use the container or run
  `ferrixdns controller` yourself.
