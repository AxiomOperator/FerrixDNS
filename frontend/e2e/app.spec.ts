import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

import { type Node, RCODE, startNode } from "./harness";

const PASSWORD = "correct horse battery";
const SHOTS = process.env.E2E_SCREENSHOTS;

test.describe.configure({ mode: "serial" });

let node: Node;
let page: Page;
const consoleErrors: string[] = [];

test.beforeAll(async ({ browser }) => {
  node = await startNode();
  const context = await browser.newContext({ baseURL: node.webUrl, colorScheme: "light" });
  page = await context.newPage();
  page.on("console", (message) => {
    if (message.type() === "error" && !message.text().includes("status of 4")) {
      consoleErrors.push(message.text());
    }
  });
  page.on("pageerror", (error) => consoleErrors.push(error.message));
});

test.afterAll(async () => {
  await page.context().close();
  await node.stop();
});

async function checkPage(name: string) {
  // Colors measured mid-transition aren't what people end up seeing.
  await page.evaluate(() =>
    Promise.all(document.getAnimations().map((animation) => animation.finished.catch(() => null))),
  );
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true });
  // Toasts fade in, so their contrast measures low mid-animation. They use normal text colors.
  const results = await new AxeBuilder({ page })
    .exclude("[data-sonner-toaster]")
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  const summary = results.violations.map(
    (violation) =>
      `${violation.id}: ${violation.nodes.map((item) => item.target.join(" ")).slice(0, 3).join(" | ")}`,
  );
  expect(summary, `accessibility problems on ${name}`).toEqual([]);
}

async function goTo(link: string, heading: string) {
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: link, exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
}

async function sendUntil(name: string, rcode: number) {
  await expect.poll(() => node.rcode(name), { timeout: 10_000 }).toBe(rcode);
}

test("first run requires the setup token, then creates the administrator", async () => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole("heading", { name: "Set up this node" })).toBeVisible();
  await checkPage("setup");

  await page.getByLabel("Setup token").fill("wrong-token");
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Confirm password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create administrator" }).click();
  await expect(page.getByText("That setup token isn't valid")).toBeVisible();

  await page.getByLabel("Setup token").fill(node.setupToken);
  await page.getByRole("button", { name: "Create administrator" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
});

test("a rule added in the dashboard blocks real DNS queries immediately", async () => {
  expect(await node.rcode("blocked-by-rule.example")).toBe(RCODE.NOERROR);

  await goTo("Rules", "Rules");
  await expect(page.getByText("No rules yet")).toBeVisible();
  await checkPage("rules-empty");

  await page.getByRole("button", { name: "Add rule" }).click();
  await page.getByRole("dialog").getByLabel("Domain", { exact: true }).fill("blocked-by-rule.example");
  await page.getByLabel("Reason (optional)").fill("Testing");
  await checkPage("rule-dialog");
  await page.getByRole("dialog").getByRole("button", { name: "Add rule" }).click();
  await expect(page.getByRole("cell", { name: /^blocked-by-rule\.example/ })).toBeVisible();

  expect(await node.rcode("blocked-by-rule.example")).toBe(RCODE.NXDOMAIN);
  expect(await node.rcode("sub.blocked-by-rule.example")).toBe(RCODE.NXDOMAIN);

  await page.locator("#test-domain").fill("x.blocked-by-rule.example");
  await page.getByRole("button", { name: "Test", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Blocked");
  await expect(page.getByRole("status")).toContainText("a domain block rule");
  await checkPage("rules");
});

test("the rule form explains invalid input", async () => {
  await page.getByRole("button", { name: "Add rule" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Add rule" }).click();
  await expect(page.getByText("Enter a domain or pattern")).toBeVisible();

  await page.getByRole("dialog").getByLabel("Domain", { exact: true }).fill("a..b");
  await page.getByRole("dialog").getByRole("button", { name: "Add rule" }).click();
  await expect(page.getByText(/empty label/)).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();
});

test("a rule can be turned off and back on", async () => {
  await page.getByRole("switch", { name: "Enable rule for blocked-by-rule.example" }).click();
  await sendUntil("blocked-by-rule.example", RCODE.NOERROR);
  await page.getByRole("switch", { name: "Enable rule for blocked-by-rule.example" }).click();
  await sendUntil("blocked-by-rule.example", RCODE.NXDOMAIN);
});

test("a downloaded blocklist applies, and failures are reported", async () => {
  node.lists.set("/hosts", "0.0.0.0 listed-ad.example\n0.0.0.0 ads-target.example\nnot a valid line\n");
  await goTo("Sources", "Sources");
  await page.getByRole("button", { name: "Add source" }).click();
  await page.getByLabel("Name").fill("Test blocklist");
  await page.getByLabel("URL").fill(`${node.listBaseUrl}/hosts`);
  await checkPage("list-dialog");
  await page.getByRole("dialog").getByRole("button", { name: "Add source" }).click();

  const row = page.getByRole("row", { name: /Test blocklist/ });
  await expect(row.getByText("Up to date")).toBeVisible({ timeout: 15_000 });
  await expect(row).toContainText("1 lines skipped");
  await checkPage("lists");

  expect(await node.rcode("listed-ad.example")).toBe(RCODE.NXDOMAIN);
  // The upstream answers this with a CNAME to a listed name.
  expect(await node.rcode("alias.harmless.example")).toBe(RCODE.NXDOMAIN);

  node.lists.delete("/hosts");
  await row.getByRole("button", { name: "Check Test blocklist for updates" }).click();
  await expect(row.getByText("Update failed")).toBeVisible({ timeout: 15_000 });
  await expect(row).toContainText("HTTP 404");
  expect(await node.rcode("listed-ad.example")).toBe(RCODE.NXDOMAIN);
});

test("the overview reports real traffic", async () => {
  await goTo("Overview", "Overview");
  await page.reload();
  await expect(page.getByText("Total queries")).toBeVisible();
  const blocked = page.locator("div", { has: page.getByText("Blocked", { exact: true }) }).last();
  await expect(blocked).not.toContainText(/^Blocked0/);
  await expect(page.getByText("blocked-by-rule.example").first()).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("127.0.0.1").first()).toBeVisible();
  await expect(page.getByRole("img", { name: /Line chart of queries/ })).toBeVisible();
  await page.waitForTimeout(500);
  await checkPage("overview");

  // It keeps up on its own, without a reload.
  const total = page.locator("div", { has: page.getByText("Total queries", { exact: true }) }).last();
  const before = await total.textContent();
  await node.rcode("overview-live.example");
  await expect(total).not.toHaveText(before ?? "", { timeout: 5_000 });

  await page.getByRole("button", { name: "Show table" }).click();
  await expect(page.getByRole("columnheader", { name: "Answered" })).toBeVisible();
  await page.getByRole("button", { name: "Show chart" }).click();
});

test("the query explorer filters, updates live and explains blocks", async () => {
  await goTo("Query Explorer", "Query Explorer");
  const log = page.getByRole("region", { name: "Query log" });
  await expect(log.getByText("blocked-by-rule.example").first()).toBeVisible();
  await checkPage("queries");

  await node.rcode("live-update.example");
  await expect(log.getByText("live-update.example").first()).toBeVisible();

  await page.getByLabel("Result").selectOption("blocked");
  await expect(page).toHaveURL(/action=blocked/);
  await expect(log.getByText("live-update.example")).toHaveCount(0);

  await log.getByRole("button", { name: /alias\.harmless\.example/ }).first().click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).toContainText("Test blocklist");
  await expect(drawer).toContainText("ads-target.example");
  await expect(drawer).toContainText("through a CNAME");
  await drawer.getByRole("button", { name: "Close" }).click();

  await log.getByRole("button", { name: /listed-ad\.example/ }).first().click();
  await checkPage("query-drawer");
  await drawer.getByLabel("Reason").fill("Needed for testing");
  await drawer.getByRole("button", { name: "Allow domain" }).click();
  await expect(page.getByText("listed-ad.example is now allowed")).toBeVisible();
  expect(await node.rcode("listed-ad.example")).toBe(RCODE.NOERROR);

  await goTo("Rules", "Rules");
  await expect(page.getByRole("cell", { name: /^listed-ad\.example/ })).toContainText("Needed for testing");
});

test("clients can be named and given their own rules", async () => {
  await goTo("Clients", "Clients");
  const row = page.getByRole("row", { name: /127\.0\.0\.1/ });
  await expect(row.getByText("Unnamed")).toBeVisible();
  await checkPage("clients");
  await row.getByRole("button", { name: "Name client" }).click();
  await page.locator("#client-name").fill("Test laptop");
  await page.getByLabel("Groups (optional)").fill("testers");
  await page.getByRole("button", { name: "Save client" }).click();
  await expect(page.getByRole("cell", { name: "Test laptop", exact: true })).toBeVisible();

  await goTo("Rules", "Rules");
  await page.getByRole("button", { name: "Add rule" }).click();
  await page.getByRole("dialog").getByLabel("Domain", { exact: true }).fill("group-rule.example");
  await page.locator("#rule-scope").selectOption("group");
  await page.locator("#rule-scope-id").selectOption("testers");
  await page.getByRole("dialog").getByRole("button", { name: "Add rule" }).click();
  await expect(page.getByRole("cell", { name: "Group: testers" })).toBeVisible();
  expect(await node.rcode("group-rule.example")).toBe(RCODE.NXDOMAIN);

  await goTo("Groups", "Groups");
  const group = page.getByRole("row", { name: /testers/ });
  await expect(group).toBeVisible();
  await checkPage("groups");
  await group.getByRole("button", { name: "Delete testers" }).click();
  await page.getByRole("button", { name: "Delete group" }).click();
  await expect(page.getByText(/still use this group/).first()).toBeVisible();
});

test("upstreams can be tested", async () => {
  await goTo("Upstreams", "Upstreams");
  await page.getByRole("button", { name: "Test upstreams" }).click();
  await expect(page.getByRole("status")).toContainText("Reachable");
  await checkPage("upstreams");
});

test("local DNS answers from zones, and lists can't block local names", async () => {
  await goTo("Local DNS", "Local DNS");
  await expect(page.getByText("No local zones yet")).toBeVisible();
  await checkPage("local-dns-empty");

  expect(await node.rcode("printer.home.arpa")).toBe(RCODE.NXDOMAIN);

  await page.locator("#zone-name").fill("home.arpa");
  await page.getByRole("button", { name: "Add zone" }).click();
  await expect(page.getByRole("cell", { name: "home.arpa", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Add record" }).click();
  await checkPage("record-dialog");
  await page.locator("#record-name").fill("nas.home.arpa");
  await page.locator("#record-value").fill("not an address");
  await page.getByRole("dialog").getByRole("button", { name: "Save record" }).click();
  await expect(page.getByText(/isn't an IPv4 address/).first()).toBeVisible();

  await page.locator("#record-value").fill("192.168.1.10");
  await page.getByRole("dialog").getByRole("button", { name: "Save record" }).click();
  await expect(page.getByRole("cell", { name: "nas.home.arpa", exact: true })).toBeVisible();
  await checkPage("local-dns");

  expect(await node.rcode("nas.home.arpa")).toBe(RCODE.NOERROR);
  expect(await node.rcode("ghost.home.arpa")).toBe(RCODE.NXDOMAIN);

  await goTo("Query Explorer", "Query Explorer");
  const log = page.getByRole("region", { name: "Query log" });
  await expect(log.getByRole("button", { name: /nas\.home\.arpa/ }).first()).toContainText("Local");
});

test("the cache page shows activity and can be flushed", async () => {
  await node.rcode("cached-page.example");
  await node.rcode("cached-page.example");

  await goTo("Query Explorer", "Query Explorer");
  const log = page.getByRole("region", { name: "Query log" });
  await expect(log.getByRole("button", { name: /Cached.*cached-page\.example/ }).first()).toBeVisible();

  await goTo("Cache", "Cache");
  await expect(page.getByText("Hit rate")).toBeVisible();
  await checkPage("cache");
  await page.getByRole("button", { name: "Flush cache" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Flush cache" }).click();
  await expect(page.getByText("Cache flushed")).toBeVisible();
});

test("settings change how blocks are answered", async () => {
  await goTo("Settings", "Settings");
  await checkPage("settings");
  await page.getByLabel("Response").selectOption("zero_address");
  await page.getByRole("button", { name: "Save settings" }).click();
  await expect(page.getByText("Settings saved and active")).toBeVisible();
  expect(await node.rcode("blocked-by-rule.example")).toBe(RCODE.NOERROR);

  await page.getByLabel("Response").selectOption("nxdomain");
  await page.getByRole("button", { name: "Save settings" }).click();
  await sendUntil("blocked-by-rule.example", RCODE.NXDOMAIN);
});

test("settings update live, without replacing unsaved edits", async () => {
  await goTo("Settings", "Settings");
  const other = await page.context().newPage();
  await other.goto("/settings");
  const response = page.getByLabel("Response");
  await expect(response).toHaveValue("nxdomain");

  await other.getByLabel("Response").selectOption("zero_address");
  await other.getByRole("button", { name: "Save settings" }).click();
  await expect(response).toHaveValue("zero_address", { timeout: 5_000 });

  await page.getByLabel("Client cache time (seconds)").fill("123");
  await other.getByLabel("Response").selectOption("nxdomain");
  await other.getByRole("button", { name: "Save settings" }).click();
  await expect(other.getByText("Settings saved and active").last()).toBeVisible();
  await page.waitForTimeout(3_000);
  await expect(page.getByLabel("Client cache time (seconds)")).toHaveValue("123");
  await expect(response).toHaveValue("zero_address");

  await other.close();
  await page.reload();
  await expect(response).toHaveValue("nxdomain");
});

test("policy history can restore an earlier revision", async () => {
  await goTo("System", "System");
  await checkPage("system");
  await expect(page.getByText("Added a rule").first()).toBeVisible();
  expect(await node.rcode("group-rule.example")).toBe(RCODE.NXDOMAIN);

  // The node keeps three revisions, and the two settings saves are the newest. Restoring the
  // oldest of them goes back to before the second save.
  await page.getByRole("button", { name: "Restore" }).last().click();
  await page.getByRole("button", { name: "Restore revision" }).click();
  await expect(page.getByText("Revision restored and active")).toBeVisible();
  await expect(page.getByText("Active").first()).toBeVisible();
});

test("a backup can be downloaded, checked and restored", async () => {
  await goTo("System", "System");
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download backup" }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/^ferrixdns-backup-.*\.tar\.gz$/);
  const path = await file.path();
  expect(path).toBeTruthy();

  // Removing a rule after the backup means restoring it has a visible effect.
  await goTo("Rules", "Rules");
  await page.getByRole("button", { name: "Delete rule for blocked-by-rule.example" }).click();
  await page.getByRole("button", { name: "Delete rule" }).click();
  await sendUntil("blocked-by-rule.example", RCODE.NOERROR);

  await goTo("System", "System");
  await page.getByLabel("Backup file to restore").setInputFiles(path);
  await expect(page.getByText("This backup is valid")).toBeVisible();
  await checkPage("backup-preview");
  expect(await node.rcode("blocked-by-rule.example"), "checking must not change anything").toBe(RCODE.NOERROR);

  await page.getByRole("button", { name: "Restore this backup" }).click();
  await expect(page.getByText("Backup restored and active")).toBeVisible();
  await sendUntil("blocked-by-rule.example", RCODE.NXDOMAIN);

  // A corrupt file is reported and changes nothing.
  await page.getByLabel("Backup file to restore").setInputFiles({
    name: "bad.tar.gz",
    mimeType: "application/gzip",
    buffer: Buffer.from("not a backup"),
  });
  await expect(page.getByText(/isn't a readable backup/).first()).toBeVisible();
});

test("blocking can be paused for a set time and resumed", async () => {
  await goTo("Rules", "Rules");
  await page.getByRole("button", { name: "Add rule" }).click();
  await page.getByRole("dialog").getByLabel("Domain", { exact: true }).fill("paused-rule.example");
  await page.getByRole("dialog").getByRole("button", { name: "Add rule" }).click();
  await expect(page.getByRole("cell", { name: "paused-rule.example", exact: true })).toBeVisible();
  expect(await node.rcode("paused-rule.example")).toBe(RCODE.NXDOMAIN);

  await page.getByRole("button", { name: "Pause blocking" }).click();
  await expect(page.getByRole("dialog")).toContainText("Emergency rules stay on");
  await checkPage("pause-dialog");
  await page.getByRole("dialog").getByRole("button", { name: "5 minutes" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Blocking paused" })).toContainText(/4m|5m/);
  await checkPage("paused");
  expect(await node.rcode("paused-rule.example")).toBe(RCODE.NOERROR);

  await page.getByRole("button", { name: "Resume" }).click();
  await expect(page.getByRole("button", { name: "Pause blocking" })).toBeVisible();
  expect(await node.rcode("paused-rule.example")).toBe(RCODE.NXDOMAIN);
});

test("the network page lists devices", async () => {
  await goTo("Network", "Network");
  const row = page.getByRole("row", { name: /127\.0\.0\.1/ });
  await expect(row).toBeVisible();
  await checkPage("network");
});

test("conditional forwarding can be added, and bad servers are explained", async () => {
  await goTo("Conditional forwarding", "Conditional forwarding");
  await checkPage("forwarders-empty");
  await page.getByRole("button", { name: "Add forwarding" }).click();
  await page.getByLabel("Domains and networks").fill("forwarded.test, 192.168.77.0/24");
  await page.getByLabel("Servers").fill("not a server");
  await page.getByRole("button", { name: "Save forwarding" }).click();
  await expect(page.getByText(/forward zone/).first()).toBeVisible();

  // The scripted upstream stands in for a router, so its answer proves the route was used. The
  // default upstream would have been asked anyway for a public name, but not for this one.
  await page.getByLabel("Servers").fill(`127.0.0.1:${node.upstreamPort}, 127.0.0.1:${node.upstreamPort + 1}`);
  await page.getByRole("switch", { name: "Load balance" }).click();
  await page.getByRole("button", { name: "Save forwarding" }).click();
  const row = page.getByRole("row", { name: /forwarded\.test/ });
  await expect(row).toContainText("(load balanced)");
  await row.getByRole("button", { name: /Edit/ }).click();
  await expect(page.getByRole("switch", { name: "Load balance" })).toBeChecked();
  await page.getByLabel("Servers").fill(`127.0.0.1:${node.upstreamPort}`);
  await page.getByRole("button", { name: "Save forwarding" }).click();
  await expect(row).not.toContainText("(load balanced)");
  expect(await node.rcode("nas.forwarded.test")).toBe(RCODE.NOERROR);
  // A private reverse lookup stays on this node until a network is forwarded.
  expect(await node.rcode("5.77.168.192.in-addr.arpa")).toBe(RCODE.NOERROR);
  expect(await node.rcode("5.78.168.192.in-addr.arpa")).toBe(RCODE.NXDOMAIN);
  await page.reload();
  await expect(row.getByRole("cell").nth(2)).not.toHaveText("0");
  await checkPage("forwarders");

  await row.getByRole("button", { name: /Remove/ }).click();
  await page.getByRole("button", { name: "Remove forwarding" }).click();
  await expect(page.getByText("Nothing is forwarded yet")).toBeVisible();
});

test("a device over the query limit is refused, and the query log says why", async () => {
  await goTo("Settings", "Settings");
  await page.getByLabel("Queries per minute, for each address").fill("20");
  await page.getByLabel("Addresses with no limit").fill("");
  await page.getByRole("button", { name: "Save settings" }).click();
  await expect(page.getByText("Settings saved and active").first()).toBeVisible();

  const results: number[] = [];
  for (let index = 0; index < 40; index++) results.push(await node.rcode(`flood-${index}.example`));
  expect(results).toContain(RCODE.REFUSED);
  expect(results[0]).toBe(RCODE.NOERROR);

  await goTo("Query Explorer", "Query Explorer");
  await page.getByLabel("Result").selectOption("rate_limited");
  await expect(page.locator("span", { hasText: "Rate limited" }).first()).toBeVisible();

  await goTo("System", "System");
  await expect(page.getByText("Queries over limit").locator("..")).not.toContainText(/\b0$/);

  await goTo("Settings", "Settings");
  await page.getByLabel("Queries per minute, for each address").fill("3000");
  await page.getByLabel("Addresses with no limit").fill("127.0.0.0/8, ::1/128");
  await page.getByRole("button", { name: "Save settings" }).click();
  await sendUntil("after-the-flood.example", RCODE.NOERROR);
});

test("the time server answers and reports its state", async () => {
  const reply = await node.ntp();
  expect(reply.length).toBe(48);
  expect((reply[0] ?? 0) & 7).toBe(4);
  // Seconds since 1900, which only needs to be close to prove this is a real clock.
  const seconds = reply.readUInt32BE(40) - 2_208_988_800;
  expect(Math.abs(seconds - Date.now() / 1000)).toBeLessThan(60);

  await goTo("System", "System");
  const card = page.getByText("Time server").locator("xpath=ancestor::*[.//dl][1]");
  await expect(card).toContainText("NTP listeners");
  await checkPage("system-ntp");
});

test("dark mode and small screens work", async () => {
  await goTo("Settings", "Settings");
  await page.getByRole("tab", { name: "Account" }).click();
  await page.getByLabel("Theme").selectOption("dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await checkPage("settings-dark");
  await goTo("Overview", "Overview");
  await page.waitForTimeout(500);
  await checkPage("overview-dark");
  await goTo("Rules", "Rules");
  await checkPage("rules-dark");

  await page.setViewportSize({ width: 360, height: 740 });
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Overview" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
  await page.waitForTimeout(500);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(overflow, "the page must not scroll sideways at 360px").toBe(false);
  await checkPage("overview-mobile");

  // The paused controls are the widest thing in the header.
  await page.getByRole("button", { name: "Pause blocking" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "5 minutes" }).click();
  await expect(page.getByRole("button", { name: "Resume" })).toBeVisible();
  const pausedOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(pausedOverflow, "the paused header must fit at 360px").toBe(false);
  await checkPage("paused-mobile");
  await page.getByRole("button", { name: "Resume" }).click();

  await page.setViewportSize({ width: 1280, height: 800 });
  await goTo("Settings", "Settings");
  await page.getByRole("tab", { name: "Account" }).click();
  await page.getByLabel("Theme").selectOption("light");
});

test("signing out and back in works, and sign-in failures are explained", async () => {
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await checkPage("login");
  await page.goto("/queries");
  await expect(page).toHaveURL(/\/login$/);

  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("not the password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("That username or password isn't right")).toBeVisible();

  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
});

test("every node setting can be changed from the dashboard", async ({ browser }) => {
  const own = await startNode({ fixedPorts: true });
  const context = await browser.newContext({ baseURL: own.webUrl, colorScheme: "light" });
  const settingsPage = await context.newPage();
  try {
    await settingsPage.goto("/");
    await settingsPage.getByLabel("Setup token").fill(own.setupToken);
    await settingsPage.getByLabel("Username").fill("admin");
    await settingsPage.getByLabel("Password", { exact: true }).fill(PASSWORD);
    await settingsPage.getByLabel("Confirm password").fill(PASSWORD);
    await settingsPage.getByRole("button", { name: "Create administrator" }).click();
    await settingsPage.getByRole("link", { name: "Settings" }).click();

    const openTab = (name: string) => settingsPage.getByRole("tab", { name }).click();
    const expectFields = async (labels: string[]) => {
      for (const label of labels) {
        await expect(settingsPage.getByLabel(label, { exact: true })).toBeVisible();
      }
    };
    const save = async () => {
      await settingsPage.getByRole("button", { name: "Save and restart" }).click();
      await settingsPage.getByRole("button", { name: "Save and restart" }).last().click();
    };

    await openTab("DNS");
    await settingsPage.getByText("Time limits and capacity").click();
    await expectFields([
      "DNS addresses",
      "Networks allowed to query",
      "Servers",
      "Time for one server (ms)",
      "Time for a whole query (ms)",
      "Requests in flight",
      "Memory (MiB)",
      "Longest time to keep an answer (seconds)",
      'Longest time to keep "not found" (seconds)',
    ]);
    await expect(settingsPage.getByRole("switch", { name: "DNSSEC validation" })).toBeVisible();
    await expect(settingsPage.getByRole("switch", { name: "Load balance" })).toBeVisible();
    await openTab("Dashboard");
    await expectFields(["Address", "Names it answers to", "TLS"]);
    await expect(settingsPage.getByRole("switch", { name: "Allow plain HTTP on a network address" })).toBeVisible();
    await openTab("System");
    await expectFields(["NTP addresses", "Policy file on this node", "Data folder", "Log filter"]);
    await expect(
      settingsPage.getByRole("switch", { name: "Allow list downloads from private addresses" }),
    ).toBeVisible();

    // The save button only appears with something to save, and edits survive changing tabs.
    await openTab("DNS");
    await expect(settingsPage.getByRole("button", { name: "Save and restart" })).toBeHidden();
    await settingsPage.getByLabel("Memory (MiB)").fill("9");
    await openTab("System");
    await expect(settingsPage.getByRole("tab", { name: /DNS.*unsaved/ })).toBeVisible();
    await settingsPage.getByRole("button", { name: "Discard" }).click();
    await openTab("DNS");
    await expect(settingsPage.getByLabel("Memory (MiB)")).not.toHaveValue("9");

    // A mistake is explained and changes nothing.
    await settingsPage.getByLabel("Servers", { exact: true }).fill("dns.google");
    await save();
    await expect(settingsPage.getByText(/isn't an upstream/)).toBeVisible();

    // A real change restarts the node, and the dashboard comes back by itself.
    await settingsPage.getByLabel("Servers", { exact: true }).fill("127.0.0.1:9");
    await settingsPage.getByLabel("Memory (MiB)").fill("8");
    await save();
    await expect(settingsPage.getByText("Settings saved and active")).toBeVisible({ timeout: 30_000 });
    expect(await own.rcode("after-restart.example")).toBe(RCODE.SERVFAIL);
    await expect(settingsPage.getByLabel("Memory (MiB)")).toHaveValue("8");
    await settingsPage.getByRole("link", { name: "Upstreams" }).click();
    await expect(settingsPage.getByRole("cell", { name: "127.0.0.1:9" })).toBeVisible();

    // A change to dashboard access must be kept.
    await settingsPage.getByRole("link", { name: "Settings" }).click();
    await openTab("Dashboard");
    await settingsPage.getByLabel("Names it answers to").fill("dns.home.arpa");
    await save();
    await expect(settingsPage.getByText(/Keep the change to dashboard access/)).toBeVisible({
      timeout: 30_000,
    });
    if (SHOTS) {
      await settingsPage.screenshot({ path: `${SHOTS}/settings-dashboard.png` });
      await openTab("DNS");
      await settingsPage.screenshot({ path: `${SHOTS}/settings-dns.png` });
      await openTab("System");
      await settingsPage.screenshot({ path: `${SHOTS}/settings-system.png` });
      await settingsPage.setViewportSize({ width: 390, height: 800 });
      await openTab("DNS");
      await settingsPage.screenshot({ path: `${SHOTS}/settings-dns-mobile.png` });
      await settingsPage.setViewportSize({ width: 1280, height: 720 });
      await openTab("Dashboard");
    }
    const axe = await new AxeBuilder({ page: settingsPage })
      .exclude("[data-sonner-toaster]")
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(axe.violations.map((violation) => violation.id)).toEqual([]);
    await settingsPage.getByRole("button", { name: "Keep change" }).click();
    await expect(settingsPage.getByText(/Keep the change to dashboard access/)).toBeHidden();
    await expect(settingsPage.getByLabel("Names it answers to")).toHaveValue("dns.home.arpa");

    // Going back to the startup values is one step.
    await openTab("System");
    await settingsPage.getByRole("button", { name: "Use startup values" }).click();
    await save();
    await expect(settingsPage.getByText(/Keep the change to dashboard access/)).toBeVisible({
      timeout: 30_000,
    });
    await settingsPage.getByRole("button", { name: "Undo" }).click();
    await openTab("Dashboard");
    await expect(settingsPage.getByLabel("Names it answers to")).toHaveValue("dns.home.arpa", {
      timeout: 30_000,
    });
  } finally {
    await context.close();
    await own.stop();
  }
});

test("the browser reported no unexpected errors", () => {
  expect(consoleErrors).toEqual([]);
});
