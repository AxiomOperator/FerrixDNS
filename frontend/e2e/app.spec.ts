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

test("dark mode and small screens work", async () => {
  await goTo("Settings", "Settings");
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

  await page.setViewportSize({ width: 1280, height: 800 });
  await goTo("Settings", "Settings");
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

test("the browser reported no unexpected errors", () => {
  expect(consoleErrors).toEqual([]);
});
