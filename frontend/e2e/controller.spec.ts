import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

import { type Controller, type NodeOnly, RCODE, startController, startNodeOnly } from "./harness";

const PASSWORD = "correct horse battery";
const SHOTS = process.env.E2E_SCREENSHOTS;

test.describe.configure({ mode: "serial" });

let controller: Controller;
let node: NodeOnly | undefined;
let page: Page;
const consoleErrors: string[] = [];

test.beforeAll(async ({ browser }) => {
  controller = await startController();
  const context = await browser.newContext({
    baseURL: controller.url,
    ignoreHTTPSErrors: true,
    colorScheme: "light",
    permissions: ["clipboard-read", "clipboard-write"],
  });
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
  await node?.stop();
  await controller.stop();
});

async function checkPage(name: string) {
  await page.evaluate(() =>
    Promise.all(document.getAnimations().map((animation) => animation.finished.catch(() => null))),
  );
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/controller-${name}.png`, fullPage: true });
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

test("the controller is set up like a node, and shows the fleet instead of DNS pages", async () => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole("heading", { name: "Set up this controller" })).toBeVisible();
  await page.getByLabel("Setup token").fill(controller.setupToken);
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Confirm password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create administrator" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Fleet overview" })).toBeVisible();
  await expect(page.getByText("Nothing is set up yet")).toBeVisible();
  await checkPage("overview-empty");

  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("link", { name: "Query Explorer" })).toHaveCount(0);
  await expect(nav.getByRole("link", { name: "Upstreams" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Pause/ })).toHaveCount(0);
});

test("a site's policy is edited with the normal pages", async () => {
  await goTo("Sites", "Sites");
  await expect(page.getByText("No sites yet")).toBeVisible();
  await page.getByRole("button", { name: "Add site" }).click();
  await page.getByLabel("Name").fill("Main office");
  await page.getByRole("dialog").getByRole("button", { name: "Add site" }).click();
  await expect(page.getByRole("cell", { name: "Main office" })).toBeVisible();
  await checkPage("sites");

  await page.getByRole("button", { name: "Edit policy" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Rules" })).toBeVisible();
  await expect(page.getByText("Editing")).toBeVisible();
  await page.getByRole("button", { name: /Add rule/ }).first().click();
  await page.getByRole("dialog").getByLabel("Domain", { exact: true }).fill("managed-block.example");
  await page.getByRole("dialog").getByRole("button", { name: /Add rule|Save/ }).click();
  await expect(page.getByRole("cell", { name: "managed-block.example", exact: true })).toBeVisible();
  await expect(page.getByText("These changes haven't been deployed")).toBeVisible();
  await checkPage("site-rules");

  await goTo("Blocked services", "Blocked services");
  await page.getByLabel("Search services").fill("tiktok");
  await page.getByRole("switch", { name: "Block TikTok" }).click();
  await expect(page.getByRole("status")).toHaveText("1 service blocked");
});

test("a node with no dashboard joins with a token and enforces what's deployed", async () => {
  await goTo("Nodes", "Nodes");
  await expect(page.getByText("No nodes yet")).toBeVisible();
  await page.getByRole("button", { name: "Add node" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Create token" }).click();
  const token = await page.getByRole("dialog").locator("pre").first().innerText();
  expect(token).toMatch(/^fxn1_/);
  await expect(page.getByRole("dialog").getByText("--node-only")).toBeVisible();
  await checkPage("add-node");
  await page.getByRole("dialog").getByRole("button", { name: "Done" }).click();

  node = await startNodeOnly(token.trim(), "branch-dns-1");
  await expect(page.getByRole("cell", { name: "branch-dns-1", exact: true })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole("row", { name: /branch-dns-1/ }).getByText("Online")).toBeVisible({ timeout: 15_000 });
  await checkPage("nodes");

  // No dashboard means nothing is listening, even though an address was given.
  await expect(fetch(`http://127.0.0.1:${node.webPort}/`)).rejects.toThrow();

  const dns = node;
  expect(await dns.rcode("managed-block.example")).toBe(RCODE.NOERROR);
  await goTo("Sites", "Sites");
  await page.getByRole("button", { name: "Deploy", exact: true }).click();
  await page.getByLabel("Reason (optional)").fill("First policy");
  await page.getByRole("dialog").getByRole("button", { name: "Deploy" }).click();

  await expect.poll(() => dns.rcode("managed-block.example"), { timeout: 20_000 }).toBe(RCODE.NXDOMAIN);
  await expect.poll(() => dns.rcode("www.tiktok.com"), { timeout: 5_000 }).toBe(RCODE.NXDOMAIN);

  await goTo("Deployments", "Deployments");
  await expect(page.getByText("Succeeded")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole("row", { name: /branch-dns-1/ }).getByText("Healthy")).toBeVisible();
  await checkPage("deployments");
});

test("metrics reach the fleet overview, and a deployment can be rolled back", async () => {
  const dns = node;
  if (!dns) throw new Error("the node isn't running");
  await dns.rcode("some-traffic.example");

  await goTo("Sites", "Sites");
  await page.getByRole("button", { name: "Edit policy" }).click();
  await page.getByRole("button", { name: /Add rule/ }).first().click();
  await page.getByRole("dialog").getByLabel("Domain", { exact: true }).fill("second-change.example");
  await page.getByRole("dialog").getByRole("button", { name: /Add rule|Save/ }).click();
  await expect(page.getByRole("cell", { name: "second-change.example", exact: true })).toBeVisible();
  await goTo("Sites", "Sites");
  await expect(page.getByText("Not deployed")).toBeVisible();
  await page.getByRole("button", { name: "Deploy", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Deploy" }).click();
  await expect.poll(() => dns.rcode("second-change.example"), { timeout: 20_000 }).toBe(RCODE.NXDOMAIN);

  await goTo("Deployments", "Deployments");
  await page.getByRole("button", { name: "Go back to this, generation 1" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Go back" }).click();
  await expect.poll(() => dns.rcode("second-change.example"), { timeout: 20_000 }).toBe(RCODE.NOERROR);
  expect(await dns.rcode("managed-block.example")).toBe(RCODE.NXDOMAIN);

  await goTo("Activity", "Activity");
  await expect(page.getByText("A node joined")).toBeVisible();
  await expect(page.getByText("Rolled back a deployment")).toBeVisible();
  await checkPage("activity");

  await goTo("Overview", "Fleet overview");
  await expect(page.getByText("1 of 1")).toBeVisible();
  // Counts arrive once a minute has finished, so this can take a little over a minute.
  await expect
    .poll(() => page.getByRole("row", { name: /branch-dns-1/ }).getByRole("cell").nth(2).innerText(), {
      timeout: 80_000,
    })
    .not.toBe("0");
  await checkPage("overview");
});

test("removing a node doesn't stop it answering DNS", async () => {
  await goTo("Nodes", "Nodes");
  await page.getByRole("button", { name: "Details for branch-dns-1" }).click();
  await expect(page.getByRole("dialog").getByText("Upstream servers")).toBeVisible();
  await checkPage("node-details");
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Remove branch-dns-1" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Remove node" }).click();
  await expect(page.getByText("No nodes yet")).toBeVisible();
  expect(await node?.rcode("managed-block.example")).toBe(RCODE.NXDOMAIN);
});

test("the browser reported no unexpected errors", () => {
  expect(consoleErrors).toEqual([]);
});
