import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";
import { chromium } from "playwright";

const origin = "http://ajar.test";
const dist = new URL("../dist/", import.meta.url);
const network = { interface: "wlan0", subnet: "192.168.1.0/24", ssid: "Office A", gateway: null };
const good = { id: "fixture", source: "import", file: "test.xml", created_at: "2026-11-07T12:00:00Z",
  score: 100, ssid: network.ssid, subnet: network.subnet, error: null, devices: [], findings: [] };

let browser;
before(async () => { browser = await chromium.launch(); });
after(async () => { await browser?.close(); });

// Serve the production bundle and intercept every API request, including scan requests.
async function open(t, hash, { scan = good, offline = false, lang = "en", onApi } = {}) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = [];
  t.after(async () => { await context.close(); assert.deepEqual(errors, []); });
  page.setDefaultTimeout(5000);
  page.on("pageerror", (error) => errors.push(error.message));
  await page.addInitScript((language) => {
    localStorage.setItem("ajar.lang", language);
    localStorage.setItem("ajar.ack.admin", "yes");
    localStorage.setItem("ajar.ack.network", "yes");
    localStorage.setItem("ajar.ack.notify", "yes");
  }, lang);
  await page.route("**/*", async (route) => {
    const { pathname } = new URL(route.request().url());
    if (pathname.startsWith("/api/")) {
      if (offline) return route.fulfill({ status: 503 });
      const reply = await onApi?.(pathname, route.request());
      if (reply) return route.fulfill(reply);
      if (pathname === "/api/history") return route.fulfill({ json: scan ? [{ ...scan, device_count: 0, finding_count: 0 }] : [] });
      if (pathname === "/api/network") return route.fulfill({ json: network });
      if (pathname === `/api/scans/${scan?.id}`) return route.fulfill({ json: scan });
      return route.fulfill({ status: 404 });
    }
    const file = pathname.slice(1) || "index.html";
    const contentType = file.endsWith(".js") ? "application/javascript" : file.endsWith(".css") ? "text/css" : "text/html";
    return route.fulfill({ body: await readFile(new URL(file, dist)), contentType });
  });
  await page.goto(`${origin}/#/${hash}`);
  return page;
}

async function confirmNetwork(page) {
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("checkbox").check();
  await dialog.getByRole("button", { name: "Yes, scan" }).click();
}

test("consent follows fresh detection and a change after consent requires another confirmation", async (t) => {
  let current = { ...network };
  const posts = [];
  const page = await open(t, "scan", { onApi(path, request) {
    if (path === "/api/network") return { json: { ...current, allowlist: [network.subnet], address: "192.168.1.7" } };
    if (path === "/api/scans") { posts.push(request.postDataJSON()); return { json: good }; }
  } });
  await page.getByText("Office A", { exact: true }).waitFor();
  current.ssid = "Office B";
  const start = page.getByRole("button", { name: "Scan this network" });
  await start.click();
  await page.getByRole("dialog").getByText("Office B").waitFor();
  current.ssid = "Office C"; // Same subnet, interface and gateway.
  await confirmNetwork(page);
  await page.getByText(/The network changed/).waitFor();
  assert.deepEqual(posts, []);
  await start.click();
  await page.getByRole("dialog").getByText("Office C").waitFor();
  await confirmNetwork(page);
  await page.waitForURL("**/#/dashboard");
  assert.deepEqual(posts, [{ confirm: true, expected_network: current }]);
});

test("shows bilingual detection and dispatch refusals, including after a retry", async (t) => {
  let blocked = true;
  const page = await open(t, "scan", { onApi(path) {
    if (path === "/api/network" && blocked) return { status: 503, json: { error: "two networks", en: "Disconnect one network.", ro: "Deconectează o rețea." } };
    if (path === "/api/scans") return { status: 403, json: { detail: { error: "refused", en: "Scope refused.", ro: "Rețea refuzată." } } };
  } });
  const alert = page.getByRole("alert");
  await alert.getByText("Disconnect one network.").waitFor();
  await alert.getByText("Deconectează o rețea.").waitFor();
  assert.equal(await page.getByText("The scanner isn't running").count(), 0);
  blocked = false;
  await page.getByRole("button", { name: "Try again" }).click();
  await confirmNetwork(page);
  await alert.getByText("Scope refused.").waitFor();
  await alert.getByText("Rețea refuzată.").waitFor();
});

for (const lang of ["en", "ro"]) {
  test(`offline demo disables XML import and describes only observed services (${lang})`, async (t) => {
    const page = await open(t, "scan", { offline: true, lang });
    await page.getByText(lang === "en" ? /Demo mode shows example scans only/ : /Modul demonstrativ afișează doar exemple/).waitFor();
    assert.equal(await page.locator("input[type=file], .dropzone, .results").count(), 0);
    for (const [ip, evidence] of [
      ["172.20.10.5", lang === "en" ? /did not check whether viewing the stream/ : /Nu a verificat dacă accesul/],
      ["172.20.10.6", lang === "en" ? /did not check who can send commands/ : /Nu a verificat cine poate trimite/],
    ]) {
      await page.goto(`${origin}/#/devices/${ip}`);
      await page.locator(".finding-text").filter({ hasText: evidence }).waitFor();
    }
  });
}

test("an unreadable scan and a scan without a score never show the all-clear message", async (t) => {
  for (const error of ["unreadable", null]) {
    const page = await open(t, "dashboard", { scan: { ...good, score: null, error } });
    await page.getByRole("heading", { name: "Network safety unknown" }).waitFor();
    await page.getByText(error ? /file couldn't be read/ : /This scan has no score/).waitFor();
    assert.equal(await page.locator(".fix-first, section[aria-label='By severity']").count(), 0);
  }
  const page = await open(t, "dashboard");
  await page.getByText("Ajar found no problems in this scan.").waitFor();
});

test("import and history protect filenames, including failures with no API response", async (t) => {
  const names = ["50:C7:BF:39:0C:8C", "50-C7-BF-39-0C-8C", "50c7.bf39.0c8c", "50c7bf390c8c", "mac-202611081200", "T5_202611081200", "fd00::11:22:33:44:55:66"];
  const upload = { name: "office-50-C7-BF-39-0C-8C.xml", mimeType: "application/xml", buffer: Buffer.from("<nmaprun/>") };
  let fail = false;
  const page = await open(t, "scan", { scan: { ...good, file: upload.name }, onApi(path) {
    if (path !== "/api/scans/import") return;
    if (fail) return { status: 500 };
    return { json: names.map((name, i) => ({ file: name + ".xml", scan_id: i ? null : good.id, score: i ? null : 100, error: i ? "unreadable" : null })) };
  } });
  const input = page.locator("input[type=file]");
  await input.setInputFiles(names.map((name) => ({ ...upload, name: name + ".xml" })));
  await page.getByText("T5_202611081200.xml", { exact: true }).waitFor();
  assert.equal(await page.getByText("50:C7:BF:xx:xx:xx.xml", { exact: true }).count(), 4);
  await page.getByText("mac-20:26:11:xx:xx:xx.xml").waitFor();
  await page.getByText("fd00::11:22:33:44:55:66.xml").waitFor();
  fail = true;
  await input.setInputFiles(upload);
  await page.getByText("File 1", { exact: true }).waitFor();
  assert.equal(await page.getByText(upload.name).count(), 0);
  await page.goto(origin + "/#/history");
  await page.locator("summary").filter({ hasText: "All scans" }).click();
  await page.getByText(/office-50:C7:BF:xx:xx:xx.xml/).waitFor();
});

test("a failed history deletion can be retried and a 204 clears the view", async (t) => {
  let deletions = 0;
  const page = await open(t, "history", { onApi(path, request) {
    if (path === "/api/history" && request.method() === "DELETE") return { status: ++deletions === 1 ? 500 : 204 };
  } });
  await page.getByRole("button", { name: "Delete my history" }).click();
  const dialog = page.getByRole("alertdialog");
  const confirm = dialog.getByRole("button", { name: "Delete history" });
  await confirm.click();
  await dialog.getByRole("alert").waitFor();
  assert.equal(await page.locator(".sidebar-recent").count(), 1);
  await confirm.click();
  await page.locator(".welcome").waitFor();
  assert.equal(await page.locator(".sidebar-recent").count(), 0);
  assert.equal(deletions, 2);
});

test("local AI consent can be declined, granted and revoked, including across reloads", async (t) => {
  const questions = [];
  const page = await open(t, "ask", { onApi(path, request) {
    if (path === "/api/ask") {
      questions.push(request.postDataJSON().question);
      return { json: { available: true, can_answer: true, answer: "Fixture reply" } };
    }
  } });
  const input = page.getByRole("textbox");
  await input.fill("First question");
  await input.press("Enter");
  const dialog = page.getByRole("dialog");
  await dialog.getByText(/AI model on this computer/).waitFor();
  await dialog.getByRole("button", { name: "Not now" }).click();
  assert.equal(await input.isDisabled(), true);
  assert.deepEqual(questions, []);
  await page.getByRole("button", { name: "Turn it on" }).click();
  await dialog.getByRole("button", { name: "Turn on the assistant" }).click();
  await input.fill("Next question");
  await input.press("Enter");
  await page.getByText("Fixture reply").waitFor();
  await page.getByRole("button", { name: "Turn off the local assistant" }).click();
  await page.reload();
  await page.getByText("The assistant is off, as you chose.").waitFor();
  assert.equal(await input.isDisabled(), true);
  assert.deepEqual(questions, ["Next question"]);
});

test("revoking the local assistant in another tab discards a pending reply", async (t) => {
  let finish;
  const pending = new Promise((resolve) => { finish = resolve; });
  const page = await open(t, "ask", { onApi(path) {
    if (path === "/api/ask") return pending;
  } });
  const question = page.getByRole("textbox");
  await question.fill("Explain this scan");
  await question.press("Enter");
  const sent = page.waitForRequest("**/api/ask");
  await page.getByRole("dialog").getByRole("button", { name: "Turn on the assistant" }).click();
  await sent;
  const otherTab = await page.context().newPage();
  await otherTab.route("**/*", (route) => route.fulfill({ body: "", contentType: "text/html" }));
  await otherTab.goto(origin);
  await otherTab.evaluate(() => localStorage.setItem("ajar.ai", "no"));
  await page.getByText("The assistant is off, as you chose.").waitFor();
  finish({ json: { available: true, can_answer: true, answer: "Late reply" } });
  assert.equal(await question.isDisabled(), true);
  assert.equal(await page.getByText("Late reply").count(), 0);
});
