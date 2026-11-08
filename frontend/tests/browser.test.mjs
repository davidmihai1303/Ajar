import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";
import { chromium } from "playwright";

const origin = "http://ajar.test";
const dist = new URL("../dist/", import.meta.url);
const network = { interface: "wlan0", subnet: "192.168.1.0/24", ssid: "Office A", gateway: null };
const good = { id: "fixture", source: "import", file: "test.xml", created_at: "2026-11-07T12:00:00Z",
  score: 100, network_id: null, findings_available: true, ssid: network.ssid, subnet: network.subnet, error: null, devices: [], findings: [] };

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

test("Ask starts Qwen after consent, retries the original message, and unloads on turn off", async t => {
  let state = "idle";
  let release;
  const questions = [];
  let unloads = 0;
  const page = await open(t, "ask", { async onApi(path, request) {
    if (path === "/api/llm/status") return { json: {
      available: state === "ready", state, ...(state === "failed" ? { reason: "memory" } : {}),
    } };
    if (path === "/api/llm/unload") { unloads++; return { status: 204 }; }
    if (path === "/api/ask") {
      questions.push(request.postDataJSON().question);
      if (questions.length === 1) {
        state = "starting";
        await new Promise(resolve => { release = resolve; });
        state = "failed";
        return { json: { available: false, can_answer: false, answer: "Offline" } };
      }
      state = "ready";
      return { json: { available: true, can_answer: true, answer: "Scan fixture answer" } };
    }
  } });
  const question = "Which device needs attention?";
  await page.getByRole("textbox").fill(question);
  await page.getByRole("button", { name: "Send", exact: true }).click();
  assert.deepEqual(questions, []);
  await page.getByRole("dialog").getByRole("button", { name: "Turn on the assistant" }).click();
  await page.getByText("Starting local AI…").waitFor();
  release();
  await page.getByText(/Qwen ran out of GPU memory/).waitFor();
  await page.getByRole("button", { name: "Try again" }).click();
  await page.getByText("Scan fixture answer").waitFor();
  assert.deepEqual(questions, [question, question]);
  assert.equal(await page.locator(".bubble-user").count(), 1);
  assert.equal(await page.locator(".bubble-ajar").count(), 1);
  await page.getByRole("button", { name: "Turn off the local assistant" }).click();
  await page.getByRole("button", { name: "Turn it on" }).waitFor();
  assert.equal(unloads, 1);
});

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
    await page.getByRole("button", { name: lang === "en" ? "Try again" : "Încearcă din nou" }).waitFor();
    assert.equal(await page.locator(".demo-banner").count(), 0);
    await page.getByRole("button", { name: lang === "en" ? "Open demo" : "Deschide demonstrația" }).click();
    await page.getByText(lang === "en" ? /Demo mode shows example scans only/ : /Modul demonstrativ afișează doar exemple/).waitFor();
    assert.equal(await page.locator("input[type=file], .dropzone, .results").count(), 0);
    for (const [ip, evidence] of [
      ["172.20.10.5", lang === "en" ? /did not check whether viewing the stream/ : /Nu a verificat dacă accesul/],
      ["172.20.10.6", lang === "en" ? /did not check who can send commands/ : /Nu a verificat cine poate trimite/],
    ]) {
      await page.goto(`${origin}/?demo=1#/devices/${ip}`);
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
  const legacy = await open(t, "dashboard", { scan: { ...good, score: 85, findings_available: false } });
  await legacy.getByText(/finding details are unavailable/).waitFor();
  assert.equal(await legacy.locator(".fix-first").count(), 0);
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

test("a delayed scan selection cannot restore deleted history", async (t) => {
  const older = { ...good, id: "old", created_at: "2026-11-05T12:00:00Z", score: 80 };
  let finish;
  const delayed = new Promise((resolve) => { finish = resolve; });
  const page = await open(t, "dashboard", { onApi(path, req) {
    if (path === "/api/history") return req.method() === "DELETE" ? { status: 204 } : { json: [good, older] };
    if (path === "/api/scans/old") return delayed;
  } });
  const reading = page.waitForRequest("**/api/scans/old");
  await page.locator(".sidebar-recent").nth(1).click();
  await reading;
  await page.locator('a[href="#/history"]').first().click();
  await page.getByRole("button", { name: "Delete my history" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Delete history" }).click();
  await page.locator(".welcome").waitFor();
  const received = page.waitForResponse("**/api/scans/old");
  finish({ json: older });
  await (await received).finished();
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await page.locator(".welcome").count(), 1);
  assert.equal(await page.locator(".score-number").count(), 0);
});

test("the last selected scan stays on screen when earlier requests finish later", async (t) => {
  const older = { ...good, id: "old", created_at: "2026-11-05T12:00:00Z", score: 80 };
  let finish;
  const delayed = new Promise(resolve => { finish = resolve; });
  const page = await open(t, "dashboard", { onApi(path) {
    if (path === "/api/history") return { json: [good, older] };
    if (path === "/api/scans/old") return delayed;
  } });
  const reading = page.waitForRequest("**/api/scans/old");
  await page.locator(".sidebar-recent").nth(1).click();
  await reading;
  const selected = page.waitForResponse("**/api/scans/fixture");
  await page.locator(".sidebar-recent").first().click();
  await (await selected).finished();
  const stale = page.waitForResponse("**/api/scans/old");
  finish({ json: older });
  await (await stale).finished();
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await page.locator(".score-number").innerText(), "100");
});

test("history automatically compares only scans of the same known network", async (t) => {
  const now = { ...good, id: "current", source: "live", network_id: "A", ssid: "Office" };
  const guest = { ...now, id: "guest", network_id: "B", score: 20, created_at: "2026-11-06T12:00:00Z" };
  const previous = { ...now, id: "previous", score: 80, created_at: "2026-11-05T12:00:00Z" };
  for (const items of [[now, guest], [now, guest, previous]]) {
    const comparisons = [];
    const page = await open(t, "history", { scan: now, onApi(path, request) {
      if (path === "/api/history") return { json: items };
      if (path === "/api/history/diff") comparisons.push(new URL(request.url()).searchParams.get("from"));
    } });
    const lead = await page.locator(".history-lead").innerText();
    if (items.length === 2) {
      assert.match(lead, /two assessed scans/);
      assert.deepEqual(comparisons, []);
    } else {
      assert.match(lead, /80 to 100/);
      assert.ok(!comparisons.includes("guest"));
    }
  }
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

const risky = {
  ...good, id: "risky", score: 70,
  devices: [
    { ip: "192.168.1.1", mac_masked: "50:C7:BF:xx:xx:xx", vendor: "TP-Link", hostname: null, device_type: "router",
      ports: [{ port: 80, protocol: "tcp", service: "http", product: null, version: null, http_title: "<img src=x onerror=alert(1)>", tunnel: null }] },
    { ip: "192.168.1.99", mac_masked: null, vendor: null, hostname: null, device_type: "unknown",
      ports: [{ port: 23, protocol: "tcp", service: "telnet", product: null, version: null, http_title: null, tunnel: null }] },
  ],
  findings: [
    { code: "HTTP_ADMIN_CLEARTEXT", severity: "medium", points: 10, ip: "192.168.1.1", port: 80, protocol: "tcp", evidence: "tcp/80 http: <img src=x onerror=alert(1)>" },
    { code: "TELNET_OPEN", severity: "high", points: 20, ip: "192.168.1.99", port: 23, protocol: "tcp", evidence: "tcp/23 telnet" },
  ],
};
const explainReply = (path) => {
  if (!path.startsWith("/api/explain/")) return;
  const code = decodeURIComponent(path.split("/")[3]);
  return { json: { code, lang: "en", title: `Title ${code}`, explanation: `Why ${code}.`, steps: [`Step one for ${code}`, "Scan again"] } };
};

test("the report lists the most dangerous device first, with fixes, references and escaped evidence", async (t) => {
  const page = await open(t, "report", { scan: risky, onApi: explainReply });
  await page.getByRole("heading", { name: "Network safety report" }).waitFor();
  const items = page.locator(".report-finding");
  await items.nth(1).getByText("Title HTTP_ADMIN_CLEARTEXT").waitFor();
  assert.equal(await items.count(), 2);
  assert.match(await items.nth(0).innerText(), /Title TELNET_OPEN[\s\S]*Unknown device[\s\S]*Step one for TELNET_OPEN/);
  assert.match(await items.nth(1).innerText(), /CIS 3\.10 · OWASP IoT I3 · OWASP IoT I7/);
  assert.match(await items.nth(1).innerText(), /<img src=x onerror=alert\(1\)>/);
  assert.equal(await page.locator(".report img").count(), 0);
  assert.match(await page.locator(".report table").innerText(), /50:C7:BF:xx:xx:xx/);
  assert.match(await page.locator(".report-summary").innerText(), /70/);

  await page.evaluate(() => { window.__printed = 0; window.print = () => { window.__printed += 1; }; });
  await page.getByRole("button", { name: "Print or save as PDF" }).click();
  assert.equal(await page.evaluate(() => window.__printed), 1);

  await page.emulateMedia({ media: "print" });
  assert.equal(await page.locator(".sidebar").isVisible(), false);
  assert.equal(await page.getByRole("button", { name: "Print or save as PDF" }).isVisible(), false);
});

test("the dashboard links to the report and finding details show the standards in Romanian", async (t) => {
  const page = await open(t, "dashboard", { scan: risky, lang: "ro", onApi: explainReply });
  await page.getByRole("link", { name: "Raport pentru omul tău de IT" }).click();
  await page.getByRole("heading", { name: "Raport despre siguranța rețelei" }).waitFor();

  const devices = await open(t, "devices/192.168.1.99", { scan: risky, lang: "ro", onApi: explainReply });
  await devices.getByText("Detalii tehnice").first().click();
  await devices.getByText("Standarde:").first().waitFor();
  assert.match(await devices.locator(".references").first().innerText(), /CIS 4\.8 · CIS 3\.10 · OWASP IoT I2 · OWASP IoT I7/);
});

test("an unreadable scan has no report", async (t) => {
  const broken = { ...good, id: "broken", score: null, error: "unreadable", findings_available: false };
  const page = await open(t, "report", { scan: broken });
  await page.getByText("This scan's file couldn't be read.").waitFor();
  assert.equal(await page.locator(".report").count(), 0);
});

test("the notification inbox can be checked off, filtered and remembers what was read", async t => {
  const page = await open(t, "inbox");
  const item = page.locator(".inbox-item").first();
  await item.getByText("Scan finished: score 100/100").waitFor();
  assert.equal(await page.locator(".sidebar .inbox-badge").textContent(), "1");
  await item.getByRole("checkbox").check();
  assert.equal(await page.locator(".sidebar .inbox-badge").count(), 0);
  await page.getByRole("button", { name: "Unread", exact: true }).click();
  await page.getByText("No unread notifications.").waitFor();
  await page.reload();
  await page.locator(".inbox-item").first().waitFor();
  assert.equal(await page.locator(".inbox-item").first().getByRole("checkbox").isChecked(), true);
  await page.getByRole("button", { name: "Mark all as unread" }).click();
  assert.equal(await page.locator(".sidebar .inbox-badge").textContent(), "1");
});

test("Ask is a conversation: follow-ups carry earlier turns, and New conversation starts over", async (t) => {
  const bodies = [];
  const page = await open(t, "ask", { onApi(path, request) {
    if (path === "/api/llm/status") return { json: { available: true, state: "ready" } };
    if (path === "/api/ask") {
      const body = request.postDataJSON();
      bodies.push(body);
      return { json: { available: true, can_answer: true, answer: `Answer ${bodies.length}` } };
    }
  } });
  const input = page.getByRole("textbox");
  await input.fill("What problems do I have?");
  await input.press("Enter");
  await page.getByRole("dialog").getByRole("button", { name: "Turn on the assistant" }).click();
  await page.getByText("Answer 1").waitFor();
  for (const [i, q] of ["Explain", "How do I close them?", "And the router?", "And the TV?"].entries()) {
    await input.fill(q);
    await input.press("Enter");
    await page.getByText(`Answer ${i + 2}`).waitFor();
  }
  assert.deepEqual(bodies[0].history, []);
  assert.deepEqual(bodies[1].history, [{ question: "What problems do I have?", answer: "Answer 1" }]);
  // Only the last three exchanges travel with a question.
  assert.deepEqual(bodies[4].history.map(turn => turn.question), ["Explain", "How do I close them?", "And the router?"]);
  await page.getByRole("button", { name: "New conversation" }).click();
  assert.equal(await page.locator(".bubble-user").count(), 0);
  await input.fill("Fresh start");
  await input.press("Enter");
  await page.getByText("Answer 6").waitFor();
  assert.deepEqual(bodies[5].history, []);
});

test("Explain for my device writes a prompt with the problem and the device into the chat without sending it", async (t) => {
  const asked = [];
  const page = await open(t, "devices/192.168.1.1", { scan: risky, onApi: (path) => {
    if (path === "/api/ask") asked.push(path);
    return explainReply(path);
  } });
  await page.getByText("Title HTTP_ADMIN_CLEARTEXT").waitFor();
  await page.getByRole("link", { name: "Explain for my device" }).click();
  const box = page.locator("#ask-question");
  await box.waitFor();
  const prompt = await box.inputValue();
  assert.match(prompt, /"Title HTTP_ADMIN_CLEARTEXT" \(medium severity, code HTTP_ADMIN_CLEARTEXT\)/);
  assert.match(prompt, /Device: Router by TP-Link, IP 192\.168\.1\.1, port tcp\/80\./);
  assert.doesNotMatch(prompt, /img|onerror/);
  assert.equal(await page.locator(".bubble-user").count(), 0);
  assert.deepEqual(asked, []);
});
