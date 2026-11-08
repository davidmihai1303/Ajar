import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { chromium } from "playwright";

const server = fileURLToPath(new URL("./fixture_api.py", import.meta.url));
const fixtures = fileURLToPath(new URL("../../backend/tests/fixtures/validation/", import.meta.url));

test("published UI imports, compares, explains and checks consent through FastAPI", { timeout: 45000 }, async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), "ajar-integration-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeFile(path.join(dir, "ssid"), "Fixture A");
  const service = spawn(process.env.NETCHECK_PYTHON || "python3", [server, dir], { stdio: ["ignore", "pipe", "inherit"] });
  const stopped = once(service, "exit");
  t.after(async () => { service.kill(); await stopped; });
  const lines = createInterface({ input: service.stdout });
  const port = await Promise.race([once(lines, "line").then(([line]) => Number(line)),
    stopped.then(([code]) => { throw Error("Fixture API stopped with " + code); })]);
  const origin = "http://127.0.0.1:" + port;
  const browser = await chromium.launch();
  t.after(() => browser.close());
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  page.setDefaultTimeout(6000);
  await page.addInitScript(() => {
    localStorage.setItem("ajar.lang", "en");
    localStorage.setItem("ajar.ack.notify", "yes");
  });
  await page.goto(origin + "/#/scan");
  const picker = page.locator("input[type=file]");
  await picker.setInputFiles(["V6a_before.xml", "V6b_after.xml", "V7_broken.xml"].map(name => path.join(fixtures, name)));
  await page.getByText("This file could not be read.").waitFor();
  await page.locator('a[href="#/history"]').first().click();
  await page.locator("summary").filter({hasText:/Compare/}).click();
  const [before, after] = await page.locator("select").all();
  async function choose(select, name) {
    const value = await select.locator("option").filter({hasText:name}).getAttribute("value");
    await select.selectOption(value);
  }
  await choose(before, "V6a_before.xml");
  await choose(after, "V6b_after.xml");
  await page.getByText("60 → 100").waitFor();
  assert.equal(await page.locator(".diff-list li").filter({hasText:/Fixed/i}).count(), 3);

  await page.goto(origin + "/#/scan");
  const xml = '<nmaprun><host><status state="up"/><address addrtype="ipv4" addr="192.168.1.5"/><hostnames><hostname name="fixture"/></hostnames><ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports></host></nmaprun>';
  await picker.setInputFiles({name:"single.xml", mimeType:"application/xml", buffer:Buffer.from(xml)});
  await page.locator(".results a").click();
  await page.getByText("80", {exact:true}).first().waitFor();
  await page.locator(".score-meta").getByText("High severity").waitFor();
  await page.locator(".ajar-score").getByText("High severity").waitFor();
  await page.locator(".fix-first-action").getByText(/administration settings/i).waitFor();
  await page.locator(".fix-first-action a.primary").click();
  await page.getByRole("heading", {name:"Unencrypted remote login"}).waitFor();

  await page.goto(origin + "/#/ask");
  const question = page.getByRole("textbox");
  await question.fill("Score?");
  await question.press("Enter");
  await page.getByRole("dialog").getByRole("button", {name:"Turn on the assistant"}).click();
  await page.getByText(/local AI model is offline/).waitFor();
  await page.locator(".bubble-ajar").filter({hasText:"80"}).waitFor();
  await question.fill("Is 192.0.2.1 safe?");
  await question.press("Enter");
  await page.locator(".bubble-ajar").filter({hasText:/only assess devices in this scan/}).waitFor();

  await page.goto(origin + "/#/scan");
  const start = page.getByRole("button", {name:"Scan this network"});
  const dialog = page.getByRole("dialog");
  await start.click();
  await dialog.getByText("Fixture A").waitFor();
  await dialog.getByRole("checkbox").check();
  await dialog.getByRole("button", {name:"Yes, scan"}).click();
  await dialog.locator("button.primary").click();
  await writeFile(path.join(dir, "ssid"), "Fixture B");
  await dialog.locator("button.primary").click();
  await page.getByText(/The network changed/).waitFor();
  await assert.rejects(readFile(path.join(dir, "dispatches")), {code:"ENOENT"});
  await start.click();
  await dialog.getByText("Fixture B").waitFor();
  await dialog.getByRole("checkbox").check();
  await dialog.getByRole("button", {name:"Yes, scan"}).click();
  await page.waitForURL("**/#/dashboard");
  assert.equal(JSON.parse(await readFile(path.join(dir, "dispatches"), "utf8")).expected_network.ssid, "Fixture B");
  assert.deepEqual(errors, []);
});
