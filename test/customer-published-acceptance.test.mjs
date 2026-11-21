import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DRIVER = path.join(ROOT, "scripts", "customer-published-acceptance");
const SHARED_HELPER = process.env.CUSTOMER_ARCHIVE_HELPER
  ?? path.join(ROOT, "..", "SilmarilCustomerTests", "scripts", "unpack_customer_plugin.py");
const STATUSES = ["PASS", "FAIL", "BLOCKED"];

function drive(env) {
  const result = spawnSync(DRIVER, {
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
    encoding: "utf8",
  });
  return result;
}

async function fixture(run) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "customer-driver-test-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("driver is executable", async () => {
  assert.ok((await stat(DRIVER)).mode & 0o100);
});

test("a wrong artifact digest is FAIL, writes only status values and never reaches the host", async () => {
  await fixture(async (directory) => {
    const artifact = path.join(directory, "source.tar.gz");
    await writeFile(artifact, "not a plugin archive");
    const result = path.join(directory, "result.json");
    const run = drive({
      CUSTOMER_RESULT: result,
      CUSTOMER_ARTIFACT: artifact,
      CUSTOMER_VERSION: "1.2.3",
      CUSTOMER_SOURCE_SHA: "a".repeat(40),
      CUSTOMER_ARTIFACT_SHA256: "0".repeat(64),
      CUSTOMER_ARCHIVE_HELPER: SHARED_HELPER,
    });
    assert.notEqual(run.status, 0);
    assert.deepEqual(JSON.parse(await readFile(result, "utf8")), {
      install: "FAIL",
      native: "BLOCKED",
      live: "BLOCKED",
    });
  });
});

test("missing inputs are BLOCKED and every result value is a status", async () => {
  await fixture(async (directory) => {
    const result = path.join(directory, "result.json");
    assert.notEqual(drive({ CUSTOMER_RESULT: result }).status, 0);
    const written = JSON.parse(await readFile(result, "utf8"));
    assert.deepEqual(written, { install: "BLOCKED", native: "BLOCKED", live: "BLOCKED" });
    assert.ok(Object.values(written).every((value) => STATUSES.includes(value)));
    assert.equal(drive({}).status, 2);
  });
});

// Opt-in: bootstraps the pinned host and dependencies (network), then runs the
// real harness. Without live credentials the live status must be BLOCKED.
test("without live credentials the live case is BLOCKED, never PASS", {
  skip: process.env.CUSTOMER_DRIVER_E2E !== "1",
}, async () => {
  await fixture(async (directory) => {
    const sha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
    const artifact = path.join(directory, "source.tar.gz");
    execFileSync("git", ["archive", "--format=tar.gz", "--prefix=source/", "-o", artifact, "HEAD"], { cwd: ROOT });
    const result = path.join(directory, "result.json");
    const run = drive({
      CUSTOMER_RESULT: result,
      CUSTOMER_ARTIFACT: artifact,
      CUSTOMER_VERSION: JSON.parse(await readFile(path.join(ROOT, "package.json"), "utf8")).version,
      CUSTOMER_SOURCE_SHA: sha,
      CUSTOMER_ARTIFACT_SHA256: createHash("sha256").update(await readFile(artifact)).digest("hex"),
      CUSTOMER_ARCHIVE_HELPER: SHARED_HELPER,
    });
    assert.notEqual(run.status, 0);
    assert.deepEqual(JSON.parse(await readFile(result, "utf8")), {
      install: "PASS",
      native: "PASS",
      live: "BLOCKED",
    });
  });
});
