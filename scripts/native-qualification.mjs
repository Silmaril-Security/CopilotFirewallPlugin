import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  access,
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const EXPECTED_COPILOT_VERSION = "1.0.108";
export const EXPECTED_ASSET_SHA256 =
  "4c14e320c5cd10234ad56cba855509206e4518e1c04a780ac05a8e1c124bd97d";
export const SAFE_BLOCK_MESSAGE =
  "Silmaril Firewall blocked potentially malicious content.";
export const COPILOT_SDK_VERSION = "1.0.30-preview.0";
export const COPILOT_SDK_CLI_VERSION = "1.0.108-0";

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, "..");
const RUNTIME_FILES = [
  "dist/copilot-hook.js",
  "hooks/hooks.json",
  "package.json",
  "plugin.json",
];
const MAX_CAPTURE_BYTES = 2 * 1024 * 1024;
const PROCESS_TIMEOUT_MS = 60_000;

const PROMPTS = Object.freeze({
  allow:
    "Native qualification allow silmaril-runtime-check:11111111-1111-4111-8111-111111111111",
  block:
    "Native qualification block silmaril-runtime-check:22222222-2222-4222-8222-222222222222",
  resumePoison:
    "Native qualification blocked history poison silmaril-runtime-check:33333333-3333-4333-8333-333333333333",
  resumeNext:
    "Native qualification resume next silmaril-runtime-check:44444444-4444-4444-8444-444444444444",
  batchFirst:
    "Native qualification batch first silmaril-runtime-check:55555555-5555-4555-8555-555555555555",
  batchSecond:
    "Native qualification batch second silmaril-runtime-check:66666666-6666-4666-8666-666666666666",
  batchThird:
    "Native qualification batch third silmaril-runtime-check:77777777-7777-4777-8777-777777777777",
});

const SESSIONS = Object.freeze({
  allow: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  block: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  resume: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  batch: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
});

export function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function byteReceipt(value) {
  const bytes = Buffer.from(value, "utf8");
  return {
    byteLength: bytes.byteLength,
    sha256: sha256Bytes(bytes),
    utf8Hex: bytes.toString("hex"),
  };
}

export function collectStrings(value, output = []) {
  if (typeof value === "string") {
    output.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, output);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) collectStrings(item, output);
  }
  return output;
}

export function assertExactModelText(request, expected) {
  const strings = collectStrings(request.body.input);
  assert.ok(
    strings.includes(expected),
    `Responses input did not contain the exact ${byteReceipt(expected).sha256} text`,
  );
  return byteReceipt(expected);
}

export function assertTextAbsent(request, forbidden) {
  assert.equal(
    collectStrings(request.body).some((value) => value.includes(forbidden)),
    false,
    `Responses input retained forbidden marker ${byteReceipt(forbidden).sha256}`,
  );
}

function boundedAppend(current, chunk) {
  const combined = Buffer.concat([current, Buffer.from(chunk)]);
  if (combined.byteLength > MAX_CAPTURE_BYTES) {
    throw new Error(`Native process output exceeded ${MAX_CAPTURE_BYTES} bytes`);
  }
  return combined;
}

async function runProcess(command, args, options) {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let settled = false;
    const terminate = () => {
      if (child.pid === undefined) return;
      try {
        if (process.platform === "win32") child.kill("SIGKILL");
        else process.kill(-child.pid, "SIGKILL");
      } catch (error) {
        if (error?.code !== "ESRCH") throw error;
      }
    };
    const rejectOnce = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      terminate();
      reject(error);
    };
    const timer = setTimeout(() => {
      rejectOnce(new Error(`Native process timed out after ${options.timeoutMs} ms`));
    }, options.timeoutMs);
    child.stdout.on("data", (chunk) => {
      try {
        stdout = boundedAppend(stdout, chunk);
      } catch (error) {
        rejectOnce(error);
      }
    });
    child.stderr.on("data", (chunk) => {
      try {
        stderr = boundedAppend(stderr, chunk);
      } catch (error) {
        rejectOnce(error);
      }
    });
    child.once("error", (error) => {
      rejectOnce(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      resolve({
        code,
        signal,
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
      });
    });
  });
}

async function sha256File(filePath) {
  const hash = createHash("sha256");
  await new Promise((resolve, reject) => {
    const input = createReadStream(filePath);
    input.on("data", (chunk) => hash.update(chunk));
    input.once("error", reject);
    input.once("end", resolve);
  });
  return hash.digest("hex");
}

async function runtimeHash(root) {
  const hash = createHash("sha256");
  for (const relativePath of RUNTIME_FILES) {
    const absolutePath = path.join(root, relativePath);
    const info = await lstat(absolutePath);
    assert.ok(info.isFile() && !info.isSymbolicLink(), `${relativePath} must be a regular file`);
    const bytes = await readFile(absolutePath);
    hash.update(relativePath);
    hash.update("\0");
    hash.update(String(bytes.byteLength));
    hash.update("\0");
    hash.update(bytes);
    hash.update("\0");
  }
  return hash.digest("hex");
}

async function copyRuntime(destination) {
  for (const relativePath of RUNTIME_FILES) {
    const target = path.join(destination, relativePath);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await copyFile(path.join(REPOSITORY_ROOT, relativePath), target);
  }
  const sourceHash = await runtimeHash(REPOSITORY_ROOT);
  const copiedHash = await runtimeHash(destination);
  assert.equal(copiedHash, sourceHash, "Copied plugin runtime differs from reviewed source bytes");
  return sourceHash;
}

async function readJsonRequest(request, maxBytes = 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.byteLength;
    if (size > maxBytes) throw new Error(`Loopback request exceeded ${maxBytes} bytes`);
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function listenLoopback(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      assert.ok(address && typeof address === "object");
      resolve(address.port);
    });
  });
}

async function closeServer(server) {
  server.closeAllConnections?.();
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function startClassifier() {
  const requests = [];
  const server = createServer(async (request, response) => {
    try {
      assert.equal(request.socket.remoteAddress, "127.0.0.1");
      assert.equal(request.method, "POST");
      assert.equal(request.url, "/classify");
      const body = await readJsonRequest(request);
      assert.equal(body.hook, "user_input");
      assert.equal(typeof body.text, "string");
      const malicious = body.text.includes(PROMPTS.block)
        || body.text.includes(PROMPTS.resumePoison);
      requests.push({
        body,
        decision: malicious ? "malicious" : "benign",
        text: byteReceipt(body.text),
      });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        prediction: malicious ? "MALICIOUS" : "BENIGN",
        score: malicious ? 0.99 : 0.01,
        threshold: 0.5,
        primary_outcome: malicious ? "prompt_injection" : undefined,
      }));
    } catch (error) {
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: error instanceof Error ? error.message : "invalid" }));
    }
  });
  return {
    requests,
    async listen() {
      const port = await listenLoopback(server);
      return `http://127.0.0.1:${port}/classify`;
    },
    close: () => closeServer(server),
  };
}

function startModel() {
  const requests = [];
  let responseCount = 0;
  let nextGate;
  const server = createServer(async (request, response) => {
    try {
      assert.equal(request.socket.remoteAddress, "127.0.0.1");
      assert.equal(request.method, "POST");
      assert.equal(request.url, "/v1/responses");
      const body = await readJsonRequest(request, 4 * 1024 * 1024);
      responseCount += 1;
      requests.push({
        body,
        bodySha256: sha256Bytes(Buffer.from(JSON.stringify(body))),
      });
      const gate = nextGate;
      nextGate = undefined;
      if (gate) {
        gate.observe();
        await gate.released;
      }
      const responseId = `resp_native_${responseCount}`;
      const item = {
        type: "message",
        id: `msg_native_${responseCount}`,
        role: "assistant",
        status: "completed",
        content: [{
          type: "output_text",
          text: `NATIVE_QUALIFICATION_OK_${responseCount}`,
          annotations: [],
        }],
      };
      const base = {
        id: responseId,
        object: "response",
        created_at: 1,
        model: "gpt-5.1",
        output: [],
        status: "in_progress",
      };
      const completed = {
        ...base,
        status: "completed",
        output: [item],
        usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 },
      };
      if (body.stream !== true) {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify(completed));
        return;
      }
      response.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
      });
      for (const event of [
        { type: "response.created", response: base },
        { type: "response.output_item.added", output_index: 0, item },
        { type: "response.output_item.done", output_index: 0, item },
        {
          type: "response.completed",
          response: completed,
        },
      ]) {
        response.write(`data: ${JSON.stringify(event)}\n\n`);
      }
      response.end();
    } catch (error) {
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: error instanceof Error ? error.message : "invalid" }));
    }
  });
  return {
    requests,
    gateNextRequest() {
      assert.equal(nextGate, undefined, "A model response gate is already armed");
      let observe;
      let release;
      const observed = new Promise((resolve) => {
        observe = resolve;
      });
      const released = new Promise((resolve) => {
        release = resolve;
      });
      nextGate = { observe, released };
      return { observed, release };
    },
    async listen() {
      const port = await listenLoopback(server);
      return `http://127.0.0.1:${port}/v1`;
    },
    close: () => closeServer(server),
  };
}

function invocationReceipt(args) {
  const promptIndex = args.indexOf("-p");
  const safe = [...args];
  if (promptIndex >= 0 && safe[promptIndex + 1]) {
    safe[promptIndex + 1] = `<synthetic:${byteReceipt(safe[promptIndex + 1]).sha256}>`;
  }
  return safe;
}

async function runCopilot({
  binary,
  childEnv,
  pluginDirectory,
  workspace,
  prompt,
  sessionId,
  resume = false,
}) {
  const args = [
    "--no-auto-update",
    "--no-custom-instructions",
    "--disable-builtin-mcps",
    "--plugin-dir",
    pluginDirectory,
    "--output-format",
    "json",
    "--stream",
    "off",
    // Copilot documents this as required for -p. The loopback model never
    // emits a tool call, so this grants no exercised capability in CI.
    "--allow-all-tools",
    "-C",
    workspace,
    ...(resume ? ["--resume", sessionId] : ["--session-id", sessionId]),
    "-p",
    prompt,
  ];
  const result = await runProcess(binary, args, {
    cwd: workspace,
    env: childEnv,
    timeoutMs: PROCESS_TIMEOUT_MS,
  });
  if (result.code !== 0) {
    const diagnostic = `${result.stderr}\n${result.stdout}`.trim().slice(-4_000);
    throw new Error(
      `Copilot exited ${result.code ?? result.signal}: ${diagnostic}`,
    );
  }
  return {
    command: invocationReceipt(args),
    exitCode: result.code,
    stdoutSha256: sha256Bytes(Buffer.from(result.stdout)),
    stderrSha256: sha256Bytes(Buffer.from(result.stderr)),
  };
}

async function withTimeout(promise, label, timeoutMs = 30_000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function runSdkBatch({
  binary,
  childEnv,
  pluginDirectory,
  workspace,
  model,
  classifier,
}) {
  const sdkPackage = JSON.parse(await readFile(
    path.join(REPOSITORY_ROOT, "node_modules", "@github", "copilot-sdk", "package.json"),
    "utf8",
  ));
  assert.equal(sdkPackage.version, COPILOT_SDK_VERSION);
  assert.equal(sdkPackage.copilotCliVersion, COPILOT_SDK_CLI_VERSION);

  const { CopilotClient, RuntimeConnection } = await import("@github/copilot-sdk");
  const runtimeEnv = { ...childEnv };
  delete runtimeEnv.COPILOT_HOME;
  const client = new CopilotClient({
    connection: RuntimeConnection.forStdio({
      path: binary,
      env: runtimeEnv,
    }),
    mode: "empty",
    workingDirectory: workspace,
    baseDirectory: childEnv.COPILOT_HOME,
    builtinPluginDirectories: [pluginDirectory],
    useLoggedInUser: false,
    logLevel: "none",
  });

  const callbackStart = classifier.requests.length;
  const modelStart = model.requests.length;
  const gate = model.gateNextRequest();
  let gateReleased = false;
  let session;
  let unsubscribe = () => undefined;
  const messageIds = [];
  try {
    await client.start();
    session = await client.createSession({
      sessionId: SESSIONS.batch,
      model: "gpt-5.1",
      workingDirectory: workspace,
      trustWorkingDirectory: "session",
      availableTools: [],
      streaming: false,
      enableConfigDiscovery: false,
      provider: {
        type: "openai",
        wireApi: "responses",
        transport: "http",
        baseUrl: childEnv.COPILOT_PROVIDER_BASE_URL,
        apiKey: "synthetic-loopback-key",
        modelId: "gpt-5.1",
        wireModel: "gpt-5.1",
      },
    });
    let resolveFinalIdle;
    const finalIdle = new Promise((resolve) => {
      resolveFinalIdle = resolve;
    });
    unsubscribe = session.on("session.idle", () => {
      if (model.requests.length >= modelStart + 3) resolveFinalIdle();
    });

    messageIds.push(await session.send({ prompt: PROMPTS.batchFirst, mode: "enqueue" }));
    await withTimeout(gate.observed, "First queued model request");
    messageIds.push(await session.send({ prompt: PROMPTS.batchSecond, mode: "enqueue" }));
    messageIds.push(await session.send({ prompt: PROMPTS.batchThird, mode: "enqueue" }));
    gate.release();
    gateReleased = true;
    await withTimeout(finalIdle, "Final queued session idle");
  } finally {
    if (!gateReleased) gate.release();
    unsubscribe();
    await session?.disconnect().catch(() => undefined);
    const stopErrors = await client.stop();
    assert.equal(stopErrors.length, 0, "Copilot SDK runtime did not stop cleanly");
  }

  const callbacks = classifier.requests.slice(callbackStart);
  const modelRequests = model.requests.slice(modelStart);
  assert.equal(callbacks.length, 3, "Native queue callback count changed");
  assert.equal(modelRequests.length, 3, "Native queue model request count changed");
  assert.deepEqual(
    callbacks.map((request) => request.body.metadata?.sessionId),
    [SESSIONS.batch, SESSIONS.batch, SESSIONS.batch],
  );
  assert.deepEqual(
    callbacks.map((request) => request.body.metadata?.conversationId),
    [SESSIONS.batch, SESSIONS.batch, SESSIONS.batch],
  );
  const prompts = [PROMPTS.batchFirst, PROMPTS.batchSecond, PROMPTS.batchThird];
  for (const [index, prompt] of prompts.entries()) {
    assert.equal(callbacks[index].decision, "benign");
    assert.ok(callbacks[index].body.text.includes(prompt));
    assertExactModelText(modelRequests[index], callbacks[index].body.text);
  }
  assert.equal(new Set(messageIds).size, 3, "SDK queue message IDs were not unique");
  const requestIds = callbacks.map(
    (request) => request.body.metadata?.silmaril?.request_id,
  );
  assert.ok(requestIds.every((requestId) => typeof requestId === "string"));
  assert.equal(new Set(requestIds).size, 3, "Native queue callback IDs were not unique");

  return {
    result: "pass",
    sdkRelease: `v${COPILOT_SDK_VERSION}`,
    sdkCopilotCliVersion: COPILOT_SDK_CLI_VERSION,
    hostCopilotCliVersion: EXPECTED_COPILOT_VERSION,
    transport: "public session.send JSON-RPC",
    mode: "enqueue",
    ordering: "FIFO",
    messageIds,
    callbackRequestIds: requestIds,
    callbackTextSha256: callbacks.map((request) => request.text.sha256),
    modelBodySha256: modelRequests.map((request) => request.bodySha256),
  };
}

async function listEvidence(directory) {
  const entries = await readdir(directory, { withFileTypes: true }).catch((error) => {
    if (error?.code === "ENOENT") return [];
    throw error;
  });
  const events = [];
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const encoded = await readFile(path.join(directory, entry.name), "utf8");
    const event = JSON.parse(encoded);
    events.push({
      hook: event.hook,
      mode: event.mode,
      prediction: event.prediction,
      policyDecision: event.policyDecision,
      nativeAction: event.nativeAction,
      evidenceTruth: event.evidenceTruth,
      pluginVersion: event.provenance?.pluginVersion,
      requestFingerprint: event.requestFingerprint,
      sessionFingerprint: event.sessionFingerprint,
    });
  }
  return events.sort((left, right) =>
    String(left.requestFingerprint).localeCompare(String(right.requestFingerprint)));
}

function callbackReceipt(request) {
  return {
    hook: request.body.hook,
    decision: request.decision,
    sessionId: request.body.metadata?.sessionId,
    conversationId: request.body.metadata?.conversationId,
    requestId: request.body.metadata?.silmaril?.request_id,
    text: request.text,
  };
}

function modelReceipt(request) {
  return {
    bodySha256: request.bodySha256,
    inputStrings: collectStrings(request.body.input)
      .filter((value) =>
        value.includes("silmaril-runtime-check:") || value === SAFE_BLOCK_MESSAGE)
      .map(byteReceipt),
  };
}

async function writeReceipt(receiptPath, receipt) {
  await mkdir(path.dirname(receiptPath), { recursive: true, mode: 0o700 });
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, {
    mode: 0o600,
  });
}

export async function qualifyNativeCopilot(env = process.env) {
  const binary = env.COPILOT_BIN;
  const assetPath = env.COPILOT_ASSET_PATH;
  const receiptPath = env.NATIVE_QUALIFICATION_RECEIPT;
  assert.ok(binary && path.isAbsolute(binary), "COPILOT_BIN must be an absolute path");
  assert.ok(assetPath && path.isAbsolute(assetPath), "COPILOT_ASSET_PATH must be absolute");
  assert.ok(
    receiptPath && path.isAbsolute(receiptPath),
    "NATIVE_QUALIFICATION_RECEIPT must be absolute",
  );

  const root = await mkdtemp(path.join(os.tmpdir(), `copilot-native-${process.pid}-`));
  await chmod(root, 0o700);
  const classifier = startClassifier();
  const model = startModel();
  const receipt = {
    schemaVersion: 1,
    qualification: "copilot-1.0.108-transformed-prompt",
    result: "fail",
    expectedCopilotVersion: EXPECTED_COPILOT_VERSION,
    asset: {
      name: "copilot-linux-x64.tar.gz",
      expectedSha256: EXPECTED_ASSET_SHA256,
      actualSha256: undefined,
      verifiedBeforeExecution: false,
    },
    plugin: {},
    invocations: [],
    callbacks: [],
    modelRequests: [],
    evidence: [],
    batching: {
      result: "unverified",
      reason:
        "Official SDK v1.0.30-preview.0 targets Copilot CLI 1.0.108-0 and documents FIFO session.send enqueue; this receipt has not completed that native queue case.",
    },
    ownedCleanup: {
      privateRoot: byteReceipt(root).sha256,
      rootRemoved: false,
      loopbackServersClosed: false,
    },
  };

  let failure;
  let evidenceDirectory;
  try {
    const actualAssetHash = await sha256File(assetPath);
    receipt.asset.actualSha256 = actualAssetHash;
    assert.equal(actualAssetHash, EXPECTED_ASSET_SHA256, "Copilot release asset hash mismatch");
    receipt.asset.verifiedBeforeExecution = true;

    const binaryInfo = await lstat(binary);
    assert.ok(binaryInfo.isFile() && !binaryInfo.isSymbolicLink(), "COPILOT_BIN is not regular");
    if (env.COPILOT_EXTRACT_ROOT) {
      const [resolvedBinary, resolvedRoot] = await Promise.all([
        realpath(binary),
        realpath(env.COPILOT_EXTRACT_ROOT),
      ]);
      assert.ok(
        resolvedBinary.startsWith(`${resolvedRoot}${path.sep}`),
        "COPILOT_BIN is outside COPILOT_EXTRACT_ROOT",
      );
    }

    const home = path.join(root, "home");
    const copilotHome = path.join(root, "copilot-home");
    const pluginDirectory = path.join(root, "plugin");
    const workspace = path.join(root, "workspace");
    evidenceDirectory = path.join(root, "evidence");
    const temporaryDirectory = path.join(root, "tmp");
    for (const directory of [
      home,
      copilotHome,
      pluginDirectory,
      workspace,
      evidenceDirectory,
      temporaryDirectory,
    ]) {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      await chmod(directory, 0o700);
    }

    const version = await runProcess(binary, ["--version"], {
      cwd: workspace,
      env: {
        HOME: home,
        COPILOT_HOME: copilotHome,
        PATH: env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
        TMPDIR: temporaryDirectory,
        COPILOT_OFFLINE: "true",
        NO_COLOR: "1",
      },
      timeoutMs: 10_000,
    });
    assert.equal(version.code, 0, `Copilot --version failed: ${version.stderr}`);
    assert.match(
      version.stdout,
      new RegExp(`^GitHub Copilot CLI ${EXPECTED_COPILOT_VERSION.replaceAll(".", "\\.")}\\.`, "m"),
    );
    receipt.copilotVersionOutput = version.stdout.trim();
    const help = await runProcess(binary, ["--help"], {
      cwd: workspace,
      env: {
        HOME: home,
        COPILOT_HOME: copilotHome,
        PATH: env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
        TMPDIR: temporaryDirectory,
        COPILOT_OFFLINE: "true",
        NO_COLOR: "1",
      },
      timeoutMs: 10_000,
    });
    assert.equal(help.code, 0, `Copilot --help failed: ${help.stderr}`);
    const advertisedFlags = [
      "--prompt",
      "--resume",
      "--session-id",
      "--plugin-dir",
      "--acp",
      "--no-auto-update",
    ];
    assert.ok(
      advertisedFlags.every((flag) => help.stdout.includes(flag)),
      "Copilot 1.0.108 help omitted a required public interface",
    );
    receipt.publicInterface = {
      helpSha256: sha256Bytes(Buffer.from(help.stdout)),
      advertisedFlags,
      explicitQueueApiAdvertised: /\bqueue(?:d|ing)?\b|session\.send|sendMessage/iu.test(
        help.stdout,
      ),
    };

    const packageJson = JSON.parse(
      await readFile(path.join(REPOSITORY_ROOT, "package.json"), "utf8"),
    );
    const pluginJson = JSON.parse(
      await readFile(path.join(REPOSITORY_ROOT, "plugin.json"), "utf8"),
    );
    assert.equal(packageJson.version, "0.3.6");
    assert.equal(pluginJson.version, packageJson.version);
    const runtimeSha256 = await copyRuntime(pluginDirectory);
    receipt.plugin = {
      version: packageJson.version,
      runtimeSha256,
      copiedRuntimeSha256: await runtimeHash(pluginDirectory),
      runtimeFiles: RUNTIME_FILES,
    };

    const [classifierUrl, modelUrl] = await Promise.all([
      classifier.listen(),
      model.listen(),
    ]);
    const childEnv = {
      HOME: home,
      COPILOT_HOME: copilotHome,
      XDG_CACHE_HOME: path.join(root, "xdg-cache"),
      XDG_CONFIG_HOME: path.join(root, "xdg-config"),
      XDG_DATA_HOME: path.join(root, "xdg-data"),
      TMPDIR: temporaryDirectory,
      PATH: env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
      LANG: "C.UTF-8",
      CI: "true",
      NO_COLOR: "1",
      NO_PROXY: "127.0.0.1,localhost",
      no_proxy: "127.0.0.1,localhost",
      COPILOT_OFFLINE: "true",
      COPILOT_PROVIDER_BASE_URL: modelUrl,
      COPILOT_PROVIDER_TYPE: "openai",
      COPILOT_PROVIDER_API_KEY: "synthetic-loopback-key",
      COPILOT_PROVIDER_WIRE_API: "responses",
      COPILOT_MODEL: "gpt-5.1",
      COPILOT_PROVIDER_MODEL_ID: "gpt-5.1",
      COPILOT_PROVIDER_WIRE_MODEL: "gpt-5.1",
      SILMARIL_API_KEY: "synthetic-loopback-key",
      SILMARIL_API_URL: classifierUrl,
      SILMARIL_MODE: "block",
      SILMARIL_TIMEOUT_MS: "2500",
      SILMARIL_LOCAL_EVENT_DIR: evidenceDirectory,
    };

    receipt.invocations.push(await runCopilot({
      binary,
      childEnv,
      pluginDirectory,
      workspace,
      prompt: PROMPTS.allow,
      sessionId: SESSIONS.allow,
    }));
    assert.equal(classifier.requests.length, 1, "Allow turn callback count changed");
    assert.equal(model.requests.length, 1, "Allow turn model request count changed");
    assertExactModelText(model.requests[0], classifier.requests[0].body.text);

    receipt.invocations.push(await runCopilot({
      binary,
      childEnv,
      pluginDirectory,
      workspace,
      prompt: PROMPTS.block,
      sessionId: SESSIONS.block,
    }));
    assert.equal(classifier.requests.length, 2, "Block turn callback count changed");
    assert.equal(model.requests.length, 2, "Block turn model request count changed");
    assert.equal(classifier.requests[1].decision, "malicious");
    assertExactModelText(model.requests[1], SAFE_BLOCK_MESSAGE);
    assertTextAbsent(model.requests[1], PROMPTS.block);
    assertTextAbsent(model.requests[1], classifier.requests[1].body.text);

    receipt.invocations.push(await runCopilot({
      binary,
      childEnv,
      pluginDirectory,
      workspace,
      prompt: PROMPTS.resumePoison,
      sessionId: SESSIONS.resume,
    }));
    assert.equal(classifier.requests.length, 3, "Initial resume callback count changed");
    assert.equal(model.requests.length, 3, "Initial resume model request count changed");
    assert.equal(classifier.requests[2].decision, "malicious");
    assertExactModelText(model.requests[2], SAFE_BLOCK_MESSAGE);
    assertTextAbsent(model.requests[2], PROMPTS.resumePoison);
    assertTextAbsent(model.requests[2], classifier.requests[2].body.text);

    receipt.invocations.push(await runCopilot({
      binary,
      childEnv,
      pluginDirectory,
      workspace,
      prompt: PROMPTS.resumeNext,
      sessionId: SESSIONS.resume,
      resume: true,
    }));
    assert.equal(classifier.requests.length, 4, "Resume reclassified replayed history");
    assert.equal(model.requests.length, 4, "Resume model request count changed");
    assert.equal(classifier.requests[3].decision, "benign");
    assert.equal(classifier.requests[3].body.metadata?.sessionId, SESSIONS.resume);
    assertExactModelText(model.requests[3], classifier.requests[3].body.text);
    assertExactModelText(model.requests[3], SAFE_BLOCK_MESSAGE);
    assertTextAbsent(model.requests[3], PROMPTS.resumePoison);
    assertTextAbsent(model.requests[3], classifier.requests[2].body.text);

    assert.deepEqual(
      classifier.requests.map((request) => request.body.metadata?.sessionId),
      [SESSIONS.allow, SESSIONS.block, SESSIONS.resume, SESSIONS.resume],
    );
    assert.deepEqual(
      classifier.requests.map((request) => request.body.metadata?.conversationId),
      [SESSIONS.allow, SESSIONS.block, SESSIONS.resume, SESSIONS.resume],
    );

    receipt.batching = await runSdkBatch({
      binary,
      childEnv,
      pluginDirectory,
      workspace,
      model,
      classifier,
    });
    receipt.callbacks = classifier.requests.map(callbackReceipt);
    receipt.modelRequests = model.requests.map(modelReceipt);
    receipt.evidence = await listEvidence(evidenceDirectory);
    assert.equal(receipt.evidence.length, 7, "Expected one evidence event per native callback");
    assert.equal(
      receipt.evidence.filter((event) =>
        event.nativeAction === "content_replaced"
        && event.policyDecision === "block"
        && event.evidenceTruth === "native_response_returned").length,
      2,
      "Blocked turns did not record native replacement evidence",
    );
    assert.equal(
      receipt.evidence.filter((event) =>
        event.nativeAction === "allowed" && event.policyDecision === "allow").length,
      5,
      "Allowed turns did not record allow evidence",
    );
    receipt.result = "pass";
  } catch (error) {
    failure = error;
    receipt.error = {
      name: error instanceof Error ? error.name : "Error",
      message: error instanceof Error ? error.message : String(error),
    };
  } finally {
    receipt.callbacks = classifier.requests.map(callbackReceipt);
    receipt.modelRequests = model.requests.map(modelReceipt);
    if (evidenceDirectory) {
      try {
        receipt.evidence = await listEvidence(evidenceDirectory);
      } catch (error) {
        receipt.evidenceReadError = error instanceof Error ? error.message : String(error);
      }
    }
    const closes = await Promise.allSettled([classifier.close(), model.close()]);
    receipt.ownedCleanup.loopbackServersClosed = closes.every(
      (outcome) => outcome.status === "fulfilled",
    );
    await rm(root, { recursive: true, force: true });
    receipt.ownedCleanup.rootRemoved = await access(root)
      .then(() => false)
      .catch((error) => error?.code === "ENOENT");
    await writeReceipt(receiptPath, receipt);
  }

  if (failure) throw failure;
  return receipt;
}

async function main() {
  const receipt = await qualifyNativeCopilot();
  process.stdout.write(`${JSON.stringify({
    result: receipt.result,
    copilotVersion: receipt.copilotVersionOutput,
    assetSha256: receipt.asset.actualSha256,
    pluginRuntimeSha256: receipt.plugin.runtimeSha256,
    callbackCount: receipt.callbacks.length,
    modelRequestCount: receipt.modelRequests.length,
    evidenceCount: receipt.evidence.length,
    batching: receipt.batching.result,
    cleanup: receipt.ownedCleanup,
  })}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  await main();
}
