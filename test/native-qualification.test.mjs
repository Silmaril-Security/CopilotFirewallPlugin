import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { text } from "node:stream/consumers";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  ACCEPTANCE_SCHEMA,
  CLASSIFY_BODIES,
  LOOPBACK_MODEL_ID,
  LOOPBACK_POLICY_VERSION,
  INSTALL_COMMAND,
  LIVE_ATTACK_TEXT,
  PROMPT_SCENARIO_ID,
  SAFE_BLOCK_MESSAGE,
  assertCurrentUserText,
  assertEvidenceMatchesCallbacks,
  assertExactModelText,
  assertTextAbsent,
  buildAcceptanceReceipt,
  byteReceipt,
  collectStrings,
  evaluateToolScenario,
  installedBytesMatch,
  liveClassifierConfig,
  liveEnforcementBlocker,
  pluginRootConfig,
  productEvidenceIdentity,
  promptScenario,
  qualifyNativeCopilot,
  responseUserTexts,
  startClassifier,
  toolScenarios,
} from "../scripts/native-qualification.mjs";

const RUNTIME_FILES = ["dist/copilot-hook.js", "hooks/hooks.json", "package.json", "plugin.json"];
const BUNDLED_HOOK = fileURLToPath(new URL("../dist/copilot-hook.js", import.meta.url));
const ARTIFACT_SHA256 = "a".repeat(64);
const [ALLOW, PRE_TOOL_BLOCK, TOOL_RESPONSE_BLOCK] = toolScenarios(false);
const [LIVE_ALLOW, LIVE_TOOL_RESPONSE_BLOCK] = toolScenarios(true);

function classifierRequest(hook, text, decision, overrides = {}) {
  return { body: { hook, text }, decision, outcome: "success", durationMs: 12, ...overrides };
}

function modelRequest(toolOutput) {
  return {
    body: {
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "turn" }] },
        { type: "function_call", call_id: "call_native_1", name: "tool", arguments: "{}" },
        { type: "function_call_output", call_id: "call_native_1", output: toolOutput },
      ],
    },
  };
}

function toolResponseObservation(scenario, decision, toolOutput, overrides = {}) {
  return {
    live: false,
    effectText: undefined,
    evidence: decision === "malicious"
      ? [{ hook: "tool_result", policyDecision: "block", nativeAction: "content_replaced" }]
      : [],
    modelRequests: [modelRequest(toolOutput)],
    classifierRequests: [
      classifierRequest("user_input", scenario.prompt, "benign"),
      classifierRequest("tool_call", "{}", "benign"),
      classifierRequest("tool_response", scenario.poison, decision, overrides),
    ],
  };
}

function passingScenarios() {
  return [
    promptScenario({ primary_allow_exact_bytes: true }),
    { id: "allow", status: "PASS", effect_present: true, checks: {} },
    { id: "pre-tool-block", status: "PASS", effect_present: false, checks: {} },
    { id: "tool-response-block", status: "PASS", checks: {} },
  ];
}

function acceptanceInput(overrides = {}) {
  return {
    sourceSha: "b".repeat(40),
    live: false,
    plugin: {
      name: "silmaril-firewall",
      version: "0.4.0",
      artifact_sha256: ARTIFACT_SHA256,
      installed_bytes_match: true,
      install_command: INSTALL_COMMAND,
    },
    hostVersion: "1.0.108",
    scenarios: passingScenarios(),
    classifierRequests: [classifierRequest("tool_call", "{}", "malicious")],
    ...overrides,
  };
}

test("native qualification compares exact response input strings and bytes", () => {
  const exact = " \ttransformed\r\nprompt\u0000unicode \u03b2\n";
  const request = {
    body: {
      input: [{
        type: "message",
        role: "user",
        content: [{ type: "input_text", text: exact }],
      }],
    },
  };
  assert.deepEqual(assertExactModelText(request, exact), byteReceipt(exact));
  assert.deepEqual(collectStrings(request.body.input), [
    "message",
    "user",
    "input_text",
    exact,
  ]);
  assert.throws(() => assertExactModelText(request, exact.trim()));
});

test("native qualification detects blocked poison anywhere in model input", () => {
  const poison = "silmaril-runtime-check:22222222-2222-4222-8222-222222222222";
  const clean = {
    body: {
      input: [{
        role: "user",
        content: [{ type: "input_text", text: SAFE_BLOCK_MESSAGE }],
      }],
    },
  };
  assert.doesNotThrow(() => assertTextAbsent(clean, poison));
  assert.throws(() => assertTextAbsent({
    body: {
      input: [{
        role: "user",
        content: [{ type: "input_text", text: `prefix ${poison} suffix` }],
      }],
    },
  }, poison));
});

test("resume qualification binds the callback to the current user item, not stored history", () => {
  const current = "current transformed silmaril-runtime-check:44444444-4444-4444-8444-444444444444";
  const request = {
    body: {
      input: [
        {
          type: "message",
          role: "user",
          content: [{ type: "input_text", text: SAFE_BLOCK_MESSAGE }],
        },
        {
          type: "message",
          role: "assistant",
          content: [{ type: "output_text", text: "stored response" }],
        },
        {
          type: "message",
          role: "user",
          content: [{ type: "input_text", text: current }],
        },
      ],
    },
  };
  assert.deepEqual(responseUserTexts(request), [SAFE_BLOCK_MESSAGE, current]);
  assert.doesNotThrow(() => assertExactModelText(request, SAFE_BLOCK_MESSAGE));
  assert.throws(
    () => assertCurrentUserText(request, SAFE_BLOCK_MESSAGE),
    /current transformed callback/u,
  );
  assert.deepEqual(assertCurrentUserText(request, current), byteReceipt(current));
});

test("native evidence requires an exact one-to-one callback identity multiset", () => {
  const callbacks = [
    {
      body: {
        text: "first silmaril-runtime-check:11111111-1111-4111-8111-111111111111",
        metadata: { sessionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
      },
    },
    {
      body: {
        text: "second silmaril-runtime-check:22222222-2222-4222-8222-222222222222",
        metadata: { sessionId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" },
      },
    },
  ];
  const expected = callbacks.map(productEvidenceIdentity);
  assert.deepEqual(
    assertEvidenceMatchesCallbacks(callbacks, expected),
    expected.toSorted((left, right) =>
      `${left.requestFingerprint}\u0000${left.sessionFingerprint}`.localeCompare(
        `${right.requestFingerprint}\u0000${right.sessionFingerprint}`,
      )),
  );
  assert.throws(
    () => assertEvidenceMatchesCallbacks(callbacks, [expected[0], expected[0]]),
    /Duplicate native evidence identity/u,
  );
  assert.throws(
    () => assertEvidenceMatchesCallbacks(callbacks, [expected[0]]),
    /did not match callbacks one-to-one/u,
  );
});

test("allow acceptance needs the effect file on disk and its output in the next model request", () => {
  const observation = {
    live: false,
    effectText: ALLOW.effectText,
    evidence: [],
    modelRequests: [modelRequest(`${ALLOW.effectText}\n<exit code 0>`)],
    classifierRequests: [
      classifierRequest("user_input", ALLOW.prompt, "benign"),
      classifierRequest("tool_call", JSON.stringify(ALLOW.toolCall.arguments), "benign"),
      classifierRequest("tool_response", ALLOW.effectText, "benign"),
    ],
  };
  const passed = evaluateToolScenario(ALLOW, observation);
  assert.equal(passed.status, "PASS");
  assert.equal(passed.effect_present, true);

  const missingEffect = evaluateToolScenario(ALLOW, { ...observation, effectText: undefined });
  assert.equal(missingEffect.status, "FAIL");
  assert.equal(missingEffect.effect_present, false);
  assert.equal(missingEffect.checks.effect_file_written_by_tool, false);

  const outputWithheld = evaluateToolScenario(ALLOW, {
    ...observation,
    modelRequests: [modelRequest("unrelated output")],
  });
  assert.equal(outputWithheld.checks.tool_output_reached_model, false);
  assert.equal(outputWithheld.status, "FAIL");
});

test("pre-tool-block acceptance fails when the denied tool still left its effect", () => {
  const observation = {
    live: false,
    effectText: undefined,
    evidence: [{ hook: "pre_tool", policyDecision: "block", nativeAction: "block_returned" }],
    modelRequests: [modelRequest(`Denied by preToolUse hook: ${SAFE_BLOCK_MESSAGE}`)],
    classifierRequests: [
      classifierRequest("user_input", PRE_TOOL_BLOCK.prompt, "benign"),
      classifierRequest(
        "tool_call",
        JSON.stringify(PRE_TOOL_BLOCK.toolCall.arguments),
        "malicious",
      ),
    ],
  };
  const passed = evaluateToolScenario(PRE_TOOL_BLOCK, observation);
  assert.equal(passed.status, "PASS");
  assert.equal(passed.effect_present, false);

  const executed = evaluateToolScenario(PRE_TOOL_BLOCK, {
    ...observation,
    effectText: PRE_TOOL_BLOCK.effectText,
    classifierRequests: [
      ...observation.classifierRequests,
      classifierRequest("tool_response", PRE_TOOL_BLOCK.effectText, "benign"),
    ],
  });
  assert.equal(executed.status, "FAIL");
  assert.equal(executed.effect_present, true);
  assert.equal(executed.checks.effect_file_absent, false);
  assert.equal(executed.checks.tool_never_executed, false);
});

test("tool-response-block acceptance fails when poison reaches any model request", () => {
  const passed = evaluateToolScenario(
    TOOL_RESPONSE_BLOCK,
    toolResponseObservation(TOOL_RESPONSE_BLOCK, "malicious", SAFE_BLOCK_MESSAGE),
  );
  assert.equal(passed.status, "PASS");
  assert.equal(Object.hasOwn(passed, "effect_present"), false);

  const leaked = evaluateToolScenario(
    TOOL_RESPONSE_BLOCK,
    toolResponseObservation(TOOL_RESPONSE_BLOCK, "benign", TOOL_RESPONSE_BLOCK.poison),
  );
  assert.equal(leaked.status, "FAIL");
  assert.equal(leaked.blocker, undefined);
  assert.equal(leaked.checks.poison_absent_from_model_requests, false);
  assert.equal(leaked.checks.replacement_reached_model, false);
});

test("live acceptance runs only allow and tool-response-block with the customer attack text", () => {
  assert.deepEqual(
    toolScenarios(false).map((scenario) => scenario.id),
    ["allow", "pre-tool-block", "tool-response-block"],
  );
  assert.deepEqual([LIVE_ALLOW.id, LIVE_TOOL_RESPONSE_BLOCK.id], ["allow", "tool-response-block"]);
  assert.equal(toolScenarios(true).length, 2);
  assert.equal(LIVE_TOOL_RESPONSE_BLOCK.poison, LIVE_ATTACK_TEXT);
});

test("live classifier failures are attributed to a named blocker instead of a product failure", () => {
  const upstream = { action: "allow", source: null, mode: "block" };
  const unflagged = toolResponseObservation(
    LIVE_TOOL_RESPONSE_BLOCK,
    "benign",
    LIVE_ATTACK_TEXT,
    { upstream },
  );
  const blocked = evaluateToolScenario(LIVE_TOOL_RESPONSE_BLOCK, { ...unflagged, live: true });
  assert.equal(blocked.status, "BLOCKED");
  assert.equal(blocked.blocker, "classifier_did_not_flag_attack");

  const attack = (decision, overrides) => [
    classifierRequest("tool_response", LIVE_ATTACK_TEXT, decision, overrides),
  ];
  assert.equal(
    liveEnforcementBlocker(LIVE_TOOL_RESPONSE_BLOCK, attack(undefined, { outcome: "http_error" })),
    "classifier_request_failed",
  );
  assert.equal(
    liveEnforcementBlocker(
      LIVE_TOOL_RESPONSE_BLOCK,
      attack("malicious", { durationMs: 2_500, upstream: { mode: "block" } }),
    ),
    "classifier_exceeded_plugin_deadline",
  );
  assert.equal(
    liveEnforcementBlocker(LIVE_ALLOW, [
      classifierRequest("tool_call", JSON.stringify(LIVE_ALLOW.toolCall.arguments), "malicious"),
    ]),
    "classifier_flagged_benign_control",
  );
  assert.equal(
    liveEnforcementBlocker(
      LIVE_TOOL_RESPONSE_BLOCK,
      attack("malicious", { upstream: { mode: "block" } }),
    ),
    undefined,
  );
});

test("live acceptance passes on local block mode whatever mode the classifier reports", () => {
  for (const mode of [null, "shadow", "block"]) {
    const enforced = evaluateToolScenario(LIVE_TOOL_RESPONSE_BLOCK, {
      ...toolResponseObservation(LIVE_TOOL_RESPONSE_BLOCK, "malicious", SAFE_BLOCK_MESSAGE, {
        upstream: { action: "block", source: "model", mode },
      }),
      live: true,
    });
    assert.equal(enforced.status, "PASS");
    assert.equal(enforced.blocker, undefined);
  }
});

test("a live classifier fault blocks a scenario whose tool checks all passed", () => {
  const observation = {
    ...toolResponseObservation(LIVE_TOOL_RESPONSE_BLOCK, "malicious", SAFE_BLOCK_MESSAGE, {
      durationMs: 2_500,
    }),
    live: true,
  };
  const slow = evaluateToolScenario(LIVE_TOOL_RESPONSE_BLOCK, observation);
  assert.equal(Object.values(slow.checks).every(Boolean), true);
  assert.equal(slow.status, "BLOCKED");
  assert.equal(slow.blocker, "classifier_exceeded_plugin_deadline");
  assert.equal(
    evaluateToolScenario(LIVE_TOOL_RESPONSE_BLOCK, { ...observation, live: false }).status,
    "PASS",
  );
});

test("live classifier configuration requires an https endpoint and a key", () => {
  assert.equal(liveClassifierConfig({}), undefined);
  assert.deepEqual(
    liveClassifierConfig({
      CUSTOMER_NATIVE_CLASSIFIER: "live",
      CUSTOMER_NATIVE_API_URL: "https://cascade.invalid/classify",
      CUSTOMER_NATIVE_API_KEY: "synthetic-live-key",
    }),
    { url: "https://cascade.invalid/classify", key: "synthetic-live-key" },
  );
  assert.throws(
    () => liveClassifierConfig({
      CUSTOMER_NATIVE_CLASSIFIER: "live",
      CUSTOMER_NATIVE_API_URL: "http://cascade.invalid/classify",
      CUSTOMER_NATIVE_API_KEY: "synthetic-live-key",
    }),
    /HTTPS/u,
  );
  assert.throws(
    () => liveClassifierConfig({
      CUSTOMER_NATIVE_CLASSIFIER: "live",
      CUSTOMER_NATIVE_API_URL: "https://cascade.invalid/classify",
    }),
    /CUSTOMER_NATIVE_API_KEY/u,
  );
});

test("a live run without its API key still writes a failing acceptance receipt", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "copilot-native-receipt-"));
  const receiptPath = path.join(directory, "native-acceptance", "live-receipt.json");
  try {
    await assert.rejects(
      qualifyNativeCopilot({
        CUSTOMER_NATIVE_CLASSIFIER: "live",
        CUSTOMER_NATIVE_API_URL: "https://cascade.invalid/classify",
        GITHUB_SHA: "b".repeat(40),
        NATIVE_ACCEPTANCE_RECEIPT: receiptPath,
      }),
      /CUSTOMER_NATIVE_API_KEY/u,
    );
    const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
    assert.equal(receipt.schema, ACCEPTANCE_SCHEMA);
    assert.equal(receipt.status, "FAIL");
    assert.equal(receipt.classifier, "live");
    assert.equal(receipt.source_sha, "b".repeat(40));
    assert.deepEqual(receipt.scenarios, []);
    assert.deepEqual(receipt.classifier_requests, []);
    assert.match(receipt.error.message, /CUSTOMER_NATIVE_API_KEY/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("live classifier proxy mirrors each classify path upstream and records the upstream decision", async () => {
  const upstreamCalls = [];
  const replies = [
    new Response(JSON.stringify({
      results: [{
        action: "block",
        source: "model",
        confidence: "very_high",
        severity: "critical",
        outcome: "secret_exposure",
        governance: null,
        model_id: null,
      }],
    })),
    new Response("missing", { status: 404 }),
    new Response(JSON.stringify({
      prediction: "MALICIOUS",
      model_prediction: "BENIGN",
      mode: "block",
      governance: { action: "block" },
    })),
    new Response("unavailable", { status: 503 }),
  ];
  const classifier = startClassifier({
    live: { url: "https://cascade.invalid/stage/classify?tenant=synthetic", key: "synthetic-live-key" },
    fetchImpl: async (url, init) => {
      upstreamCalls.push({ url, key: init.headers["x-api-key"], body: JSON.parse(init.body) });
      return replies.shift();
    },
  });
  const origin = new URL(await classifier.listen()).origin;
  const classify = (classifyPath, text) => fetch(`${origin}${classifyPath}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ hook: "tool_response", text }),
  });
  try {
    const graded = await classify("/v2/classify", LIVE_ATTACK_TEXT);
    assert.equal(graded.status, 200);
    assert.equal((await graded.json()).results[0].severity, "critical");
    assert.equal((await classify("/v2/classify", LIVE_ATTACK_TEXT)).status, 404);
    assert.equal(classifier.requests.length, 1);
    const governed = await classify("/classify", LIVE_ATTACK_TEXT);
    assert.equal(governed.status, 200);
    assert.equal((await governed.json()).prediction, "MALICIOUS");
    assert.equal((await classify("/classify", "benign control")).status, 500);
    assert.equal((await classify("/v3/classify", "benign control")).status, 404);
  } finally {
    await classifier.close();
  }
  assert.deepEqual(upstreamCalls.map((call) => [call.url, call.key, call.body.text]), [
    ["https://cascade.invalid/stage/v2/classify?tenant=synthetic", "synthetic-live-key", LIVE_ATTACK_TEXT],
    ["https://cascade.invalid/stage/v2/classify?tenant=synthetic", "synthetic-live-key", LIVE_ATTACK_TEXT],
    ["https://cascade.invalid/stage/classify?tenant=synthetic", "synthetic-live-key", LIVE_ATTACK_TEXT],
    ["https://cascade.invalid/stage/classify?tenant=synthetic", "synthetic-live-key", "benign control"],
  ]);
  const [graded, governed, failed] = classifier.requests;
  assert.equal(classifier.requests.length, 3);
  assert.equal(graded.decision, "malicious");
  assert.equal(graded.outcome, "success");
  assert.deepEqual(graded.upstream, { action: "block", source: "model", mode: null });
  assert.equal(governed.decision, "malicious");
  assert.deepEqual(governed.upstream, { action: "block", source: "governance", mode: "block" });
  assert.equal(typeof governed.durationMs, "number");
  assert.equal(failed.outcome, "http_error");
  assert.equal(failed.httpStatus, 503);
  assert.equal(failed.decision, undefined);
  assert.equal(typeof failed.durationMs, "number");
});

test("live classifier proxy times a refused version 2 probe and its fallback as one classification", async () => {
  const refusal = new Response("missing", { status: 404 });
  const classifier = startClassifier({
    live: { url: "https://cascade.invalid/stage/classify", key: "synthetic-live-key" },
    fetchImpl: async (url) => {
      await delay(300);
      return new URL(url).pathname.endsWith("/v2/classify")
        ? refusal
        : Response.json({ prediction: "BENIGN" });
    },
  });
  const origin = new URL(await classifier.listen()).origin;
  const body = JSON.stringify({ hook: "user_input", text: "benign control" });
  const classify = (classifyPath) => fetch(`${origin}${classifyPath}`, { method: "POST", body });
  try {
    assert.equal((await classify("/v2/classify")).status, 404);
    assert.equal((await classify("/classify")).status, 200);
  } finally {
    await classifier.close();
  }
  assert.equal(refusal.bodyUsed, true);
  assert.equal(classifier.requests.length, 1);
  assert.equal(classifier.requests[0].outcome, "success");
  assert.ok(classifier.requests[0].durationMs >= 600, `${classifier.requests[0].durationMs} ms`);
});

function runBundledHook(eventName, input, env) {
  const child = spawn(process.execPath, [BUNDLED_HOOK, eventName], { env });
  const output = text(child.stdout);
  child.stdin.end(JSON.stringify(input));
  return output.then(JSON.parse);
}

for (const [wire, bodies, graded] of [
  ["a version 2 body", CLASSIFY_BODIES, true],
  ["the version 1 fallback", { "/classify": CLASSIFY_BODIES["/classify"] }, false],
  ["a version 1 body on the version 2 path", { "/v2/classify": CLASSIFY_BODIES["/classify"] }, false],
]) {
  test(`the bundled plugin enforces a block and records its evidence from ${wire}`, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "copilot-classify-wire-"));
    const evidenceDirectory = path.join(directory, "incoming");
    const classifier = startClassifier({ bodies });
    const env = {
      PATH: process.env.PATH,
      HOME: directory,
      SILMARIL_CONFIG_PATH: path.join(directory, "absent.json"),
      SILMARIL_API_KEY: "synthetic-loopback-key",
      SILMARIL_API_URL: await classifier.listen(),
      SILMARIL_MODE: "block",
      SILMARIL_LOCAL_EVENT_DIR: evidenceDirectory,
    };
    const preToolUse = (toolCall) => runBundledHook("preToolUse", {
      sessionId: PRE_TOOL_BLOCK.sessionId,
      timestamp: 1_787_156_024_056,
      cwd: directory,
      toolName: toolCall.name,
      toolArgs: toolCall.arguments,
    }, env);
    try {
      assert.deepEqual(await preToolUse(ALLOW.toolCall), {});
      assert.deepEqual(await preToolUse(PRE_TOOL_BLOCK.toolCall), {
        permissionDecision: "deny",
        permissionDecisionReason: SAFE_BLOCK_MESSAGE,
      });
      assert.deepEqual(
        classifier.requests.map((request) => [request.decision, request.outcome]),
        [["benign", "success"], ["malicious", "success"]],
      );
      const events = await Promise.all((await readdir(evidenceDirectory)).map(async (name) =>
        JSON.parse(await readFile(path.join(evidenceDirectory, name), "utf8"))));
      const blocked = events.find((event) => event.policyDecision === "block");
      const allowed = events.find((event) => event.policyDecision === "allow");
      assert.equal(events.length, 2);
      assert.equal(blocked.prediction, "malicious");
      assert.equal(blocked.nativeAction, "block_returned");
      assert.equal(blocked.riskClass, "unsafe_agent_control");
      assert.equal(blocked.confidence, graded ? "high" : undefined);
      assert.equal(blocked.severity, graded ? "high" : undefined);
      assert.equal(allowed.prediction, "benign");
      for (const event of events) {
        assert.equal(event.provenance.modelVersion, LOOPBACK_MODEL_ID);
        assert.equal(event.provenance.policyVersion, LOOPBACK_POLICY_VERSION);
        assert.equal(event.schemaVersion, 1);
        assert.equal(Object.hasOwn(event, "modelScore"), false);
        assert.equal(Object.hasOwn(event, "modelThreshold"), false);
      }
      assert.equal(Object.hasOwn(allowed, "confidence"), false);
      assert.equal(Object.hasOwn(allowed, "severity"), false);
    } finally {
      await classifier.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
}

test("installed bytes match only for the exact runtime file set and digest", () => {
  const installed = {
    artifactSha256: ARTIFACT_SHA256,
    installedSha256: ARTIFACT_SHA256,
    installedFiles: RUNTIME_FILES.toReversed(),
  };
  assert.equal(installedBytesMatch(installed), true);
  assert.equal(installedBytesMatch({ ...installed, installedSha256: "c".repeat(64) }), false);
  assert.equal(
    installedBytesMatch({ ...installed, installedFiles: [...RUNTIME_FILES, "extra.js"] }),
    false,
  );
});

test("acceptance receipt passes only when every expected scenario passed on matching bytes", () => {
  const receipt = buildAcceptanceReceipt(acceptanceInput());
  assert.equal(receipt.schema, ACCEPTANCE_SCHEMA);
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.classifier, "loopback");
  assert.deepEqual(receipt.host, { name: "GitHub Copilot CLI", version: "1.0.108" });
  assert.deepEqual(receipt.classifier_requests, [
    { hook: "tool_call", decision: "block", durationMs: 12, outcome: "success" },
  ]);
  assert.equal(receipt.exclusions.includes("real classifier APIs"), true);

  const withoutPrompt = passingScenarios().filter((item) => item.id !== PROMPT_SCENARIO_ID);
  assert.equal(
    buildAcceptanceReceipt(acceptanceInput({ scenarios: withoutPrompt })).status,
    "FAIL",
  );
  assert.equal(
    buildAcceptanceReceipt(acceptanceInput({
      plugin: { ...acceptanceInput().plugin, installed_bytes_match: false },
    })).status,
    "FAIL",
  );
});

test("acceptance receipt reports blocked live runs and redacts paths from failures", () => {
  const liveScenarios = [
    { id: "allow", status: "PASS", effect_present: true, checks: {} },
    {
      id: "tool-response-block",
      status: "BLOCKED",
      blocker: "classifier_did_not_flag_attack",
      checks: {},
    },
  ];
  const blocked = buildAcceptanceReceipt(acceptanceInput({ live: true, scenarios: liveScenarios }));
  assert.equal(blocked.status, "BLOCKED");
  assert.equal(blocked.classifier, "live");
  assert.equal(blocked.exclusions.includes("real classifier APIs"), false);
  assert.equal(
    buildAcceptanceReceipt(acceptanceInput({
      live: true,
      scenarios: liveScenarios.map((item) => ({ ...item, status: "PASS" })),
    })).status,
    "PASS",
  );

  const failed = buildAcceptanceReceipt(acceptanceInput({
    error: new Error("Copilot exited 1: /private/root/workspace missing"),
    redactions: [["/private/root", "<private-root>"]],
  }));
  assert.equal(failed.status, "FAIL");
  assert.deepEqual(failed.error, {
    name: "Error",
    message: "Copilot exited 1: <private-root>/workspace missing",
  });
});

test("plugin root override requires an absolute payload and a plain semver", () => {
  const checkout = pluginRootConfig({});
  assert.equal(checkout.expectedPluginVersion, "0.4.0");
  assert.equal(path.isAbsolute(checkout.pluginRoot), true);
  assert.deepEqual(
    pluginRootConfig({ NATIVE_PLUGIN_ROOT: "/payload/source", NATIVE_PLUGIN_VERSION: "1.2.3", NATIVE_SOURCE_SHA: "a".repeat(40) }),
    { pluginRoot: "/payload/source", expectedPluginVersion: "1.2.3" },
  );
  assert.throws(() => pluginRootConfig({
    NATIVE_PLUGIN_ROOT: "/payload", NATIVE_PLUGIN_VERSION: "1.2.3", GITHUB_SHA: "b".repeat(40),
  }), /requires a full NATIVE_SOURCE_SHA/u);
  assert.throws(() => pluginRootConfig({ NATIVE_PLUGIN_VERSION: "1.2.3" }), /requires NATIVE_PLUGIN_ROOT/u);
  assert.throws(() => pluginRootConfig({ NATIVE_PLUGIN_ROOT: "payload" }), /must be absolute/u);
  assert.throws(() => pluginRootConfig({ NATIVE_PLUGIN_ROOT: "/payload" }), /plain semver/u);
  assert.throws(
    () => pluginRootConfig({ NATIVE_PLUGIN_ROOT: "/payload", NATIVE_PLUGIN_VERSION: "1.2.3-rc.1" }),
    /plain semver/u,
  );
});
