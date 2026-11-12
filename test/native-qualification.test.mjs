import assert from "node:assert/strict";
import test from "node:test";
import {
  ACCEPTANCE_SCHEMA,
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
  productEvidenceIdentity,
  promptScenario,
  responseUserTexts,
  startClassifier,
  toolScenarios,
} from "../scripts/native-qualification.mjs";

const RUNTIME_FILES = ["dist/copilot-hook.js", "hooks/hooks.json", "package.json", "plugin.json"];
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
      version: "0.3.6",
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
  const upstream = { prediction: "BENIGN", mode: "block", action: null };
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
    liveEnforcementBlocker(
      LIVE_TOOL_RESPONSE_BLOCK,
      attack("malicious", { upstream: { mode: "shadow" } }),
    ),
    "tenant_not_in_block_mode",
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

test("live classifier proxy forwards each request upstream and records the upstream verdict", async () => {
  const upstreamCalls = [];
  const verdicts = [
    new Response(JSON.stringify({
      prediction: "MALICIOUS",
      mode: "block",
      governance: { action: "block" },
    })),
    new Response("unavailable", { status: 503 }),
  ];
  const classifier = startClassifier({
    live: { url: "https://cascade.invalid/classify", key: "synthetic-live-key" },
    fetchImpl: async (url, init) => {
      upstreamCalls.push({ url, key: init.headers["x-api-key"], body: JSON.parse(init.body) });
      return verdicts.shift();
    },
  });
  const classifierUrl = await classifier.listen();
  const classify = (text) => fetch(classifierUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ hook: "tool_response", text }),
  });
  try {
    const flagged = await classify(LIVE_ATTACK_TEXT);
    assert.equal(flagged.status, 200);
    assert.equal((await flagged.json()).prediction, "MALICIOUS");
    assert.equal((await classify("benign control")).status, 500);
  } finally {
    await classifier.close();
  }
  assert.deepEqual(upstreamCalls.map((call) => [call.url, call.key, call.body.text]), [
    ["https://cascade.invalid/classify", "synthetic-live-key", LIVE_ATTACK_TEXT],
    ["https://cascade.invalid/classify", "synthetic-live-key", "benign control"],
  ]);
  const [flagged, failed] = classifier.requests;
  assert.equal(flagged.decision, "malicious");
  assert.equal(flagged.outcome, "success");
  assert.deepEqual(flagged.upstream, { prediction: "MALICIOUS", mode: "block", action: "block" });
  assert.equal(typeof flagged.durationMs, "number");
  assert.equal(failed.outcome, "http_error");
  assert.equal(failed.httpStatus, 503);
  assert.equal(failed.decision, undefined);
  assert.equal(typeof failed.durationMs, "number");
});

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
