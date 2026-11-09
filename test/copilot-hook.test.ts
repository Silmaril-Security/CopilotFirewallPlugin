import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { Firewall, type ClassifyOptions } from "@silmaril-security/sdk";
import {
  MAX_SAFE_REPLACEMENT_BYTES,
  PLUGIN_NAME,
  PLUGIN_VERSION,
  SAFE_BLOCK_MESSAGE,
  SAFE_WARN_MESSAGE,
  buildHookTarget,
  effectiveMode,
  governanceContext,
  isBlockCandidate,
  runCopilotHook,
  withProvenance,
  type CopilotEventName,
  type RuntimeDependencies,
} from "../src/copilot-hook.ts";
import {
  buildLocalProtectionEvent,
  writeLocalProtectionEvent,
} from "../src/local-evidence.ts";
import { resolveRuntimeConfig } from "../src/runtime-config.ts";

const MISSING_CONFIG = path.join(os.tmpdir(), "silmaril-copilot-missing", "settings.json");
const BASE_ENV = {
  SILMARIL_CONFIG_PATH: MISSING_CONFIG,
  SILMARIL_API_KEY: "test-key",
  SILMARIL_API_URL: "https://firewall.example/classify",
  SILMARIL_ENDPOINT_ID: "2b64e603-f82a-4aec-9524-9736472dc80a",
  SILMARIL_TIMEOUT_MS: "2500",
  SILMARIL_BLOCK_MALICIOUS: "false",
  SILMARIL_DEBUG: "false",
};

test("effective mode keeps an explicit non-blocking override authoritative", () => {
  assert.equal(effectiveMode({ prediction: "MALICIOUS", mode: "block" }, "shadow"), "shadow");
  assert.equal(effectiveMode({ prediction: "MALICIOUS" }), "shadow");
});

test("governance context normalizes tool, MCP, and subagent identities", () => {
  assert.deepEqual(governanceContext({
    eventName: "preToolUse",
    toolName: "bash",
    metadata: {},
  }), {
    agent: "copilot",
    resource: { kind: "tool", id: "bash" },
  });
  assert.deepEqual(governanceContext({
    eventName: "preToolUse",
    toolName: "mcp__github__create_issue",
    metadata: {},
  }), {
    agent: "copilot",
    resource: { kind: "mcp_tool", id: "create_issue", parentId: "github" },
  });
  assert.deepEqual(governanceContext({
    eventName: "subagentStop",
    metadata: { agentType: "task" },
  }), {
    agent: "copilot",
    resource: { kind: "agent", id: "task" },
  });
  assert.equal(isBlockCandidate({ prediction: "BENIGN", governance: { action: "block" } }), true);
  assert.equal(isBlockCandidate({ prediction: "MALICIOUS", governance: { action: "allow" } }), true);
});

function dependencies(
  results: Array<Record<string, unknown> | Error>,
  events: unknown[] = [],
  calls: unknown[] = [],
) {
  class FakeFirewall {
    constructor(options: unknown) {
      calls.push({ constructor: options });
    }

    async classify(text: string, options: ClassifyOptions) {
      calls.push({ text, options });
      const result = results.shift();
      if (result instanceof Error) throw result;
      return result ?? { prediction: "BENIGN", score: 0.01, threshold: 0.5 };
    }
  }
  return {
    firewallConstructor: FakeFirewall,
    evidenceEmitter: async (event: unknown) => { events.push(event); },
  };
}

function payload(event: CopilotEventName, transcriptPath?: string): Record<string, unknown> {
  const base = {
    sessionId: "session-1",
    timestamp: 1_787_156_024_056,
    cwd: "/tmp/project",
  };
  switch (event) {
    case "userPromptSubmitted":
      return { ...base, prompt: "user prompt" };
    case "userPromptTransformed":
      return {
        ...base,
        prompt: "user prompt",
        transformedPrompt: "runtime-transformed user prompt",
      };
    case "preToolUse":
      return { ...base, toolName: "bash", toolArgs: { command: "pwd" } };
    case "postToolUse":
      return {
        ...base,
        toolName: "bash",
        toolArgs: { command: "pwd" },
        toolResult: { resultType: "success", textResultForLlm: "tool result" },
      };
    case "postToolUseFailure":
      return { ...base, toolName: "bash", toolArgs: {}, error: "tool failed" };
    case "agentStop":
      return { ...base, transcriptPath, stopReason: "end_turn" };
    case "subagentStop":
      return {
        ...base,
        agentId: "agent-1",
        agentType: "task",
        agentName: "explore",
        response: "subagent output",
        stopReason: "end_turn",
      };
  }
}

test("runtime configuration requires a private schema-v1 file when present", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-copilot-config-"));
  const filePath = path.join(root, "silmaril-firewall.json");
  await writeFile(filePath, JSON.stringify({
    schemaVersion: 1,
    enabled: true,
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    endpointId: "2b64e603-f82a-4aec-9524-9736472dc80a",
    timeoutMs: 375,
    mode: "block",
    blockMalicious: true,
    debug: true,
  }), { mode: 0o600 });
  assert.deepEqual(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: filePath }), {
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    endpointId: "2b64e603-f82a-4aec-9524-9736472dc80a",
    timeoutMs: 375,
    mode: "block",
    blockMalicious: true,
    debug: true,
  });
  await chmod(filePath, 0o644);
  assert.equal(resolveRuntimeConfig({ ...BASE_ENV, SILMARIL_CONFIG_PATH: filePath }), undefined);
  await chmod(filePath, 0o600);
  const linked = path.join(root, "linked.json");
  await symlink(filePath, linked);
  assert.equal(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: linked }), undefined);
  await writeFile(filePath, JSON.stringify({ schemaVersion: 2 }), { mode: 0o600 });
  assert.equal(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: filePath }), undefined);
});

test("shadow mode classifies only events with current native content", async () => {
  const events: any[] = [];
  const calls: any[] = [];
  const eventNames: CopilotEventName[] = [
    "userPromptSubmitted",
    "userPromptTransformed",
    "preToolUse",
    "postToolUse",
    "postToolUseFailure",
    "agentStop",
    "subagentStop",
  ];
  const deps = dependencies(
    eventNames.map(() => ({ prediction: "MALICIOUS", score: 0.9, threshold: 0.5 })),
    events,
    calls,
  );
  for (const eventName of eventNames) {
    assert.deepEqual(
      await runCopilotHook(
        eventName,
        payload(eventName, "/tmp/ignored-transcript.jsonl"),
        BASE_ENV,
        deps,
      ),
      {},
    );
  }
  assert.deepEqual(
    calls.filter((call) => call.text).map((call) => call.options.hook),
    ["user_input", "tool_call", "tool_response", "tool_response", "llm_output"],
  );
  assert.ok(calls.filter((call) => call.text).every(
    (call) => call.options.metadata.silmaril.provenance.harness === "copilot",
  ));
  assert.ok(events.every((event) => event.mode === "shadow" && event.policyDecision === "monitor"));
  assert.doesNotMatch(
    JSON.stringify(events),
    /user prompt|tool result|tool failed|subagent output/u,
  );
});

test("transformed prompts preserve bytes and use only bounded model-facing replacement", async () => {
  const exact = " \tprimary\r\npreceding\u0000unicode \u03b2 \n";
  const input = {
    sessionId: " session-1 ",
    timestamp: 1_787_156_024_056,
    cwd: "/tmp/project",
    prompt: "visible prompt",
    transformedPrompt: exact,
  };
  const calls: any[] = [];
  const benign = await runCopilotHook(
    "userPromptTransformed",
    input,
    BASE_ENV,
    dependencies([{ prediction: "BENIGN" }], [], calls),
  );
  assert.deepEqual(benign, {});
  assert.equal(calls.find((call) => call.text)?.text, exact);
  assert.equal(buildHookTarget("userPromptTransformed", input)?.text, exact);

  const events: any[] = [];
  const blocked = await runCopilotHook(
    "userPromptTransformed",
    input,
    { ...BASE_ENV, SILMARIL_MODE: "block" },
    dependencies([{ prediction: "MALICIOUS" }], events),
  );
  assert.deepEqual(blocked, { modifiedTransformedPrompt: SAFE_BLOCK_MESSAGE });
  assert.deepEqual(Object.keys(blocked), ["modifiedTransformedPrompt"]);
  assert.ok(Buffer.byteLength(SAFE_BLOCK_MESSAGE, "utf8") <= MAX_SAFE_REPLACEMENT_BYTES);
  assert.doesNotMatch(JSON.stringify(blocked), /primary|preceding|unicode/u);
  assert.equal(events[0].nativeAction, "content_replaced");
  assert.equal(events[0].policyDecision, "block");
  assert.equal(events[0].evidenceTruth, "native_response_returned");
});

test("transformed prompt identity is deterministic for primary, batch, retry, and resume fixtures", async () => {
  const primary = payload("userPromptTransformed");
  const preceding = {
    ...payload("userPromptTransformed"),
    prompt: "preceding prompt",
    transformedPrompt: "preceding model-facing bytes",
  };
  const resumed = { ...primary };
  const differentSession = { ...primary, sessionId: "session-2" };

  const primaryTarget = buildHookTarget("userPromptTransformed", primary);
  const retryTarget = buildHookTarget("userPromptTransformed", { ...primary });
  const resumedTarget = buildHookTarget("userPromptTransformed", resumed);
  const precedingTarget = buildHookTarget("userPromptTransformed", preceding);
  const isolatedTarget = buildHookTarget("userPromptTransformed", differentSession);
  assert.ok(primaryTarget);
  assert.equal(retryTarget?.requestId, primaryTarget.requestId);
  assert.equal(resumedTarget?.requestId, primaryTarget.requestId);
  assert.notEqual(precedingTarget?.requestId, primaryTarget.requestId);
  assert.notEqual(isolatedTarget?.requestId, primaryTarget.requestId);

  const expected = `${PLUGIN_NAME}-${createHash("sha256").update([
    "session-1",
    "userPromptTransformed",
    "1787156024056",
    createHash("sha256").update("user prompt").digest("hex"),
    createHash("sha256").update("runtime-transformed user prompt").digest("hex"),
  ].join("\u0000")).digest("hex")}`;
  assert.equal(primaryTarget.requestId, expected);

  const calls: any[] = [];
  const batchDependencies = dependencies(
    [{ prediction: "BENIGN" }, { prediction: "BENIGN" }],
    [],
    calls,
  );
  assert.deepEqual(await runCopilotHook("userPromptTransformed", preceding, BASE_ENV, batchDependencies), {});
  assert.deepEqual(await runCopilotHook("userPromptTransformed", primary, BASE_ENV, batchDependencies), {});
  assert.deepEqual(
    calls.filter((call) => call.text).map((call) => call.text),
    ["preceding model-facing bytes", "runtime-transformed user prompt"],
  );

  const malicious = { prediction: "MALICIOUS" };
  const blockEnv = { ...BASE_ENV, SILMARIL_MODE: "block" };
  const originalOutput = await runCopilotHook(
    "userPromptTransformed",
    primary,
    blockEnv,
    dependencies([malicious]),
  );
  const replayOutput = await runCopilotHook(
    "userPromptTransformed",
    resumed,
    blockEnv,
    dependencies([malicious]),
  );
  assert.deepEqual(originalOutput, { modifiedTransformedPrompt: SAFE_BLOCK_MESSAGE });
  assert.deepEqual(replayOutput, originalOutput);

  const legacyCalls: any[] = [];
  assert.deepEqual(
    await runCopilotHook(
      "userPromptSubmitted",
      payload("userPromptSubmitted"),
      BASE_ENV,
      dependencies([{ prediction: "MALICIOUS" }], [], legacyCalls),
    ),
    {},
  );
  assert.equal(legacyCalls.filter((call) => call.text).length, 0);
});

test("transformed prompt parser requires only the official required schema", () => {
  const valid = payload("userPromptTransformed");
  assert.ok(buildHookTarget("userPromptTransformed", valid));
  for (const field of ["sessionId", "timestamp", "cwd", "prompt", "transformedPrompt"]) {
    const invalid = { ...valid };
    delete invalid[field];
    assert.equal(buildHookTarget("userPromptTransformed", invalid), undefined);
  }
  assert.equal(buildHookTarget("userPromptTransformed", { ...valid, timestamp: 1.5 }), undefined);
  assert.equal(buildHookTarget("userPromptTransformed", { ...valid, sessionId: " \t" }), undefined);
});

test("conversation metadata does not change existing non-transformed request identities", () => {
  const input = payload("preToolUse");
  const target = buildHookTarget("preToolUse", input);
  const text = JSON.stringify({ command: "pwd" });
  const expected = `${PLUGIN_NAME}-${createHash("sha256").update([
    "session-1",
    "preToolUse",
    "1787156024056",
    createHash("sha256").update(text).digest("hex"),
  ].join("\u0000")).digest("hex")}`;
  assert.equal(target?.requestId, expected);
  assert.equal(target?.metadata.sessionId, "session-1");
  assert.equal(target?.metadata.conversationId, "session-1");
});

test("SDK serializes native agent, tool, and MCP governance resources on the wire", async () => {
  const cases = [
    {
      eventName: "userPromptTransformed" as const,
      input: payload("userPromptTransformed"),
      resource: { kind: "agent", id: "copilot" },
    },
    {
      eventName: "preToolUse" as const,
      input: payload("preToolUse"),
      resource: { kind: "tool", id: "bash" },
    },
    {
      eventName: "preToolUse" as const,
      input: {
        ...payload("preToolUse"),
        toolName: "mcp__github__create_issue",
      },
      resource: { kind: "mcp_tool", id: "create_issue", parent_id: "github" },
    },
  ];

  const requests = await captureSdkRequests(async (apiUrl) => {
    for (const item of cases) {
      assert.deepEqual(
        await runCopilotHook(
          item.eventName,
          item.input,
          { ...BASE_ENV, SILMARIL_API_URL: apiUrl },
          {
            firewallConstructor: Firewall as unknown as RuntimeDependencies["firewallConstructor"],
            evidenceEmitter: async () => undefined,
            deviceName: () => undefined,
          },
        ),
        {},
      );
    }
  });

  assert.equal(requests.length, cases.length);
  for (const [index, request] of requests.entries()) {
    const expected = cases[index]!;
    assert.deepEqual(request.resource, expected.resource);
    assert.deepEqual(request.metadata.silmaril.governance, {
      agent: "copilot",
      resource: expected.resource,
    });
    assert.equal(
      Object.hasOwn(request.metadata.silmaril.governance.resource, "parentId"),
      false,
    );
    assert.equal(request.metadata.silmaril.sdk_version, "0.8.2");
    assert.equal(request.metadata.sessionId, "session-1");
    assert.equal(request.metadata.conversationId, "session-1");
    assert.equal(
      request.metadata.silmaril.request_id,
      buildHookTarget(expected.eventName, expected.input)?.requestId,
    );
  }
});

test("SDK wire metadata preserves session correlation and retry request identity", async () => {
  const input = payload("userPromptTransformed");
  const requests = await captureSdkRequests(async (apiUrl) => {
    for (const current of [input, { ...input }, { ...input, sessionId: "session-2" }]) {
      assert.deepEqual(
        await runCopilotHook(
          "userPromptTransformed",
          current,
          { ...BASE_ENV, SILMARIL_API_URL: apiUrl },
          {
            firewallConstructor: Firewall as unknown as RuntimeDependencies["firewallConstructor"],
            evidenceEmitter: async () => undefined,
            deviceName: () => undefined,
          },
        ),
        {},
      );
    }
  });
  assert.equal(requests.length, 3);
  assert.equal(requests[0].metadata.silmaril.request_id, requests[1].metadata.silmaril.request_id);
  assert.notEqual(requests[0].metadata.silmaril.request_id, requests[2].metadata.silmaril.request_id);
  assert.deepEqual(
    requests.map((request) => [request.metadata.sessionId, request.metadata.conversationId]),
    [["session-1", "session-1"], ["session-1", "session-1"], ["session-2", "session-2"]],
  );
});

test("block mode uses native deny, replacement, and stop decisions", async () => {
  const malicious = { prediction: "MALICIOUS", primaryOutcome: "code_execution" };
  const env = { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" };
  const events: any[] = [];
  const preTool = await runCopilotHook(
    "preToolUse",
    payload("preToolUse"),
    env,
    dependencies([malicious], events),
  );
  assert.deepEqual(preTool, {
    permissionDecision: "deny",
    permissionDecisionReason: SAFE_BLOCK_MESSAGE,
  });
  const postTool = await runCopilotHook(
    "postToolUse",
    payload("postToolUse"),
    env,
    dependencies([malicious], events),
  );
  assert.deepEqual(postTool, {
    modifiedResult: {
      resultType: "success",
      textResultForLlm: SAFE_BLOCK_MESSAGE,
    },
    additionalContext: SAFE_BLOCK_MESSAGE,
  });
  assert.doesNotMatch(JSON.stringify(postTool), /tool result/u);
  assert.deepEqual(
    await runCopilotHook(
      "userPromptTransformed",
      payload("userPromptTransformed"),
      env,
      dependencies([malicious], events),
    ),
    { modifiedTransformedPrompt: SAFE_BLOCK_MESSAGE },
  );
  for (const eventName of ["userPromptSubmitted", "postToolUseFailure"] as const) {
    assert.deepEqual(
      await runCopilotHook(eventName, payload(eventName), env, dependencies([malicious], events)),
      {},
    );
  }
  assert.deepEqual(
    await runCopilotHook("subagentStop", payload("subagentStop"), env, dependencies([malicious], events)),
    { decision: "block", reason: SAFE_BLOCK_MESSAGE },
  );
  assert.deepEqual(events.map((event) => event.policyDecision), [
    "block", "block", "block", "monitor", "block",
  ]);
  assert.deepEqual(events.map((event) => event.nativeAction), [
    "block_returned", "content_replaced", "content_replaced", "allowed", "block_returned",
  ]);
  assert.equal(events[1].blockUnavailable, undefined);
  assert.equal(events[1].evidenceTruth, "native_response_returned");
});

test("governance block uses native deny only in existing block mode", async () => {
  const governed = {
    prediction: "BENIGN",
    governance: { action: "block", rule_id: "block-tool", policy_version: "v1" },
  };

  assert.deepEqual(
    await runCopilotHook(
      "preToolUse",
      payload("preToolUse"),
      { ...BASE_ENV, SILMARIL_MODE: "shadow" },
      dependencies([governed]),
    ),
    {},
  );
  const warned = await runCopilotHook(
    "preToolUse",
    payload("preToolUse"),
    { ...BASE_ENV, SILMARIL_MODE: "warn" },
    dependencies([governed]),
  );
  assert.equal(warned.permissionDecision, undefined);
  assert.equal(warned.additionalContext, SAFE_WARN_MESSAGE);

  assert.deepEqual(
    await runCopilotHook(
      "preToolUse",
      payload("preToolUse"),
      { ...BASE_ENV, SILMARIL_MODE: "block" },
      dependencies([governed]),
    ),
    {
      permissionDecision: "deny",
      permissionDecisionReason: SAFE_BLOCK_MESSAGE,
    },
  );
  assert.deepEqual(
    await runCopilotHook(
      "postToolUse",
      payload("postToolUse"),
      { ...BASE_ENV, SILMARIL_MODE: "block" },
      dependencies([governed]),
    ),
    {
      modifiedResult: {
        resultType: "success",
        textResultForLlm: SAFE_BLOCK_MESSAGE,
      },
      additionalContext: SAFE_BLOCK_MESSAGE,
    },
  );
});

test("warn mode surfaces one bounded warning only on supported context hooks", async () => {
  const malicious = { prediction: "MALICIOUS", mode: "warn", score: 0.99 };
  const events: any[] = [];
  const backendControlledEnv: Record<string, string> = { ...BASE_ENV };
  delete backendControlledEnv.SILMARIL_BLOCK_MALICIOUS;
  for (const eventName of ["preToolUse", "postToolUse", "postToolUseFailure"] as const) {
    assert.deepEqual(
      await runCopilotHook(eventName, payload(eventName), backendControlledEnv, dependencies([malicious], events)),
      { additionalContext: SAFE_WARN_MESSAGE },
    );
  }
  for (const eventName of ["userPromptTransformed", "userPromptSubmitted", "subagentStop"] as const) {
    assert.deepEqual(
      await runCopilotHook(eventName, payload(eventName), backendControlledEnv, dependencies([malicious], events)),
      {},
    );
  }
  assert.ok(events.slice(0, 3).every((event) => event.warnDelivery === "delivered"));
  assert.ok(events.slice(3).every((event) => event.warnDelivery === "unsupported"));
  assert.ok(events.slice(3).every((event) => event.nativeAction === "allowed"));
  assert.doesNotMatch(JSON.stringify(events), /tool result|tool failed|user prompt|subagent output/u);
});

test("classification and evidence failures always fail open", async () => {
  const output = await runCopilotHook(
    "preToolUse",
    payload("preToolUse"),
    { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
    dependencies([new Error("network failure")]),
  );
  assert.deepEqual(output, {});
  const evidenceFailure = await runCopilotHook(
    "preToolUse",
    payload("preToolUse"),
    { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
    {
      ...dependencies([{ prediction: "MALICIOUS" }]),
      evidenceEmitter: async () => { throw new Error("disk failure"); },
    },
  );
  assert.equal(evidenceFailure.permissionDecision, "deny");

  const cli = spawnSync(
    process.execPath,
    [new URL("../dist/copilot-hook.js", import.meta.url).pathname, "preToolUse"],
    { input: "not-json", encoding: "utf8" },
  );
  assert.equal(cli.status, 0);
  assert.deepEqual(JSON.parse(cli.stdout), {});
});

test("agentStop ignores transcript paths instead of reconstructing output", async () => {
  const transcript = path.join(await mkdtemp(path.join(os.tmpdir(), "silmaril-copilot-transcript-")), "events.jsonl");
  await writeFile(transcript, Array.from({ length: 300 }, (_, index) => JSON.stringify({
    type: "assistant.message",
    data: { content: `historical output ${index}` },
  })).join("\n"));
  const calls: any[] = [];
  assert.equal(buildHookTarget("agentStop", payload("agentStop", transcript)), undefined);
  assert.deepEqual(
    await runCopilotHook("agentStop", payload("agentStop", transcript), BASE_ENV, dependencies([], [], calls)),
    {},
  );
  assert.equal(calls.filter((call) => call.text).length, 0);
});

test("runtime check markers become the exact repair request fingerprint", () => {
  const marker = "silmaril-runtime-check:12345678-1234-4123-8123-123456789abc";
  const target = buildHookTarget("userPromptTransformed", {
    sessionId: "session-1",
    timestamp: 1,
    cwd: "/tmp/project",
    prompt: `Verify ${marker}`,
    transformedPrompt: `Verify ${marker}`,
  });
  assert.equal(
    target?.requestFingerprint,
    createHash("sha256").update(marker).digest("hex"),
  );
});

test("provenance is plugin-owned and local evidence is private and raw-content free", async () => {
  assert.deepEqual(withProvenance({
    trace: "keep",
    silmaril: { provenance: { harness: "spoofed", device_name: "spoofed-host" } },
  }, "2b64e603-f82a-4aec-9524-9736472dc80a"), {
    trace: "keep",
    silmaril: {
      provenance: {
        schema_version: 1,
        endpoint_id: "2b64e603-f82a-4aec-9524-9736472dc80a",
        harness: "copilot",
      },
    },
  });
  assert.deepEqual(withProvenance({
    trace: "keep",
    silmaril: { integration: "silmaril-firewall", provenance: { device_name: "spoofed-host", endpoint_id: "spoofed" } },
  }, undefined, undefined, "  Office Mac \n"), {
    trace: "keep",
    silmaril: {
      integration: "silmaril-firewall",
      provenance: {
        schema_version: 1,
        harness: "copilot",
        device_name: "Office Mac",
      },
    },
  });
  assert.deepEqual(withProvenance(
    {},
    undefined,
    governanceContext({
      eventName: "preToolUse",
      toolName: "mcp__github__create_issue",
      metadata: {},
    }),
  ), {
    silmaril: {
      provenance: {
        schema_version: 1,
        harness: "copilot",
      },
      governance: {
        agent: "copilot",
        resource: {
          kind: "mcp_tool",
          id: "create_issue",
          parent_id: "github",
        },
      },
    },
  });
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-copilot-evidence-"));
  const event = buildLocalProtectionEvent({
    pluginVersion: PLUGIN_VERSION,
    hook: "pre_tool",
    mode: "block",
    requestFingerprint: "request-fingerprint",
    sessionId: "raw-session-id",
    toolName: "bash",
    classification: {
      prediction: "MALICIOUS",
      primaryOutcome: "code_execution",
      raw: "must-not-leak",
    },
    policyDecision: "block",
    nativeAction: "block_returned",
  });
  const destination = await writeLocalProtectionEvent(event, { SILMARIL_LOCAL_EVENT_DIR: root });
  assert.ok(destination);
  const encoded = await readFile(destination, "utf8");
  assert.doesNotMatch(encoded, /must-not-leak|raw-session-id/u);
  assert.equal((await stat(destination)).mode & 0o777, 0o600);
  assert.equal((await stat(root)).mode & 0o777, 0o700);
});

test("manifests are Copilot-native and version aligned", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const pluginJson = JSON.parse(await readFile(new URL("../plugin.json", import.meta.url), "utf8"));
  const hooks = JSON.parse(await readFile(new URL("../hooks/hooks.json", import.meta.url), "utf8"));
  assert.equal(packageJson.version, "0.3.6");
  assert.equal(pluginJson.name, "silmaril-firewall");
  assert.equal(pluginJson.version, packageJson.version);
  assert.equal(pluginJson.hooks, "hooks/hooks.json");
  assert.equal(packageJson.dependencies["@silmaril-security/sdk"], "0.8.2");
  assert.deepEqual(Object.keys(hooks.hooks), [
    "userPromptTransformed",
    "preToolUse",
    "postToolUse",
    "postToolUseFailure",
    "agentStop",
    "subagentStop",
  ]);
});

test("classify metadata includes the mac computer name without an endpoint id", async () => {
  const calls: any[] = [];
  const events: any[] = [];
  const env: Record<string, string> = { ...BASE_ENV, SILMARIL_DEBUG: "true" };
  delete env.SILMARIL_ENDPOINT_ID;
  const stderr = await captureStderr(async () => {
    assert.deepEqual(
      await runCopilotHook("userPromptTransformed", payload("userPromptTransformed"), env, {
        ...dependencies([{ prediction: "BENIGN" }], events, calls),
        deviceName: () => "  Office Mac \n",
      }),
      {},
    );
  });
  const metadata = calls.find((call) => call.text).options.metadata;
  assert.deepEqual(metadata.silmaril.provenance, {
    schema_version: 1,
    harness: "copilot",
    device_name: "Office Mac",
  });
  assert.deepEqual(metadata.silmaril.governance, {
    agent: "copilot",
    resource: { kind: "agent", id: "copilot" },
  });
  assert.doesNotMatch(JSON.stringify(events), /Office Mac/u);
  assert.doesNotMatch(stderr, /Office Mac/u);
});

test("invalid or failed device-name lookup still classifies and drops spoofed metadata", async () => {
  const calls: any[] = [];
  const events: any[] = [];
  const env = { ...BASE_ENV, SILMARIL_DEBUG: "true" };
  const stderr = await captureStderr(async () => {
    assert.deepEqual(
      await runCopilotHook("userPromptTransformed", payload("userPromptTransformed"), env, {
        ...dependencies([{ prediction: "BENIGN" }], events, calls),
        deviceName: () => {
          throw new Error("scutil failed for Office Mac");
        },
      }),
      {},
    );
    for (const deviceName of ["Office\u0000Mac", "Office\u007FMac", "Office\u0085Mac"]) {
      assert.deepEqual(
        await runCopilotHook("preToolUse", payload("preToolUse"), env, {
          ...dependencies([{ prediction: "BENIGN" }], events, calls),
          deviceName: () => deviceName,
        }),
        {},
      );
    }
  });
  const provenances = calls.filter((call) => call.text).map((call) => call.options.metadata.silmaril.provenance);
  assert.equal(provenances.length, 4);
  assert.ok(provenances.every((provenance: { device_name?: string; harness: string; endpoint_id: string }) => (
    provenance.device_name === undefined
    && provenance.harness === "copilot"
    && provenance.endpoint_id === "2b64e603-f82a-4aec-9524-9736472dc80a"
  )));
  assert.doesNotMatch(JSON.stringify(events), /Office Mac/u);
  assert.doesNotMatch(stderr, /Office Mac/u);
});

async function captureStderr(run: () => Promise<void>): Promise<string> {
  const chunks: string[] = [];
  const original = process.stderr.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  try {
    await run();
  } finally {
    process.stderr.write = original;
  }
  return chunks.join("");
}

async function captureSdkRequests(
  run: (apiUrl: string) => Promise<void>,
): Promise<any[]> {
  const requests: any[] = [];
  const server = createServer(async (request, response) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      requests.push(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        prediction: "BENIGN",
        score: 0.01,
        threshold: 0.5,
      }));
    } catch {
      response.writeHead(500);
      response.end();
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    await run(`http://127.0.0.1:${address.port}/classify`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
  return requests;
}
