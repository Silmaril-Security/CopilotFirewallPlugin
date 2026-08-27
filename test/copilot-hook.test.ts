import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import {
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
    resource: { kind: "mcp_tool", id: "create_issue", parent_id: "github" },
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

    async classify(text: string, options: unknown) {
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
    "block", "block", "monitor", "monitor", "block",
  ]);
  assert.deepEqual(events.map((event) => event.nativeAction), [
    "block_returned", "content_replaced", "allowed", "allowed", "block_returned",
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
  for (const eventName of ["userPromptSubmitted", "subagentStop"] as const) {
    assert.deepEqual(
      await runCopilotHook(eventName, payload(eventName), backendControlledEnv, dependencies([malicious], events)),
      {},
    );
  }
  assert.ok(events.slice(0, 3).every((event) => event.warnDelivery === "delivered"));
  assert.ok(events.slice(3).every((event) => event.warnDelivery === "unsupported"));
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
  const target = buildHookTarget("userPromptSubmitted", {
    sessionId: "session-1",
    timestamp: 1,
    prompt: `Verify ${marker}`,
  });
  assert.equal(
    target?.requestFingerprint,
    createHash("sha256").update(marker).digest("hex"),
  );
});

test("provenance is plugin-owned and local evidence is private and raw-content free", async () => {
  assert.deepEqual(withProvenance({
    trace: "keep",
    silmaril: { provenance: { harness: "spoofed" } },
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
  assert.equal(packageJson.version, "0.2.4");
  assert.equal(pluginJson.name, "silmaril-firewall");
  assert.equal(pluginJson.version, packageJson.version);
  assert.equal(pluginJson.hooks, "hooks/hooks.json");
  assert.equal(packageJson.dependencies["@silmaril-security/sdk"], "0.6.2");
  assert.deepEqual(Object.keys(hooks.hooks), [
    "userPromptSubmitted",
    "preToolUse",
    "postToolUse",
    "postToolUseFailure",
    "agentStop",
    "subagentStop",
  ]);
});
