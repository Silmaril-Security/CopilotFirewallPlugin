import assert from "node:assert/strict";
import * as hook from "../dist/copilot-hook.js";

// Exercise the shipped bundle and its actual SDK, without network or a native host.
const originalFetch = globalThis.fetch;
const originalTimeout = AbortSignal.timeout;
try {
  for (const [configured, expected] of [[250, 250], [10000, 8000]]) {
    const deadlines = [];
    let attempts = 0;
    AbortSignal.timeout = (ms) => {
      deadlines.push(ms);
      const controller = new AbortController();
      // Accelerate the deadline; SDK retry waits must still be cancelled.
      setTimeout(() => controller.abort(new DOMException("deadline", "TimeoutError")), 20);
      return controller.signal;
    };
    globalThis.fetch = async () => {
      attempts += 1;
      return new Response("throttled", { status: 429 });
    };
    const env = {
      SILMARIL_API_KEY: "synthetic-key",
      SILMARIL_API_URL: "https://firewall.invalid/classify",
      CODEX_HOME: "/nonexistent/silmaril-deadline-codex-home",
      SILMARIL_CONFIG_PATH: "/nonexistent/silmaril-deadline-test.json",
      SILMARIL_TIMEOUT_MS: String(configured),
      SILMARIL_LOCAL_EVENT_DIR: "/dev/null/silmaril-deadline-test",
    };
    const started = performance.now();
    await hook.runCopilotHook("userPromptSubmitted", { prompt: "synthetic test" }, env);
    assert.deepEqual(deadlines, [expected], "one deadline spans the complete classification");
    assert.equal(attempts, 1, "deadline cancels the first retry wait before another request");
    assert.ok(performance.now() - started < 1000, "hook returns during backoff, before host timeout");
  }
  console.log("bundled SDK deadline: configured budget, host cap, and retry cancellation passed");
} finally {
  globalThis.fetch = originalFetch;
  AbortSignal.timeout = originalTimeout;
}
