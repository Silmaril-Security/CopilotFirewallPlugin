import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as hook from "../dist/copilot-hook.js";

// Exercise the shipped bundle and its actual SDK, without network or a native host.
const originalFetch = globalThis.fetch;
const originalTimeout = AbortSignal.timeout;
try {
  for (const status of [429, 200, 503, "stalled-disposal"]) {
    for (const [configured, expected] of [[250, 250], [10000, 8000]]) {
      const deadlines = [];
      let attempts = 0;
      let bodyWasBeingRead = false;
      let bodyAbortReason;
      const deadlineReason = new DOMException("deadline", "TimeoutError");
      AbortSignal.timeout = (ms) => {
        deadlines.push(ms);
        const controller = new AbortController();
        // Accelerate the deadline; SDK retry waits must still be cancelled.
        setTimeout(() => controller.abort(deadlineReason), 20);
        return controller.signal;
      };
      globalThis.fetch = async (_url, { signal }) => {
        attempts += 1;
        if (status === 429) return new Response("throttled", { status });
        if (status === "stalled-disposal") {
          return new Response(new ReadableStream({
            cancel() {
              bodyWasBeingRead = true;
              // Cancellation closes the stream, but its cleanup promise never settles.
              return new Promise(() => {});
            },
          }), { status: 429 });
        }
        let response;
        const stream = new ReadableStream({
          start(controller) {
            // Leave JSON and API error bodies unfinished, like a slow native fetch.
            controller.enqueue(new TextEncoder().encode(status === 200 ? '{"prediction":' : 'partial error'));
            signal.addEventListener("abort", () => {
              bodyWasBeingRead = response.bodyUsed;
              bodyAbortReason = signal.reason;
              controller.error(signal.reason);
            }, { once: true });
          },
        });
        response = new Response(stream, { status });
        return response;
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
      assert.equal(attempts, 1, "deadline stops classification before another request");
      if (status === "stalled-disposal") {
        assert.ok(bodyWasBeingRead, "SDK reached the stalled body-disposal await");
      } else if (status !== 429) {
        assert.ok(bodyWasBeingRead, "deadline expires during an active body read");
        assert.equal(bodyAbortReason, deadlineReason, "caller deadline cancels the body, not the later per-attempt timeout");
      }
      assert.ok(performance.now() - started < 1000, "hook returns during backoff, before host timeout");
    }
  }
  console.log("bundled SDK deadline: configured budget, host cap, retry cancellation, stalled success/error bodies, and stalled 429 disposal passed");
} finally {
  globalThis.fetch = originalFetch;
  AbortSignal.timeout = originalTimeout;
}

// Verify actual process exit after retry cleanup stalls, using real deadline timers.
const child = spawnSync(process.execPath, [fileURLToPath(new URL("stalled-retry-process.mjs", import.meta.url))], {
  timeout: 30000,
  encoding: "utf8",
  env: {
    PATH: process.env.PATH,
    HOME: "/nonexistent/silmaril-deadline-home",
    CODEX_HOME: "/nonexistent/silmaril-deadline-home/.codex",
    SILMARIL_API_KEY: "synthetic-test-key",
    SILMARIL_API_URL: "https://firewall.invalid/classify",
    SILMARIL_CONFIG_PATH: "/nonexistent/silmaril-deadline-test.json",
    SILMARIL_TIMEOUT_MS: "10000",
    SILMARIL_LOCAL_EVENT_DIR: "/dev/null/silmaril-deadline-test",
  },
});
assert.equal(child.status, 0, child.stderr || String(child.error));
const timing = JSON.parse(child.stdout);
assert.equal(timing.attempts, 3, "reached cleanup after two retry waits");
assert.ok(timing.hookMS < 10000, "hook obeys its capped classification budget");
assert.ok(timing.processMS < 10000, "classification and remaining timers finish within the host budget");
assert.ok(timing.processMS - timing.hookMS < 1000, "SDK timers do not retain the process after the hook finishes");
console.log("shipped-bundle process exits within the host budget after stalled retry cleanup");
