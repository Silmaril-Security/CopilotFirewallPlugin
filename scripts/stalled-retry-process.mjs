import { writeSync } from "node:fs";
import * as hook from "../dist/copilot-hook.js";
// Exercise the default shipped runtime dependencies, including their bounded optional device-name lookup.
let attempts = 0;
globalThis.fetch = async () => ++attempts < 3
  ? new Response("throttled", { status: 429 })
  : new Response(new ReadableStream({ cancel: () => new Promise(() => {}) }), { status: 429 });
const env = process.env;
const started = performance.now();
let hookMS;
// Observe natural process exit after every SDK timer has drained, excluding startup.
process.once("exit", () => writeSync(1, JSON.stringify({ attempts, hookMS, processMS: performance.now() - started }) + "\n"));
await hook.runCopilotHook("userPromptSubmitted", { prompt: "synthetic test" }, env);
hookMS = performance.now() - started;
