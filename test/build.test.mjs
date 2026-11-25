import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

test("build succeeds in a checkout path with spaces and non-ASCII characters", async () => {
  const scratch = path.join(ROOT, ".test-build");
  await mkdir(scratch, { recursive: true });
  const checkout = await mkdtemp(path.join(scratch, "copilot café checkout-"));
  try {
    await mkdir(path.join(checkout, "scripts"));
    await cp(path.join(ROOT, "scripts", "build.mjs"), path.join(checkout, "scripts", "build.mjs"));
    await cp(path.join(ROOT, "src"), path.join(checkout, "src"), { recursive: true });
    await cp(path.join(ROOT, "package.json"), path.join(checkout, "package.json"));
    await cp(path.join(ROOT, "tsconfig.json"), path.join(checkout, "tsconfig.json"));

    // The nested checkout resolves dependencies from the repository's installed node_modules.
    execFileSync(process.execPath, [path.join(checkout, "scripts", "build.mjs")], {
      cwd: checkout,
      stdio: "pipe",
    });

    const output = await stat(path.join(checkout, "dist", "copilot-hook.js"));
    assert.ok(output.isFile() && output.size > 0);
  } finally {
    await rm(checkout, { recursive: true, force: true });
  }
});
