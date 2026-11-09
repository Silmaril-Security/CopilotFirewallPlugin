import assert from "node:assert/strict";
import test from "node:test";
import {
  SAFE_BLOCK_MESSAGE,
  assertExactModelText,
  assertTextAbsent,
  byteReceipt,
  collectStrings,
} from "../scripts/native-qualification.mjs";

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
