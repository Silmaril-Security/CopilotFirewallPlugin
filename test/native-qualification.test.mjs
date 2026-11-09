import assert from "node:assert/strict";
import test from "node:test";
import {
  SAFE_BLOCK_MESSAGE,
  assertCurrentUserText,
  assertEvidenceMatchesCallbacks,
  assertExactModelText,
  assertTextAbsent,
  byteReceipt,
  collectStrings,
  productEvidenceIdentity,
  responseUserTexts,
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
