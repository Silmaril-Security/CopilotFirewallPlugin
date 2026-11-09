# Changelog

## 0.3.6 - 2026-11-09

- Register `userPromptTransformed` instead of `userPromptSubmitted` and classify
  the exact model-facing `transformedPrompt` bytes.
- In Block mode, replace a block candidate with the fixed bounded
  `modifiedTransformedPrompt` value without claiming turn rejection.
- Keep transformed content unchanged in Shadow and Warn; record transformed
  Warn delivery as unsupported.
- Map validated Copilot `sessionId` values to Firewall `conversationId`
  metadata without changing existing non-transformed request identities.
- Add deterministic primary, preceding-batch, retry, resume-fixture, and
  loopback wire-contract coverage.
- Add a disposable CI qualification gate with recorded evidence from the
  checksum-pinned GitHub Copilot CLI 1.0.108 host, loopback-only model and
  classifier fixtures, exact primary transformed bytes, fixed Block
  replacement, and resume history.
- Pin the public Copilot SDK v1.0.30-preview.0 queue contract and record
  `session.send` FIFO enqueue behavior against the exact 1.0.108 executable
  with a gated first model response, three ordered callbacks, and three
  ordered model turns.
- Bind resumed-turn qualification to the current model user item, require an
  exact production-fingerprint join between callbacks and evidence, and align
  the declared Node.js minimum with the SDK at 22.12.0.

## 0.3.5

The published v0.3.5 artifacts remain immutable and retain their original
submitted-prompt observation behavior.
