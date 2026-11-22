# Changelog

## 0.4.0 - Unreleased

- Bundle `@silmaril-security/sdk` 1.0.0. It calls `/v2/classify` on the
  configured endpoint and repeats the request on `/classify` when a deployment
  answers 403, 404, or 405, so configuration is unchanged.
- Treat every classification whose `action` is not `allow` as a block
  candidate. The decision already includes governance, so a governance block
  and a model block follow the same Shadow, Warn, and Block behavior as before.
- Read the local evidence risk category from the classification `outcome`.
- Record `confidence` and `severity` in local evidence when the classification
  carries one of the documented levels, and stop recording `modelScore` and
  `modelThreshold`. The event schema version and every other field are
  unchanged.
- Record the SDK result's `modelId` as the local evidence `modelVersion` and
  the governance decision's `policyVersion` as `policyVersion`. The fields
  previously read `model_id` and a top-level `policy_version`, which the SDK
  never returned, so they were always absent. Both have control and format
  characters removed and are limited to 128 UTF-8 bytes, the limits Silmaril
  for macOS enforces on ingestion.
- Serve a version 2 body on `/v2/classify` and a version 1 body on `/classify`
  from the native qualification classifier. In live mode it mirrors the
  requested classify path upstream and records `{action, source, mode}`.

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
