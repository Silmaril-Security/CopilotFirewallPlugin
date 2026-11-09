# Changelog

## 0.3.6 - Unreleased

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
- Target the GitHub Copilot CLI 1.0.108 transformed-prompt contract. Native batch and resume qualification remains
  pending because no approved 1.0.108 host copy or no-inference host harness
  was available in this worktree.

## 0.3.5

The published v0.3.5 artifacts remain immutable and retain their original
submitted-prompt observation behavior.
