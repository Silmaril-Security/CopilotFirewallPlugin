# Copilot Firewall Plugin

Silmaril Firewall protection for GitHub Copilot CLI.

The plugin classifies Copilot model-facing transformed prompts, tool calls, tool results, tool failures, and subagent responses from their current native hook payloads. Every native hook event produces at most one classification of that current event. The plugin does not read transcript history or send prior turns. It maps Copilot's validated `sessionId` to both `metadata.sessionId` and `metadata.conversationId`, so events in one session share the Firewall sequence key while different sessions remain isolated.

Shadow records that classification without changing Copilot content. Warn preserves content and returns one bounded content-free `additionalContext` warning on the events that support it. The transformed-prompt hook has no native Warn output, so Warn leaves those bytes unchanged and records unsupported warning delivery. Block uses Copilot-native deny and stop responses, replaces malicious tool results with fixed content, and replaces malicious transformed prompts with the same bounded fixed text before they reach the model.

A governance action of `block` is a block candidate even when the prediction is benign. Native deny, replacement, and stop still require block mode and a supported boundary. Warn mode uses the warning instead of a deny, and shadow mode leaves content unchanged.

## Install

Release [v0.3.5](https://github.com/Silmaril-Security/CopilotFirewallPlugin/releases/tag/v0.3.5)
remains the latest published immutable release. Current source is the unreleased
v0.3.6 candidate and targets the GitHub Copilot CLI
1.0.108 `userPromptTransformed` contract. The disposable
[`native-copilot`](docs/NATIVE_QUALIFICATION.md) CI job qualifies primary and
resume behavior against the checksum-pinned native 1.0.108 host. It also
qualifies FIFO native queueing through the pinned public Copilot SDK
`session.send({mode: "enqueue"})` JSON-RPC contract. Deterministic handler tests
alone do not establish native behavior. For a reproducible installation
of the published release, check out v0.3.5 and use
Copilot CLI's supported local-directory form:

```sh
git clone --branch v0.3.5 --depth 1 https://github.com/Silmaril-Security/CopilotFirewallPlugin.git
cd CopilotFirewallPlugin
copilot plugin install .
```

To install current source instead, Copilot CLI also supports
`copilot plugin install Silmaril-Security/CopilotFirewallPlugin`. The repository
form follows the default branch; no `@tag` syntax is claimed here.

SilmarilMacOS manages the private runtime configuration at `~/.copilot/silmaril-firewall.json`. `COPILOT_HOME` changes that directory, and `SILMARIL_CONFIG_PATH` selects another file. The plugin uses a file only when it is schema version 1, no larger than 64 KiB, a regular non-symlink file owned by the current user when a process uid is available, with no group or other permissions, and with typed values for the fields it sets. That file is the only configuration source, so `enabled: false` or missing credentials fail open without using `SILMARIL_*` variables. A missing file falls back to those variables, including `SILMARIL_ENABLED`. An invalid file fails open and does not use the environment. The plugin also fails open when the Firewall API is unavailable or the hook runtime hits an error. A failed evidence write does not undo a deny, replacement, or stop already chosen.

### Classification deadline

The configured timeout bounds the entire classification, including throttling retries and response reads. Classification is capped at 8 seconds to leave time for hook output before the host deadline. Deadline errors follow the existing hook error behavior.


## Develop

Node.js 22 or newer:

```sh
npm ci
npm run typecheck
npm test
```

`npm test` rebuilds `dist/copilot-hook.js` through `scripts/build.mjs`. That file stays committed because `hooks/hooks.json` executes it directly. The bundle includes `@silmaril-security/sdk` 0.8.2.

## Protection boundaries

Current classify responses omit mode. With no `mode` or legacy `blockMalicious` flag, the plugin falls back to shadow; set warn or block explicitly when intended. A valid mode from a legacy response remains a compatibility fallback. An explicit `shadow`, `warn`, or `block` overrides the legacy flag and the response mode. Without an explicit mode, `blockMalicious: true` selects block and `false` selects shadow.

For a block candidate, the current event behaves as follows:

| Event | Warn | Block |
| --- | --- | --- |
| `userPromptTransformed` | unchanged (`warnDelivery` `unsupported`) | returns only bounded `modifiedTransformedPrompt`; the turn continues with fixed replacement text |
| `preToolUse` | one `additionalContext` warning | `permissionDecision` `deny` with the fixed block message |
| `postToolUse` | one `additionalContext` warning | replaces the tool result text and returns that fixed message as `additionalContext` |
| `postToolUseFailure` | one `additionalContext` warning | unchanged (`blockUnavailable` true) |
| `agentStop` | not classified | not classified |
| `subagentStop` | unchanged (`warnDelivery` `unsupported`) | `decision` `block` with the fixed block message, unless `stopHookActive` is true |

`userPromptSubmitted` is not registered or classified because command-hook output for that event is ignored and classifying it would duplicate the primary transformed-prompt scan. The compatibility CLI entry point accepts the old event name and returns `{}`. Copilot invokes `userPromptTransformed` once for the primary message and once for every preceding message in a batched submission. Benign, Shadow, Warn, and failed classifications return `{}`, preserving the model-facing bytes exactly. In Block mode only a block candidate returns `modifiedTransformedPrompt`; this replaces model-facing and persisted session-history content but does not reject or handle the turn. Copilot's documented contract replays that stored replacement unchanged on resume.

`agentStop` stays registered, and the handler ignores its payload, including `transcriptPath`. `subagentStop` classifies the current `response`. When `stopHookActive` is true, block mode leaves that response unchanged and sets `blockUnavailable`. Tool events identify a tool, or an MCP tool when the name is `mcp__<server>__<tool>`. Prompt and subagent events identify an agent. The plugin passes that native identity through the SDK's typed governance option. SDK 0.8.2 owns canonical top-level `resource` serialization, including `parent_id` for a recognized MCP tool; governance metadata remains compatibility attribution.

Local evidence contains fingerprints, decisions, bounded risk metadata, and provenance for producer `CopilotFirewallPlugin` at the plugin version. `policyVersion` and `modelVersion` are copied only from `policy_version` and `model_id` on the classification object. The shipped SDK 0.8.2 result does not include those keys, and it does not copy governance `policyVersion` into local evidence. Local evidence never stores raw prompts, tool arguments, results, responses, or the Mac computer name. The default directory is `$HOME/Library/Application Support/Silmaril/Evidence/incoming`. `SILMARIL_LOCAL_EVENT_DIR`, or `SILMARIL_EVIDENCE_ROOT/incoming`, overrides it.

Classify metadata provenance is plugin-owned: `schema_version` 1, `harness` `copilot`, an optional v4 endpoint id, and on macOS a sanitized ComputerName in `device_name`. Spoofed provenance is replaced. A failed or non-macOS lookup omits `device_name`, and classification still runs.
