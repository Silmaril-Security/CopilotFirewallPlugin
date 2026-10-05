# Copilot Firewall Plugin

Silmaril Firewall protection for GitHub Copilot CLI.

The plugin classifies Copilot user prompts, tool calls, tool results, tool failures, and subagent responses from their current native hook payloads. Every native hook event produces at most one classification of that current event. The plugin does not read transcript history or send prior turns. Incremental conversation state belongs to the Firewall backend, which keys its sequence cache on `metadata.conversationId`. This hook sends the Copilot session as `metadata.sessionId` and does not set the backend sequence key `metadata.conversationId`, so accumulated conversation state is not established by this integration.

Shadow records that classification without changing Copilot content. Warn preserves content and returns one bounded content-free `additionalContext` warning on the events that support it. Block uses Copilot-native deny and stop responses, and replaces malicious tool results with fixed content before they reach the model.

A governance action of `block` is a block candidate even when the prediction is benign. Native deny, replacement, and stop still require block mode and a supported boundary. Warn mode uses the warning instead of a deny, and shadow mode leaves content unchanged.

## Install

Install the plugin with Copilot CLI:

```sh
copilot plugin install Silmaril-Security/CopilotFirewallPlugin
```

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

`npm test` rebuilds `dist/copilot-hook.js` through `scripts/build.mjs`. That file stays committed because `hooks/hooks.json` executes it directly. The bundle includes `@silmaril-security/sdk` 0.7.1.

## Protection boundaries

Omit `mode` and the legacy `blockMalicious` flag to use the backend mode. If that response has no mode, the plugin uses shadow. An explicit `shadow`, `warn`, or `block` overrides the legacy flag and the response mode. Without an explicit mode, `blockMalicious: true` selects block and `false` selects shadow.

For a block candidate, the current event behaves as follows:

| Event | Warn | Block |
| --- | --- | --- |
| `userPromptSubmitted` | unchanged (`warnDelivery` `unsupported`) | unchanged (`blockUnavailable` true) |
| `preToolUse` | one `additionalContext` warning | `permissionDecision` `deny` with the fixed block message |
| `postToolUse` | one `additionalContext` warning | replaces the tool result text and returns that fixed message as `additionalContext` |
| `postToolUseFailure` | one `additionalContext` warning | unchanged (`blockUnavailable` true) |
| `agentStop` | not classified | not classified |
| `subagentStop` | unchanged (`warnDelivery` `unsupported`) | `decision` `block` with the fixed block message, unless `stopHookActive` is true |

`agentStop` stays registered, and the handler ignores its payload, including `transcriptPath`. `subagentStop` classifies the current `response`. When `stopHookActive` is true, block mode leaves that response unchanged and sets `blockUnavailable`. Tool events identify a tool, or an MCP tool when the name is `mcp__<server>__<tool>`. Prompt and subagent events identify an agent.

Local evidence contains fingerprints, decisions, bounded risk metadata, and provenance for producer `CopilotFirewallPlugin` at the plugin version. `policyVersion` and `modelVersion` are copied only from `policy_version` and `model_id` on the classification object. The shipped SDK 0.7.1 result does not include those keys, and it does not copy governance `policyVersion` into local evidence. Local evidence never stores raw prompts, tool arguments, results, responses, or the Mac computer name. The default directory is `$HOME/Library/Application Support/Silmaril/Evidence/incoming`. `SILMARIL_LOCAL_EVENT_DIR`, or `SILMARIL_EVIDENCE_ROOT/incoming`, overrides it.

Classify metadata provenance is plugin-owned: `schema_version` 1, `harness` `copilot`, an optional v4 endpoint id, and on macOS a sanitized ComputerName in `device_name`. Spoofed provenance is replaced. A failed or non-macOS lookup omits `device_name`, and classification still runs.
