# Copilot Firewall Plugin

Silmaril Firewall protection for GitHub Copilot CLI.

The plugin classifies Copilot user prompts, tool calls, tool results, tool failures, and subagent responses from their current native hook payloads. Shadow records backend evidence only. Warn preserves content and adds one bounded content-free warning at supported same-turn context surfaces. Block uses Copilot-native deny and stop responses, and replaces malicious tool results with fixed content before they reach the model.

## Install

Install the plugin with Copilot CLI:

```sh
copilot plugin install Silmaril-Security/CopilotFirewallPlugin
```

SilmarilMacOS manages the private runtime configuration at `~/.copilot/silmaril-firewall.json`. The plugin intentionally fails open when that configuration is missing or invalid, when the Firewall API is unavailable, or when the hook runtime encounters an error.

## Develop

```sh
npm ci
npm run typecheck
npm test
```

The built `dist/copilot-hook.js` file is committed because Copilot installs plugins directly from the repository and executes the hook without a package build step.

## Protection boundaries

Omit `mode` to use the backend, or set `shadow`, `warn`, or `block`. Explicit mode takes precedence over legacy booleans. Unsupported Block boundaries remain unchanged and record `block_unavailable`; failures fail open without agent-visible context.

Local evidence contains fingerprints, decisions, bounded risk metadata, and version provenance. It never stores raw prompts, tool arguments, results, or responses.

Every native hook event produces at most one classification, and conversation state is owned by the Firewall sequence cache. Copilot's `agentStop` currently exposes only a transcript path, so the plugin intentionally skips that event instead of reading history to reconstruct a final response. `subagentStop` remains covered because Copilot exposes the current response directly.

Official Copilot hook payloads do not include a selected model ID. This command hook also cannot see Copilot SDK streaming events such as `session.start` `selectedModel`, `session.model_change`, or `assistant.usage` `model`, and it does not read the CLI configuration, the session store, or transcripts to guess one. Those sources are either unavailable here or describe a different call, so joining them would attribute a stale model. `metadata.silmaril.agent_model_id` is set only when the current hook payload itself carries a direct host-supplied ID in `selectedModel`, `selected_model`, `modelId`, `model_id`, or a string `model`. A missing field, a blank value, a non-string value, or the `auto` selector omits the field. Normal `userPromptSubmitted`, tool, and `subagentStop` events from Copilot CLI therefore stay unknown. The Firewall classifier `model_id` remains local-evidence `provenance.modelVersion` and is never copied into `agent_model_id`.
