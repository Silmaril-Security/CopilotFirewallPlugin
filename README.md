# Copilot Firewall Plugin

Silmaril Firewall protection for GitHub Copilot CLI.

The plugin classifies Copilot user prompts, tool calls, tool results, tool failures, final responses, and subagent responses. Shadow mode records findings without changing Copilot behavior. Enforce mode denies malicious tool calls and replaces malicious tool results before they return to the model. Copilot command hooks cannot deny an initial prompt, so prompts and agent outputs remain monitoring-only in both modes.

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

| Copilot event | Shadow | Enforce |
| --- | --- | --- |
| `userPromptSubmitted` | Monitor | Monitor |
| `preToolUse` | Monitor | Deny malicious calls |
| `postToolUse` | Monitor | Replace malicious results |
| `postToolUseFailure` | Monitor | Monitor |
| `agentStop` | Monitor | Monitor |
| `subagentStop` | Monitor | Monitor |

Local evidence contains fingerprints, decisions, bounded risk metadata, and version provenance. It never stores raw prompts, tool arguments, results, or responses.

