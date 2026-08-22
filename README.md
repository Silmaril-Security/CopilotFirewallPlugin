# Copilot Firewall Plugin

Silmaril Firewall protection for GitHub Copilot CLI.

The plugin classifies Copilot user prompts, tool calls, tool results, tool failures, final responses, and subagent responses. Shadow records backend evidence only. Warn preserves content and adds one bounded content-free warning at supported same-turn context surfaces. Block uses Copilot-native deny or stop responses where available; it never replaces completed content.

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
