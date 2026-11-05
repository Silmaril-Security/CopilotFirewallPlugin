# Contributing

Use Node.js 22 or newer. Run `npm ci`, `npm run typecheck`, and `npm test` before submitting a change. `npm test` rebuilds `dist/copilot-hook.js`; commit that output with the change. Keep hook failures fail-open, keep local evidence raw-content free, and update `plugin.json`, `package.json`, runtime constants, tests, and committed build output together when changing the plugin version. The shipped `@silmaril-security/sdk` dependency is pinned in `package.json` and `package-lock.json`.

