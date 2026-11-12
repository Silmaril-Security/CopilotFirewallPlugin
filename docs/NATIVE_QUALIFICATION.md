# Copilot CLI 1.0.108 native qualification

The `native-copilot` CI job qualifies the unreleased 0.3.6 plugin against the
official Linux x64 Copilot CLI 1.0.108 executable. It is separate from the
deterministic handler tests and does not qualify the published 0.3.5 artifact.

## Isolation and provenance

The job downloads only the captured official release URL for
`copilot-linux-x64.tar.gz` and requires SHA-256
`4c14e320c5cd10234ad56cba855509206e4518e1c04a780ac05a8e1c124bd97d`.
It rejects unsafe archive paths and links, then the harness verifies the
archive hash again before its first execution of the extracted binary. The
first execution checks the exact `GitHub Copilot CLI 1.0.108.` version output.
The harness selects the pinned hash by platform asset name; besides the CI
asset it pins the official `copilot-darwin-arm64.tar.gz` 1.0.108 hash
`567198e7cd947f5b05bef7f036116e6286ddcd8286ec45830082b28c664dbfb0` for local
macOS runs. Any other platform fails the hash check.

The harness creates one private, uniquely named temporary root. It copies the
runtime files from the checked-out source and verifies the copied aggregate
hash before loading them with `--plugin-dir`. `HOME`, `COPILOT_HOME`, XDG
directories, the working directory, logs, evidence, and temporary files stay
under that root. `COPILOT_OFFLINE=true`, `--no-auto-update`, and
`--disable-builtin-mcps` request offline behavior and disable updates and
built-in MCPs, but they are application controls rather than an enforced
network boundary. Removed remote-control flags are not passed to 1.0.108.

The GitHub `native-copilot` job downloads dependencies and the pinned CLI
before qualification, then executes on the normally networked hosted runner.
It verifies loopback routing and that no real credentials or providers are
configured; it does **not** prove zero egress. A zero-egress qualification must
separately bootstrap the verified asset, dependencies, build, and source bytes
in a connected stage, then run that immutable result in a new runtime with an
enforced network namespace such as Docker `--network none`. That runtime still
needs loopback for the two local fixtures and executable temporary storage for
the CLI's extracted native addon.

Both services are loopback-only fixtures:

- The classifier returns deterministic benign or malicious decisions from
  synthetic runtime-check markers.
- The OpenAI Responses fixture uses the BYOK variables advertised by
  `copilot help providers` and returns a fixed assistant message. In the
  prompt scenarios it never emits tool calls. In the tool scenarios it emits
  one scripted `function_call` item, then a fixed assistant message.

Copilot documents `--allow-all-tools` as required for non-interactive `-p`.
The job uses that public flag only in its disposable runner. The only tool
calls are the scripted ones described under "Tool enforcement scenarios",
which act inside the private root. It does not use `--allow-all`, `--yolo`,
account credentials, external model providers, customer data, proxies, or
host configuration.

## Required native assertions

The job fails unless all of these hold:

1. A primary benign turn produces exactly one transformed-prompt callback,
   and the model request contains the exact untrimmed bytes observed by the
   classifier.
2. A primary malicious turn produces exactly one callback, and the model sees
   only the fixed `modifiedTransformedPrompt` replacement. Neither the original
   synthetic poison nor the classifier-observed transformed value may appear
   in the model request.
3. An initial blocked turn uses a fixed session UUID. A second process resumes
   that UUID with `--resume <id> -p <next-turn>`.
4. The resumed model request contains the stored fixed replacement and the
   exact next-turn transformed bytes as its current user item, contains no
   original poison, and causes no callback for replayed history. A stored
   replacement found elsewhere in history cannot satisfy the current-item
   assertion.
5. The callback session and conversation IDs remain stable, and there is
   exactly one local evidence event per callback. The harness derives expected
   request and session fingerprints through the production identity and
   evidence builders, then requires an exact one-to-one identity multiset with
   no duplicate or missing event. Blocked turns must record `content_replaced`
   and `native_response_returned`.
6. The official `@github/copilot-sdk` v1.0.30-preview.0
   (`copilotCliVersion` `1.0.108-0`) starts the exact 1.0.108 executable over
   its public stdio JSON-RPC transport. The first model response is gated while
   two additional `session.send({mode: "enqueue"})` messages are queued. After
   releasing the gate, all three turns must run FIFO with one exact transformed
   callback and model request per message, stable session identity, and unique
   SDK message and callback request IDs.

The receipt contains the asset hash and version, copied runtime hash,
redacted command arguments, exact synthetic byte lengths/SHA-256/UTF-8 hex,
callback classifications, matching model-input fingerprints, evidence
summaries, and owned cleanup results. CI prints it and retains it as the
`copilot-native-qualification` artifact for 14 days.

The harness receipt does not attest the host or container network mode. Pair
it with independently captured runtime configuration when making a
zero-egress claim.

## Tool enforcement scenarios

The same run then installs the staged runtime files into a second isolated
`COPILOT_HOME` with the host's own `copilot plugin install ./` and requires
the installed directory to contain exactly the runtime file set with the same
aggregate hash. These scenarios load the plugin only from that installation,
with their own loopback classifier and model fixtures, in block mode:

| Scenario | Scripted tool call | Required result |
| --- | --- | --- |
| `allow` | built-in `bash` writes and prints an effect file | the file exists on disk with the expected bytes, and the tool output is in the next model request |
| `pre-tool-block` | built-in `bash` whose arguments the classifier flags | `preToolUse` returns `permissionDecision: "deny"`, the effect file is absent, no `postToolUse` callback occurs, and the model receives the denial text |
| `tool-response-block` | `read_notes` on a local stdio MCP server (`scripts/native-tool-response-mcp.mjs`, passed with `--additional-mcp-config`) that returns the poison | `postToolUse` returns `modifiedResult`, the poison is in no model request, and the fixed replacement is in the next one |

The block scenarios also require the plugin's local evidence event
(`block_returned` or `content_replaced`). The effect file is read directly
from disk by the harness.

## Shared acceptance receipt

The run always writes a `silmaril.native-acceptance.v1` receipt, also on
failure, to `NATIVE_ACCEPTANCE_RECEIPT` or `.test-build/native-acceptance/receipt.json`.
The process exits 0 only when its status is `PASS`. CI retains it as the
`native-acceptance` artifact (`receipt.json`, plus `live-receipt.json` when
the live step ran).

- `plugin.artifact_sha256` is not a packed archive hash: the repository
  releases no archive. It is the SHA-256 over the runtime file set
  (`dist/copilot-hook.js`, `hooks/hooks.json`, `package.json`, `plugin.json`),
  each entry hashed as path, byte length, and bytes. `installed_bytes_match`
  compares that digest and the file list with the installed directory.
- The prompt, resume, queue, and evidence assertions above are reported as the
  extra scenario `prompt-transform`.
- `classifier_requests` lists every classifier request of the run with hook,
  decision, and duration.

## Live classifier mode

`CUSTOMER_NATIVE_CLASSIFIER=live` with `CUSTOMER_NATIVE_API_URL` (https only)
and `CUSTOMER_NATIVE_API_KEY` makes the loopback classifier forward each
request to that endpoint and record its duration and upstream
`{prediction, mode, action}`. Live mode runs only `allow` and
`tool-response-block`, with the shared customer attack text as the poison; it
skips the prompt scenarios and writes only the shared receipt. A failure
caused by the classifier is reported as `BLOCKED` with one of
`classifier_request_failed`, `classifier_exceeded_plugin_deadline`,
`classifier_flagged_benign_control`, `classifier_did_not_flag_attack`, or
`tenant_not_in_block_mode`. CI runs the live step on manual dispatch with
`live` set, or when `vars.CUSTOMER_NATIVE_ENABLED` is `true`; the nightly
schedule runs only with that variable.

## Batching contract

The CLI help surface itself advertises one `-p <text>` prompt and does not
advertise a queue operation. Native queue qualification therefore uses the
official public Copilot SDK JSON-RPC contract, not sequential CLI processes,
multiline prompt text, PTY timing, or fabricated hook payloads.

The pinned SDK release documents `session.send({mode: "enqueue"})` as FIFO
queueing that returns after admission and gives each queued message a full
turn. Its package metadata targets Copilot CLI `1.0.108-0`; the harness
overrides its bundled runtime with the checksum-verified final 1.0.108
executable and verifies the behavior described above.

## Running

Development and qualification require Node.js 22.12.0 or newer, matching the
pinned Copilot SDK's Node 22 engine floor.

The native command is intended for CI or a disposable environment, because
the scripted tool calls run with `--allow-all-tools`:

```sh
COPILOT_BIN=/absolute/path/to/verified/copilot \
COPILOT_ASSET_PATH=/absolute/path/to/copilot-linux-x64.tar.gz \
COPILOT_EXTRACT_ROOT=/absolute/path/to/private/extract-root \
NATIVE_QUALIFICATION_RECEIPT=/absolute/path/to/receipt.json \
NATIVE_ACCEPTANCE_RECEIPT=/absolute/path/to/native-acceptance/receipt.json \
npm run test:native
```

On macOS arm64, use the extracted `copilot-darwin-arm64.tar.gz` 1.0.108
asset for `COPILOT_BIN` and `COPILOT_ASSET_PATH`.

Do not point this command at a globally installed Copilot executable or a real
model/classifier endpoint.
