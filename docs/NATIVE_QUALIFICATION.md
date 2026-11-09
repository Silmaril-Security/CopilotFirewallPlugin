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
  `copilot help providers` and returns a fixed assistant message. It never
  emits tool calls.

Copilot documents `--allow-all-tools` as required for non-interactive `-p`.
The job uses that public flag only in its disposable runner; because the
loopback provider never emits a tool call, no granted tool capability is
exercised. It does not use `--allow-all`, `--yolo`, account credentials,
external model providers, customer data, proxies, or host configuration.

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
   exact next-turn transformed bytes, contains no original poison, and causes
   no callback for replayed history.
5. The callback session and conversation IDs remain stable, and there is
   exactly one local evidence event per callback. Blocked turns must record
   `content_replaced` and `native_response_returned`.
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

The native command is intentionally CI/container-only:

```sh
COPILOT_BIN=/absolute/path/to/verified/copilot \
COPILOT_ASSET_PATH=/absolute/path/to/copilot-linux-x64.tar.gz \
COPILOT_EXTRACT_ROOT=/absolute/path/to/private/extract-root \
NATIVE_QUALIFICATION_RECEIPT=/absolute/path/to/receipt.json \
npm run test:native
```

Do not point this command at a globally installed Copilot executable or a real
model/classifier endpoint.
