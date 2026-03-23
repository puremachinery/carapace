# Plugin Development

This guide covers the plugin surface that Carapace currently ships and loads at
runtime.

The workflow documented here is:

1. choose a plugin shape and WIT world
2. build a WASM component against [`wit/plugin.wit`](https://github.com/puremachinery/carapace/blob/main/wit/plugin.wit)
3. load it locally through `plugins.load.paths`
4. restart Carapace
5. verify activation with `cara plugins status` and `cara logs`
6. use `cara plugins install` / `cara plugins update` only when you want the
   managed distribution path

This guide is intentionally written around the public surfaces Carapace
exposes:

- the WIT contract in `wit/plugin.wit`
- the runtime loader behavior in `src/plugins/*`
- the operator CLI in `cara plugins ...`

## What you can build

This guide covers these public plugin targets:

| Plugin shape | WIT world | Notes |
|---|---|---|
| Tool | `tool-plugin` | Agent-callable tools |
| Webhook | `webhook-plugin` | HTTP handlers under `/plugins/<plugin-id>/...` |
| Service | `service-plugin` | Background lifecycle services |
| Channel | `channel-plugin` | Channel metadata + adapter exports, plus hook exports for channel lifecycle integration |

Not covered here:

- **Provider plugins**: `provider-plugin` exists in the WIT file, but the
  public manifest/runtime contract does not expose it as a supported plugin
  kind.
- **Hook-only or `full-plugin` compositions**: the runtime has hook support,
  but this guide stays on the direct public worlds above.

## Two plugin workflows

Carapace has two distinct plugin workflows:

- **Local development**
  - Use `plugins.load.paths`
  - Fastest edit/build/restart loop
  - Best default for authoring a plugin
- **Managed plugins**
  - Use `cara plugins install` / `cara plugins update`
  - Artifacts live under `state_dir/plugins`
  - Artifact metadata lives in `plugins-manifest.json`
  - Install lifecycle metadata lives in `plugins.entries`
  - Intended for managed distribution, not your normal inner loop

If you are writing a new plugin, start with `plugins.load.paths`.

## Plugin identity, names, and manifest metadata

There are two different names you will see in the plugin tooling:

- **`pluginId`**
  - comes from the `.wasm` filename stem at load time
  - identifies the runtime plugin instance
  - appears in `cara plugins status`
  - must be lowercase alphanumeric plus hyphens
  - maximum length: `32`
  - should match the manifest `id` if you embed explicit manifest metadata
- **managed plugin `name`**
  - the name you pass to `cara plugins install <name>` or
    `cara plugins update <name>`
  - identifies the managed artifact/install entry under `plugins.entries`
  - may contain ASCII alphanumeric characters, hyphens, and underscores
  - maximum length: `128`

For simplest operations, keep the managed plugin name and the runtime
`pluginId` the same.

Reserved managed plugin names:

- `enabled`
- `entries`
- `load`
- `sandbox`
- `signature`

Core manifest fields:

- `id`
- `name`
- `description`
- `version`
- `kind`

Optional manifest fields:

- `permissions`

Carapace can load a plugin even if you do not embed explicit manifest metadata.
The loader derives metadata in this order:

1. `plugin-manifest` custom section, if present
2. component export inspection for the plugin kind
3. file name / file metadata fallbacks

Inference details:

- `id`: file stem
- `name`: component/module name if available, otherwise a display name derived
  from the file stem
- `version`: file modification time, formatted as `0.0.YYYYMMDDHHMMSS`
- `kind`: inferred from exported interfaces, defaulting to `tool` if the
  component exports are otherwise unrecognizable

For reproducible managed distribution, prefer explicit manifest metadata rather
than relying on inference.

## Build target

Carapace plugins are WebAssembly Component Model components. Target the package
namespace declared in [`wit/plugin.wit`](https://github.com/puremachinery/carapace/blob/main/wit/plugin.wit):

```wit
package carapace:plugin@1.0.0;
```

Practical Rust setup with `cargo-component`:

```sh
cargo install cargo-component
cargo component new --lib my-plugin
```

Point your component target at Carapace's WIT file and choose the world that
matches your plugin shape:

```toml
[package.metadata.component]
target = { path = "/absolute/path/to/carapace/wit/plugin.wit", world = "tool-plugin" }
```

The absolute path above is just an example. A path relative to your component
crate or a package/dependency reference is also fine as long as it resolves to
the same `wit/plugin.wit` contract.

Build:

```sh
cargo component build --release
```

Use the generated `.wasm` artifact from your component build output directory.
The exact `target/.../release/` path can vary by toolchain version; the thing
that matters is the built component file.

Any toolchain that produces a valid WASM component for the same WIT contract is
fine. Rust plus `cargo-component` is just the most direct path.

## Fastest path: first tool plugin

If you are building your first plugin, start with a tool plugin. It has the
smallest surface and the fastest edit/build/restart loop.

Recommended sequence:

1. create a new component crate:

   ```sh
   cargo install cargo-component
   cargo component new --lib my-tool
   ```

2. point it at Carapace's WIT and select the `tool-plugin` world:

   ```toml
   [package.metadata.component]
   target = { path = "/absolute/path/to/carapace/wit/plugin.wit", world = "tool-plugin" }
   ```

3. implement the required exports for that world:
   - `manifest.get-manifest()`
   - `tool.get-definitions()`
   - `tool.invoke(...)`

4. build the component:

   ```sh
   cargo component build --release
   ```

5. copy the generated `.wasm` into a directory listed in `plugins.load.paths`

6. restart Carapace and verify:

   ```sh
   cara plugins status --port 18789 --name my-tool
   cara logs -n 200 --port 18789
   ```

If that path works, then move on to webhook, service, or channel plugins. The
local development loop stays the same; only the WIT world and required exports
change.

## Shape-specific contracts

### Tool plugins

A tool plugin built against `tool-plugin` exports:

- `manifest.get-manifest()`
- `tool.get-definitions()`
- `tool.invoke(...)`

Its manifest kind should be `tool`.

Tool definition name rules:

- lowercase alphanumeric plus underscores
- maximum length: `64`

Config and credential lookups are exact:

- `config-get("apiKey")` reads `plugins.<plugin-id>.apiKey`
- `credential-get("token")` reads `<plugin-id>:token`
- `credential-set("token", value)` stores `<plugin-id>:token`

Carapace does not translate `api_key` to `apiKey` for you.

### Webhook plugins

A webhook plugin built against `webhook-plugin` exports:

- `manifest.get-manifest()`
- `webhook.get-paths()`
- `webhook.handle(...)`

Webhook-specific behavior:

- webhook paths are mounted under `/plugins/<plugin-id>/...`
- `get-paths()` returns paths inside that namespace, without the
  `/plugins/<plugin-id>/` prefix
- request bodies are capped by `gateway.hooks.maxBodyBytes` in the server
  config
  (default: `256 KiB`)
- Carapace currently forwards request headers through to the plugin as-is

### Service plugins

A service plugin built against `service-plugin` exports:

- `manifest.get-manifest()`
- `service.start()`
- `service.stop()`
- `service.health()`

Service-specific behavior:

- `start()` runs when the plugin is activated
- `stop()` runs during shutdown or unload
- `stop()` should finish promptly so shutdown or unload is not blocked
- `health()` is part of the service ABI, but the current runtime does not poll
  it on a fixed interval

### Channel plugins

A channel plugin built against `channel-plugin` exports:

- `manifest.get-manifest()`
- `channel-meta.get-info()`
- `channel-meta.get-capabilities()`
- channel adapter methods such as:
  - `send-text()`
  - `send-media()`
  - `send-poll()`
  - `edit-message()`
  - `delete-message()`
  - `react()`
- `hooks.get-hooks()`
- `hooks.handle(...)`

Channel-specific behavior:

- `channel-info.id` uses the same lowercase alphanumeric plus hyphen rule as
  plugin IDs
- capabilities declare what the channel supports: polls, reactions, media,
  threads, group management, and so on
- the channel world includes hooks because channel plugins often need lifecycle
  integration in addition to outbound delivery methods

## Advanced manifest path

If your build pipeline can embed a `plugin-manifest` custom section, Carapace
will use it directly instead of inferring metadata from the file and component
exports.

The JSON structure below shows the core `PluginManifest` fields:

```json
{
  "id": "my-tool",
  "name": "My Tool",
  "description": "Example plugin",
  "version": "1.0.0",
  "kind": "tool"
}
```

This is the most predictable path for managed distribution because it avoids:

- filename-stem/runtime-ID mismatches
- file-mtime-derived versions
- kind inference from exports

Embedding that custom section is toolchain-specific, so this guide keeps the
main workflow on the plain `cargo-component` path and treats the custom-section
manifest as an advanced option.

## Local development walkthrough

Use `plugins.load.paths` for day-to-day development. Do not use
`state_dir/plugins` for your normal edit/build loop.

Recommended config shape:

```json5
{
  plugins: {
    enabled: true,
    load: {
      paths: [
        "/absolute/path/to/dev-plugins",
      ],
    },

    "my-tool": {
      apiKey: "dev-key-here",
    },
  },
}
```

Concrete inner loop:

```sh
mkdir -p /absolute/path/to/dev-plugins
cargo component build --release
cp /path/to/generated/my_plugin.wasm /absolute/path/to/dev-plugins/my-tool.wasm
cara start --port 18789
cara plugins status --port 18789 --name my-tool
cara logs -n 200 --port 18789
```

What success looks like in `cara plugins status`:

- `name`: your configured plugin name
- `pluginId`: the loaded plugin filename stem / runtime plugin ID
- `state`: `active`
- `reason`: `null`

Useful status fields to watch:

- `source`
  - `config` for `plugins.load.paths`
  - `managed` for managed installs
- `enabled`
- `requestedAt`
- `restartRequiredForChanges`
- `activationErrorCount`

On each edit cycle:

1. rebuild the component
2. copy the new `.wasm` into your dev plugin directory
3. restart Carapace
4. rerun:
   - `cara plugins status --port 18789 --name my-tool`
   - `cara logs -n 200 --port 18789`

Important behavior:

- `plugins.enabled = false` disables both managed plugins and
  `plugins.load.paths`
- `plugins.load.paths` is trusted local input
- never place untrusted `.wasm` files in a `plugins.load.paths` directory;
  plugins loaded from those paths can read plugin-scoped config and credentials
  and can make outbound HTTP or media requests on your behalf
- there is no hot reload
- plugin activation changes require restart
- `cara plugins status --json` is the easiest way to inspect the full structured
  runtime state if the default table output is not enough

## Managed plugins and distribution

Use managed plugins when you want the managed distribution path, not when you
just want the fastest local development loop.

Managed plugin commands:

```sh
cara plugins install demo-plugin --file ./path/to/demo_plugin.wasm --port 18789
cara plugins update demo-plugin --file ./path/to/demo_plugin.wasm --port 18789
cara plugins bins --port 18789
cara plugins status --port 18789 --name demo-plugin
```

Important managed-plugin behavior:

- artifacts live under `state_dir/plugins`
- metadata lives in `plugins-manifest.json`
- install metadata lives under `plugins.entries.<name>`
- operational runtime config still lives under `plugins.<plugin-id>.*`
- install/update changes still require restart before activation
- `--file` is local-only; use it for loopback targets, not remote servers
- `cara plugins bins` lists the managed binary filenames currently present on
  disk

`plugins-manifest.json` entries carry the managed artifact metadata Carapace
uses at load time, including:

- `sha256`
- optional `version`
- optional `publisher_key`
- optional `signature`
- optional `url`
- optional `path` (absolute or relative to `state_dir/plugins`); when omitted,
  Carapace defaults to `<name>.wasm`

`plugins.entries.<name>` carries the managed install metadata that shows up in
`cara plugins status`, including:

- `enabled`
- `installId`
- `requestedAt`

Do not put runtime configuration like `apiKey`, webhook settings, or service
options under `plugins.entries.<name>`. Those still belong under
`plugins.<plugin-id>.*`.

Optional publisher metadata:

- `--publisher-key`
- `--signature`

Those values are recorded at install/update time and enforced later at plugin
load time according to `plugins.signature` policy.

Relevant config keys:

- `plugins.signature.enabled`
- `plugins.signature.requireSignature`
- `plugins.signature.trustedPublishers`
- `plugins.sandbox.enabled`
- `plugins.sandbox.defaults.allowHttp`
- `plugins.sandbox.defaults.allowCredentials`
- `plugins.sandbox.defaults.allowMedia`

## Host capabilities and sandbox boundaries

Every plugin imports the host interface from
[`wit/plugin.wit`](https://github.com/puremachinery/carapace/blob/main/wit/plugin.wit).

Common host functions:

| Host function | Purpose |
|---|---|
| `log-debug/info/warn/error` | Structured plugin logs |
| `config-get(key)` | Read `plugins.<plugin-id>.*` config |
| `credential-get/set` | Plugin-scoped secret storage |
| `http-fetch(request)` | HTTP client with SSRF protection |
| `media-fetch(url, max-bytes, timeout-ms)` | Media fetch with SSRF protection |

Runtime limits worth designing for:

- memory: `64 MB` per plugin instance
- execution timeout: `30s` per function call
- HTTP limit: `100/min` per plugin
- log limit: `1000/min` per plugin
- HTTP body size: `10 MB` max
- webhook paths live under `/plugins/<plugin-id>/...`

Other behavioral rules worth knowing:

- config reads are always scoped to `plugins.<plugin-id>.*`
- credential reads/writes are always scoped to `<plugin-id>:...`
- outbound HTTP and media fetches go through SSRF protections
- plugin networking only supports `https`

The WIT file is the authoritative ABI and capability reference.

## Troubleshooting

- Plugin did not load:
  - confirm `plugins.enabled` is not `false`
  - confirm the `.wasm` file is inside a directory listed under
    `plugins.load.paths`
  - confirm you built a WASM component, not a core module
  - restart Carapace and check both:
    - `cara plugins status --port 18789`
    - `cara logs -n 200 --port 18789`
- `config-get(...)` returned `None`:
  - check the exact key under `plugins.<plugin-id>.*`
  - use the same key name inside the plugin
- Managed install did not activate:
  - restart Carapace
  - run:
    - `cara plugins status --port 18789 --name <name>`
    - `cara plugins bins --port 18789`
  - check `plugins-manifest.json` completeness and `plugins.signature` policy
- `cara plugins status` shows a different `pluginId` than you expected:
  - check whether your plugin is using inferred metadata from the file stem
  - prefer explicit manifest metadata for managed distribution
- `cara plugins install` or `update` succeeded but the plugin is still not
  active:
  - managed install/update only stages the artifact and metadata
  - activation still happens on restart
