# Plugin Development

This guide covers the plugin surface that Carapace currently ships and loads at
runtime.

The workflow that works today is:

1. build a WASM component against [`wit/plugin.wit`](../wit/plugin.wit)
2. load it locally through `plugins.load.paths`
3. restart Carapace
4. verify activation with `cara plugins status` and `cara logs`
5. use `cara plugins install` / `cara plugins update` only when you want the
   managed distribution path

## What you can build

This guide covers these public plugin targets:

| Plugin shape | WIT world | Notes |
|---|---|---|
| Tool | `tool-plugin` | Agent-callable tools |
| Webhook | `webhook-plugin` | HTTP handlers under `/plugins/<plugin-id>/...` |
| Service | `service-plugin` | Background lifecycle services |
| Channel | `channel-plugin` | Channel metadata + adapter exports |

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
  - Metadata lives in `plugins-manifest.json` and `plugins.entries`
  - Intended for managed distribution, not your normal inner loop

If you are writing a new plugin, start with `plugins.load.paths`.

## Build target

Carapace plugins are WebAssembly Component Model components. Target the package
namespace declared in [`wit/plugin.wit`](../wit/plugin.wit):

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

Build:

```sh
cargo component build --release
```

Use the generated `.wasm` artifact from your component build output directory.
The exact `target/.../release/` path can vary by toolchain version; the thing
that matters is the built component file.

Any toolchain that produces a valid WASM component for the same WIT contract is
fine. Rust plus `cargo-component` is just the most direct path.

## What a minimal tool plugin exports

A tool plugin built against `tool-plugin` exports:

- `manifest.get-manifest()`
- `tool.get-definitions()`
- `tool.invoke(...)`

Its manifest kind should be `tool`.

Plugin ID rules:

- lowercase alphanumeric plus hyphens
- maximum length: `32`

Tool definition name rules:

- lowercase alphanumeric plus underscores
- maximum length: `64`

Config and credential lookups are exact:

- `config-get("apiKey")` reads `plugins.<plugin-id>.apiKey`
- `credential-get("token")` reads `<plugin-id>:token`
- `credential-set("token", value)` stores `<plugin-id>:token`

Carapace does not translate `api_key` to `apiKey` for you.

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
cp /path/to/generated/my_plugin.wasm /absolute/path/to/dev-plugins/
cara start --port 18789
cara plugins status --port 18789 --name my-tool
cara logs -n 200 --port 18789
```

What success looks like in `cara plugins status`:

- `name`: your configured plugin name
- `pluginId`: your plugin manifest ID
- `state`: `active`
- `reason`: `null`

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
- there is no hot reload
- plugin activation changes require restart

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
- config state lives under `plugins.entries.<name>`
- install/update changes still require restart before activation
- `--file` is local-only; use it for loopback targets, not remote servers

Optional publisher metadata:

- `--publisher-key`
- `--signature`

Those values are recorded at install/update time and enforced later at plugin
load time according to `plugins.signature` policy.

Relevant config keys:

- `plugins.signature.enabled`
- `plugins.signature.requireSignature`
- `plugins.signature.trustedPublishers`

## Host capabilities and sandbox boundaries

Every plugin imports the host interface from
[`wit/plugin.wit`](../wit/plugin.wit).

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
