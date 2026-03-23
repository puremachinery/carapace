# Plugin Development

This guide covers the plugin surface that Carapace currently ships and loads at
runtime. It is centered on the workflow that works today: build a WASM
component, load it through `plugins.load.paths`, restart Carapace, and verify
activation with `skills.status` and server logs.

## Plugin vs skill

- A **plugin** is a WASM component that exports one or more interfaces from
  [`wit/plugin.wit`](../wit/plugin.wit).
- A **skill** is a managed plugin install. Managed installs are tracked under
  `state_dir/skills`, recorded in `skills-manifest.json`, and activated on
  restart.

Every skill is a plugin. Not every plugin needs to go through the managed skill
flow.

## Supported public surface

This guide covers these public plugin targets:

| Plugin shape | WIT world | Notes |
|---|---|---|
| Tool | `tool-plugin` | Agent-callable tools |
| Webhook | `webhook-plugin` | HTTP handlers under `/plugins/<plugin-id>/...` |
| Service | `service-plugin` | Background lifecycle services |
| Channel | `channel-plugin` | Channel metadata + adapter exports |

Not covered here:

- **Provider plugins**: the WIT file contains `provider-plugin`, but the public
  manifest contract does not expose a `provider` plugin kind today. Treat this
  as unsupported for public plugin development.
- **Hook-only or `full-plugin` compositions**: the runtime has hook support, but
  there is no dedicated hook-only world in the public WIT contract. This guide
  stays on the supported direct worlds above.

## Build target

Carapace plugins are WebAssembly Component Model components. Target the current
package namespace in [`wit/plugin.wit`](../wit/plugin.wit):

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
target = { path = "/path/to/your/carapace/repo/wit/plugin.wit", world = "tool-plugin" }
```

Build:

```sh
cargo component build --release
# target/wasm32-wasip2/release/my_plugin.wasm
```

Any toolchain that produces a valid WASM component for the same WIT contract is
fine. Rust + `cargo-component` is just the most direct path.

## What a minimal tool plugin exports

A tool plugin built against `tool-plugin` exports:

- `manifest.get-manifest()`
- `tool.get-definitions()`
- `tool.invoke(...)`

Its manifest kind should be `tool`, and its plugin ID must stay lowercase
alphanumeric plus hyphens with a maximum length of 32 characters.

Tool definition names use a different rule: lowercase alphanumeric plus
underscores, with a maximum length of 64 characters.

For plugin config and credentials:

- `config-get("apiKey")` reads `plugins.<plugin-id>.apiKey`
- `credential-get("token")` reads `<plugin-id>:token`
- `credential-set("token", value)` stores `<plugin-id>:token`

Those keys are exact. Carapace does not translate `api_key` to `apiKey` for you.

## Local development workflow

Use `plugins.load.paths` for local development. Do not use `state_dir/skills` as
your day-to-day dev load path.

1. Build your plugin component.
2. Put the built `.wasm` file in a dedicated local plugin directory.
3. Add that directory to `plugins.load.paths`.
4. Add any plugin-local config under `plugins.<plugin-id>.*`.
5. Start or restart Carapace.
6. Check plugin activation in logs first, then verify the structured state with
   `skills.status`.

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
cp target/wasm32-wasip2/release/my_plugin.wasm /absolute/path/to/dev-plugins/
cara start --port 18789
cara logs -n 200 --port 18789
```

On each edit/build cycle:

1. rebuild the component
2. copy the new `.wasm` into your dev plugin directory
3. restart Carapace
4. check logs again

Important behavior:

- `plugins.enabled = false` disables both managed skill activation and
  `plugins.load.paths`.
- `plugins.load.paths` is the explicit dev/advanced path. Treat those
  directories as trusted local input.
- Activation changes require restart.
- `skills.status` reports activation state, restart requirements, and sanitized
  failure counts. Use server logs for detailed filesystem/runtime diagnostics.

## Verifying activation

Use two checks together:

1. **Fast smoke check via logs**

   ```sh
   cara logs -n 200 --port 18789
   ```

   Look for your plugin ID or activation failures in the recent log output.

2. **Structured status via `skills.status`**

   `skills.status` is a WebSocket method, not a dedicated CLI subcommand today.
   Use the Control UI or another WebSocket client if you need the structured
   activation state. A successful load should show your plugin entry with:

   - `name`: your configured skill or plugin name
   - `pluginId`: your plugin manifest ID
   - `state`: typically `active`
   - `reason`: `null` when activation succeeded

   If `state` is `failed` or `ignored`, use the paired server logs for the full
   local diagnostic detail.

## Managed installs and distribution

Managed installs are the distribution path, not the simplest inner-loop dev
workflow.

Managed skills:

- live under `state_dir/skills`
- are tracked in `skills-manifest.json`
- use pinned `sha256` entries
- can also carry `publisher_key` and `signature`
- activate on restart

Managed skill signature policy is controlled by:

- `skills.signature.enabled`
- `skills.signature.requireSignature`
- `skills.signature.trustedPublishers`

For normal `plugins.load.paths` development, you usually do not need to touch
those settings. They matter when you are using the managed install flow.

## Host capabilities and sandbox boundaries

Every plugin imports the `host` interface from [`wit/plugin.wit`](../wit/plugin.wit).
The most commonly used host functions are:

| Host function | Purpose |
|---|---|
| `log-debug/info/warn/error` | Structured plugin logs |
| `config-get(key)` | Read `plugins.<plugin-id>.*` config |
| `credential-get/set` | Plugin-scoped secret storage |
| `http-fetch(request)` | HTTP client with SSRF protection |
| `media-fetch(url, max-bytes, timeout-ms)` | Media fetch with SSRF protection |

Runtime constraints worth designing for:

- 64 MB memory limit per instance
- 30 second execution timeout per function call
- 100 HTTP requests per minute per plugin
- 1000 log messages per minute per plugin
- SSRF protections on host networking calls
- webhook path namespacing under `/plugins/<plugin-id>/`

The WIT file is the authoritative ABI and capability reference. Use it when you
need the exact request/response shapes or lifecycle details.

## Troubleshooting

- Plugin did not load:
  - confirm `plugins.enabled` is not `false`
  - confirm the `.wasm` file is in a directory listed under `plugins.load.paths`
  - confirm the file is a WASM component, not a core module
- Config lookup returned `None`:
  - check the exact key under `plugins.<plugin-id>.*`
  - use the same key name in `config-get(...)`
- Managed install did not activate:
  - restart Carapace
  - check `skills.status`
  - check `skills-manifest.json` completeness and signature policy
