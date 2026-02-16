# Security Comparison: Carapace vs. OpenClaw

In January–February 2026, security researchers disclosed a series of vulnerabilities in the OpenClaw ecosystem (Clawdbot/Moltbot) that exposed tens of thousands of personal AI assistant instances to remote exploitation. The initial disclosures were covered by [The Register](https://www.theregister.com/2026/01/27/clawdbot_moltbot_security_concerns/), [Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/moltbot-security-alert-exposed-clawdbot-control-panels-risk-credential-leaks-and-account-takeovers), [Cisco](https://blogs.cisco.com/ai/personal-ai-agents-like-moltbot-are-a-security-nightmare), [SOC Prime](https://socprime.com/active-threats/the-moltbot-clawdbots-epidemic/), and [Intruder](https://www.intruder.io/blog/clawdbot-when-easy-ai-becomes-a-security-nightmare), followed by a second wave from [Kaspersky](https://www.kaspersky.com/blog/openclaw-vulnerabilities-exposed/55263/), [Palo Alto Networks](https://www.paloaltonetworks.com/blog/network-security/why-moltbot-may-signal-ai-crisis/), [Snyk](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/), [SecurityScorecard](https://securityscorecard.com/blog/beyond-the-hype-moltbots-real-risk-is-exposed-infrastructure-not-ai-superintelligence/), and [VirusTotal](https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html). The headline numbers:

- **42,000+ exposed instances** found on Shodan with no authentication ([78% still unpatched](https://securityscorecard.com/blog/beyond-the-hype-moltbots-real-risk-is-exposed-infrastructure-not-ai-superintelligence/) as of Feb 2026)
- **3 CVEs with public exploits** — 1-click RCE (CVE-2026-25253), SSH command injection (CVE-2026-25157), Docker sandbox escape (CVE-2026-24763)
- **341–900+ malicious skills** published to ClawHub with no moderation or signature verification ([Snyk found 36% of all skills contain security flaws](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/))
- **7.1% of ClawHub skills** leaked credentials to third parties
- **1.5M auth tokens leaked** from a misconfigured Moltbook database

Carapace is a Rust rewrite of OpenClaw built from the ground up to address these vulnerability classes. This document walks through each threat and explains how Carapace handles it.

## Threat-by-Threat Comparison

### 1. Unauthenticated Access

**How it was exploited:** Researchers found hundreds of internet-facing OpenClaw instances with no authentication. Eight instances had full unauthenticated access — API keys, conversation histories, and command execution exposed to anyone. The root cause: OpenClaw defaults to open access when no credentials are configured and binds to all network interfaces.

**Carapace:**
- **Fails closed.** When no auth token or password is configured, all connections are denied (`TokenMissingConfig` / `PasswordMissingConfig`). There is no "accidentally open" state.
- **Localhost-only by default.** Carapace binds to `127.0.0.1`. External access requires the operator to explicitly set bind mode to `lan`, `tailnet`, or `all`. A default Carapace instance is unreachable from the internet.
- **Timing-safe credential comparison.** Auth checks use constant-time SHA-256 digest comparison — no length side-channel.
- **CSRF protection enabled by default.** Double-submit cookie with `__Host-` prefix, `SameSite=Strict`, origin/host validation.

### 2. Plaintext Secret Storage

**How it was exploited:** Credentials stored in plaintext JSON and Markdown files. Commodity infostealers (RedLine, Lumma, Vidar) trivially harvest API keys, OAuth tokens, and credentials from the standard OpenClaw directory structure.

**Carapace:**
- **OS credential stores.** Secrets are stored in macOS Keychain, Linux Keyutils, or Windows Credential Manager — not in filesystem-accessible files.
- **AES-256-GCM fallback.** When OS keychains are unavailable (containers, CI), secrets are encrypted with AES-256-GCM using PBKDF2-HMAC-SHA256 key derivation (600,000 iterations per OWASP 2024 recommendation). Each value has its own random salt and nonce.
- **Zeroization.** Encryption keys and auth secrets are zeroized in memory after use via the `zeroize` crate.
- An infostealer reading Carapace's state directory gets ciphertext and keychain references, not credentials.

### 3. Skills Supply Chain

**How it was exploited:** A researcher uploaded a poisoned skill to ClawHub, inflated the download count to 4,000+, and demonstrated code execution on instances in 7 countries. ClawHub had no moderation, no signing, no verification. Their own docs stated: "all code downloaded from the library will be treated as trusted code." A subsequent audit found 341 malicious skills and 7.1% of all skills leaking credentials.

**Carapace:**
- **Ed25519 signature verification.** Skills are cryptographically signed and verified against a trusted publisher list at load time. Unsigned code does not run.
- **WASM capability sandbox.** Plugins run in a wasmtime sandbox with deny-by-default capabilities. A plugin must declare what it needs (HTTP access, credential scopes, media access) and is denied everything else.
- **Resource limits.** 64 MB memory cap, fuel-based CPU budget (1B instructions), 30-second wall-clock timeout, 100 req/min HTTP rate limit per plugin.
- **SSRF protection.** Skill download URLs are validated against private IP ranges, localhost variants, and cloud metadata endpoints before any request is made.
- **No centralized skill store.** There is no equivalent of ClawHub to poison.

### 4. Control UI Token Exfiltration (1-Click RCE)

**How it was exploited (GHSA-g8p2-7wf7-98mq):** OpenClaw's Control UI accepted `gatewayUrl` as a query parameter. A malicious link could redirect the UI to an attacker-controlled server, leaking the auth token. Combined with command execution capabilities, this was a 1-click RCE.

**Carapace:**
- The service URL is set server-side only. No query parameter override exists.
- Control endpoints enforce CSRF protection and require service authentication.
- Sensitive config paths (`gateway.auth`, `gateway.hooks.token`, `credentials`, `secrets`) are blocked from modification via the control API.

### 5. Prompt Injection

**How it was exploited:** Researcher Matvey Kukuy sent a malicious email to an OpenClaw instance. The AI read the email, treated it as legitimate instructions, and forwarded the user's last 5 emails to an attacker-controlled address. It took 5 minutes. OpenClaw ships with no guardrails by default.

**Carapace:**
- **Prompt guard.** Pre-flight system prompt analysis for injection patterns. Untrusted content is tagged before the LLM sees it.
- **Inbound classifier.** Secondary LLM call classifies messages for prompt injection, social engineering, instruction override, data exfiltration, and tool abuse before the main agent loop.
- **Exec approval flow.** Tool calls require explicit user approval before execution, with configurable timeout (default 2 minutes).
- **Tool policy allowlists.** Agents can be restricted to a specific set of tools. Tools are filtered at both definition time and dispatch time (defense in depth).
- **Output sanitization.** PII/credential filter on agent output. Error messages are stripped of API keys and auth headers before entering LLM context.

Prompt injection remains an industry-wide unsolved problem. No AI system fully prevents it. Carapace provides defense-in-depth, not a guarantee.

### 6. No Process Sandboxing

**How it was exploited:** OpenClaw runs with full host privileges. Researchers demonstrated turning a compromised instance into a persistent backdoor for infostealers and cryptocurrency theft.

**Carapace:**
- **macOS Seatbelt.** sandbox-exec SBPL profiles restrict filesystem, network, and IPC access.
- **Linux Landlock.** Filesystem access rules via raw syscalls. Read/write restricted to declared paths only.
- **Resource limits.** RLIMIT_CPU, RLIMIT_AS, RLIMIT_NOFILE per tool execution.
- **Output content security.** HTML/Markdown sanitizer strips XSS vectors, dangerous tags, and non-image data URIs from agent output.

*Caveat: sandbox primitives are implemented but subprocess wiring is not yet complete. See the status section below.*

### 7. SSRF / DNS Rebinding

**How it was exploited:** Not explicitly reported as exploited in OpenClaw, but the skill download and outbound request surface has no URL validation or private IP blocking.

**Carapace:**
- Full private IP blocking: all RFC 1918 ranges, loopback, link-local, CGNAT, multicast, reserved, and test networks — IPv4 and IPv6.
- Cloud metadata endpoint blocking: AWS (169.254.169.254, fd00:ec2::254), GCP (metadata.google.internal), Azure.
- DNS rebinding defense: post-resolution IP validation prevents TOCTOU attacks where DNS returns a public IP initially but a private IP on connection.
- Configurable CGNAT bypass for Tailscale deployments.

## Summary Table

| Vulnerability | OpenClaw | Carapace |
|---|---|---|
| Unauthenticated access | Open by default | Denied by default (fail-closed) |
| Exposed network ports | Binds 0.0.0.0 (all interfaces) | Binds 127.0.0.1 (localhost only) |
| Plaintext secret storage | JSON/Markdown on disk | OS keychains + AES-256-GCM fallback |
| Skills supply chain | No verification, no moderation | Ed25519 signatures + WASM sandbox |
| Control UI token exfil | 1-click RCE via query param | No query param override; CSRF enforced |
| Prompt injection | No defenses | Prompt guard + classifier + approval flow |
| Process sandboxing | Full host privileges | Seatbelt / Landlock / rlimits |
| SSRF / DNS rebinding | No protections | Comprehensive IP + DNS defense |

## Why Rust

Rust is not a silver bullet, but it eliminates vulnerability classes that are irrelevant to mention because they cannot happen:

- **Memory safety without GC.** No buffer overflows, use-after-free, or double-free — the categories that account for ~70% of CVEs in C/C++ codebases (per Microsoft and Google's published data). This matters for a long-running daemon that processes untrusted input.
- **Thread safety at compile time.** The borrow checker prevents data races. No "works on my machine" concurrency bugs that surface under load.
- **Minimal runtime.** No V8 engine, no npm dependency tree. The attack surface is the binary and its direct dependencies, auditable via `cargo deny` and `cargo geiger`.

Rust does not help with logic bugs, auth bypass, or prompt injection. Those require architecture, which is what the rest of this document covers.

## Honest Caveats

Carapace is in preview. The security architecture is real and tested (~5,000 automated tests, multi-platform CI), but some items are incomplete:

- **Subprocess sandbox wiring.** Seatbelt/Landlock/rlimit primitives are implemented and tested, but not yet wired into tool subprocess execution. A tool that spawns a child process does not yet inherit the sandbox.
- **Control UI.** The backend (routes, auth, CSRF) is complete. The frontend is not built yet.
- **Channels.** Discord is verified end-to-end. Telegram requires a webhook (no long-polling), so it needs a tunnel or public endpoint. Signal and Slack are implemented but not yet smoke-tested in real environments.
- **Audit log emission.** The audit log module is implemented (append-only JSONL, 19 event types, 50 MB rotation) but event emission is not yet wired into all runtime paths.

We'd rather ship an honest "here's what works and what doesn't" than pretend everything is finished.

## Links

- [Repository](https://github.com/puremachinery/carapace)
- [Full security model](security.md)
- [Getting started](getting-started.md)
