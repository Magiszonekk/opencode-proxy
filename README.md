# opencode-proxy (opencode-egress-router)

Small Go reverse proxy that sits between an OpenAI-compatible client (e.g.
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)) and
[OpenCode Zen](https://opencode.ai/zen) (`https://opencode.ai/zen/v1`).

It does two things:

1. **Free-tier gate rewrite (zenfix).** Zen only serves its free models
   (`*-free`, `big-pickle`) to requests that look like they come from the
   opencode CLI. Plain API calls get
   `403 FreeTierError: OpenCode's free tier can only be used from within OpenCode`.
   For free model ids the router rewrites the request so it passes the gate.
   Requests for paid models, or ones carrying a real `sk-` key, pass through
   unchanged.
2. **Egress failover.** When the current egress path gets `429`, it is parked
   for `-cooldown` and the same request is retried through the next backend:
   `direct -> -ovh-proxy -> -oracle-proxy -> -tor-socks`.

## Current gate (measured 2026-10-14, re-verified 2026-10-17, opencode 1.18.32)

Found by capturing a real opencode request and replaying it with one field
removed at a time:

- `x-opencode-session` must be an opencode **descending** identifier:
  `ses_` + 12 hex of `^(unix_ms*0x1000 + counter) & 0xFFFFFFFFFFFF` + 14 base62.
  Random hex, ascending ids and static strings are rejected.
- the request must declare tools named `bash` **and** `read` (stubs with any
  description or schema pass, so the router appends them if missing).
- `"stream": true` is required. Non-streaming callers still work: the router
  streams upstream and folds the SSE back into a single `chat.completion`.
- `User-Agent` must start with `opencode/<version>`.
- Not checked: the auth header, the system prompt, `x-opencode-client/project/request`.

The rewrite applies to every model id ending in `-free` plus the explicit list
in `zenfix.go` (`freeTierModels`), so new Zen free models work without code
changes. Zen changes this gate every few weeks. When every free model starts
returning `FreeTierError` again, re-capture and re-bisect (see `gate.go`).

## ⚠️ Tor exit nodes currently get 403

As of **2026-10-17** Zen rejects **every Tor exit** with `403 FreeTierError`,
whatever the request looks like. A test sent through 10 fresh circuits,
each from a different exit IP across different networks, got 10/10 403s,
while the identical request sent directly at the same moment got 200. Tor
still worked on 2026-10-14, so this is a recent block of the public Tor
exit list, not bad luck with a single node. Changing the circuit or exit IP
does not help (the router already uses a fresh circuit per attempt).

**Use your own proxies instead.** HTTP proxies on VPSes with "clean"
datacenter or residential IPs (`-ovh-proxy`, `-oracle-proxy`) are what
actually adds capacity when the direct IP is rate-limited. `-tor-socks` is
kept for the day the block is lifted. Today it only adds a few seconds of
retries before the request fails, so leave it empty unless you have checked
that Tor works again.

## Build & run

```bash
go vet . && go test ./... && go build -o opencode-egress-router .

./opencode-egress-router \
  -listen 127.0.0.1:8318 \
  -upstream https://opencode.ai/zen/v1 \
  -ovh-proxy http://<your-proxy-1>:<port> \
  -oracle-proxy http://user:pass@<your-proxy-2>:<port> \
  -cooldown 60s
  # -tor-socks 127.0.0.1:9050 -tor-attempts 3   # currently useless, see above
```

Flags:

| flag | default | meaning |
|---|---|---|
| `-listen` | `127.0.0.1:8318` | local listen address |
| `-upstream` | `https://opencode.ai/zen/v1` | real upstream base URL |
| `-ovh-proxy` | `http://10.8.0.1:8888` | 2nd egress (HTTP proxy) |
| `-oracle-proxy` | empty | 3rd egress (HTTP proxy), skipped if empty |
| `-tor-socks` | empty | last egress, Tor SOCKS5, new circuit per request |
| `-tor-attempts` | `3` | fresh Tor circuits to try |
| `-cooldown` | `60s` | how long a 429'd backend is skipped |
| `-test-only-backend` | empty | debug: force one backend (`direct`, `via-ovh`, `via-oracle`, `via-tor`) |

Each response is logged as `[backend] POST /chat/completions -> <code> (zenfix)`.
The `(zenfix)` tag means the gate rewrite was applied.
Errors (>= 400) and every 429 that triggers a failover are also logged with the
model, `Retry-After` / `*ratelimit*` headers and the first 160 bytes of the
body, e.g.

```
[direct] 429 model=deepseek-v4.1-flash-free retry-after=30 body="..."
```

Use it to tell a per-IP rate limit (own proxies help) from upstream overload
such as `Upstream request failed: Endpoint is unavailable.` (no egress rotation
helps; retry later or switch model).

## CLIProxyAPI config

```yaml
openai-compatibility:
  - name: "opencode"
    base-url: "http://127.0.0.1:8318"
    disable-cooling: true
    api-key-entries:
      - api-key: "public"
    models:
      - name: "deepseek-v4.1-flash-free"
      - name: "mimo-v2.6-flash-free"
      - name: "glm-5.3-flash-free"
      # ...see `opencode models opencode` for the current free list
```

## Files

- `main.go`: backends, failover, flags
- `gate.go`: current gate (descending session id, stub `bash`/`read` tools)
- `zenfix.go`: free-model detection, request rewrite, legacy prompt-prefix gate (off)
- `sse.go`: SSE → single `chat.completion` reassembly for non-stream callers
- `musespark.go`: Muse Spark (`/responses`) specifics
