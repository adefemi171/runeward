# Bring your own model gateway

`byo-model-gateway` is a deny-by-default profile for running agents against a
**local or self-hosted model** while keeping full runeward audit trails. The
model runs on your machine (or your private network) — nothing goes to a hosted
API.

> **"OpenAI" here is a protocol, not a vendor.** Local runtimes like Ollama,
> vLLM, llama.cpp, LM Studio, LiteLLM, and TGI all expose an OpenAI-compatible
> `/v1` API, and agent SDKs read `OPENAI_BASE_URL` / `OPENAI_API_KEY`. Pointing
> those at `localhost` is exactly how you keep inference local. The profile
> injects the endpoint under the common aliases (`OPENAI_BASE_URL`,
> `OPENAI_API_BASE`) so OpenAI SDK, LangChain, and LiteLLM agents all pick it up.

Use it when you need:

- air-gapped or private-network model serving
- strict egress lockdown to one gateway host
- policy + limits + redacted audit on every action

## One-command start

Start runeward pointing at your **local** model runtime (Ollama's default port
shown); the key is a placeholder for servers that ignore auth:

```bash
OPENAI_BASE_URL=http://host.docker.internal:11434/v1 \
OPENAI_API_KEY=local \
runeward --config-dir examples serve
```

Then create a sandbox with profile `byo-model-gateway`:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/sandboxes \
  -H 'content-type: application/json' \
  -d '{"profile":"byo-model-gateway"}'
```

## Local runtime targets

Set `OPENAI_BASE_URL` to your local runtime's OpenAI-compatible `/v1` endpoint:

- Ollama: `http://<ollama-host>:11434/v1`
- vLLM: `http://<vllm-host>:8000/v1`
- llama.cpp server: `http://<host>:8080/v1`
- LM Studio: `http://<host>:1234/v1`
- Text Generation Inference (TGI): `http://<host>:8080/v1`
- LiteLLM proxy (front any of the above, incl. local Anthropic-style models):
  `http://<litellm-host>:4000/v1`

If you run the Docker backend and the runtime is on your host machine, use
`host.docker.internal` as the hostname (as in the example profile). On the
Kubernetes backend, use the in-cluster Service DNS name of your runtime instead
and update the `[[network.rule]]` hostname to match.

### Runtimes that are not OpenAI-compatible

A few local stacks speak their own protocol (Ollama's native `/api/*`, raw
Anthropic-style servers, custom gRPC). Two options:

- **Front it with LiteLLM** (recommended): it exposes a local OpenAI-compatible
  `/v1` over almost any backend, so this profile works unchanged.
- **Or fork the profile**: keep `default = "deny"` / `enforce = "strict"`, point
  the one `[[network.rule]]` hostname at your runtime, and inject whatever env
  vars your agent expects (e.g. `ANTHROPIC_BASE_URL`, `OLLAMA_HOST`) via
  `op = "env://..."`. Remember each `env://` source must be exported on the host
  or sandbox creation fails closed.

## Egress pinning note

The profile allows exactly one hostname under `[[network.rule]]` and keeps
`default = "deny"` with `enforce = "strict"`. In strict mode, runeward resolves
that hostname and pins enforcement to the resolved destination IPs for the
sandbox lifetime. If the gateway DNS target changes, create a new sandbox.

See `examples/byo-model-gateway.toml` for the complete profile.
