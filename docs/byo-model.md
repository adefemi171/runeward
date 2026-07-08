# Bring your own model gateway

`byo-model-gateway` is a deny-by-default profile for running agents against a
local or self-hosted OpenAI-compatible endpoint while keeping full runeward
audit trails.

Use it when you need:

- air-gapped or private-network model serving
- strict egress lockdown to one gateway host
- policy + limits + redacted audit on every action

## One-command start

Start runeward with the required model endpoint and key injected from your host
environment:

```bash
OPENAI_BASE_URL=http://host.docker.internal:11434/v1 \
OPENAI_API_KEY=dummy \
runeward --config-dir examples serve
```

Then create a sandbox with profile `byo-model-gateway`:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/sandboxes \
  -H 'content-type: application/json' \
  -d '{"profile":"byo-model-gateway"}'
```

## Gateway targets

Set `OPENAI_BASE_URL` to your gateway's OpenAI-compatible `/v1` endpoint:

- vLLM: `http://<vllm-host>:8000/v1`
- Ollama (OpenAI shim): `http://<ollama-host>:11434/v1`
- LiteLLM proxy: `http://<litellm-host>:4000/v1`

If you run Docker backend and the gateway is on your host machine, use
`host.docker.internal` as shown in the example profile.

## Egress pinning note

The profile allows exactly one hostname under `[[network.rule]]` and keeps
`default = "deny"` with `enforce = "strict"`. In strict mode, runeward resolves
that hostname and pins enforcement to the resolved destination IPs for the
sandbox lifetime. If the gateway DNS target changes, create a new sandbox.

See `examples/byo-model-gateway.toml` for the complete profile.
