# llm-auth

Small local auth surface manager for LLM credentials.

It treats a project `.env` as a bootstrapping auth store with metadata
envelopes:

```text
# BEGIN LLM AUTH SURFACE research api-key
# surface=research
# provider=openai
# auth=api-key
# env=OPENAI_RESEARCH_API_KEY
# renew=false
OPENAI_RESEARCH_API_KEY=...
# END LLM AUTH SURFACE research api-key
```

For ChatGPT subscription OAuth, `llm-auth` patches LiteLLM's ChatGPT
authenticator so reads and writes go through `CHATGPT_AUTH_JSON` in `.env`
instead of LiteLLM's default token file.

## Commands

```bash
llm-auth status
llm-auth status <surface>
llm-auth login chatgpt
llm-auth renew
llm-auth renew <surface>
llm-auth test
llm-auth test chatgpt
llm-auth test <surface>
```

`llm-auth test` discovers surfaces from the auth-store metadata envelopes. A
surface-specific test prints detailed subtests; aggregate mode prints one
pass/fail line per discovered surface.

API-key surfaces get a generic env-var presence check. If an API-key surface
declares `provider=openai` and a `model`, `model_env`, or CLI model override,
`llm-auth test` also checks model access through the OpenAI models endpoint.

```bash
llm-auth test research --model o4-mini-deep-research
llm-auth test --surface-model research=o4-mini-deep-research
```

## Install From Local Checkout

```bash
pip install -e /home/omry/dev/llm-auth
```

or use the module directly:

```bash
python -m llm_auth.cli status
```
