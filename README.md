# llm-auth

Small local auth surface manager for LLM credentials.

It treats a project `.env` as a bootstrapping auth store with metadata
envelopes:

```text
# BEGIN LLM AUTH SURFACE deepresearch api-key
# surface=deepresearch
# provider=openai
# auth=api-key
# env=OPENAI_DEEP_RESEARCH_API_KEY
# renew=false
OPENAI_DEEP_RESEARCH_API_KEY=...
# END LLM AUTH SURFACE deepresearch api-key
```

For ChatGPT subscription OAuth, `llm-auth` patches LiteLLM's ChatGPT
authenticator so reads and writes go through `CHATGPT_AUTH_JSON` in `.env`
instead of LiteLLM's default token file.

## Commands

```bash
llm-auth status
llm-auth login
llm-auth renew
llm-auth test
llm-auth test chatgpt
llm-auth test deepresearch
```

## Install From Local Checkout

```bash
pip install -e /home/omry/dev/llm-auth
```

or use the module directly:

```bash
python -m llm_auth.cli status
```
