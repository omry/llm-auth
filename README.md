# llm-auth
|  | Description |
| --- | --- |
| Project | [![PyPI version](https://badge.fury.io/py/llm-auth.svg)](https://badge.fury.io/py/llm-auth)[![Downloads](https://pepy.tech/badge/llm-auth/month)](https://pepy.tech/project/llm-auth)![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue) |
| Code quality | [![CI](https://github.com/omry/llm-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/omry/llm-auth/actions/workflows/ci.yml)[![Publish](https://github.com/omry/llm-auth/actions/workflows/publish.yml/badge.svg)](https://github.com/omry/llm-auth/actions/workflows/publish.yml) |

`llm-auth` is a local credential manager for LLM developer tools. It keeps
API-key and subscription-OAuth credentials in an ignored project `.env` file,
with metadata that makes each auth surface discoverable, testable, and
refreshable.

It is built for local workflows where scripts, benchmarks, and agent tools need
model access without committing secrets or scattering credentials across many
ad hoc files.

## What It Supports

- API-key surfaces for providers such as OpenAI and OpenRouter.
- ChatGPT subscription OAuth through LiteLLM's ChatGPT provider.
- Redacted credential status checks.
- Lightweight auth validation.
- OAuth token refresh for renewable surfaces.
- Repo-local `.env` auth storage with explicit metadata envelopes.

## Install

```bash
pip install llm-auth
```

ChatGPT subscription OAuth uses LiteLLM's ChatGPT provider. Install the extra
when you want `llm-auth login chatgpt`:

```bash
python -m pip install 'llm-auth[chatgpt]'
```

After installation, use the `llm-auth` command:

```bash
llm-auth status
```

## Mental Model

A **surface** is a named auth target, such as `chatgpt`, `research`, or `evals`.
Each surface has an auth mode:

- `api-key`: a provider key stored in a named env var.
- `subscription-oauth`: a renewable OAuth record managed through LiteLLM.

`llm-auth` stores those surfaces in `.env` as metadata envelopes. The env file
must be ignored by version control.

Before using an existing `.env`, `llm-auth` checks that the file is not readable
by group or other users. In Git, Sapling, and Mercurial repositories, it also
checks that the file is ignored, not currently tracked, and not present in
commit history.

## Common Workflows

### ChatGPT Subscription OAuth

```bash
# Create or refresh the ChatGPT subscription OAuth surface.
llm-auth login chatgpt

# Show redacted status for the ChatGPT surface.
llm-auth status chatgpt

# Validate the ChatGPT auth state without printing secrets.
llm-auth test chatgpt
```

`login chatgpt` uses LiteLLM's ChatGPT authenticator. LiteLLM owns the
device-code flow and token exchange; `llm-auth` stores the resulting auth
record in `.env` as `CHATGPT_AUTH_JSON`.

If LiteLLM is not installed, `llm-auth login chatgpt` prints the install command:

```bash
python -m pip install 'llm-auth[chatgpt]'
```

If the stored access token is still valid, `llm-auth login chatgpt` exits with
`ok`. If a refresh token exists, it attempts refresh before opening a new
device-code login.

When you already have refreshable OAuth state, renew without opening a browser:

```bash
# Refresh only the ChatGPT subscription OAuth surface.
llm-auth renew chatgpt
```

Device codes are sensitive while active. Never share them.

### API-Key Surface

Create an API-key surface:

```bash
# Create a research surface for OpenAI. The default env var template is
# <PROVIDER>_<SURFACE>_API_KEY, so this uses OPENAI_RESEARCH_API_KEY.
llm-auth add-api-key research openai --model gpt-4.1-mini
```

This appends an empty env assignment to `.env`:

```bash
# BEGIN LLM AUTH SURFACE research api-key
# surface=research
# provider=openai
# auth=api-key
# env=OPENAI_RESEARCH_API_KEY
# model=gpt-4.1-mini
OPENAI_RESEARCH_API_KEY=
# END LLM AUTH SURFACE research api-key
```

Fill in the key manually, then check it:

```bash
# Show redacted status for every configured surface.
llm-auth status

# Test every configured surface.
llm-auth test

# Test only the research surface.
llm-auth test research
```

Use a specific env var when a provider already has a conventional name:

```bash
# Create an OpenRouter surface backed by OPENROUTER_API_KEY.
llm-auth add-api-key evals openrouter \
  --env OPENROUTER_API_KEY \
  --api-base https://openrouter.ai/api/v1 \
  --model openrouter/openai/gpt-5.4-mini
```

Use `--key` only when you intentionally want the command to write the secret:

```bash
llm-auth add-api-key research openai \
  --model gpt-4.1-mini \
  --key "$OPENAI_RESEARCH_API_KEY"
```

API-key surfaces do not use `login` or `renew`. Rotate them by changing the
configured env var value.

## LiteLLM App Integration

Apps that use LiteLLM can treat `.env` as the local auth bootstrap file.

For API-key surfaces, load `.env` before creating LiteLLM requests and read the
configured env var, such as `OPENAI_RESEARCH_API_KEY` or `OPENROUTER_API_KEY`.
The metadata envelope tells your app which provider, model, API base, and env
var belong to a surface.

For ChatGPT subscription OAuth, load `.env` so `CHATGPT_AUTH_JSON` is present,
then install the `llm-auth` ChatGPT/LiteLLM integration before making
`chatgpt/...` calls. That integration makes LiteLLM read and refresh the auth
record from `.env` instead of its default token file.

## Command Reference

### `llm-auth status`

Show redacted status for all discovered surfaces:

```bash
# Show every API-key and OAuth surface discovered in .env.
llm-auth status
```

Show one surface:

```bash
# Show only ChatGPT subscription OAuth status.
llm-auth status chatgpt

# Show only an API-key surface named research.
llm-auth status research
```

Example ChatGPT status:

```json
{
  "chatgpt": {
    "access_token": true,
    "account_id": true,
    "auth": "subscription-oauth",
    "auth_json": true,
    "env": "CHATGPT_AUTH_JSON",
    "expired": false,
    "refresh_token": true
  }
}
```

Example API-key status:

```json
{
  "research": {
    "api_key": true,
    "auth": "api-key",
    "env": "OPENAI_RESEARCH_API_KEY",
    "provider": "openai"
  }
}
```

Status output reports whether credentials are present, but does not print
secret values.

### `llm-auth test`

Run lightweight checks for all discovered surfaces:

```bash
# Test every configured auth surface discovered in .env.
llm-auth test
```

Run detailed checks for one surface:

```bash
# Test only ChatGPT subscription OAuth state.
llm-auth test chatgpt

# Test only an API-key surface named research.
llm-auth test research
```

For ChatGPT subscription OAuth, the default test checks that `CHATGPT_AUTH_JSON`
exists and contains usable OAuth state. The ChatGPT backend completion path is
Cloudflare-gated and is not part of the documented OpenAI API, so the live
completion check is opt-in. Add `live_backend=true` to the `chatgpt` surface
envelope only when you explicitly want `llm-auth test chatgpt` to send a live
backend prompt.

For OpenAI API-key surfaces, `llm-auth test` calls the OpenAI `/models`
endpoint so corrupted keys fail even when no model is configured. When a model
is declared, it also checks model access and sends a small prompt through the
official OpenAI Responses API:

```bash
llm-auth test research --model gpt-4.1-mini
llm-auth test --surface-model research=gpt-4.1-mini
```

### `llm-auth login`

Create or refresh a managed login surface:

```bash
# Run the ChatGPT subscription OAuth login flow.
llm-auth login chatgpt
```

Today, `login` is for ChatGPT subscription OAuth. API-key surfaces are created
with `add-api-key`.

### `llm-auth renew`

Refresh renewable OAuth surfaces without a new browser/device-code flow:

```bash
# Refresh every renewable auth surface discovered in .env.
llm-auth renew

# Refresh only ChatGPT subscription OAuth.
llm-auth renew chatgpt
```

Use `login` when you need to create a new auth surface or complete a new
browser/device-code flow. Use `renew` when a surface already has refreshable
OAuth state.

### `llm-auth add-api-key`

Create an API-key metadata envelope:

```bash
llm-auth add-api-key <surface> <provider>
```

Useful options:

- `--env`: choose the env var name.
- `--model`: record default model metadata for tests and consumers.
- `--api-base`: record provider API base metadata.
- `--key`: write the secret value directly.
- `--allow-unignored`: allow writing to an env file that is not ignored.

By default, `llm-auth` refuses to write credentials unless the target is an
ignored repo-root `.env`. Use `--allow-unignored` only for deliberate temporary
setups; it does not bypass checks for unsafe file permissions, tracked files,
or committed history.

## Auth Store Format

`llm-auth` treats `.env` as a bootstrapping auth store. Each auth surface is
wrapped in a metadata envelope:

```bash
# BEGIN LLM AUTH SURFACE research api-key
# surface=research
# provider=openai
# auth=api-key
# env=OPENAI_RESEARCH_API_KEY
# model=gpt-5.4-mini
# renew=false
OPENAI_RESEARCH_API_KEY=...
# END LLM AUTH SURFACE research api-key
```

The `.env` file should be ignored by version control. `llm-auth` sets file mode
`0600` when it writes the file, where supported by the operating system. If an
existing `.env` has broader permissions, fix it before running commands:

```bash
chmod 600 .env
```

## Security Notes

- Do not commit `.env` or copied credential values.
- Keep `.env` ignored and untracked. `llm-auth` refuses to use it when Git,
  Sapling, or Mercurial reports that it is tracked or appears in commit history.
- Prefer leaving `--key` out and filling the secret manually when possible.
- Treat device codes as temporary secrets.
- `llm-auth status` redacts credential presence and does not print secret
  values.
- `llm-auth` is local tooling, not a hosted secret manager.

## Requirements

- Python 3.11 or newer.
- LiteLLM is required only for ChatGPT subscription OAuth. Install it with
  `python -m pip install 'llm-auth[chatgpt]'`.

## License

MIT. See [LICENSE](LICENSE).
