# Demo 01 — Linting an intentionally insecure OpenAPI spec

`petstore-insecure.json` is a small OpenAPI 3.0 spec that deliberately
contains several common API security gaps. APISECLINT performs **static
analysis only** — it reads the spec file you own and reports weaknesses. It
never makes network calls and has no attack capability.

## What's wrong with the demo spec (and which rule catches it)

| Issue in the spec                                            | Rule     | Severity |
|--------------------------------------------------------------|----------|----------|
| Server URL is plaintext `http://`                            | TLS001   | high     |
| `GET /pets` sets `security: []` (anonymous access)           | AUTHZ001 | medium   |
| `POST /pets` has no auth + no global default                 | AUTHZ002 | high     |
| HTTP Basic auth scheme                                       | AUTHN003 | medium   |
| API key passed in the **query string**                       | AUTHN004 | high     |
| No global `security` requirement                             | AUTHN002 | medium   |
| `User` schema returns `password` / `api_key` (not writeOnly) | DATA001  | high     |
| `POST /pets` body has no `additionalProperties:false`        | MASS001  | medium   |
| `GET /pets` lists a collection with no pagination params     | DOS001   | low      |
| No 429 / rate-limit headers anywhere                         | RATE001  | medium   |
| Operations document no 401 response                          | DOC001   | low      |

## Run it

```bash
# Human-readable table (exits non-zero because findings exist)
python -m apiseclint lint demos/01-basic/petstore-insecure.json

# Machine-readable JSON for CI pipelines
python -m apiseclint lint demos/01-basic/petstore-insecure.json --format json

# Shareable self-contained HTML report (the tool's "UI")
python -m apiseclint lint demos/01-basic/petstore-insecure.json \
    --format html -o report.html
```

## Exit codes

- `0` — no medium-or-higher findings (or `--exit-zero` passed)
- `1` — findings at medium/high/critical severity (CI gate fails)
- `2` — could not read or parse the spec

> All analysis is read-only on a spec you already own. No network access.
