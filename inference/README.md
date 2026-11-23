# inference

Typed-decision service `POST /v1/systemone` (concept §9, §11.3). Day-one backend: `rules` (German and English
pattern tier, `calibrated: false`). Optional backends are plumbed but off.

## Container

| Item | Value |
|---|---|
| Build | `docker build -t zetru/inference:1.0.0 inference` (`--build-arg WITH_ENCODER=1` adds ONNX Runtime) |
| Command | `python3 -m zetru_inference` |
| Port | 8082, plain HTTP, `core` network only, no DNS needed |
| User | uid/gid 10003 |
| Volumes | `models:/models:ro` (only read by the optional `encoder` backend) |
| Health | `GET /healthz` → `{"status":"ok","backends":[{"id","enabled","calibrated","licence_notice"}]}` |

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `ZETRU_INFERENCE_PORT` | `8082` | listen port |
| `ZETRU_INFERENCE_BACKENDS` | `rules` | backends the operator enables (comma list of `rules,encoder,llm,openjev,jev`); the tenant policy in each request then selects among them |
| `ZETRU_MODELS_DIR` | `/models` | `encoder` model location (`/models/encoder/current.json`) |
| `ZETRU_LLM_URL`, `ZETRU_LLM_MODEL_VERSION`, `ZETRU_LLM_CALIBRATED` | unset | llama.cpp server for `llm` (VPS only; Apache-2.0/MIT models only) |
| `ZETRU_OPENJEV_URL`, `ZETRU_OPENJEV_API_KEY` | unset | OpenJev adapter; **requires `ZETRU_ALLOW_NONCOMMERCIAL=1`** (CC BY-NC 4.0, licence notice shown) |
| `ZETRU_JEV_URL`, `ZETRU_JEV_API_KEY` | unset | hosted Jev adapter (mail text leaves the server; tenant consent via policy) |
| `ZETRU_ALLOW_NONCOMMERCIAL` | `0` | enables non-commercial backends |
| `ZETRU_INFERENCE_CONCURRENCY` | `8` | requests handled at once; further connections get `503 busy` |

Router rules (§9.3): known questions go to `encoder` if available, else `rules`; with both, rules can only raise a
probability (when strong); `llm` is asked only for encoder probabilities in 0.40–0.80 and can only raise them
(uncalibrated: to at most 0.79); remote backends raise only, 5 s timeout; unknown question IDs are answered only
by an enabled zero-shot backend, else `abstain: "unsupported_question"`.

Time and failure bounds: one 6 s deadline per request (the analyzer waits 8 s); the rule tier stops at it and
abstains with `backend_error`; `llm`, `openjev` and `jev` run in parallel on a 4-thread pool, and a tier that fails,
answers late or returns garbage is ignored — the rule answers are still returned with `200`. A failing encoder
falls back to `rules`. Remote backends (`openjev`, `jev`) need `https://` unless the host is loopback. Each
connection has a 15 s socket timeout; request bodies up to 1 MiB.

## Rule tier

`zetru_inference/rules/de.yaml` and `en.yaml` (`rules-1.1.0`): pattern groups per question over normalised text
(NFKC, case folding, homoglyph folding, umlaut folding). Evidence none/weak/moderate/strong → 0.05/0.35/0.65/0.90;
strong = two groups in the same or adjacent sentence plus a call to action nearby (link marker, reply request,
attachment reference, phone number, IBAN or wallet address for payment questions). A `suppress` pattern cancels
only the matches it overlaps. Language by stop-word ratio; other languages and fewer than 20 tokens abstain; text
padded below the ratio is evaluated against its densest German/English 40-token window and then reports strong
findings only. `category` and `risk_score` are derived (concept §9.4). Every pattern is timed against adversarial
strings when a pack is loaded; a super-linear pattern stops the service from starting.

## Tests

From the repository root: `.venv/bin/python -m pytest inference/tests` — 30+ positive and 30+ negative snippets per question
and language (`tests/corpus_de.py`, `tests/corpus_en.py`), router raise-only rules, HTTP handler.
