# App ↔ server contract

The Zetru app (repository `zetru`) and this server talk over a signed protocol and must compute a few
things byte for byte the same way. This folder holds the shared test vectors, so each side can prove
in its own test suite that it still matches the other.

| File | Written by | Checked by |
|---|---|---|
| `signing/swift_signed_request.json` | the app's Swift signing code (`RequestSigning.sign`) | `gateway/internal/auth/contract_test.go` `TestSwiftSignedRequest`: the gateway verifies the app's signature and request binding (concept §4.4) |
| `signing/gateway_signed_response.json` | `gateway/internal/auth/contract_test.go` `TestWriteResponseFixture` with `ZETRU_WRITE_FIXTURES=1` | the app's test "contract: a response signed by the Go gateway verifies in the app" (concept §4.5) |
| `url-canonicalization.json` | `analyzer/tests/test_contract_vectors.py` with `ZETRU_WRITE_CONTRACT=1` | that test (the server's `canonicalize()`) and the app's `LinkCanonicalizer` test; both must give the same canonical URL, because `url_sha256` is compared across the two (concept §11.4) |

Other shared material is copied from the app repository, which is its source:

- `docs/concept.md`: the binding product and protocol concept.
- `analyzer/zetru_analyzer/packs/brands-de-en.json` and the official domains in
  `updater/zetru_updater/never_list.txt`: generated from the app's brand pack.

## Keeping both sides in sync

The app repository has `scripts/sync-server-contract.py`. With both repositories checked out next to
each other:

```bash
scripts/sync-server-contract.py --server ../zetru-server          # copy every piece in its direction
scripts/sync-server-contract.py --server ../zetru-server --check  # exit 1 if anything differs
```

Run it after changing the protocol, the canonicalisation, the concept or the brand pack, then run both
test suites. A protocol change is only done when both suites pass against the regenerated files.

## Regenerating

```bash
# server repository
(cd gateway && ZETRU_WRITE_FIXTURES=1 go test ./internal/auth/)
ZETRU_WRITE_CONTRACT=1 .venv/bin/python -m pytest -q analyzer/tests/test_contract_vectors.py

# app repository
ZETRU_SWIFT_FIXTURE_OUT=$PWD/ios/ZetruKitTests/Fixtures/swift_signed_request.json scripts/test-ios-core.sh
```

The Swift fixture is signed with a fresh random key on every regeneration, so its bytes change each
time; that is expected.
