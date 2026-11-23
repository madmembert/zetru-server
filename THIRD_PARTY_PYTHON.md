# Third-party Python components

All licences are permissive and allow commercial use. Versions are pinned in the `requirements*.txt` files.

## Runtime (shipped in images)

| Package | Version | Licence | Used by | Purpose |
|---|---|---|---|---|
| dnspython | 2.9.2 | ISC | analyzer | asyncio TXT lookups (DKIM keys, DMARC) via the local resolver |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | analyzer | RSA/Ed25519 DKIM verification, AES for PDF R6 password check |
| cffi | 2.1.1 | MIT-0 | analyzer (dependency of cryptography) | — |
| pycparser | 3.12 | BSD-3-Clause | analyzer (dependency of cffi) | — |
| PyYAML | 6.0.4 | MIT | inference | rule files |

The updater uses only the Python standard library (PSF licence, part of the base image).

## Optional runtime (`inference`, build argument `WITH_ENCODER=1`, off by default)

| Package | Licence | Purpose |
|---|---|---|
| onnxruntime | MIT | encoder backend |
| tokenizers | Apache-2.0 | encoder tokenisation |
| numpy | BSD-3-Clause | tensors |

Versions are to be pinned and re-checked when the first encoder model is released (milestone M8).

## Bundled data (analyzer image)

| Data | Licence | Notes |
|---|---|---|
| Public Suffix List (`zetru_analyzer/data/public_suffix_list.dat`) | MPL-2.0 | fallback when the `psl` feed is missing; updated by the updater |
| Unicode `confusables.txt` (UTS #39, 2026-08-06) | Unicode License v3 | skeletons for look-alike detection |

## Feeds fetched at runtime (updater)

See `updater/README.md`: Public Suffix List (MPL-2.0), IANA TLD list and RDAP bootstrap (IANA public data),
CERT Polska Warning List (data usage policy: any use incl. commercial, attribution not required, no implied
endorsement), Majestic Million (CC BY 3.0, attribution "Majestic Million by Majestic (majestic.com)"),
disposable-email-domains (CC0).

## Development and tests only (`requirements-dev.txt`, never in images)

| Package | Version | Licence | Purpose |
|---|---|---|---|
| pytest | 9.2.0 | MIT | tests |
| pluggy | 1.7.0 | MIT | pytest dependency |
| iniconfig | 2.3.1 | MIT | pytest dependency |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | pytest dependency |
| Pygments | 2.21.0 | BSD-2-Clause | pytest dependency |
| dkimpy | 1.1.8 | zlib-style ("BSD-like", DFSG) | signs test mails, cross-checks the DKIM verifier |
| PyNaCl | 1.6.2 | Apache-2.0 | Ed25519 signing for dkimpy in tests |
| pypdf | 7.1.1 | BSD-3-Clause | creates encrypted test PDFs |

dkimpy is published only as a source distribution; on Python 3.14 install it with
`pip install --no-build-isolation dkimpy==1.1.8` after installing setuptools.
