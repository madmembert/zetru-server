"""DMARC policy discovery and evaluation per RFC 9989 (DMARCbis) on the server (concept §6.3).

- Policy discovery by DNS Tree Walk, at most 8 `_dmarc` queries; tags p, sp, np, psd, t, adkim, aspf;
  pct, rf and ri are ignored; t=y softens the policy by one step.
- Organisational Domain from the same walk (psd=n / psd=y / fewest labels), PSL only as fallback.
- SPF is never re-evaluated. The server reports `fail` only when DMARC must fail regardless of SPF: no
  aligned DKIM pass, no aligned signature that is merely unverifiable, and an unaligned (non-null)
  Return-Path. Everything else that is not a pass is `none` (not determinable).
"""

from __future__ import annotations

from dataclasses import dataclass

from .domains import PublicSuffixList

_POLICIES = ("none", "quarantine", "reject")


def tree_walk(domain: str) -> list[str]:
    labels = domain.split(".")
    names = [domain]
    n = len(labels)
    if n > 8:
        n = 7
        names.append(".".join(labels[-7:]))
    while n > 1:
        n -= 1
        names.append(".".join(labels[-n:]))
    # Deduplicate while keeping order (the 7-label step can coincide with the start).
    seen, out = set(), []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out[:8]


@dataclass
class Record:
    domain: str
    tags: dict[str, str]

    def policy(self, key: str) -> str | None:
        value = self.tags.get(key, "").strip().lower()
        return value if value in _POLICIES else None

    @property
    def psd(self) -> str:
        value = self.tags.get("psd", "u").strip().lower()
        return value if value in ("y", "n", "u") else "u"

    @property
    def testing(self) -> bool:
        return self.tags.get("t", "n").strip().lower() == "y"


def parse_record(domain: str, txts: list[str]) -> Record | None:
    valid = []
    for txt in txts:
        stripped = txt.strip()
        if not stripped.lower().startswith("v=dmarc1"):
            continue
        tags: dict[str, str] = {}
        parts = [p.strip() for p in stripped.split(";")]
        head = parts[0].replace(" ", "")
        if head.lower() != "v=dmarc1":
            continue
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                tags.setdefault(key.strip().lower(), value.strip())
        valid.append(Record(domain, tags))
    return valid[0] if len(valid) == 1 else None


@dataclass
class Policy:
    status: str                 # ok | absent | temperror
    record_domain: str | None = None
    published: str = "absent"   # none | quarantine | reject | absent
    testing: bool = False
    org_domain: str | None = None
    adkim: str = "r"
    aspf: str = "r"

    @property
    def effective(self) -> str:
        if self.published == "absent":
            return "absent"
        if self.testing:
            return {"reject": "quarantine", "quarantine": "none"}.get(self.published, "none")
        return self.published


def discover(from_domain: str, lookups: dict[str, tuple[str, list[str]]], from_exists: bool | None) -> Policy:
    """`lookups` maps each tree-walk domain to (dns status, TXT strings) of `_dmarc.<domain>`."""
    names = tree_walk(from_domain)
    records: dict[str, Record] = {}
    policy_record: Record | None = None
    for name in names:
        status, txts = lookups.get(name, ("error", []))
        if status == "ok":
            rec = parse_record(name, txts)
            if rec is not None:
                records[name] = rec
                if policy_record is None:
                    policy_record = rec
        elif status not in ("nxdomain", "nodata"):
            if policy_record is None:
                return Policy(status="temperror")
    if policy_record is None:
        return Policy(status="absent")
    org = _org_domain(from_domain, names, records)
    rec = policy_record
    if rec.domain == from_domain:
        published = rec.policy("p") or "none"
    else:
        published = None
        if from_exists is False:
            published = rec.policy("np")
        if published is None:
            published = rec.policy("sp")
        if published is None:
            published = rec.policy("p") or "none"
    org_rec = records.get(org) if org else None
    align_src = rec if rec.domain == from_domain else (org_rec or rec)
    return Policy(status="ok", record_domain=rec.domain, published=published, testing=rec.testing, org_domain=org,
                  adkim=align_src.tags.get("adkim", "r").strip().lower()[:1] or "r",
                  aspf=align_src.tags.get("aspf", "r").strip().lower()[:1] or "r")


def _org_domain(from_domain: str, names: list[str], records: dict[str, Record]) -> str | None:
    labels = from_domain.split(".")
    for name in names:
        rec = records.get(name)
        if rec is None:
            continue
        if rec.psd == "n":
            return name
        if rec.psd == "y":
            n = len(name.split(".")) + 1
            return ".".join(labels[-n:]) if n <= len(labels) else from_domain
    found = [n for n in names if n in records]
    return min(found, key=lambda n: n.count(".")) if found else None


def aligned(identifier: str, from_domain: str, org: str, mode: str) -> bool:
    if mode == "s":
        return identifier == from_domain
    return identifier == org or identifier.endswith("." + org)


@dataclass
class Outcome:
    result: str          # pass | fail | none
    policy: Policy
    signal: str | None   # AUTH_DMARC_FAIL_ENFORCED | AUTH_DMARC_FAIL_NONE | None


def evaluate(from_domain: str, policy: Policy, psl: PublicSuffixList, dkim: list[tuple[str, str]],
             return_path: str | None, modified_domains: set[str]) -> Outcome:
    """`dkim`: (d, result) per verified signature; `modified_domains`: d values whose failure is attributed
    to in-store modification (provider reported a pass)."""
    org = policy.org_domain or psl.registrable_domain(from_domain) or from_domain
    if policy.status != "ok":
        return Outcome("none", policy, None)
    if any(r == "pass" and aligned(d, from_domain, org, policy.adkim) for d, r in dkim):
        return Outcome("pass", policy, None)
    if any((r == "unverifiable" or d in modified_domains) and aligned(d, from_domain, org, policy.adkim)
           for d, r in dkim):
        return Outcome("none", policy, None)
    if return_path is None or return_path == "":
        return Outcome("none", policy, None)
    rp_domain = return_path.rpartition("@")[2]
    if not rp_domain or aligned(rp_domain, from_domain, org, policy.aspf):
        return Outcome("none", policy, None)
    effective = policy.effective
    signal = "AUTH_DMARC_FAIL_ENFORCED" if effective in ("quarantine", "reject") else "AUTH_DMARC_FAIL_NONE"
    return Outcome("fail", policy, signal)
