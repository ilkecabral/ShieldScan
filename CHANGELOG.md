# ShieldScan Changelog

All version changes are recorded here per component.
Format: `[VERSION] YYYY-MM-DD — description`

Versioning scheme: **SemVer** (`MAJOR.MINOR.PATCH`)
- `MAJOR` — breaking change (API contract, DB schema, auth flow, model format)
- `MINOR` — new feature or check, backwards compatible
- `PATCH` — bug fix, no new behaviour

---

## APP

| Version | Date | Notes |
|---------|------|-------|
| `1.0.0-beta` | 2026-06-20 | Initial release — full stack: CSPM, CWPP, AI, Risk Scorer, Auth |

---

## API

| Version | Date | Notes |
|---------|------|-------|
| `1.0.0` | 2026-06-20 | Initial release — all core endpoints live: auth, scans, AI, version, health |

---

## CSPM

| Version | Date | Notes |
|---------|------|-------|
| `1.0.0` | 2026-06-20 | Initial release — 13 checks: S3, IAM root, IAM MFA, IAM admin policies, EC2 ports, CloudTrail, password policy, EBS encryption, RDS encryption, VPC flow logs, S3 access logging, KMS rotation, GuardDuty |

---

## CWPP

| Version | Date | Notes |
|---------|------|-------|
| `1.0.0` | 2026-06-20 | Initial release — Trivy integration, CVE scanning with CVSS scoring, severity classification |

---

## RISK_SCORER

| Version | Date | Notes |
|---------|------|-------|
| `1.0.0` | 2026-06-20 | Initial release — weighted severity scoring: CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1, normalised to 0–100 |

---

## AI_SERVICE

| Version | Date | Notes |
|---------|------|-------|
| `1.0.0` | 2026-06-20 | Initial release — ollama / groq / claude provider abstraction, scope-locked system prompt, findings context injection |

---

## RAG

| Version | Date | Notes |
|---------|------|-------|
| `1.0.0` | 2026-06-20 | Initial release — ChromaDB persistent store, 15 CIS AWS Benchmark v2.0 documents seeded |

---

## AUTH

| Version | Date | Notes |
|---------|------|-------|
| `1.0.0` | 2026-06-20 | Initial release — JWT HS256, bcrypt, TOTP 2FA, WebAuthn passkeys, email verification, account lockout, soft delete, password reset, account recovery |

---

## FRONTEND

| Version | Date | Notes |
|---------|------|-------|
| `1.0.0` | 2026-06-20 | Initial release — dashboard, findings table, AI chat widget, scan progress, admin panel |

---

## How to bump a version

1. Edit the relevant constant in `app/backend/version.py`
2. Add a row to the component's table above
3. Update `VERSION` file at repo root if bumping `APP`
4. Commit with message: `chore: bump <component> to <version> — <reason>`
5. If bumping `APP`, create a git tag: `git tag v1.1.0 && git push origin v1.1.0`

### Example

You added a new CSPM check for SecurityHub:

```
# version.py
CSPM = Version(1, 1, 0)   # was 1.0.0

# CHANGELOG.md — CSPM table
| `1.1.0` | 2026-07-01 | Added SecurityHub findings check |

# commit
git commit -m "feat(cspm): add SecurityHub check — bump CSPM to 1.1.0"
```

The `/api/version` endpoint will immediately reflect the new version on next deploy.
