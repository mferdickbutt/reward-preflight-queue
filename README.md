# reward-preflight-queue

A self-contained Python module that decides whether a reward payout should proceed, wait, or get rejected. It joins reward candidates against assignment-gate decisions, bypass classifications, identity resolution, verification state, and authorization facts, then emits a deterministic `ALLOW`, `HOLD`, or `REJECT` per candidate with full audit metadata.

Zero external dependencies. Runs with `python3 reward_preflight.py`.

## What it does

The preflight queue processes a batch of reward candidates through a fixed routing ladder:

1. **Authorization check** — reject unauthorized contributors outright
2. **Identity resolution** — hold if the contributor identity is unresolved
3. **Verification check** — hold if the contributor is unverified
4. **Gate existence** — hold if no assignment-gate decision exists
5. **Gate decision** — reject on `REJECTED`, hold on `BLOCK` or uncleared `REVIEW`, allow on `ACCEPTED` or cleared `REVIEW`
6. **Bypass override** — a single post-decision pass promotes `HOLD` or `REJECT` to `ALLOW` when an active `ADMIN_OVERRIDE` bypass is present for the contributor, preserving the original decision and risk tier for audit

Every output record carries `event_fingerprint`, `hold_reason`, `risk_tier`, `required_release_action` (for holds), `policy_version`, and `policy_checksum`.

## Output

The module prints two things to stdout:

- An operator-readable console summary with decision counts, hold-reason breakdowns, and formatted release/hold/rejection queues
- A stable JSON handoff artifact containing `total_candidates`, `allow_count`, `hold_count`, `reject_count`, `blocked_pft_total`, `bypass_count`, `bypass_detail`, `hold_reason_counts`, `impacted_identities`, and sorted `release_queue`, `hold_queue`, and `rejection_queue` keyed by `event_fingerprint`

The JSON artifact is deterministic: same fixtures in, same bytes out. The expiry evaluation uses a fixed `EVAL_REF_TIMESTAMP` instead of wall-clock time.

## Fixtures

Nine sanitized reward candidates are embedded in the code, covering:

| Event | Identity | Outcome | Reason |
|---|---|---|---|
| EVT-001 | alice | ALLOW | clean passage through accepted gate |
| EVT-002 | frank | HOLD | unresolved identity |
| EVT-003 | mallory | REJECT | unauthorized contributor |
| EVT-004 | bob | HOLD | missing verification |
| EVT-005 | carol | ALLOW | bypass overrides a BLOCK gate (critical underlying risk) |
| EVT-006 | dave | HOLD | uncleared REVIEW gate |
| EVT-007 | eve | HOLD | no gate decision exists |
| EVT-008 | grace | ALLOW | cleared REVIEW gate |
| EVT-009 | heidi | REJECT | gate decision is REJECTED |

Final tally: 3 ALLOW, 4 HOLD, 2 REJECT.

## Bypass system

Bypass overrides are applied in a single post-decision evaluation step after the initial routing ladder completes. This keeps the routing logic clean: one place to add new bypass types, one audit trail.

When a bypass promotes a record from HOLD/REJECT to ALLOW, the output preserves:
- `original_decision` and `original_hold_reason` — what the decision was before override
- `underlying_risk_tier` — the severity of the condition that was overridden (`critical` for Carol's block)
- `bypass_type`, `bypass_granted_by`, `bypass_reason` — provenance for the override

## Handoff integration

The output shape is designed to plug into a settlement review operator without remapping. Key fields in the top-level artifact:

- `policy_version` / `policy_checksum` — pin the routing logic version
- `eval_ref_timestamp` — the fixed reference point for bypass expiry checks
- `bypass_count` / `bypass_pft_total` / `bypass_identities` — at-a-glance override exposure
- `hold_reason_counts` — frequency breakdown for triage
- `impacted_identities` — identities grouped by decision category

## Running

```bash
python3 reward_preflight.py
```

No install step, no config files, no network calls.
