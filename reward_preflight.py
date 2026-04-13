"""
Reward Settlement Authorization Preflight Queue
Deterministic ALLOW / HOLD / REJECT routing for payout-side governance.
Bypass override applied as single post-decision pass.
Fully deterministic — no wall-clock dependencies.
No external dependencies.
"""

import json
import hashlib
from datetime import datetime, timezone
from collections import Counter

POLICY_VERSION = "2026.04.13-v2"

EVAL_REF_TIMESTAMP = "2026-04-13T00:00:00Z"

ROUTING_SPEC = (
    "authorization->REJECT_unauthorized;"
    "identity_resolved->HOLD_unresolved-identity;"
    "verified->HOLD_missing-verification;"
    "gate_exists->HOLD_missing-decision;"
    "gate_REJECTED->REJECT_gate-rejected;"
    "gate_BLOCK->HOLD_accepted-after-block;"
    "gate_REVIEW-uncleared->HOLD_accepted-after-review;"
    "gate_REVIEW-cleared->ALLOW_cleared-review;"
    "gate_ACCEPTED->ALLOW_clean;"
    "ADMIN_OVERRIDE->promote_HOLD_or_REJECT_to_ALLOW"
)


def _event_fingerprint(candidate):
    raw = ":".join([
        candidate["event_id"],
        candidate["identity"],
        str(candidate["pft_amount"]),
        candidate["assignment_id"],
        candidate["reward_type"],
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _policy_checksum():
    return hashlib.sha256(ROUTING_SPEC.encode()).hexdigest()[:12]


def _parse_iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def build_fixtures():
    candidates = [
        {"event_id": "EVT-001", "identity": "alice",  "pft_amount": 120.0, "assignment_id": "ASGN-001", "reward_type": "task_completion"},
        {"event_id": "EVT-002", "identity": "frank",  "pft_amount":  75.0, "assignment_id": "ASGN-002", "reward_type": "bug_report"},
        {"event_id": "EVT-003", "identity": "mallory","pft_amount": 200.0, "assignment_id": "ASGN-003", "reward_type": "exploit_submission"},
        {"event_id": "EVT-004", "identity": "bob",    "pft_amount":  90.0, "assignment_id": "ASGN-004", "reward_type": "task_completion"},
        {"event_id": "EVT-005", "identity": "carol",  "pft_amount": 150.0, "assignment_id": "ASGN-005", "reward_type": "audit_find"},
        {"event_id": "EVT-006", "identity": "dave",   "pft_amount":  60.0, "assignment_id": "ASGN-006", "reward_type": "review_contribution"},
        {"event_id": "EVT-007", "identity": "eve",    "pft_amount": 110.0, "assignment_id": "ASGN-007", "reward_type": "task_completion"},
        {"event_id": "EVT-008", "identity": "grace",  "pft_amount":  85.0, "assignment_id": "ASGN-008", "reward_type": "task_completion"},
        {"event_id": "EVT-009", "identity": "heidi",  "pft_amount":  50.0, "assignment_id": "ASGN-009", "reward_type": "spam_submission"},
    ]

    gate_decisions = {
        "ASGN-001": {"decision": "ACCEPTED", "decided_at": "2026-04-12T10:00:00Z"},
        "ASGN-002": {"decision": "ACCEPTED", "decided_at": "2026-04-12T10:05:00Z"},
        "ASGN-003": {"decision": "ACCEPTED", "decided_at": "2026-04-12T10:10:00Z"},
        "ASGN-004": {"decision": "ACCEPTED", "decided_at": "2026-04-12T10:15:00Z"},
        "ASGN-005": {"decision": "BLOCK",    "decided_at": "2026-04-12T10:20:00Z"},
        "ASGN-006": {"decision": "REVIEW",   "review_cleared": False, "decided_at": "2026-04-12T10:25:00Z"},
        "ASGN-008": {"decision": "REVIEW",   "review_cleared": True,  "decided_at": "2026-04-12T10:30:00Z"},
        "ASGN-009": {"decision": "REJECTED", "decided_at": "2026-04-12T10:35:00Z"},
    }

    bypass_classifications = {
        "carol": {
            "bypass_type": "ADMIN_OVERRIDE",
            "granted_at":   "2026-04-10T00:00:00Z",
            "expires_at":   "2026-04-20T00:00:00Z",
            "granted_by":   "uid-operator-001",
            "reason":       "escalated_block_false_positive",
        },
    }

    verification_state = {
        "alice":  {"verified": True,  "method": "oauth_github",   "verified_at": "2026-04-01T08:00:00Z"},
        "frank":  {"verified": True,  "method": "oauth_google",   "verified_at": "2026-04-02T09:00:00Z"},
        "mallory":{"verified": True,  "method": "api_key",        "verified_at": "2026-04-03T10:00:00Z"},
        "bob":    {"verified": False, "method": None,             "verified_at": None},
        "carol":  {"verified": True,  "method": "oauth_github",   "verified_at": "2026-04-04T11:00:00Z"},
        "dave":   {"verified": True,  "method": "oauth_google",   "verified_at": "2026-04-05T12:00:00Z"},
        "eve":    {"verified": True,  "method": "oauth_github",   "verified_at": "2026-04-06T13:00:00Z"},
        "grace":  {"verified": True,  "method": "oauth_github",   "verified_at": "2026-04-07T14:00:00Z"},
        "heidi":  {"verified": True,  "method": "oauth_google",   "verified_at": "2026-04-08T15:00:00Z"},
    }

    identity_state = {
        "alice":  {"resolved": True,  "canonical_id": "uid-a1b2c3"},
        "frank":  {"resolved": False, "canonical_id": None},
        "mallory":{"resolved": True,  "canonical_id": "uid-m4l1c"},
        "bob":    {"resolved": True,  "canonical_id": "uid-b0b1b2"},
        "carol":  {"resolved": True,  "canonical_id": "uid-c4r0l"},
        "dave":   {"resolved": True,  "canonical_id": "uid-d4v3d"},
        "eve":    {"resolved": True,  "canonical_id": "uid-3v3v3"},
        "grace":  {"resolved": True,  "canonical_id": "uid-gr4c3"},
        "heidi":  {"resolved": True,  "canonical_id": "uid-h31d1"},
    }

    authorization_facts = {
        "alice":  {"authorized": True,  "role": "contributor",    "source": "rbac"},
        "frank":  {"authorized": True,  "role": "contributor",    "source": "rbac"},
        "mallory":{"authorized": False, "role": None,             "source": None},
        "bob":    {"authorized": True,  "role": "contributor",    "source": "rbac"},
        "carol":  {"authorized": True,  "role": "contributor",    "source": "rbac"},
        "dave":   {"authorized": True,  "role": "contributor",    "source": "rbac"},
        "eve":    {"authorized": True,  "role": "contributor",    "source": "rbac"},
        "grace":  {"authorized": True,  "role": "contributor",    "source": "rbac"},
        "heidi":  {"authorized": True,  "role": "contributor",    "source": "rbac"},
    }

    return (candidates, gate_decisions, bypass_classifications,
            verification_state, identity_state, authorization_facts)


RISK_TIERS = {
    "unauthorized":          "high",
    "gate-rejected":         "high",
    "unresolved-identity":   "high",
    "missing-verification":  "medium",
    "accepted-after-block":  "critical",
    "accepted-after-review": "medium",
    "missing-decision":      "medium",
}

RELEASE_ACTIONS = {
    "unresolved-identity":   "identity_verification_required",
    "missing-verification":  "verification_required",
    "accepted-after-block":  "manual_block_override_review",
    "accepted-after-review": "manual_review_clearance",
    "missing-decision":      "gate_decision_required",
}


def _evaluate_bypass(bypass_entry, ref_timestamp):
    if bypass_entry is None:
        return False, None, None, None
    bypass_type = bypass_entry.get("bypass_type")
    if not bypass_type:
        return False, None, None, None
    expires_str = bypass_entry.get("expires_at")
    if expires_str:
        expires_dt = _parse_iso(expires_str)
        ref_dt = _parse_iso(ref_timestamp)
        if ref_dt > expires_dt:
            return False, None, None, None
    granted_by = bypass_entry.get("granted_by")
    bypass_reason = bypass_entry.get("reason")
    return True, bypass_type, granted_by, bypass_reason


def _initial_route(candidate, gates, verifications, identities, authorizations):
    identity = candidate["identity"]
    aid = candidate["assignment_id"]

    auth = authorizations.get(identity, {"authorized": False})
    ident = identities.get(identity, {"resolved": False})
    verif = verifications.get(identity, {"verified": False})
    gate = gates.get(aid)

    decision = None
    hold_reason = None
    risk_tier = None
    required_release_action = None

    if not auth.get("authorized"):
        decision = "REJECT"
        hold_reason = "unauthorized"
        risk_tier = RISK_TIERS["unauthorized"]
    elif not ident.get("resolved"):
        decision = "HOLD"
        hold_reason = "unresolved-identity"
        risk_tier = RISK_TIERS["unresolved-identity"]
        required_release_action = RELEASE_ACTIONS["unresolved-identity"]
    elif not verif.get("verified"):
        decision = "HOLD"
        hold_reason = "missing-verification"
        risk_tier = RISK_TIERS["missing-verification"]
        required_release_action = RELEASE_ACTIONS["missing-verification"]
    elif gate is None:
        decision = "HOLD"
        hold_reason = "missing-decision"
        risk_tier = RISK_TIERS["missing-decision"]
        required_release_action = RELEASE_ACTIONS["missing-decision"]
    elif gate["decision"] == "REJECTED":
        decision = "REJECT"
        hold_reason = "gate-rejected"
        risk_tier = RISK_TIERS["gate-rejected"]
    elif gate["decision"] == "BLOCK":
        decision = "HOLD"
        hold_reason = "accepted-after-block"
        risk_tier = RISK_TIERS["accepted-after-block"]
        required_release_action = RELEASE_ACTIONS["accepted-after-block"]
    elif gate["decision"] == "REVIEW" and not gate.get("review_cleared"):
        decision = "HOLD"
        hold_reason = "accepted-after-review"
        risk_tier = RISK_TIERS["accepted-after-review"]
        required_release_action = RELEASE_ACTIONS["accepted-after-review"]
    elif gate["decision"] == "REVIEW" and gate.get("review_cleared"):
        decision = "ALLOW"
        hold_reason = "cleared-review"
    elif gate["decision"] == "ACCEPTED":
        decision = "ALLOW"
        hold_reason = "clean"
    else:
        decision = "HOLD"
        hold_reason = "unknown-gate-state"
        risk_tier = "high"
        required_release_action = "gate_unknown"

    return {
        "decision":                decision,
        "hold_reason":             hold_reason,
        "risk_tier":               risk_tier,
        "required_release_action": required_release_action,
    }


def route(candidate, gates, bypasses, verifications, identities, authorizations, ref_timestamp):
    identity = candidate["identity"]
    aid = candidate["assignment_id"]
    fp = _event_fingerprint(candidate)

    initial = _initial_route(candidate, gates, verifications, identities, authorizations)

    bypass_entry = bypasses.get(identity)
    bypass_active, bypass_type, granted_by, bypass_reason = _evaluate_bypass(
        bypass_entry, ref_timestamp
    )

    decision = initial["decision"]
    hold_reason = initial["hold_reason"]
    risk_tier = initial["risk_tier"]
    required_release_action = initial["required_release_action"]
    overridden = False
    original_decision = None
    original_hold_reason = None
    underlying_risk_tier = None
    applied_bypass_type = None
    applied_bypass_granted_by = None
    applied_bypass_reason = None

    if decision in ("HOLD", "REJECT") and bypass_active and bypass_type == "ADMIN_OVERRIDE":
        overridden = True
        original_decision = decision
        original_hold_reason = hold_reason
        underlying_risk_tier = risk_tier
        applied_bypass_type = bypass_type
        applied_bypass_granted_by = granted_by
        applied_bypass_reason = bypass_reason
        decision = "ALLOW"
        hold_reason = f"bypass-{original_hold_reason}"
        risk_tier = None
        required_release_action = None

    return {
        "event_fingerprint":        fp,
        "event_id":                 candidate["event_id"],
        "identity":                 identity,
        "pft_amount":               candidate["pft_amount"],
        "assignment_id":            aid,
        "reward_type":              candidate["reward_type"],
        "decision":                 decision,
        "hold_reason":              hold_reason,
        "risk_tier":                risk_tier,
        "required_release_action":  required_release_action,
        "bypass_applied":           overridden,
        "bypass_type":              applied_bypass_type,
        "bypass_granted_by":        applied_bypass_granted_by,
        "bypass_reason":            applied_bypass_reason,
        "original_decision":        original_decision,
        "original_hold_reason":     original_hold_reason,
        "underlying_risk_tier":     underlying_risk_tier,
        "policy_version":           POLICY_VERSION,
    }


def build_handoff(results):
    _sort = lambda r: r["event_fingerprint"]

    allows  = sorted([r for r in results if r["decision"] == "ALLOW"],  key=_sort)
    holds   = sorted([r for r in results if r["decision"] == "HOLD"],   key=_sort)
    rejects = sorted([r for r in results if r["decision"] == "REJECT"], key=_sort)

    blocked_pft_total = sum(
        r["pft_amount"] for r in results if r["decision"] in ("HOLD", "REJECT")
    )

    hold_reason_counts = dict(Counter(r["hold_reason"] for r in holds))

    bypass_entries = [r for r in results if r["bypass_applied"]]
    bypass_count = len(bypass_entries)
    bypass_identities = sorted(set(r["identity"] for r in bypass_entries))
    bypass_pft_total = sum(r["pft_amount"] for r in bypass_entries)

    bypass_detail = sorted([
        {
            "event_fingerprint":    r["event_fingerprint"],
            "event_id":             r["event_id"],
            "identity":             r["identity"],
            "pft_amount":           r["pft_amount"],
            "original_decision":    r["original_decision"],
            "original_hold_reason": r["original_hold_reason"],
            "underlying_risk_tier": r["underlying_risk_tier"],
            "bypass_type":          r["bypass_type"],
            "bypass_granted_by":    r["bypass_granted_by"],
            "bypass_reason":        r["bypass_reason"],
        }
        for r in bypass_entries
    ], key=_sort)

    impacted_identities = {
        "ALLOW":  sorted(set(r["identity"] for r in allows)),
        "HOLD":   sorted(set(r["identity"] for r in holds)),
        "REJECT": sorted(set(r["identity"] for r in rejects)),
    }

    release_queue = sorted([
        {
            "event_fingerprint":    r["event_fingerprint"],
            "event_id":             r["event_id"],
            "identity":             r["identity"],
            "pft_amount":           r["pft_amount"],
            "hold_reason":          r["hold_reason"],
            "bypass_applied":       r["bypass_applied"],
            "underlying_risk_tier": r["underlying_risk_tier"],
        }
        for r in allows
    ], key=_sort)

    rejection_queue = sorted([
        {
            "event_fingerprint":   r["event_fingerprint"],
            "event_id":            r["event_id"],
            "identity":            r["identity"],
            "pft_amount":          r["pft_amount"],
            "hold_reason":         r["hold_reason"],
            "risk_tier":           r["risk_tier"],
        }
        for r in rejects
    ], key=_sort)

    hold_queue = sorted([
        {
            "event_fingerprint":        r["event_fingerprint"],
            "event_id":                 r["event_id"],
            "identity":                 r["identity"],
            "pft_amount":               r["pft_amount"],
            "hold_reason":              r["hold_reason"],
            "risk_tier":                r["risk_tier"],
            "required_release_action":  r["required_release_action"],
        }
        for r in holds
    ], key=_sort)

    return {
        "policy_version":      POLICY_VERSION,
        "policy_checksum":     _policy_checksum(),
        "eval_ref_timestamp":  EVAL_REF_TIMESTAMP,
        "total_candidates":    len(results),
        "allow_count":         len(allows),
        "hold_count":          len(holds),
        "reject_count":        len(rejects),
        "blocked_pft_total":   blocked_pft_total,
        "bypass_count":        bypass_count,
        "bypass_pft_total":    bypass_pft_total,
        "bypass_identities":   bypass_identities,
        "bypass_detail":       bypass_detail,
        "hold_reason_counts":  dict(sorted(hold_reason_counts.items())),
        "impacted_identities": impacted_identities,
        "release_queue":       release_queue,
        "hold_queue":          hold_queue,
        "rejection_queue":     rejection_queue,
        "results":             sorted(results, key=_sort),
    }


def console_summary(handoff):
    print("=" * 72)
    print("  REWARD SETTLEMENT PREFLIGHT SUMMARY")
    print("=" * 72)
    print(f"  policy_version      : {handoff['policy_version']}")
    print(f"  policy_checksum     : {handoff['policy_checksum']}")
    print(f"  eval_ref_timestamp  : {handoff['eval_ref_timestamp']}")
    print("-" * 72)
    print(f"  total_candidates    : {handoff['total_candidates']}")
    print(f"  ALLOW               : {handoff['allow_count']}")
    print(f"  HOLD                : {handoff['hold_count']}")
    print(f"  REJECT              : {handoff['reject_count']}")
    print(f"  blocked_pft_total   : {handoff['blocked_pft_total']:.2f}")
    print("-" * 72)
    print(f"  bypass_count        : {handoff['bypass_count']}")
    print(f"  bypass_pft_total    : {handoff['bypass_pft_total']:.2f}")
    print(f"  bypass_identities   : {', '.join(handoff['bypass_identities']) or 'none'}")
    print("-" * 72)
    print("  HOLD REASON BREAKDOWN:")
    for reason, count in sorted(handoff["hold_reason_counts"].items()):
        print(f"    {reason:<30s} : {count}")
    print("-" * 72)
    print("  RELEASE QUEUE:")
    for entry in handoff["release_queue"]:
        bypass_flag = " [BYPASS]" if entry["bypass_applied"] else ""
        underlying = ""
        if entry["underlying_risk_tier"]:
            underlying = f"  underlying={entry['underlying_risk_tier']}"
        print(f"    {entry['event_fingerprint']}  {entry['event_id']}  "
              f"{entry['identity']:<10s}  {entry['pft_amount']:>8.2f}  "
              f"{entry['hold_reason']}{bypass_flag}{underlying}")
    print("  REJECTION QUEUE:")
    for entry in handoff["rejection_queue"]:
        print(f"    {entry['event_fingerprint']}  {entry['event_id']}  "
              f"{entry['identity']:<10s}  {entry['pft_amount']:>8.2f}  "
              f"{entry['hold_reason']}  [{entry['risk_tier']}]")
    print("  HOLD QUEUE:")
    for entry in handoff["hold_queue"]:
        print(f"    {entry['event_fingerprint']}  {entry['event_id']}  "
              f"{entry['identity']:<10s}  {entry['pft_amount']:>8.2f}  "
              f"{entry['hold_reason']:<30s}  [{entry['risk_tier']}]  "
              f"action={entry['required_release_action']}")
    if handoff["bypass_detail"]:
        print("-" * 72)
        print("  BYPASS DETAIL:")
        for entry in handoff["bypass_detail"]:
            print(f"    {entry['event_fingerprint']}  {entry['event_id']}  "
                  f"{entry['identity']:<10s}  {entry['pft_amount']:>8.2f}")
            print(f"      original: {entry['original_decision']} / "
                  f"{entry['original_hold_reason']}  "
                  f"[{entry['underlying_risk_tier']}]")
            print(f"      override: {entry['bypass_type']}  "
                  f"granted_by={entry['bypass_granted_by']}  "
                  f'reason="{entry["bypass_reason"]}"')
    print("=" * 72)


def main():
    (candidates, gates, bypasses,
     verifications, identities, authorizations) = build_fixtures()

    results = []
    for c in candidates:
        result = route(c, gates, bypasses, verifications, identities,
                       authorizations, EVAL_REF_TIMESTAMP)
        results.append(result)

    handoff = build_handoff(results)
    console_summary(handoff)

    print("\nDETERMINISTIC JSON HANDOFF:\n")
    print(json.dumps(handoff, indent=2, sort_keys=False))


if __name__ == "__main__":
    main()
