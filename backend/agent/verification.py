SHOULD_BLOCK = {"confirmed_breach", "suspicious_repeat_actor", "data_integrity_anomaly", "override_disputed"}
SHOULD_NOT_BLOCK = {"false_positive", "attempted_and_contained", "attempted_but_failed", "authorized_activity"}

def check_consistency(case):
    checks=[]; final_blocked=case.evidence.get("firewall_check_after_override",case.evidence.get("firewall_check",False))
    if case.verdict in SHOULD_BLOCK: checks.append((final_blocked is True, f"{case.verdict} should have a currently active simulated block"))
    if case.verdict in SHOULD_NOT_BLOCK: checks.append((final_blocked is False, f"{case.verdict} should not have a currently active simulated block"))
    if any(a.get("action")=="block" for a in case.actions_taken): checks.append(("firewall_check" in case.evidence,"Block action was verified"))
    if any(a.get("action")=="unblock" for a in case.actions_taken): checks.append(("firewall_check_after_override" in case.evidence,"Unblock action was verified"))
    if hasattr(case,"previous_verdict"): checks.append((case.previous_verdict is not None,"Previous verdict retained"))
    checks.append((bool(case.reasoning and case.reasoning.strip()),"Verdict has a reasoning explanation"))
    return checks

def all_passed(checks): return all(p for p,_ in checks)
