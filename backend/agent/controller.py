"""Evidence-led incident investigation adapted from SOCrates for a synthetic campus sandbox."""
from datetime import datetime
from tools.asset_lookup import get_asset
from tools.cve_lookup import check_vulnerability
from tools.log_lookup import get_logs
from tools.packet_metadata import get_packet_metadata
from tools.ip_reputation import get_ip_reputation
from tools.configuration_lookup import get_configuration
from tools.response_log import get_response_evidence
from tools.llm_reasoner import classify_with_llm
from tools.firewall import block, unblock, is_blocked
from tools.override_lookup import get_override
from agent.state import Investigation
from agent.verification import check_consistency, all_passed

_attacker_ledger = {}
SUSPICIOUS = {"confirmed_breach", "attempted_and_contained", "suspicious_repeat_actor"}

def reset_session_memory():
    _attacker_ledger.clear()

def _finalize(case):
    checks=check_consistency(case)
    case.add_evidence("self_consistency_check", {"passed":all_passed(checks),"checks":[{"passed":p,"note":n} for p,n in checks]})
    case.add_step("SELF-CHECK", f"Ran {len(checks)} consistency checks: {'all passed' if all_passed(checks) else 'some failed; human review recommended'}.")
    return case

def _classify_logs(logs):
    damage=("outbound connection established","data exfiltrated","data sent","large transfer completed","backdoor persistence established")
    intrusion=("process spawned","shell spawned","unauthorized shell","malicious process started")
    mitigation=("terminated","killed","quarantined","blocked","prevented","reset")
    saw_intrusion=False; mitigated=False
    for entry in logs:
        s=(entry.get("event","")+" "+entry.get("detail","")).lower()
        if any(x in s for x in damage): return "succeeded"
        if any(x in s for x in intrusion): saw_intrusion=True
        if saw_intrusion and any(x in s for x in mitigation): mitigated=True
    if saw_intrusion and mitigated: return "contained"
    if saw_intrusion: return "succeeded"
    return "no_evidence"

def _classify_packets(metadata):
    return "succeeded" if any(x.get("bytes_transferred",0)>1_000_000 for x in metadata) else "no_evidence"

def _block(case, source, note):
    result=block(source); case.record_action(result); case.add_step("ACTION",note)
    case.add_evidence("firewall_check",is_blocked(source)); case.add_step("VERIFICATION",f"Simulated block verified: {case.evidence['firewall_check']}.")

def investigate(alert):
    case=Investigation(alert); host=alert.get("dest_host") or alert.get("destination_id"); src=alert.get("source_ip") or alert.get("source_id")
    alert_id=alert.get("alert_id") or ("CAMPUS-"+str(alert.get("event_id","synthetic")))
    alert={**alert,"alert_id":alert_id,"dest_host":host,"source_ip":src,"severity":alert.get("severity","High"),"signature":alert.get("signature",alert.get("event_type","Suspicious network event"))}
    case.alert=alert; severity=str(alert.get("severity","")).lower()
    case.add_step("GOAL",f"Investigate {alert_id}: {alert['signature']} on {host}; claimed severity={severity}.")
    asset=get_asset(host); case.add_evidence("asset",asset)
    if asset is None:
        case.add_step("EVIDENCE",f"No inventory record for {host}; cannot confidently assess this host.")
        case.set_verdict("inconclusive","low",f"Unknown asset {host}; escalate for asset inventory validation.")
        case.add_step("FINAL OUTCOME","Inconclusive; no containment action taken based on unknown inventory.")
        return _finalize(case)
    case.add_step("EVIDENCE",f"Inventory: {host} runs {asset['software']} {asset['version']} (status={asset.get('status','unknown')}).")
    if asset.get("status")=="decommissioned":
        logs=get_logs(host); case.add_evidence("logs",logs)
        _block(case,src,"Applied precautionary simulated block because a retired host appears active.")
        case.set_verdict("data_integrity_anomaly","high","Reported activity conflicts with decommissioned asset inventory; likely stale telemetry, spoofing, or unauthorized reuse. Human review required.")
        case.add_step("FINAL OUTCOME","Data-integrity anomaly; precautionary simulated block and escalation.")
        return _finalize(case)
    rep=get_ip_reputation(src); case.add_evidence("ip_reputation",rep)
    if rep and rep.get("trusted"):
        case.add_step("DECISION",f"Source matches authorized entity {rep.get('label','trusted source')}.")
        case.set_verdict("authorized_activity","high",f"Source {src} is allowlisted: {rep.get('reason','trusted source')}.")
        case.add_step("FINAL OUTCOME","Authorized activity; no containment action.")
        return _finalize(case)
    vuln=check_vulnerability(asset["software"],asset["version"]); case.add_evidence("vulnerability",vuln)
    case.add_step("EVIDENCE",f"Vulnerability record: {vuln['cve_id'] if vuln else 'no matching CVE in local demo knowledge base'}.")
    if not vuln and severity not in {"critical","high"}:
        case.set_verdict("false_positive","medium","No local vulnerability match and alert severity does not warrant deeper sandbox investigation; this is a heuristic, not proof the host is safe.")
        case.add_step("FINAL OUTCOME","Low-stakes alert not escalated for deeper analysis.")
        return _finalize(case)
    logs=get_logs(host); case.add_evidence("logs",logs); case.add_step("EVIDENCE",f"Retrieved {len(logs)} synthetic server-log entries.")
    config=get_configuration(host); case.add_evidence("configuration",config)
    if config: case.add_step("EVIDENCE",f"Configuration: public-facing={config.get('public_facing')}, WAF enabled={config.get('waf_enabled')}.")
    response=get_response_evidence(host); case.add_evidence("response_evidence",response)
    if response: case.add_step("EVIDENCE",f"Found {len(response)} synthetic prior response record(s).")
    ai=classify_with_llm(host,asset,vuln,logs)
    if ai:
        outcome=ai["outcome"]; explanation=ai["explanation"]; case.add_evidence("ai_reasoning",explanation); case.add_step("REASONING (AI)",explanation)
    else:
        outcome=_classify_logs(logs); explanation="Deterministic chronological log analysis; optional AI unavailable or not configured."; case.add_step("REASONING (rule-based)",f"Initial outcome: {outcome}.")
    if outcome=="no_evidence":
        metadata=get_packet_metadata(host); case.add_evidence("packet_metadata",metadata); case.add_step("DECISION","Logs inconclusive; requested a separate packet-metadata evidence source.")
        ai2=classify_with_llm(host,asset,vuln,logs,metadata)
        if ai2: outcome=ai2["outcome"]; explanation=ai2["explanation"]
        else: outcome=_classify_packets(metadata)
        case.add_step("REASONING",f"After packet metadata, outcome={outcome}.")
    context=f"{host} runs {asset['software']} {asset['version']}; vulnerability match={vuln['cve_id'] if vuln else 'none'}."
    if outcome=="succeeded":
        case.set_verdict("confirmed_breach","high",context+" Evidence suggests malicious activity succeeded. "+explanation)
        _block(case,src,"Applied simulated containment to the source after evidence of a successful attack.")
        case.add_step("FINAL OUTCOME","Confirmed-breach assessment; simulated block recorded and verified.")
    elif outcome=="contained":
        case.set_verdict("attempted_and_contained","high",context+" Malicious activity appears to have been stopped before confirmed impact. "+explanation)
        case.add_evidence("firewall_check",is_blocked(src)); case.add_step("FINAL OUTCOME","Attempt detected and contained by simulated endpoint response; no additional block.")
    else:
        if vuln and any(v in SUSPICIOUS for v in _attacker_ledger.get(src,[])):
            case.set_verdict("suspicious_repeat_actor","medium",context+f" This source {src} was associated with a prior suspicious incident in this session despite inconclusive local evidence.")
            _block(case,src,"Precautionary simulated block due to repeat suspicious activity in the current session.")
        else:
            verdict="attempted_but_failed" if vuln else "false_positive"
            case.set_verdict(verdict,"medium" if vuln else "high",context+" No evidence of successful compromise in the available synthetic logs/packet metadata. "+explanation)
            case.add_evidence("firewall_check",is_blocked(src)); case.add_step("FINAL OUTCOME",f"Assessment: {verdict}; no new simulated block.")
    _attacker_ledger.setdefault(src,[]).append(case.verdict)
    return _finalize(case)

def reconsider(case, override=None):
    override=override if override is not None else get_override(case.alert["alert_id"])
    if not override: return case
    case.add_step("NEW EVIDENCE",f"New analyst note received: {override.get('note','(no note)')}")
    if case.verdict!="confirmed_breach":
        case.add_step("DECISION","Automatic reversal not applied because the current verdict is not a confirmed breach; human review remains available.")
        return case
    src=case.alert["source_ip"]; start=override.get("claimed_window_start"); end=override.get("claimed_window_end"); at=case.alert.get("timestamp","")
    if start and end and not (start <= at <= end):
        case.add_evidence("override_consistency_check",{"consistent":False,"alert_time":at,"window":[start,end]})
        case.apply_new_evidence(override,"override_disputed","high","Override time window conflicts with alert timestamp; block remains active pending human review.")
        case.add_step("FINAL OUTCOME","Override disputed; simulated block intentionally retained.")
    else:
        case.add_evidence("override_consistency_check",{"consistent":True,"alert_time":at,"window":[start,end]})
        result=unblock(src); case.record_action(result); still=is_blocked(src); case.add_evidence("firewall_check_after_override",still)
        case.apply_new_evidence(override,"authorized_activity","high","New analyst evidence was temporally consistent; previous simulated block was reversed and verified.")
        case.add_step("VERIFICATION",f"Reversal verification passed: {not still}."); case.add_step("FINAL OUTCOME","Verdict revised to authorized activity after consistent override.")
    return _finalize(case)
