"""
Deterministic investigation tools.

Design principle (deliberate, and worth saying out loud in the interview):
The LLM never computes anything itself — it only DECIDES which tool to call
next and interprets/summarizes results. Every fact (is this country new,
how many files were downloaded, does this IP match the corporate VPN range)
is computed here, in plain, auditable, testable Python. This mirrors the
real weakness we identified in the rule-based email scorer project: an LLM
making the actual determination is non-deterministic and hard to audit.
Here, the LLM plans and narrates; the code decides the facts.
"""

import ipaddress
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


def _load(filename):
    with open(DATA_DIR / filename) as f:
        return json.load(f)


def get_user_baseline(user_id: str) -> dict:
    """Return the known-normal profile for a user: countries, devices, IP ranges."""
    data = _load("signins.json")
    baseline = data["user_baselines"].get(user_id)
    if not baseline:
        return {"error": f"No baseline found for {user_id}"}
    return baseline


def check_unusual_signin(user_id: str, event_id: str) -> dict:
    """
    Compare a specific sign-in event against the user's baseline.
    Returns which specific attributes are anomalous, and whether the
    source IP falls inside a known corporate VPN range (a strong
    counter-signal, since new-country + known VPN range is very
    different from new-country + unrecognized IP).
    """
    data = _load("signins.json")
    baseline = data["user_baselines"].get(user_id, {})
    event = next((e for e in data["events"] if e["event_id"] == event_id), None)
    if not event:
        return {"error": f"No sign-in event {event_id} found"}

    is_new_country = event["country"] not in baseline.get("known_countries", [])
    is_new_device = event["device_id"] not in baseline.get("known_devices", [])

    ip = ipaddress.ip_address(event["ip_address"])
    in_vpn_range = any(
        ip in ipaddress.ip_network(r) for r in baseline.get("corporate_vpn_ranges", [])
    )
    in_known_range = any(
        ip in ipaddress.ip_network(r) for r in baseline.get("known_ip_ranges", [])
    )

    return {
        "event_id": event_id,
        "country": event["country"],
        "is_new_country": is_new_country,
        "device_id": event["device_id"],
        "is_new_device": is_new_device,
        "ip_address": event["ip_address"],
        "ip_in_corporate_vpn_range": in_vpn_range,
        "ip_in_known_range": in_known_range,
        "timestamp": event["timestamp"],
    }


def get_post_login_activity(user_id: str, after_timestamp: str) -> dict:
    """Return cloud/document activity for the user after a given timestamp."""
    data = _load("cloud_activity.json")
    matches = [e for e in data["events"] if e["user"] == user_id]
    return {"user": user_id, "activity": matches}


def check_permission_changes(user_id: str, after_timestamp: str) -> dict:
    """Return identity events (MFA registration, role assignment) for the user."""
    data = _load("identity_events.json")
    matches = [e for e in data["events"] if e["user"] == user_id]
    return {"user": user_id, "identity_events": matches}


def search_related_entities(ip_address: str = None, device_id: str = None) -> dict:
    """
    Search whether an IP or device appears in connection with any OTHER
    user — a real investigation step to catch whether the same attacker
    infrastructure has touched multiple accounts.
    """
    data = _load("signins.json")
    matches = [
        e for e in data["events"]
        if (ip_address and e["ip_address"] == ip_address)
        or (device_id and e["device_id"] == device_id)
    ]
    return {"matches": matches, "distinct_users_affected": len({m["user"] for m in matches})}


def map_to_mitre(observations: list) -> dict:
    """
    Map a list of plain-language observation strings to MITRE ATT&CK
    technique IDs. Deliberately a small, explicit lookup rather than an
    LLM guess — keeps the mapping auditable and correctable.
    """
    mapping_rules = {
        "new_country_signin": ("T1078", "Valid Accounts"),
        "new_device_signin": ("T1078", "Valid Accounts"),
        "mfa_method_added": ("T1098", "Account Manipulation"),
        "privileged_role_assigned": ("T1098", "Account Manipulation"),
        "bulk_document_download": ("T1530", "Data from Cloud Storage Object"),
    }
    techniques = []
    for obs in observations:
        if obs in mapping_rules:
            tid, name = mapping_rules[obs]
            techniques.append({"technique_id": tid, "technique_name": name, "trigger": obs})
    return {"techniques": techniques}


def generate_kql_queries(user_id: str, ip_address: str = None) -> dict:
    """
    Return follow-up KQL query templates for continued investigation.
    Table/column names follow Microsoft Sentinel-style schema conventions
    (SigninLogs, AuditLogs) — noted in the README as illustrative, not
    tested against a real tenant.
    """
    queries = [
        {
            "purpose": "Confirm scope: has this IP touched any other accounts in the org?",
            "kql": (
                "SigninLogs\n"
                "| where TimeGenerated > ago(7d)\n"
                f"| where IPAddress == \"{ip_address}\"\n"
                "| summarize AffectedUsers = make_set(UserPrincipalName), "
                "SignInCount = count() by IPAddress"
            ),
        },
        {
            "purpose": "Full sign-in timeline for the investigated user",
            "kql": (
                "SigninLogs\n"
                "| where TimeGenerated > ago(30d)\n"
                f"| where UserPrincipalName == \"{user_id}\"\n"
                "| project TimeGenerated, Location, IPAddress, DeviceDetail, ResultType\n"
                "| order by TimeGenerated desc"
            ),
        },
        {
            "purpose": "Detection rule draft: new-country sign-in immediately followed by MFA registration",
            "kql": (
                "let RiskySignins = SigninLogs\n"
                "| where TimeGenerated > ago(1d)\n"
                "| where Location !in (KnownLocationsTable);\n"
                "AuditLogs\n"
                "| where OperationName == \"Register security info\"\n"
                "| join kind=inner RiskySignins on UserPrincipalName\n"
                "| where TimeGenerated - SigninTime < 10m"
            ),
        },
    ]
    return {"queries": queries}


TOOL_REGISTRY = {
    "get_user_baseline": get_user_baseline,
    "check_unusual_signin": check_unusual_signin,
    "get_post_login_activity": get_post_login_activity,
    "check_permission_changes": check_permission_changes,
    "search_related_entities": search_related_entities,
    "map_to_mitre": map_to_mitre,
    "generate_kql_queries": generate_kql_queries,
}
