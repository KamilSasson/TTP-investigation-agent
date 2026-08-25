"""
TTP-Aware Investigation Agent — orchestration loop.

Run locally: `python agent.py <event_id>`
Requires: pip install anthropic
           export ANTHROPIC_API_KEY=sk-...

This is a genuine tool-use agent loop, not a single prompt:
the model receives tool results and DECIDES what to investigate next.
It can stop early (e.g. legitimate scenario: known device + corporate VPN
range -> no need to check permission changes or downloads) or escalate
through every tool (malicious scenario: each result raises suspicion,
prompting the next check).

All arithmetic/lookups happen in tools.py, never inside the model.
"""

import json
import sys

import anthropic

from tools import TOOL_REGISTRY

MODEL = "claude-sonnet-5"

TOOLS = [
    {
        "name": "get_user_baseline",
        "description": "Get the known-normal profile for a user: historical countries, devices, and IP ranges they sign in from.",
        "input_schema": {
            "type": "object",
            "properties": {"user_id": {"type": "string"}},
            "required": ["user_id"],
        },
    },
    {
        "name": "check_unusual_signin",
        "description": "Compare a specific sign-in event against the user's baseline. Returns which attributes are anomalous and whether the IP falls in a known corporate VPN range.",
        "input_schema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
                "event_id": {"type": "string"},
            },
            "required": ["user_id", "event_id"],
        },
    },
    {
        "name": "get_post_login_activity",
        "description": "Get cloud/document activity for the user after a given timestamp (e.g. bulk downloads).",
        "input_schema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
                "after_timestamp": {"type": "string"},
            },
            "required": ["user_id", "after_timestamp"],
        },
    },
    {
        "name": "check_permission_changes",
        "description": "Get identity events for the user after a given timestamp: MFA registration, role/permission changes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
                "after_timestamp": {"type": "string"},
            },
            "required": ["user_id", "after_timestamp"],
        },
    },
    {
        "name": "search_related_entities",
        "description": "Search whether a given IP or device has touched any OTHER user account, to check blast radius.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {"type": "string"},
                "device_id": {"type": "string"},
            },
        },
    },
    {
        "name": "map_to_mitre",
        "description": "Map a list of plain-language observation keys (e.g. 'new_country_signin', 'mfa_method_added', 'bulk_document_download', 'privileged_role_assigned') to MITRE ATT&CK technique IDs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "observations": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["observations"],
        },
    },
    {
        "name": "generate_kql_queries",
        "description": "Generate follow-up KQL query templates for continued investigation in Sentinel-style telemetry.",
        "input_schema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
                "ip_address": {"type": "string"},
            },
            "required": ["user_id"],
        },
    },
]

SYSTEM_PROMPT = """You are a security research assistant investigating a potentially \
suspicious sign-in event, in the style of a nation-state threat-hunting workflow.

You have access to investigation tools. Use them to gather evidence BEFORE concluding \
anything. You do not have to call every tool — decide what's actually needed based on \
what you learn. If early evidence (e.g. a known device on a corporate VPN range) \
strongly suggests legitimate activity, you may stop investigating early and say so \
explicitly, rather than mechanically running every check.

If evidence is genuinely ambiguous or suspicious, continue investigating: check \
post-login activity, permission changes, and related entities before concluding.

When you have enough evidence, produce a final structured report with EXACTLY these \
sections:

Verdict: <Likely Account Compromise | Likely Legitimate Activity | Inconclusive>
Confidence: <High | Medium | Low>

Supporting evidence:
- <bullet list of evidence pointing toward compromise>

Refuting evidence:
- <bullet list of evidence pointing toward legitimate activity — an empty list is \
fine if there genuinely isn't any, but check honestly>

MITRE ATT&CK mapping:
- <technique IDs and names, from map_to_mitre tool results>

Recommended next steps:
- <concrete, specific actions>

Note: This system does NOT take automated containment action. Any recommended \
response action requires human approval before execution.

Be precise and evidence-based. Do not state something as fact unless a tool result \
supports it. If you are uncertain, say so and reflect that in the Confidence level."""


def run_investigation(user_id: str, event_id: str):
    client = anthropic.Anthropic()
    messages = [
        {
            "role": "user",
            "content": (
                f"Investigate sign-in event {event_id} for user {user_id}. "
                "Determine whether this represents likely account compromise."
            ),
        }
    ]

    print(f"\n{'='*70}\nInvestigating {event_id} for {user_id}\n{'='*70}\n")

    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        messages.append({"role": "assistant", "content": response.content})

        # Print any reasoning/narration text the model produced this turn
        for block in response.content:
            if block.type == "text" and block.text.strip():
                print(f"[agent] {block.text.strip()}\n")

        if response.stop_reason != "tool_use":
            break  # model produced its final report, no more tool calls

        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                print(f"[tool call] {block.name}({json.dumps(block.input)})")
                fn = TOOL_REGISTRY[block.name]
                result = fn(**block.input)
                print(f"[tool result] {json.dumps(result, indent=2)}\n")
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result),
                    }
                )

        messages.append({"role": "user", "content": tool_results})


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python agent.py <user_id> <event_id>")
        print("Try:   python agent.py dana.levi@corp.local sig-1001   (malicious scenario)")
        print("       python agent.py omer.katz@corp.local sig-2001   (legitimate scenario)")
        sys.exit(1)

    run_investigation(sys.argv[1], sys.argv[2])
