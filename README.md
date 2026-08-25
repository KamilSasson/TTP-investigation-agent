# TTP-Aware Investigation Agent (Prototype)

A small, focused prototype demonstrating an agentic investigation workflow for a
suspicious sign-in scenario — built to explore the intersection of AI tool-use and
security research, not to simulate a production detection system.

## What this is — and isn't

**Is:** a real tool-calling agent loop. The model receives evidence from each tool
call and decides what to investigate next — it can stop early when evidence looks
legitimate, or escalate through multiple checks when evidence looks suspicious.
That branching decision is made live by the model, not hardcoded.

**Isn't:** a production detection system, connected to real Sentinel data, or a
claim that this "detects nation-state attacks." It runs on two small synthetic
scenarios to demonstrate the architecture and reasoning process end to end.

## Design principle

The model never computes anything itself. Every fact — is this country new for
this user, does this IP fall in the corporate VPN range, how many files were
downloaded — is computed in plain, deterministic, testable Python (`tools.py`).
The model's job is narrower and more honest: **decide which tool to call next,
and turn the assembled evidence into a structured, evidence-cited report.**

This is a direct, deliberate extension of a lesson from an earlier project (a
rule-based phishing email scorer): letting an LLM make the actual determination
is non-deterministic and hard to audit. Here, the LLM plans and narrates; the
code decides the facts.

## Architecture

```
Investigate(user, event)
      |
      v
  Agent (Claude, tool-calling loop)
      |
      +--> get_user_baseline(user)              — deterministic
      +--> check_unusual_signin(user, event)     — deterministic
      +--> get_post_login_activity(user, ts)     — deterministic  [only if warranted]
      +--> check_permission_changes(user, ts)    — deterministic  [only if warranted]
      +--> search_related_entities(ip/device)    — deterministic  [only if warranted]
      +--> map_to_mitre(observations)            — deterministic lookup table
      +--> generate_kql_queries(user, ip)        — deterministic templates
      |
      v
  Structured report: Verdict / Confidence / Supporting evidence /
  Refuting evidence / MITRE mapping / Recommended next steps
  (Human approval required before any containment action — no
  automated response actions are taken.)
```

The two synthetic scenarios exist specifically so the agent isn't just a "flag
everything" system:

- **Malicious scenario** (`dana.levi`, event `sig-1001`): new country, unrecognized
  device, IP outside any known/VPN range, MFA method added 4 minutes after
  sign-in, 340 documents downloaded, privileged role assigned.
- **Legitimate scenario** (`omer.katz`, event `sig-2001`): new country, but
  *known* device, IP falls inside the corporate VPN range, no follow-on identity
  or download activity. This is the "employee traveling for a conference" case —
  included on purpose to show the agent gathers refuting evidence, not just
  confirming evidence.

## Setup (run on your own machine — requires network access)

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...

python agent.py dana.levi@corp.local sig-1001   # malicious scenario
python agent.py omer.katz@corp.local sig-2001   # legitimate scenario
```

## What would change for a real deployment

- Real Sentinel/KQL connection instead of local JSON files
- Tool functions would query live telemetry tables (`SigninLogs`, `AuditLogs`)
  rather than reading synthetic fixtures
- Cost/latency controls (caching baselines, batching, model choice per step)
- A real detection-rule deployment pipeline instead of a printed KQL suggestion
- Logging/audit trail of every tool call and model decision, for after-the-fact
  review — important for exactly the auditability reasons noted above
