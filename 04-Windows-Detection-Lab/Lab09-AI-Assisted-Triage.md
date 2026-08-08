# Lab 09 - Capstone: AI-Assisted Alert Triage

## Objective
Wazuh tells you *that* a rule fired. A tier-1 analyst still has to read the
alert, decide what the attacker is likely doing, and pick the single most
important next action. This capstone builds the plumbing for an **automated
triage layer** that sits on top of Wazuh alerts and writes a short,
analyst-style case note for each one - turning a raw rule hit into a decision.

The capstone has two halves. This lab documents the **AI-enrichment pipeline**;
the **Active Response** containment half (auto-disable account / block source)
is tracked separately.

The enrichment pipeline is built and verified end-to-end against a **local,
deterministic mock triage**. The live-LLM backend is implemented and gated
behind an API key that is deliberately left unset - a cost and data-egress
decision explained in section 6, not an unfinished step.

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 (agent, Wazuh v4.14.6, ID 002 `windows`) |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Trigger detection | Rule **100411** (T1490), built in [Lab 08](Lab08-Shadow-Copy-Deletion.md) |
| Integration host | `wazuh-integratord` on the manager |
| Triage script | `/var/ossec/integrations/custom-claude-triage` (Python 3, stdlib only) |
| Output | Markdown case notes in `/var/ossec/logs/ai-triage/` |

## Architecture
```
Windows agent 002                     Wazuh manager
  vssadmin delete shadows  --4688-->  analysisd
                                          |
                            rule 100411 (group=local)
                                          |
                                   wazuh-integratord
                                          |  argv[1] = alert JSON
                              custom-claude-triage (Python)
                                          |
                              extract host/user/MITRE/cmdline
                                          |
                        +-----------------+------------------+
                        |                                    |
               (no key) MOCK triage               (key set) Claude Messages API
               local MITRE map                    + cyber-refusal fallback
                        |                                    |
                        +-----------------+------------------+
                                          |
                            case note .md  ->  /var/ossec/logs/ai-triage/
```

A command on the endpoint generates Event 4688, `analysisd` matches it to
detection rule 100411, the integrator daemon invokes the triage script with the
alert JSON, the script extracts the fields it needs, and writes a case note. The
triage text comes from one of two backends chosen at runtime.

## The integration
Wazuh's `<integration>` framework runs an external program whenever an alert
matches a filter. Registered in `/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>custom-claude-triage</name>
  <group>local</group>
  <alert_format>json</alert_format>
</integration>
```

The integrator passes the script `argv[1]` = the path to a JSON file containing
the single alert. The script reads and parses it, extracts host, account, rule
id/level, MITRE technique(s), description, and command line, builds the triage
input, and writes a Markdown case note.

### Why rule 100411 reaches the integration
The filter is `<group>local</group>`: only alerts whose rule carries the `local`
group are handed to the script. Rule 100411 was defined in Lab 08 under
`<group name="local,windows,ransomware_prep,">`, so it already qualifies - no
change to the rule was needed. **This is the whole routing contract, and its
failure mode is silent:** if a triggering rule is not in the `local` group, the
integrator never sees the alert and `integrations.log` says nothing at all.

### Deployment notes (the parts that bite)
- **Silent log = filter problem; logged error = exec problem.** That single
  distinction is the fastest way to diagnose a dead integration.
- **A no-extension script is exec'd directly.** Naming the file
  `custom-claude-triage` (no `.py`) means the integrator runs it as
  `./custom-claude-triage`, so it needs a valid shebang (`#!/usr/bin/env
  python3`) and `750 root:wazuh` permissions.
- **The integration runs as the `wazuh` user**, so the script and any key file
  must be readable by it.

## Triage backends
The script picks a backend at runtime based on whether an API key is present.

### Mock (default) - deterministic, no key, no cost, no egress
A local MITRE ATT&CK map (`technique -> name / what it means / recommended
action`) drives a canned but well-structured note. This proves the entire
pipeline with zero external dependencies. Output for the T1490 trigger:

```markdown
# AI Triage - Rule 100411 (level 13)

- Host: windows
- Account: vboxuser
- MITRE: T1490
- Detection: Ransomware recovery inhibition ... vssadmin.exe delete shadows /all /quiet
- Generated by: mock (local map)

---
Summary:  Inhibit System Recovery on `windows` (rule 100411, level 13).
Likely activity:  Backups/shadow copies were destroyed - ransomware pre-encryption.
Next action:  ISOLATE THE HOST NOW; the window before data loss is minutes; correlate backwards.
Observed command: "C:\WINDOWS\system32\vssadmin.exe" delete shadows /all /quiet
```

Field extraction is verified: host, account, MITRE technique, rule/level, and
the full command line are all pulled correctly from the alert JSON, and the note
gives an analyst *decision* ("ISOLATE THE HOST NOW"), not just a restatement of
the alert. The recommended action is consistent with Lab 08's investigation
guidance for 100411 (contain first, correlate backwards - this is late in the
kill chain).

### Live LLM (gated) - implemented, deliberately not run
The real backend sends the extracted fields to the Anthropic Claude Messages
API and asks for a triage under 150 words: one-line summary, likely attacker
activity, and the single most important next action. Two design points:

- **Cyber-refusal fallback.** SOC triage prompts are full of attack indicators
  (`vssadmin delete shadows`, Defender tampering, log clearing) - exactly the
  content that can trip an LLM's cybersecurity safety classifier as a *false
  positive* on legitimate defensive work. The client sends `fallbacks:
  "default"`, so a declined request is automatically retried on a fallback model
  in the same call. A triage pipeline that goes blind on its highest-severity
  alerts is worse than no pipeline; the fallback is the guardrail against that.
- **Cost and latency instrumentation.** Each call records the served model,
  latency, token counts, and an estimated cost into the case-note footer and
  `integrations.log` - the data needed to decide whether the LLM layer earns its
  place over the free static map.

The key is read from the environment or a `chmod 600` key file that is
**git-ignored and never committed** - the script contains no secret.

## 6. Why the LLM leg is intentionally off
A deliberate engineering decision, not an unfinished step:

- **Cost.** The API is pay-per-call; on a real alert stream that is a recurring
  charge for a homelab.
- **Data egress.** Live mode ships hostnames and command lines off-box to a
  third-party API. Acceptable for synthetic lab data; a decision that needs
  redaction and a data-classification review before any real environment.

Mock mode proves every hop of the pipeline - routing, exec convention, group
filter, field extraction, note write - with none of that exposure. The live path
is one config value away, fully instrumented, and gated behind exactly the
controls a real deployment would need.

## Verification
`vssadmin delete shadows /all /quiet` on the Windows agent, read from the
manager side.

| Check | Expected | Result |
|---|---|---|
| Rule 100411 fires (group `local`) | alert routed to integrator | **passed** |
| `integrations.log` | `wrote .../<ts>-rule100411.md (mode=mock, rule=100411)` | **passed** |
| Case note on disk | correct field extraction + actionable triage | **passed** |
| Field extraction | host / account / MITRE / rule-level / command line | **all correct** |

The trigger was driven from the agent and every hop confirmed from the manager
(note file + integrator log), exercising the detection and the enrichment
independently.

## Operational lessons
- **Line-number `sed` is not idempotent.** A config edit re-run by hand deleted
  the `</ossec_config>` closing tag and left the manager unable to parse its
  config (`systemctl restart` failed). Fixes: edit by *content match*
  (`sed '/pattern/d'`) or back up first, and **validate before restarting** with
  `wazuh-analysisd -t` (there is no `wazuh-logtest -t`).
- **File transfers run from the host that holds the file, not from inside the
  SSH session.** `scp` with host-shell variables (`$env:USERPROFILE`) only
  expands on the host; run inside the guest it is a literal string and the copy
  silently fails.
- **Verify the deployed artifact - do not assume the copy worked.** A stale file
  in `/tmp` will be re-deployed with no error. `grep` for a marker unique to the
  new version before restarting.
- **Secrets belong in a file the integrator reads, not on the command line or in
  an editor buffer.** Getting the key into place cleanly (single line, correct
  perms, no stray content) was the single most error-prone step; a length check
  (`wc -c` ~ 108 for a real key) plus a prefix check (`head -c 7` = `sk-ant-`)
  catches the common mistakes without echoing the secret.

## Notes and limitations
- **The "mock" triage is a deterministic rule -> text lookup, not an LLM.** It
  validates the pipeline; it is not AI. The live model is where the enrichment
  value would come from, and it was not run (section 6). This lab documents a
  working pipeline and a deliberate cost/egress decision, not a live model
  evaluation.
- **JSON string escaping in the command line renders raw** in the mock note
  (backslashes and quotes not unescaped). Cosmetic; fixed by unescaping the
  extracted `commandLine` before writing - deferred until the live path is
  exercised so the fix can be validated against real API input.
- **Data egress is unresolved for production.** Sending alert content to a
  third-party API needs redaction and a data-classification policy first.

## Status
The AI-enrichment pipeline is **built and verified in mock mode**: a Wazuh
custom integration routes `local`-group alerts (rule 100411, T1490) to a triage
script that extracts the alert fields and writes an analyst-style case note.
Verified end-to-end from a live Windows 11 trigger through to the note on the
manager.

The live-LLM backend is implemented - Claude Messages API call, server-side
cyber-refusal fallback, and per-call cost/latency instrumentation - and left
gated behind an unset API key by design (cost + data egress). Future work:
enable the key to quantify the LLM's lift over the static map (does it match on
a mapped technique, reason on an unmapped one, and de-escalate a benign alert?),
and build the Active Response containment half of the capstone.
```
