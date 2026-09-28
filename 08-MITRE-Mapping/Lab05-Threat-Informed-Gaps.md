# Lab 05 - Threat-Informed Gap Analysis: INC Ransom vs. This SIEM

## Objective
Labs 01-04 measured coverage against the whole ATT&CK matrix. A matrix has
hundreds of cells and most of them will never matter to a given organisation, so
"what should we build next?" cannot be answered from it. This lab answers it from
the attacker's side:

> If a ransomware group that actually targets universities and hospitals broke in,
> which of its steps would this SIEM catch - and which gap should be closed first?

The adversary's cited techniques are overlaid on the evidence map from Lab 03, each
technique is checked at the level of **what the group actually did**, and the gaps
are ranked.

**No custom rule.** Output: a per-technique overlay, an ATT&CK Navigator layer and
a ranked gap list.

## Framing
| Field | Value |
|---|---|
| Discipline | Threat-informed defense - adversary emulation planning, gap prioritisation |
| Adversary | INC Ransom, ATT&CK [G1032](https://attack.mitre.org/groups/G1032/) (alias GOLD IONIC) |
| Adversary data | ATT&CK's own group layer, `G1032-enterprise-layer.json`, ATT&CK **v19** |
| Our data | [`coverage-comparison.csv`](coverage-comparison.csv) (Lab 03/04), ATT&CK **v17** IDs |
| Outputs | [`adversary-overlay-g1032.csv`](adversary-overlay-g1032.csv), [`layer-g1032-overlay.json`](layer-g1032-overlay.json) |
| Lab infrastructure | None - offline analysis on the host (PowerShell 5.1) |

## View the layer
[INC Ransom overlay in ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/Priyanshutomar-8/Enterprise-SOC-Lab/main/08-MITRE-Mapping/layer-g1032-overlay.json)

Amber = technique matched but the procedure is partial, indeterminate or untested;
purple = a shipped tag or written rule, never tested; red = gap; pink = gap with no
data source in the lab; grey = out of scope. **No cell is green.** Hover a cell for
INC's procedure and our detections; score = gap priority.

## Step 1 - Choose the adversary
| Candidate | ATT&CK | Why / why not |
|---|---|---|
| **INC Ransom** (chosen) | G1032 | ATT&CK's group description names **healthcare and education** among its most common targets. 25 cited techniques - small enough to check every procedure by hand. |
| Wizard Spider (Ryuk/Conti) | G0102 | Hit hospitals, but ~90 techniques - the gap list would be too long to act on. |
| Vice Society, Rhysida | - | Well-known education/healthcare attackers, but not ATT&CK groups. Using them means mapping techniques by hand from advisories - weaker sourcing for a first pass. |

## Step 2 - Extract INC's techniques
```powershell
curl.exe -sSfL -o g1032-inc-ransom-layer.json https://attack.mitre.org/groups/G1032/G1032-enterprise-layer.json
(Get-Content g1032-inc-ransom-layer.json -Raw | ConvertFrom-Json).techniques |
  Where-Object { $_.score -eq 1 } | ForEach-Object { $_.techniqueID } |
  Sort-Object -Unique | Set-Content -Encoding ascii g1032-techniques.txt
```

(`curl` in Windows PowerShell is an alias for `Invoke-WebRequest`; `curl.exe`
calls the real curl.)

### Trap 1 - the layer pads the adversary with empty parents
The first extraction, without the `score` filter, returned **34** techniques. Nine
were empty parent entries - no score, no citation - that Navigator needs only to
draw the sub-technique underneath (`T1087` is empty; `T1087.002` is cited). Counting
them inflates the adversary by about a third, and every one of them would appear
as a false gap. Filtering on `score -eq 1` leaves **25** cited techniques. This is
Lab 02's parent double-counting, on the attacker's side.

## Step 3 - Join against the evidence map
Three decisions were fixed **before** looking at the result, so the scoring could
not be tuned to the answer:

| Decision | Rule | Reason |
|---|---|---|
| Parent vs sub-technique | **Exact match only** - a parent tag never earns credit for a sub-technique | A rule tagged `T1021` says "some remote service"; it does not prove RDP is seen. |
| SIEM scope | **Exclude T1588.002** (Obtain Capabilities: Tool) | It happens in the attacker's infrastructure, before the victim network; no SIEM data source can see it. Counting it pads the gap list. |
| No data source | **Keep T1190 and T1566 as gaps**, labelled `gap-no-datasource` | They are real INC entry points (Citrix NetScaler CVE-2023-3519, phishing). Excluding them would make the map look better by hiding the front door. |

```powershell
$ours = @{}
Import-Csv coverage-comparison.csv | ForEach-Object { $ours[$_.technique] = $_ }
$overlay = Get-Content g1032-techniques.txt | ForEach-Object {
  $t = $_; $row = $ours[$t]
  if     ($t -eq 'T1588.002')                        { $s = 'out-of-scope' }
  elseif ($row -and $row.evidence_status -ne 'none') { $s = $row.evidence_status }
  elseif ($row)                                      { $s = 'wazuh-tag-unvalidated' }
  elseif ($t -in 'T1190','T1566')                    { $s = 'gap-no-datasource' }
  else                                               { $s = 'gap' }
  [pscustomobject]@{ technique = $t; inc_status = $s; our_detections = $row.detections; wazuh_rules = $row.wazuh_top_rules }
}
$overlay | Group-Object inc_status | Sort-Object Count -Descending | Format-Table Count, Name
```

The hashtable lookup is exact by construction, which enforces the first decision.

| Raw join (24 in scope) | Count | Techniques |
|---|---|---|
| `fired` | 2 | T1078, T1105 |
| `not-deployed` | 1 | T1021.001 (100412) |
| `wazuh-tag-unvalidated` | 4 | T1047, T1059.003, T1070.004, T1570 |
| `gap-no-datasource` | 2 | T1190, T1566 |
| `gap` | 15 | the rest |

## Step 4 - Check the procedure, not the ID
A shared technique ID means the rule and the attacker are in the same ATT&CK cell.
It does not mean the rule would fire on what the attacker did. Each match was read
against INC's cited procedure in the layer:

| Technique | INC's cited procedure | Our rule | Verdict |
|---|---|---|---|
| T1078 | "Used compromised valid accounts" | 100401 - privileged logon (4672) | **Partial, non-discriminating.** INC scans for domain admin accounts (T1087.002); a domain-admin logon **would** fire 100401 (Lab 04 proved it on `LAB\Administrator`). But it fires identically on every legitimate admin logon and misses a non-privileged stolen account - Module 07 Lab 04's lesson again. |
| T1105 | "Downloaded tools ... including Advanced IP Scanner" | 100405/100406 - PowerShell `DownloadString` | **Indeterminate.** The citation does not say *how* the tool arrived. A PowerShell cradle fires; a browser download or an RDP clipboard paste does not. |

Two weak mappings exist on the attacker side as well: INC's T1071 (Application
Layer Protocol) and T1049 are both cited for **RDP** activity, not C2 or connection
discovery. They stay in the overlay as gaps, flagged. ATT&CK group data is also
limited to what has been publicly reported - a technique absent from the layer is
not proof INC does not use it (ransomware operators commonly delete shadow copies,
T1490, which the layer does not cite).

## Step 5 - Version drift: the join compared v17 to v19
Every Module 08 layer was built on ATT&CK **v17**; INC's layer is **v19**. v19
(April 2026) split Defense Evasion into two new tactics, **Stealth** and **Defense
Impairment**, and revoked a set of techniques into new IDs. Two of ours are affected:

| Our v17 ID | Our detections | v19 replacement |
|---|---|---|
| T1562.001 Disable or Modify Tools | 100408-100410 (Defender), 100507-100508 (Sysmon) | **T1685** Disable or Modify Tools |
| T1070.001 Clear Windows Event Logs | 100407 | **T1685.005** Clear Windows Event Logs |

INC cites **T1685** ("can use SystemSettingsAdminFlows.exe, a native Windows
utility, to disable Windows Defender"). The raw join called it a **gap** - it was
the only INC technique we had real detections for. Normalised to v19:

- **T1685 is a technique match** - 3 of 24, not 2.
- At procedure level it is the most promising cell in the overlay. Module 04 Lab 07's
  **100409 keys on the outcome, not the tool**: Defender event **5013**, "Tamper
  Protection blocked a change". If INC's utility tries to turn real-time protection
  off on a Tamper-Protected host, 5013 should fire regardless of which binary asked.
  If Tamper Protection is off, the change succeeds, Defender logs **5001**, and only
  shipped rule 62152 (level 5, untagged) sees it. **Verdict: plausible, untested.**

**A cross-version join produces false gaps silently** - nothing errors, the ID
simply does not match. The Lab 01-04 layers still carry v17 IDs; re-tagging them
to v19 is carried forward.

## Step 6 - Rank the gaps
Each candidate was scored 0-2 on four criteria:

1. **Before encryption** - T1486 (encryption) and T1657 (extortion) are the end of
   the attack. Detection there reports the damage; they are deliberately not ranked.
2. **Data source already in the lab** - Windows Security, Sysmon, PowerShell logs.
3. **Matches INC's cited procedure** - can the cited behaviour be emulated and
   detected, not just something with the same ID?
4. **Cost** - an existing shipped rule to test or a written rule to deploy is cheaper
   than a new rule.

| Priority | Gap | Before encryption | Data source | Procedure match | Cost | Total |
|---|---|---|---|---|---|---|
| **1** | PsExec deployment cluster - T1570 + T1569.002 + T1036.005 | 2 | 2 | 2 | 1 | 7 |
| **2** | T1537 exfiltration to MEGA | 2 | 2 | 2 | 1 | 7 |
| **3** | T1021.001 RDP lateral movement | 2 | 2 | 1 | 2 | 7 |
| - | T1047 WMIC deployment | 1 | 2 | 0-2 | 2 | 5-7 |
| - | T1087.002 / T1069.002 domain admin discovery | 2 | 0 | 1 | 0 | 3 |

Three candidates tie at 7. **Tie-break: which step INC cannot skip, then how well
the procedure is corroborated.**

**1 - PsExec deployment cluster.** The encryptor has to reach every host; that step
cannot be skipped or swapped out the way a tool can. Three cited behaviours are one
move: copy the encryptor across endpoints in rapid succession (T1570), name the
PsExec binary `winupd` to look like a Windows update (T1036.005), and run it as a
service (T1569.002). The T1569.002 citation *is* a log line - `Service Control
Manager/7045; winupd, %SystemRoot%\winupd.exe, user mode service, demand start,
LocalSystem` - and SCM 7045 is the one tamper event that reliably reached Wazuh in
Module 05 Lab 06 (via shipped rule 61138). Design notes for the future rule: key on
7045 as a child of 61138 with the image path directly under `%SystemRoot%` (not
`System32`), demand start, LocalSystem; do **not** key on the service name
`PSEXESVC`, because the citation shows the rename; key process detections on
`OriginalFileName` (Module 05 Lab 03), not the file name.

**2 - T1537 exfiltration to MEGA.** INC steals data before it encrypts (T1657,
double extortion). For a university or hospital, the stolen data - not the
encryption - is what makes it a reportable breach, and exfiltration comes before
the encryption. Lab 03 found Exfiltration only shape-tested. Data sources exist:
Sysmon EID 1 for the sync client process and EID 22 for DNS queries to MEGA
domains. Ranked below PsExec because it has one citation (Secureworks) and the tool
is swappable - an operator can change the exfil client, but cannot skip deployment.

**3 - T1021.001 RDP lateral movement.** Four sources cite it, it fills the empty
Lateral Movement tactic, and rule 100412 is already written (blocked only because
Windows 11 Home cannot host RDP - DC01 is Server 2022 and can). It ranks third on
procedure match: INC moves with valid accounts, so a rule on `4624 LogonType 10`
fires on the attacker and on every admin RDP session alike. Deploying 100412 as
written would repeat T1078's problem. It needs context - a source that is not an
admin host, a workstation-to-DC session, a first-seen source - before it counts.

**Cheapest test, outside the ranking:** T1685. It needs no new rule - emulate
`SystemSettingsAdminFlows.exe` against Defender on a Tamper-Protected host and see
whether 100409 fires. One test could turn a false gap into the overlay's first
proven procedure.

## Result - INC Ransom vs. this SIEM
| Level | Result (24 techniques in scope) |
|---|---|
| Technique ID, raw v17 join | 2 match |
| Technique ID, normalised to v19 | **3 match** (T1078, T1105, T1685) |
| **Procedure proven detected** | **0** |
| Procedure partial / indeterminate / plausible | 1 / 1 / 1 |
| Shipped tag or written rule, never tested | 5 (T1021.001, T1047, T1059.003, T1070.004, T1570) |
| Gap / gap with no data source | 14 / 2 |

## Key findings
- **Against a real education/healthcare ransomware group, this SIEM proves 0 of 24
  procedures.** Technique-level matching reports 3; the procedure check removes all
  of them from `proven`.
- **A group layer pads the adversary.** 9 of 34 entries were empty parents drawn
  for display. Unfiltered, they are a third of the attacker and all false gaps.
- **Cross-version joins fail silently.** ATT&CK v19 revoked T1562.001 into T1685;
  the one INC technique we had real detections for came back as a gap.
- **Outcome-keyed rules survive procedure changes; tool-keyed rules do not.** 100409
  (5013, "Tamper Protection blocked") should catch INC's Defender tampering without
  ever having seen its binary. 100405 (PowerShell cradle) catches INC's downloads
  only if INC happens to use PowerShell.
- **Attacker-side mapping has errors too.** INC's T1071 and T1049 are both cited for
  RDP activity.
- **The priority is the step the attacker cannot skip,** not the cell with the most
  alerts: mass deployment of the encryptor via PsExec, cited down to the 7045 log line.

## Carried forward
- **Build and live-fire the PsExec deployment rule** (7045 child of 61138, image under
  `%SystemRoot%`, `OriginalFileName`), then T1537 exfiltration, then a context-aware
  100412 - a detection module, not this one.
- **Test T1685 with 100409** - `SystemSettingsAdminFlows.exe` against Defender with
  Tamper Protection on.
- **Re-tag the Lab 01-04 inventory and layers to ATT&CK v19** (T1562.001 -> T1685,
  T1070.001 -> T1685.005; Defense Evasion -> Stealth / Defense Impairment).
- Check `where.exe wmic` on DC01 before any T1047 test.

**No custom rule.** Module 08's question - which techniques this SIEM detects, and
how we know - ends here with a threat-specific answer: for INC Ransom, none are
proven, and the first three to build are ranked.
