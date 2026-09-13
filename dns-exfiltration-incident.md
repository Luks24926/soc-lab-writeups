# Investigating a DNS Exfiltration Incident — TryHackMe SOC Simulator

## Objective

Triage a series of Sysmon alerts flagged as "suspicious parent-child relationships" in TryHackMe's SOC Simulator, determine whether they represented a genuine threat, and trace the full scope of the incident across multiple related alerts.

## Environment & Tools

- SIEM: Splunk (embedded in TryHackMe SOC Sim)
- Log source: Sysmon (Process Create events)
- Reference lookups: VirusTotal (for hash checks where available)
- Host under investigation: `win-3450`

## Process

The investigation started with a single alert: a `net.exe use Z:` command mapping a drive to `\\FILESRV-01\SSF-FinancialRecords`, spawned by `powershell.exe`. On its own, drive mapping isn't inherently malicious — Windows environments do this routinely via logon scripts and GPOs. So the first step was establishing a baseline: *is this how drive mapping normally happens here?*

Two details broke that baseline:
1. The parent process was an **interactive PowerShell session**, not `SYSTEM` or a service account (which is how legitimate provisioning scripts/GPOs typically run).
2. The working directory was the user's **Downloads folder** — not a location associated with sanctioned IT scripts.

Combined with the target share being sensitive financial data, this was enough to classify the alert as a likely True Positive rather than routine access, and to flag it for escalation pending confirmation of the user's actual role/access rights.

Minutes later, a second alert appeared on the same host: `nslookup.exe`, again spawned by the *same* `powershell.exe` process (same PID), querying a DNS record containing what looked like a Base64-encoded string, prepended to an external domain (`haz4rdw4re.io`). This is a recognizable pattern — **DNS tunneling**, where data is broken into chunks and smuggled out via DNS queries, which often evade traditional outbound traffic monitoring since DNS is rarely blocked outright.

Rather than treat this as an isolated new alert, the shared parent PID was the key pivot point: it linked this DNS activity directly back to the drive-mapping event. From there, three more `nslookup.exe` alerts appeared over the following minutes, each with a different Base64 fragment sent to the same domain, from the same parent process, with working directories under `...\downloads\` or `...\downloads\exfiltration\` — the latter making intent unambiguous.

## Findings

What initially looked like five separate, unrelated alerts was actually **one continuous incident**:

1. Attacker (or compromised user session) mapped a drive to a financial records share via an anomalous PowerShell → net.exe chain.
2. The same PowerShell session then used `nslookup.exe` to exfiltrate data in multiple Base64-encoded chunks via DNS queries to an external domain.
3. All five events were tied together by a single parent process ID, forming a clear, chronological attack timeline rather than five independent anomalies.

## Screenshots / Evidence


## Lessons Learned

- **Don't triage alerts in isolation.** The individual DNS lookups looked unusual but not obviously malicious on their own; it was the shared parent process ID connecting them to the earlier, more clearly suspicious drive-mapping event that revealed the full picture.
- **Context beats a single indicator.** An uncommon TLD, a PowerShell parent, or a Downloads working directory are each weak signals alone — but layered together (and repeated across multiple correlated events), they built a strong case.
- **Not every hash is available.** This environment's Sysmon config didn't log file hashes, which meant VirusTotal wasn't usable here — a reminder that investigation technique has to adapt to what the logging actually provides, not just the "ideal" workflow.
- **Escalation timing matters.** Flagging the first alert for escalation before the full DNS exfiltration chain appeared meant the incident could have been contained earlier in a real environment — a good habit to reinforce: escalate on strong partial evidence rather than waiting for full certainty.

---

## For comparison: the incident-report version (work product, not portfolio writing)

This is the format actually used to close out the alert in the SOC queue — concise, structured, no narrative:

**Time of activity:** 09/13/2026 16:12:11.786 – 16:14:12.786 (multi-event incident)

**List of Affected Entities:**
- Host: `win-3450`
- User: `michael.ascot`
- Parent Process: `powershell.exe` (PID 3728)
- Child Processes: `net.exe` (PID 5784), `nslookup.exe` (PIDs 5520, 3648, 3700, 4752)
- Target Share: `\\FILESRV-01\SSF-FinancialRecords`
- Exfiltration Domain: `haz4rdw4re.io`

**Reason for Classifying as True Positive:** Anomalous PowerShell-initiated drive mapping to a sensitive financial share, followed by multiple DNS queries containing Base64-encoded data segments sent to the same external domain — all originating from a single parent process session launched from the user's Downloads folder. Working directory `...\downloads\exfiltration\` on later events removes any ambiguity about intent.

**Reason for Escalating the Alert:** Confirmed multi-stage data exfiltration in progress, tied to unauthorized access of sensitive financial records — requires immediate containment and IR involvement.

**Recommended Remediation Actions:**
- Isolate `win-3450` from the network.
- Block `haz4rdw4re.io` at DNS/firewall level.
- Terminate the `powershell.exe` (PID 3728) process tree.
- Reset credentials for `michael.ascot` pending investigation.
- Collect and reconstruct all DNS query chunks for payload analysis.

**List of Attack Indicators:**
- PowerShell-spawned `net.exe` and `nslookup.exe` (abnormal parent-child pairing)
- Base64-encoded data in DNS queries (DNS tunneling)
- Working directory under user Downloads / `exfiltration` subfolder
- External C2/exfil domain: `haz4rdw4re.io`
- Single parent PID linking five otherwise-separate-looking alerts into one incident
