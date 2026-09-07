# Incident Response with Splunk

## Overview

In this project, I simulated a real-world cyber attack scenario: an external attacker performing network reconnaissance, launching a brute-force attack against a Windows SMB service, and eventually gaining unauthorized access.

Using **Splunk Enterprise**, I monitored the entire attack lifecycle, created custom detection rules to catch the brute-force attempt, tuned alerts to reduce noise, and correlated event logs to detect the eventual breach.

This hands-on exercise demonstrates practical skills in **SIEM engineering, Windows event log analysis, threat detection tuning, and incident response**.

---

## Lab Architecture

| Host Role | OS / System | IP Address | Description |
| --- | --- | --- | --- |
| **Attacker** | Kali Linux | `192.168.15.137` | Used for port scanning and generating authentication attacks. |
| **Target** | Windows Workstation (`DESKTOP-A1EPRVU`) | `192.168.15.141` | Target endpoint forwarding `WinEventLog:Security` logs to SIEM. |
| **SIEM** | Splunk Enterprise | `localhost:8000` | Ingests telemetry, executes detection queries, and triggers alerts. |

---

## Phase 1: Reconnaissance & Target Discovery

Before launching any attack, I mapped out the target network from the Kali Linux system to identify accessible services.

* **Attacker System Verification:** Confirmed local IP configuration to ensure proper network attribution during log analysis.
* **Proof:** `1 (34).png` *(Running `ip addr` on Kali Linux showing IP `192.168.15.137`)*


* **Port Scanning:** Ran an Nmap scan against the target to verify that SMB (port 445) was open and exposed.
* **Proof:** `1 (37).png` *(Nmap output confirming port `445/tcp` open on `192.168.15.141`)*



---

## Phase 2: Attack Simulation & Telemetry Ingestion

With port 445 confirmed open, I generated authentication traffic using `smbclient` to simulate a password-guessing attempt.

* **Executing Brute-Force Attempts:** Launched multiple failed login requests using invalid credentials against the SMB share.
* **Proof:** `1 (39).png` *(Terminal showing repeated `NT_STATUS_LOGON_FAILURE` messages)*


* **Verifying Ingestion in Splunk:** Searched Splunk to ensure real-time log forwarding of Windows **EventCode 4625** (Failed Logon).
* **Proof:** `1 (40).png` *(Splunk capturing failed login events tied to attacker IP `192.168.15.137`)*


* **Building the Attack Timeline:** Formatted raw event data into a clean table view showing timestamps, user accounts, and logon types.
* **Proof:** `1 (26).png` *(Detailed event table of failure logs across the 15-minute attack window)*



---

## Phase 3: Detection Engineering & Alert Tuning

To catch brute-force attempts without flooding the SOC team with false positives from normal user typos, I wrote a custom threshold-based query in Splunk Search Processing Language (SPL).

### Detection Logic (SPL)

```splunk
index=* sourcetype="WinEventLog:Security" EventCode=4625 
| bin _time span=5m 
| stats count by _time, Source_Network_Address, Account_Name 
| where count >= 5

```

* **Validating Rule Logic:** Tested the query to ensure it accurately identified instances where 5 or more failed logins occurred within a 5-minute window.
* **Proof:** `1 (27).png` *(SPL query successfully highlighting the threshold breach)*


* **Alert Throttling & Tuning:** Configured the alert to trigger per result and added a 60-second suppression rule for `Account_Name` to prevent duplicate alerts during sustained attacks.
* **Proof:** `1 (33).png` *(Alert setup screen showing throttle conditions and triggered actions)*


* **Firing the Alert:** Verified that Splunk created a live, actionable notification once the rule threshold was met.
* **Proof:** `1 (30).png` *(Splunk Triggered Alerts dashboard showing `Windows - Possible Attacks` firing at Medium severity)*



---

## Phase 4: Initial Access & Post-Exploitation Correlation

After establishing detection coverage, I authenticated with valid credentials to simulate successful initial access and track the transition from failure to compromise.

* **Gaining Access:** Successfully authenticated via SMB and dropped into an interactive terminal session.
* **Proof:** `1 (43).png` *(Terminal showing successful connection at the `smb: \>` prompt)*


* **Correlating Post-Exploitation Logs:** Queried Splunk for **EventCode 4624** (Successful Logon) linked to the attacker IP (`192.168.15.137`) immediately following the brute-force activity.
* **Proof:** `1 (44).png` *(Splunk showing EventCode 4624 log confirming successful authentication from the attacker machine)*



---

## Key Skills & Takeaways

* **Log Analysis:** Interpreted Windows Security Event Logs, specifically focusing on EventCodes **4625** (Failed Logon) and **4624** (Successful Logon).
* **SIEM Rule Engineering:** Wrote efficient SPL queries utilizing aggregation (`stats`), time-binning (`bin`), and conditional filtering (`where`).
* **Noise Reduction & Alert Tuning:** Applied throttling and suppression rules to lower false positive rates and avoid alert fatigue.
* **Attack Reconstruction:** Connected network layer activity with endpoint log evidence to build a full incident timeline.

---
## Summary of Evidence Artifacts

| Evidence | Investigation Phase | Description |
|---|---|---|
| ![Evidence 01](Attacker_Local_IP/1%20%2834%29.png) | Reconnaissance | Attacker local IP verification (`192.168.15.137`) |
| ![Evidence 02](Evidences/1%20%2837%29.png) | Reconnaissance | Service discovery scan confirming open SMB port |
| ![Evidence 03](Evidences/1%20%2839%29.png) | Attack Generation | SMB authentication failures generated via `smbclient` |
| ![Evidence 04](Evidences/1%20%2840%29.png) | Telemetry Verification | Real-time SIEM log capture of EventCode `4625` |
| ![Evidence 05](Evidences/1%20%2826%29.png) | Log Analysis | Formatted table breaking down failed login events |
| ![Evidence 06](Evidences/1%20%2827%29.png) | Rule Engineering | Time-binned detection query evaluating threshold breaches |
| ![Evidence 07](Evidences/1%20%2833%29.png) | Alert Tuning | Throttle settings and account suppression configuration |
| ![Evidence 08](Evidences/1%20%2830%29.png) | Alert Testing | Triggered alert actively firing on Splunk dashboard |
| ![Evidence 09](Evidences/1%20%2843%29.png) | Initial Access | Interactive SMB session established with valid credentials |
| ![Evidence 10](Evidences/1%20%2844%29.png) | Correlation | Post-compromise log analysis showing EventCode `4624` |






