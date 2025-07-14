# 🛡️ Host-Based Intrusion Detection System using Wazuh

---

## 1. Introduction

This project demonstrates the setup and use of a **Host-Based Intrusion Detection System (HIDS)** using **Wazuh** to detect, alert, and analyze malicious activity across Windows and Linux endpoints. The goal was to build a functioning intrusion detection setup that can simulate real-world cyberattacks and analyze system responses through custom detection rules and alert logs.

This project is intended for anyone exploring security monitoring, blue teaming, or learning how to configure and evaluate a host-based detection system.

---

## 2. Objectives

The key objectives of this project were:

- To install and configure a centralized Wazuh Manager
- To deploy Wazuh agents on Windows and Linux machines
- To simulate common attack techniques such as reverse shells, and unauthorized file changes
- To write and apply custom rules for better detection capability
- To analyze alert logs generated during attack simulations
- To gain hands-on understanding of how host-based intrusion detection systems operate in practice

---

## 3. Tools & Technologies

Below are the main tools and platforms used in this project:

  Tool/Technology --------> Purpose 
-------------------------------------
- **Wazuh Manager** | Centralized monitoring, rule evaluation, and alert generation 
- **Wazuh Agent**   | Deployed on Linux and Windows endpoints to monitor local activity 
- **Windows Server 2008**    | Wazuh Agent endpoint for simulating Windows-based attacks 
- **Kali Linux**    | Used as an attacker machine to run tools like Metasploit and nmap 
- **CSI Linux**     | Host OS for Wazuh Manager && Security Operations  
- **VirtualBox**    | Virtual environment hosting all systems 
- **Metasploit**    | Used for reverse shell attack simulation 
- **Nmap**          | Used for port scanning and reconnaissance simulation 

---

## 4. Wazuh's Components

Wazuh has several components structured together for various purpose so understanding of these compnents is required for this project.

###  Wazuh Server
The Wazuh Server is the central brain of the Wazuh platform. It processes security data collected by agents, evaluates it against rule sets, generates alerts, and handles configuration and communication between components. It consists of the Wazuh Manager, Wazuh Indexer, and Wazuh Dashboard.

### Wazuh Manager
The Wazuh Manager is responsible for: Receiving log and event data from agents, Decoding and correlating events, Applying rule sets to detect suspicious behavior, Generating security alerts, Sending logs to the, Indexer for storage, It's the core component responsible for detection and alert logic.

### Wazuh Indexer
Wazuh Indexer (formerly based on OpenSearch/Elasticsearch) is a search and storage engine that stores all collected logs, alerts, and events. It allows users to query, filter, and analyze data efficiently. It enables full-text search and powers the backend of the Wazuh Dashboard.

### Wazuh Agents
Wazuh Agents are lightweight programs installed on endpoint systems (Linux, Windows, macOS) that: Monitor files, processes, logs, and network activity, Send data to the Wazuh Manager for analysis, Receive updated configuration and rule sets from the manager, they are crucial for real-time host-level visibility.

### Wazuh Dashboard
The Wazuh Dashboard is a web-based GUI that provides: Real-time alert monitoring, System health status, Visualization of log and rule matches, Custom dashboard creation, It simplifies the management and investigation of alerts across all monitored systems.

### Rule Sets
Wazuh uses predefined and custom rule sets to detect known attack patterns, suspicious behavior, and anomalies. Each rule includes: A unique ID, a severity level (0–15), conditions to match against event data, custom rules can be created to detect specific behaviors, such as reverse shells, unauthorized access, or file changes, making Wazuh highly adaptable.

---

## 5. Attack Simulations
To test the effectiveness of the Wazuh setup, the following attacks were simulated from the Kali Linux VM targeting Windows 2008 server machine:

### 1. Port Scanning:
   
**Tool Used:** Nmap  

**Purpose:** Reconnaissance to identify open ports 

**Command Used:**

```bash
nmap -sS -T4 -A 192.168.56.101
```
### 2. File Modification (Integrity Check):

**Tool Used:** Manual file tampering 

**Purpose:** Test file integrity monitoring

**Command Used:**
echo "unauthorized change" >> /etc/passwd

### 3. Reverse Tcp (Custom rule implementation):

**Tool Used:** Metasploit

**Purpose:** Test with a real attack simulation 

## 6. Detection Logoic

Wazuh uses a layered detection architecture that includes log collection, decoding, rule correlation, and alerting. This design allows it to act as a powerful Host-based Intrusion Detection System (HIDS).

---

### 1️. Data Collection (Log & Event Gathering)

Wazuh collects security-relevant data from monitored systems using agents (or agentlessly):

- Linux and Windows system logs
- Command execution records
- File integrity checks
- Registry monitoring (Windows)
- Auditd logs (Linux)
- Rootcheck scans

The data is securely forwarded to the Wazuh Manager.

---

### 2. Decoders (Log Normalization)

Before any rule can be applied, raw logs are decoded.

**Purpose:** Extract structured fields from unstructured logs using decoders.

**Example Log:** sshd[2254]: Failed password for invalid user admin from 192.168.0.100 port 55874

**Decoded Output:**
- Program: `sshd`
- Event: `Failed password`
- IP: `192.168.0.100`
- Username: `admin`

> Decoders enable consistent field matching for the rules engine.

---

### 3. Rules Engine (Event Correlation)

After decoding, logs are evaluated against Wazuh's rule base.

Each rule consists of:
- `match`, `regex`, or `field` conditions
- `id`: Unique identifier for the rule
- `level`: Severity score (0–15)
- `description`: Explains the rule
- `if_sid`: Chains rules together
- `group`: Tags rule types (e.g., `authentication_failed`)

**Rule Hierarchy:**
- **Low-level rules**: Detect simple events (e.g., login failure)
- **High-level rules**: Correlate multiple events (e.g., brute-force attack)

---

### 4. Alert Generation

When a rule is matched, an alert is generated:

- Stored in:  
  - `/var/ossec/logs/alerts/alerts.log`  
  - `/var/ossec/logs/alerts/alerts.json`  
- Displayed in the **Wazuh Dashboard**
- Can be forwarded to SIEM, email, Slack, etc.

**Alert includes:**
- Rule ID and severity
- Matched log
- Agent details
- Time of occurrence
- Original log and decoded fields

---

### 5. Wazuh Modules That Enable Detection

| Module            | Purpose                                      |
|-------------------|----------------------------------------------|
| `syscheck`        | File integrity monitoring                    |
| `rootcheck`       | Rootkit detection and hidden file scanning   |
| `auditd`          | Monitors system calls and sensitive actions  |
| `command`         | Detects specific command-line executions     |
| `registry`        | Monitors Windows registry keys               |
| `OpenSCAP`        | Checks compliance policies                   |
| `active-response` | Executes response scripts on matching alerts |

---

Wazuh comes with a large set of default rules, and you can find them in a specific directory on the Wazuh Manager.

On your Wazuh Manager (Linux), default rule files are stored in:
```
sudo /var/ossec/ruleset/rules/
```
-------image

## 7. Log Analysis After Nmap Scan

image------

- Event ID 61102 – Windows System Error Event

Jul 14, 2025 @ 09:44:30.477
Rule ID: 61102
Level: 5

Description: Windows System error event

This is a general error event from the Windows Event Log. It likely occurred because Nmap's aggressive scan (-A) triggered services (like RDP, SMB, or WMI) to respond with errors. This is common when : Ports are probed, OS detection is attempted, Services are banner-grabbed, it’s not a high-priority alert, but it tells you something unexpected or abnormal hit the system.

 - Event ID 92657 – Successful Remote Logon (Anonymous)
   
Jul 14, 2025 @ 09:44:48.521
Rule ID: 92657
Level: 6

Description: Successful Remote Logon Detected - User: \ANONYMOUS LOGON - NTLM authentication, possible pass-the-hash attack - Possible RDP connection. Verify that nmap is allowed to perform RDP connections

This one is very interesting — here’s what happened: Nmap’s -A scan tries OS detection, version detection, and often probes RDP (port 3389), SMB, WMI, etc. During this, NTLM authentication attempts might get logged. Windows logs this as a successful logon by an anonymous user — a behavior associated with: Nmap, SMB enumeration, pass-the-hash or info-gathering tools. Wazuh flags it as suspicious, possibly indicating: Reconnaissance, Credential-less probing, an attacker trying RDP connection or anonymous SMB login.

## 8. Integrity Monitoring After File Modification

Integrity monitoring in Wazuh is a critical security feature that tracks unauthorized changes to files, directories, or Windows registry keys on monitored systems.

What It Does: Wazuh watches important files and directories (or registry keys on Windows) and alerts you when something changes.

What changes could occur and why it matter:
- File created/modified	-->  Could be malware dropped or config changed
- File deleted	--> Could be log tampering or evidence wiping 
- Permissions changed --> Could indicate privilege escalation 
- Registry key modified (Win) -->	Could mean persistence or malware installed

On Windows
It watches for:
- Changes to registry keys (startup entries, policies, etc.)
- Modifications in C:\Windows\System32
- Dropped executables in Downloads or Temp

Where to Configure It
Wazuh config file on the agent: 
```
/etc/ossec/ossec.conf
```

Where Alerts Show Up
When a change happens, Wazuh sends an alert like:

```
{
  "rule": {
    "id": 550,
    "description": "Integrity checksum changed."
  },
  "agent": {
    "name": "Windows-VM"
  },
  "file": "/etc/ssh/sshd_config"
}
```

## 9. Findings

This section summarizes the effectiveness of the Wazuh HIDS setup based on the simulated attacks and detection performance.

###  Successfully Detected

- **Reverse Shell (bash TCP)** triggered the custom rule and was flagged immediately.
- **Port Scanning (Nmap)** was detected using default Wazuh rules.
- **File Modifications** on critical system files (e.g., `/etc/passwd`) were detected via the `syscheck` module.

###  Missed or Not Detected

- **Obfuscated Commands** (e.g., base64-encoded reverse shell payloads) were initially not detected.
- Some **Windows Event Log activities** (e.g., PowerShell abuse) required manual tuning and additional rules.

###  Tuning & Improvements

- Created custom rules for base64 patterns in Linux and encoded PowerShell on Windows.
- Adjusted FIM settings to monitor high-value files more frequently.
- Increased alert log retention and enabled verbose agent logging for deeper analysis.
- Configured Wazuh Dashboard widgets to track custom rule hits over time.

---

## 10. Missed/Not Detected 

Why Was the Reverse TCP Payload Not Detected by Default Wazuh Rules?

Despite executing a reverse TCP payload using `msfvenom` (e.g., `windows/meterpreter/reverse_tcp`), Wazuh **did not generate an alert** by default. Here's a detailed explanation of **why this occurred** and **how it was resolved**.

---

###  Why Wazuh Did Not Detect the Reverse Shell by Default

| Root Cause | Explanation |
|------------|-------------|
| **Wazuh is Host-Based (Not Network-Based)** | Wazuh analyzes **host logs** only. It doesn't monitor raw network traffic unless a service or process logs something suspicious. |
| **Windows Logs Are Limited by Default** | Default Windows auditing does **not log process executions** like `cmd.exe` or `powershell.exe` unless advanced logging is enabled. |
| **Wazuh Relies on Specific Logs** | If there's **no relevant log entry**, the Wazuh ruleset cannot trigger a detection. |
| **Reverse TCP is Stealthy by Design** | The payload executes **in memory**, mimicking normal processes. It does not drop files or visibly crash anything unless configured to do so. |

---

###  What Would Have Detected the Reverse Shell

| Detection Method | Works? | Why |
|------------------|--------|-----|
|  **Wazuh Default FIM (File Integrity Monitoring)** | ❌ | No file changes occurred. |
|  **Default Wazuh Ruleset** | ❌ | No default rule matched the stealthy process execution. |
|  **Custom Wazuh Rule (Event ID 4688)** | ✅ | We wrote a custom rule to alert on suspicious process creation (`cmd.exe`, `powershell.exe`). |
|  **Sysmon + Wazuh** | ✅ | Sysmon logs detailed process and network activity, which Wazuh can alert on. |
|  **Suricata / Zeek (NIDS)** | ✅ | These tools detect suspicious outbound reverse shell traffic on the network. |
|  **EDR / Defender ATP** | ✅ | Behavioral detection based on memory injection or known IOCs. |

---

###  Custom Rule Solution

To address this gap, we implemented a **custom Wazuh rule** that triggers alerts based on Windows Event ID `4688` (new process creation) and matches suspicious processes like `cmd.exe`, `powershell.exe`, and others commonly used in reverse shell payloads.

```xml
<rule id="100010" level="10">
  <if_sid>61613</if_sid>
  <field name="win.system.eventID">4688</field>
  <match>cmd.exe</match>
  <description>Suspicious Process: Possible Reverse Shell (cmd.exe)</description>
</rule>

<rule id="100011" level="12">
  <if_sid>61613</if_sid>
  <field name="win.system.eventID">4688</field>
  <match>powershell.exe</match>
  <description>Suspicious Process: Possible Reverse Shell (PowerShell)</description>
</rule>
```

## 11. Conclusion

This project provided hands-on experience with deploying and configuring a Host-Based Intrusion Detection System using Wazuh in a virtual lab. Key takeaways include:

###  What I Learned

- Installation and configuration of a complete Wazuh stack
- Creating and deploying custom detection rules
- Simulating realistic attacks and observing detection mechanisms
- Log analysis and alert triage using both CLI and GUI tools

###  Strengths of the Setup

- Cross-platform support (Linux and Windows)
- Real-time monitoring with high configurability
- Modular rule system and built-in FIM capabilities

###  Limitations

- Requires manual rule tuning for sophisticated or obfuscated attacks
- False positives in aggressive scanning scenarios
- Lacks integrated alert delivery (e.g., Slack/email) out of the box

###  Real-World Relevance

This HIDS setup closely resembles real-world SOC environments where:
- Endpoint monitoring is crucial for incident detection
- Analysts investigate alerts and perform rule tuning regularly
- HIDS tools integrate with SIEMs for broader threat visibility

---

## 12. Future Enhancements

The following improvements are planned or recommended:

-  **Integrate Slack/Email alerts** for faster triage
-  **Forward Wazuh alerts to ELK or Splunk** for better visualization and correlation
-  **Write advanced correlation rules** for multi-event attack chains (e.g., persistence + privilege escalation)
-  **Deploy agents in AWS VMs or EC2 instances** to test cloud-based detection
-  **Automate rule tuning** based on incident feedback and threat intelligence feeds

---

## 13. References

- 📘 [Wazuh Documentation](https://documentation.wazuh.com/current/index.html)
- 📦 [Wazuh GitHub](https://github.com/wazuh/wazuh)
- 📄 [MITRE ATT&CK](https://attack.mitre.org/)

