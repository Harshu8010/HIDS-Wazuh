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
1. Port Scanning:
   
**Tool Used:** Nmap  

**Purpose:** Reconnaissance to identify open ports 

**Command Used:**

```bash
nmap -sS -T4 -A 192.168.56.101
```
2. File Modification (Integrity Check):

**Tool Used:** Manual file tampering 

**Purpose:** Test file integrity monitoring

**Command Used:**
echo "unauthorized change" >> /etc/passwd



