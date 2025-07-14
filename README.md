# 🛡️ Wazuh HIDS Detection Lab

A virtual lab project that demonstrates how to deploy and configure a **Host-based Intrusion Detection System (HIDS)** using **Wazuh** to detect real-world attacks like reverse shells, unauthorized file changes, and port scans. This project integrates custom rules, multi-platform agents, and actionable log analysis—all from scratch.

---

## 🎯 Project Objectives

- ✅ Deploy Wazuh Manager, Indexer, and Dashboard (All-in-One setup)
- ✅ Install and configure agents on **Kali Linux** and **Windows 11**
- ✅ Simulate attacks using tools like **Metasploit** and **Nmap**
- ✅ Detect and alert on suspicious activity using **custom rules**
- ✅ Analyze logs via the Wazuh Dashboard and CLI
- ✅ Document detection logic, findings, and improvements

---

## 🖥️ Lab Architecture

Kali Linux (Attacker) ---> Wazuh Agents (Win) ---> Wazuh Manager + Dashboard (CSI Linux)

---

## 🔍 Simulated Attacks

| Attack Type           | Tool Used     | Detection Method                |
|-----------------------|---------------|----------------------------------|
| Reverse Shell         | msfvenom      | Custom rule on bash pattern      |
| Port Scan             | Nmap          | Built-in network scan rule       |
| File Modification     | Manual Edit   | File Integrity Monitoring (FIM)  |

➡️ Screenshots and alert logs available in `/screenshots/`  
➡️ Rule logic and detection flow explained in `/report.md`

---

## 📦 Project Structure

├── setup_process.md # Step-by-step installation guide
├── report.md # Attack simulation, detection, and analysis
├── custom_rules.xml # Wazuh custom detection rules
├── screenshots/ # Alert logs and dashboard captures
└── README.md # This file


---

## 📚 Documentation & References

- [📘 Wazuh Documentation](https://documentation.wazuh.com/)
- [🛠️ Wazuh GitHub Repo](https://github.com/wazuh/wazuh)

---

## 🚀 Why This Project Matters

Security teams rely on HIDS tools like Wazuh to monitor endpoints in real-time. This project showcases practical skills in:

- Threat detection and log analysis
- Agent-based monitoring across platforms
- Custom rule creation and tuning
- Hands-on red vs blue teaming concepts

Ideal for showcasing cybersecurity skills in a **SOC**, **Blue Team**, or **Security Engineering** context.

---
