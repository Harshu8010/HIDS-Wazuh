## 🔧 Setup Process

This section covers the complete installation and configuration process of the Wazuh HIDS environment including the manager, agents, and custom rule deployment.

---

### 1️⃣ Wazuh Manager Setup (Ubuntu 22.04)

The Wazuh Manager handles event correlation, rule evaluation, and alerting. It also hosts the Wazuh Dashboard and Indexer.

#### 🔹 Install Wazuh All-In-One (Manager, Dashboard, Indexer)

```bash
# Download Wazuh install script
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh

# Make the script executable
chmod +x wazuh-install.sh

# Run the script with all-in-one installation
sudo bash wazuh-install.sh -a
```

#### 🔹 Post-Installation Access

- Wazuh Dashboard: `https://<wazuh-manager-ip>`
- Default credentials:
  - **Username**: `admin`
  - **Password**: retrieved from `/var/ossec/api/configuration/auth/credentials.json`

---

### 2️⃣ Wazuh Linux Agent Setup (Kali Linux or other)

Wazuh agents are responsible for collecting log, process, and system data from endpoints.

#### 🔹 Install Wazuh Agent

```bash
# Download and run the agent install script with manager IP
curl -sO https://packages.wazuh.com/4.7/wazuh-agent.sh
sudo WAZUH_MANAGER="192.168.56.10" bash ./wazuh-agent.sh
```

#### 🔹 Authenticate with Manager

```bash
sudo /var/ossec/bin/agent-auth -m 192.168.56.10
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

### 3️⃣ Wazuh Windows Agent Setup (Windows 11)

1. Download `.msi` agent installer:\
   [https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.x.msi](https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.x.msi)

2. Run the installer and during setup:

   - Set the **Wazuh Manager IP**
   - Provide a unique **agent name** (e.g., `win-agent`)
   - Accept default ports and enable firewall exception if prompted

3. Start the service:

   - Open `services.msc`
   - Locate **Wazuh Agent**
   - Set to `Automatic` and click \*\*Start\`

---

### 4️⃣ Register Agents on Wazuh Manager

On the Wazuh Manager:

```bash
sudo /var/ossec/bin/manage_agents

# Options:
# A – Add an agent
# E – Extract key
# I – Import key
```

Use the key output to register the agent on the remote system.

---

### 5️⃣ Configure ossec.conf (Optional Tuning)

On the Wazuh Manager:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Optional edits:

- Enable or adjust FIM, rootcheck, and log sources
- Increase alert levels or retention settings

Restart to apply changes:

```bash
sudo systemctl restart wazuh-manager
```

---

### 6️⃣ Add Custom Detection Rules

To detect reverse shells, encoded commands, or suspicious logins, create a custom rule file:

```bash
sudo nano /var/ossec/etc/rules/custom_rules.xml
```

#### 🔹 Example Rule – Reverse Shell Detection

```xml
<group name="reverse_shell,">
  <rule id="100200" level="12">
    <if_sid>18107</if_sid>
    <match>bash -i >& /dev/tcp</match>
    <description>Reverse Shell Detected via bash</description>
  </rule>
</group>
```

Restart Wazuh Manager:

```bash
sudo systemctl restart wazuh-manager
```

---

### 7️⃣ Verify Setup

- Ensure agents are listed as `active` in Wazuh Dashboard
- Simulate attacks (e.g., reverse shell or file change)
- Check for generated alerts:
  - Wazuh Dashboard → Security Events
  - `/var/ossec/logs/alerts/alerts.log`

---

### ✅ Setup Completed

| Component        | Status       |
| ---------------- | ------------ |
| Wazuh Manager    | ✅ Installed  |
| Linux Agent      | ✅ Active     |
| Windows Agent    | ✅ Active     |
| Custom Rules     | ✅ Working    |
| Alert Monitoring | ✅ Functional |

