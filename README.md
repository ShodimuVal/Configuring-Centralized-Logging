# Assisted Lab: Configuring Centralized Logging

## Description
This project was completed as part of my learning path toward the **CompTIA CySA+ certification**.  
The lab explored **log management and analysis**, including centralized Windows event collection and regex-based log searching in Linux.  
By configuring a centralized logging system, I learned how to aggregate logs across multiple systems for easier monitoring, correlation, and security analysis — a key component in **Security Operations and Incident Response**.

---

## Objective
To implement and verify centralized logging between Windows systems and to apply basic **regular expression (regex)** techniques to search Linux log files.  
Key tasks include:
- Configuring **Windows Event Forwarding (WEF)** between a collector and source system.
- Enabling necessary Windows Firewall and WinRM configurations.
- Creating and verifying an **Event Viewer subscription** for centralized event collection.
- Using `grep` and regex patterns to search and analyze logs on a Linux server.

---

## Skills Learned
- Setting up **Windows Event Collector** and **Windows Event Forwarding**.
- Configuring **Group Policy** for WinRM listener permissions.
- Enabling **Remote Event Log Management** via PowerShell.
- Creating and testing **Event Viewer subscriptions** for log aggregation.
- Using **grep** with **Perl-compatible regular expressions (PCRE)** for advanced log searching.
- Extracting IPv4 addresses, usernames, and sudo session activity from log files.
- Understanding the importance of **centralized log management** for SIEM integration and forensic analysis.

---

## Tools Used
- **Windows Server 2019 (DC10)** – Configured as the centralized log collector.  
- **Windows Server 2016 (MS10)** – Configured as the event log source.  
- **Ubuntu Server (LAMP)** – Used for regex and grep log analysis.  
- **PowerShell** – For Windows configuration and scripting.  
- **Event Viewer** – To create and manage event subscriptions.  
- **Linux utilities** – `grep`, `wc`, `iptables`, `less`, `more`.

---

## Steps

### 1. Configure Centralized Logging on Windows

#### a. Prepare the Collector (DC10)
- Logged into **DC10** as `Structureality\Administrator` with `Pa$$w0rd`.  
- Opened **PowerShell (Admin)** and ran the following script:
  ```powershell
  Import-Module GroupPolicy

  # Get the cc-domain-default GPO object
  $gpo = Get-GPO -Name "cc-domain-default"

  # Set WinRM IPv4 listener filter to accept all connections
  $winrmRegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
  Set-GPRegistryValue -Name $gpo.DisplayName -Key $winrmRegKey -ValueName "IPv4Filter" -Type String -Value "*"

  # Refresh group policy
  gpupdate /force
  ```
- Ran:
  ```powershell
  wecutil qc
  ```
  Responded **Y** when prompted.  
  ✅ Output confirmed: *Windows Event Collector service was configured successfully.*

---

#### b. Prepare the Source (MS10)
- Logged into **MS10** as `jaime` with `Pa$$w0rd`.  
- Restarted VM to confirm domain login.  
- Opened **PowerShell (Admin)** and enabled required firewall rules:
  ```powershell
  Set-NetFirewallRule -DisplayGroup "Remote Event Log Management" -Enabled True -Profile Domain
  Set-NetFirewallRule -DisplayGroup "Remote Event Monitor" -Enabled True -Profile Domain
  ```
- Confirmed **WinRM** configuration:
  ```powershell
  winrm quickconfig
  ```
  - Expected message: `WinRM service is already running on this machine.`  
  - If not configured, start the service manually as prompted.

- Added **DC10** to **Event Log Readers** group:
  1. Opened **Computer Management → Local Users and Groups → Groups → Event Log Readers**.
  2. Selected **Add → Object Types → Computers → OK**.
  3. Entered `DC10` → **OK**.
  4. Confirmed membership: `structureality\DC10`.
- Restarted **MS10**.

---

#### c. Configure the Subscription on DC10
- Logged into **DC10** again as Administrator.
- Opened **Event Viewer → Subscriptions → Create Subscription…**
  - **Subscription name:** `Logs from MS10`
  - **Destination log:** `Forwarded Events`
  - **Type:** `Collector initiated`
  - **Select Computers → Add Domain Computers → MS10 → Test → OK**
  - ✅ Connectivity test succeeded.
- Selected **Select Events → Last 24 hours**, checked all levels:
  - Critical, Warning, Verbose, Error, Information.
  - Chose **By log → Windows Logs → Application, Security, Setup, System, Forwarded Events**.
  - Saved changes.
- Verified:
  - Subscription listed as **Active** under *Subscriptions*.
  - Viewed **Runtime Status → Active**.
- In **Event Viewer → Windows Logs → Forwarded Events**, selected **Refresh** until events appeared.  
  ✅ Confirmed that logs from `MS10.ad.structureality.com` appeared.

---

### 2. Search Logs with Regex on Linux (LAMP)
#### a. Enable and Inspect Network Logging
- Logged into **LAMP** as `lamp` (`Pa$$w0rd`) and switched to root:
  ```bash
  sudo su
  ```
- Enabled network logging:
  ```bash
  iptables -A INPUT -j LOG
  ```
- Saved filters:
  ```bash
  iptables -S > /home/lamp/filter-list.txt
  ```
- Viewed log files:
  ```bash
  cd /var/log
  ls -l
  less kern.log
  ```
  Used `space` and `b` to navigate, `q` to quit.

---

#### b. Extract IPv4 Addresses Using Regex
- Initial test (digits only):
  ```bash
  grep -oP '[0-9]' kern.log
  ```
- Matched multi-digit numbers:
  ```bash
  grep -oP '[0-9]*' kern.log
  ```
- Added literal dot:
  ```bash
  grep -oP '[0-9]*\.' kern.log
  ```
- Used regex for IP-like patterns:
  ```bash
  grep -oP '\d+\.\d+\.\d+\.\d+' kern.log
  ```
- Restricted to 1–3 digits per octet:
  ```bash
  grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' kern.log
  ```
- Simplified pattern with repeater:
  ```bash
  grep -oP '(\d{1,3}\.){3}\d{1,3}' kern.log
  ```
- Saved to a file:
  ```bash
  grep -oP '(\d{1,3}\.){3}\d{1,3}' kern.log > ipaddresses.txt
  ```
- Viewed output:
  ```bash
  grep -oP '(\d{1,3}\.){3}\d{1,3}' kern.log | less
  ```
- Counted IPv4 occurrences:
  ```bash
  grep -oP '(\d{1,3}\.){3}\d{1,3}' kern.log | wc -l
  ```
- Searched for a specific address:
  ```bash
  grep 172.16.0.254 kern.log | wc -l
  grep 172.16.0.254 kern.log --color=always | more
  ```

---

#### c. Analyze Authentication Logs
- Searched for “user” entries:
  ```bash
  grep user auth.log.1
  ```
- Excluded `ruser` entries:
  ```bash
  grep -v ruser auth.log.1 | grep user
  ```
- Highlighted usernames:
  ```bash
  grep -v ruser auth.log.1 | grep -P 'user \w+'
  ```
- Filtered for `sudo` sessions:
  ```bash
  grep -v ruser auth.log.1 | grep -P 'user \w+' | grep sudo
  ```
- Limited to open sessions:
  ```bash
  grep -v ruser auth.log.1 | grep -P 'user \w+' | grep sudo | grep 'session opened'
  ```
- Counted open sessions:
  ```bash
  grep -v ruser auth.log.1 | grep -P 'user \w+' | grep sudo | grep 'session opened' | wc -l
  ```

✅ Regex successfully isolated IPv4 addresses and user activity from large logs.

---

## Shared Responsibility & Risks
- **Analyst Role:** Centralize and analyze log data to detect anomalies and support incident response.  
- **Risks:**  
  - Misconfigured WinRM or firewall rules preventing log forwarding.  
  - Collector overload due to excessive event volume.  
  - Regex misuse leading to incomplete or inaccurate results.  
- **Mitigations:**  
  - Test connectivity and event subscriptions regularly.  
  - Use filtering in subscriptions to control event volume.  
  - Validate regex patterns before applying in automation scripts.

---

## Results
- Configured **DC10** as Windows Event Collector.  
- Enabled **MS10** to forward events successfully.  
- Verified logs appearing in **Forwarded Events**.  
- Used **regex and grep** to locate IPv4 addresses and user activities in Linux logs.  
- Reinforced **CySA+ objectives**:  
  - **1.1:** System and network architecture in security operations.  
  - **1.2:** Indicators of potentially malicious activity.  
  - **1.3:** Tools and techniques for detecting malicious activity.  

This lab demonstrated the practical application of **centralized log management and regex-based analysis** — both critical skills for cybersecurity analysts monitoring enterprise environments.
