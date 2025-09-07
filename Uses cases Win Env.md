

## 1. Use Case: Unauthorized Access to a High-Value Server (e.g., Trading Engine)

<img width="1281" height="641" alt="image" src="https://github.com/user-attachments/assets/e7b69a4c-4854-4f21-9e8d-065d0e23dbf5" />

*   **Description:** Detection of successful logon to a critical server holding trading engine software or sensitive market data by a user account not authorized for access.
*   **Signals & Logic:**
    *   (Wazuh/Windows Event Log) Event ID 4624 (Successful Logon) from a critical server tag.
    *   **Correlation:** The user is NOT a member of the approved admin group (e.g., `Trading-Server-Admins`). Check against a list of authorized users from LDAP/Active Directory.
    *   **Context:** Source IP address is not from a designated secure administrative subnet.
*   **SOC Response:** **HIGH SEVERITY** alert in Kibana. Cortex playbook automatically initiates a user session termination and triggers an immediate ticket. Analyst consults MISP to see if the source IP is known as a threat actor C2.

## 2. Use Case: Data Exfiltration Attempt via Encrypted Channels (TLS/HTTPS)

*   **Description:** A internal workstation or server starts sending unusually large amounts of data to an external domain over port 443/TLS.
*   **Signals & Logic:**
    *   (Network Sensor/Zeek logs in ELK) A internal asset establishes a TLS connection to an external domain with a massive volume of data upload (e.g., >500MB in a short time).
    *   **Correlation:** The external domain is not whitelisted (e.g., not `cdn.microsoft.com`, `update.symantec.com`). Check domain against MISP threat feeds and internal allowed lists.
    *   **Context:** The internal asset is a database server or a developer's workstation, not a web proxy.
*   **SOC Response:** **CRITICAL SEVERITY** alert. Cortex playbook can trigger Wazuh to isolate the host from the network and block the destination domain/IP at the firewall.

## 3. Use Case: Lateral Movement using PsExec / WMI

*   **Description:** Attackers who compromise one machine often use tools like PsExec to move laterally to others, especially domain controllers.
*   **Signals & Logic:**
    *   (Wazuh/Windows Event Log) Event ID 4688 (Process Creation) showing `psexec.exe`, `psexecsvc.exe`, or `wmiprvse.exe` being launched.
    *   **Correlation:** The parent process is a command-line (`cmd.exe`, `powershell.exe`) and the network connection is initiated from a different subnet or a non-trusted host.
    *   **Context:** The target host is a critical server or a domain controller.
*   **SOC Response:** **HIGH SEVERITY** alert. Analyst investigates the source of the lateral movement attempt to find the initially compromised host.

## 4. Use Case: API Credential Abuse for Market Data Feed

*   **Description:** The exchange provides real-time market data via APIs. This detects anomalous usage of API keys.
*   **Signals & Logic:**
    *   (Application Logs from API Gateway in ELK) A single API key is making requests at a frequency 10x the baseline for that user/service account.
    *   **Correlation:** Requests are coming from a geo-location different from the key owner's usual pattern (e.g., key owned by a firm in London, but requests originate from a datacenter in Moldova).
    *   **Context:** The key is accessing sensitive data endpoints it doesn't normally use.
*   **SOC Response:** **MEDIUM/HIGH SEVERITY** alert. Cortex playbook automatically disables the API key and alerts the key owner via email/ticketing system.

## 5. Use Case: Phishing Link Clicked & Subsequent Callback

*   **Description:** An employee clicks a link in a phishing email, leading to malware download or credential harvesting.
*   **Signals & Logic:**
    *   (Proxy/Firewall Logs in ELK) HTTP request from an internal user to a known malicious URL (IOC from MISP feed).
    *   **Correlation:** Shortly after, the same host makes a DNS request to a suspicious, newly registered domain (DGA-like). Wazuh detects the creation of a new, suspicious file.
*   **SOC Response:** **MEDIUM SEVERITY** alert. Analyst uses Wazuh to take a disk image of the host for forensic analysis. Cortex quarantines the email for all users.

## 6. Use Case: Privilege Escalation via Service Exploitation

*   **Description:** An attacker exploits a misconfigured service to gain higher privileges (e.g., SYSTEM/root).
*   **Signals & Logic:**
    *   (Wazuh) Alert from its built-in Vulnerability Detector module identifying a service with a known privilege escalation CVE.
    *   **Correlation:** Shortly after the vulnerability is detected, Wazuh/OS logs show a service (e.g., `Apache`, `MySQL`) spawning a shell (`bash.exe`, `cmd.exe`).
*   **SOC Response:** **HIGH SEVERITY** alert. Ticket is automatically created for the sysadmin team to patch the system. Host is closely monitored for further malicious activity.

## 7. Use Case: Denial-of-Service Attack on Public Website

*   **Description:** Detection of a coordinated flood of traffic aimed at disrupting the availability of the exchange's public website or member portal.
*   **Signals & Logic:**
    *   (Network Traffic logs in ELK) A massive spike in incoming traffic from multiple sources to a single destination IP/URL.
    *   **Correlation:** Traffic patterns are anomalous (e.g., same User-Agent, same HTTP request pattern from thousands of IPs). The server responds with a high rate of 5xx errors.
*   **SOC Response:** **CRITICAL SEVERITY** alert. SOC declares an incident and engages the network team. Traffic is automatically diverted through a DDoS mitigation provider (can be orchestrated by Cortex).

## 8. Use Case: Suspicious Database Query (Potential Insider Threat)

*   **Description:** A user or application queries a database for an unusually large volume of sensitive client or trading data.
*   **Signals & Logic:**
    *   (Database Audit Logs in ELK) A `SELECT * FROM clients` or a query with a `WHERE` clause on a large dataset (e.g., all records from the last 10 years).
    *   **Correlation:** The query is run by a user who normally only has access to a small subset of data or during off-business hours.
    *   **Context:** The query is followed by a large data transfer (see Use Case #2).
*   **SOC Response:** **HIGH SEVERITY** alert. Analyst immediately contacts the data owner to verify the legitimacy of the query. User account is temporarily suspended pending investigation.

---
