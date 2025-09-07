
# Use Cases for a SOC on Unix-Oriented Infrastructure 

<img width="768" height="460" alt="image" src="https://github.com/user-attachments/assets/10bef00e-cf98-4e7a-8f26-cea1d1b84623" />

### 1. Use Case: Failed Privilege Escalation Attempts
*   **Description:** Detection of multiple failed attempts to gain root access on a critical server (e.g., DB or application web server).
*   **Signals & Logic (Unix version):**
    *   (Wazuh / syslog/auth.log) Multiple `FAILED su` events for root or `sudo: pam_authenticate: Authentication failure`.
    *   **Correlation:** More than 5 attempts within 60 seconds from a single IP address or for a single user.
    *   **Context:** The server is tagged as "critical" in Wazuh/ELK. Successful logins under other accounts follow the failed attempts.
*   **SOC Response:** **HIGH SEVERITY** alert. Cortex runs a playbook that adds the source IP to the firewall blocklist (via API) and initiates a password reset for the account used in the attempts.

### 2. Use Case: Malicious Process / Script Activity
*   **Description:** Execution of a suspicious process characteristic of bots, cryptominers, or backdoors.
*   **Signals & Logic (Unix version):**
    *   (Wazuh System Call Monitoring) Launch of a process attempting to hide its presence (e.g., with a name resembling a system process: `kworkerds`, `systemd-service`).
    *   **Correlation:** The process makes network connections to non-standard ports or to domains not on the allowlist (checked via MISP). Or the process has high CPU usage but is not a known legitimate application.
    *   **Context:** The process is launched from a temporary directory (`/tmp/`, `/dev/shm/`).
*   **SOC Response:** **CRITICAL SEVERITY** alert. Cortex runs a playbook that forcefully terminates (kills) the process, blocks outgoing connections from this host, and isolates it for further analysis.

### 3. Use Case: Modification of Critical Configuration Files
*   **Description:** Unauthorized changes to configuration files (SSH, cron, web servers, firewall).
*   **Signals & Logic (Unix version):**
    *   (Wazuh File Integrity Monitoring - FIM) Changes to files in `/etc/ssh/sshd_config`, `/etc/crontab`, `/etc/apache2/`, `/etc/nginx/`, `/etc/iptables/rules.v4`.
    *   **Correlation:** The change was not made from an approved configuration management process (Ansible, Puppet) and was not preceded by a Change Request.
*   **SOC Response:** **HIGH SEVERITY** alert. The analyst immediately reviews the change content. Cortex can automatically revert the change by restoring the file from a trusted backup.

### 4. Use Case: Suspicious Web Access Activity (Nginx/Apache)
*   **Description:** Detection of attacks on web applications (credential stuffing, SQL injections, Local File Inclusion - LFI).
*   **Signals & Logic (Unix version):**
    *   (Nginx/Apache logs in ELK) Patterns in the URL or User-Agent indicating an attack (e.g., `POST /wp-login.php`, `../etc/passwd`, `UNION SELECT`, `nikto`, `sqlmap`).
    *   **Correlation:** A high number of 4xx (Client Error) or 5xx (Server Error) response codes from a single IP address in a short time.
    *   **Enrichment:** The source IP is checked in MISP against lists of known vulnerability scanners or bots.
*   **SOC Response:** **MEDIUM/HIGH SEVERITY** alert. The Cortex playbook automatically adds the source IP to the blocklist at the WAF level (e.g., mod_security) or the web server itself.

### 5. Use Case: Suspicious SSH Connections
*   **Description:** Detection of brute-force attacks or successful unauthorized SSH connections.
*   **Signals & Logic (Unix version):**
    *   (Wazuh / syslog/auth.log) Multiple `Failed password for root` or `Failed password for invalid user` events.
    *   **Correlation:** A successful login (`Accepted password`) after a series of failed attempts from the same IP. Or a successful login outside of business hours.
    *   **Context:** The source IP is geolocated to a region unusual for the company.
*   **SOC Response:** **HIGH SEVERITY** alert. The analyst immediately checks the activity of the logged-in user. Cortex can forcefully terminate the suspicious SSH session and block the IP.

### 6. Use Case: Suspicious Database Queries (MySQL/PostgreSQL)
*   **Description:** Detection of SQL injection attempts or unauthorized access to sensitive data.
*   **Signals & Logic (Unix version):**
    *   (MySQL logs in ELK) Queries containing dangerous patterns (`UNION`, `SELECT LOAD_FILE`, `xp_cmdshell`, `DROP TABLE`, `OR 1=1`).
    *   **Correlation:** Queries are not coming from a legitimate application server IP but from another one. Or a single user is making an abnormally high number of data selection queries.
*   **SOC Response:** **HIGH SEVERITY** alert. The Cortex playbook can temporarily block the database account and notify the administrator.

### 7. Use Case: Mass Network or Port Scanning
*   **Description:** Detection of activity aimed at reconnaissance of the internal network.
*   **Signals & Logic (Unix version):**
    *   (Suricata/Zeek network logs in ELK) Multiple connection attempts to closed ports on different hosts from a single source.
    *   **Correlation:** Packets have signs of scanners (nmap, masscan) in their fields (e.g., specific flags).
    *   **Enrichment:** The source IP is checked in MISP.
*   **SOC Response:** **LOW/MEDIUM SEVERITY** alert. The IP is automatically added to the network firewall blocklist.

---
