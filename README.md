# Open-Source SOC 

A curated collection of practical Security Operations Center (SOC) use cases focused on detecting threats in Unix-like environments (Linux, BSD) and common open-source software stacks (Nginx, Apache, MySQL, SSH).

<img width="1000" height="525" alt="image" src="https://github.com/user-attachments/assets/415dc5b3-b60d-456c-aa38-44fb597929e0" />

## What is a Security Operations Center (SOC)?

A Security Operations Center (SOC) is a centralized function within an organization that employs people, processes, and technology to continuously monitor and improve an organization's security posture while preventing, detecting, analyzing, and responding to cybersecurity incidents.

### Key Components of a Modern SOC:
*   **People:** Security Analysts, Incident Responders, Threat Hunters.
*   **Processes:** Incident Response Plans, Playbooks, Standard Operating Procedures (SOPs).
*   **Technology:** Security Information and Event Management (SIEM), Endpoint Detection and Response (EDR), Security Orchestration, Automation, and Response (SOAR), Threat Intelligence Platforms (TIP).

## Core Open-Source Software for a SOC

This repository's use cases are built using a powerful open-source stack that can serve as the foundation for a full-featured SOC:

*   **Wazuh:** A free, open-source platform for XDR (Extended Detection and Response) and SIEM (Security Information and Event Management) capabilities. It provides threat detection, integrity monitoring, incident response, and regulatory compliance.
    *   🔗 [Official Installation Guide](https://documentation.wazuh.com/current/installation-guide/index.html)
*   **The ELK Stack (Elasticsearch, Logstash, Kibana):** The core platform for aggregating, processing, storing, and visualizing log data from any source. Elasticsearch is the search and analytics engine, Logstash is the server-side data processing pipeline, and Kibana is the visualization layer.
    *   🔗 [Official Elastic Installation Guide](https://www.elastic.co/guide/en/elastic-stack/current/installing-elastic-stack.html)
*   **Cortex:** A powerful open-source SOAR (Security Orchestration, Automation, and Response) platform designed to automate and streamline security operations. Analysts can use playbooks to automate response actions.
    *   🔗 [Official Cortex Documentation](https://docs.thehive-project.org/cortex/)
*   **MISP (Open Source Threat Intelligence Platform):** A platform for sharing, storing, and correlating Indicators of Compromise (IOCs) and threat intelligence.
    *   🔗 [Official MISP Installation Guide](https://www.misp-project.org/download/)

*Note: Installation and configuration of these tools are complex and beyond the scope of this README. Please refer to the official documentation linked above.*

## What are Use Cases?

In a SOC context, a **Use Case** is a predefined scenario that describes a specific pattern of activity indicative of a potential security threat. It consists of:
1.  **Trigger:** The specific event or log that starts the investigation.
2.  **Logic:** The correlation rules and analytical reasoning that ties events together to form an alert.
3.  **Response:** The action taken by the SOC analyst or an automated system upon detection.

## Use Cases in this Repository

This repository contains conceptual examples of use cases designed for the open-source stack mentioned above. The provided examples focus on threat scenarios common in infrastructure built on **Unix-like systems and open-source software**.

**Categories of use cases considered include:**
*   Privilege Escalation Attempts
*   Malicious Process Execution
*   Unauthorized Configuration Changes
*   Web Application Attacks (OWASP Top 10)
*   SSH Brute-Force & Anomalous Access
*   Suspicious Database Activity
*   Network Reconnaissance & Scanning

*Specific implementation details, rules, and queries are contained within the repository files.*

## Author & Contribution

This collection of use cases was conceptualized and documented by Ivan Piskunov.

Contributions, suggestions, and additional use cases are welcome. Please feel free to open an Issue or submit a Pull Request.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Disclaimer

These use cases are provided for **educational and illustrative purposes only**. They are conceptual examples and may require significant modification and tuning to work effectively in a specific production environment. The author is not responsible for any damage or misuse caused by the application of these examples. Always test thoroughly in a lab environment before deploying any new detection logic.
