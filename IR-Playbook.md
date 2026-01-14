# Incident Response Playbook: Phishing Email with Malicious Link

## Overview

This playbook outlines the steps for detecting, analyzing, containing, eradicating, recovering from, and documenting incidents involving phishing emails with malicious links. It integrates both automated actions, leveraging AI-driven security tools and SOAR platforms, and manual procedures for human analysts. The goal is to provide a structured and efficient response to mitigate the impact of phishing attacks.

## How to Use This Playbook

1.  **Store in Version Control:** Keep this Markdown file in a Git repository (e.g., GitHub, GitLab) for version control, collaboration, and auditability.
2.  **Integrate with SOAR (Optional but Recommended):** While this playbook documents the process, a Security Orchestration, Automation, and Response (SOAR) platform can execute many of the "Automated Actions" directly. Update `link_to_soar_definition` placeholders with actual links to your SOAR playbooks.
3.  **Link to Tools:** Update `link_to_github_repo` or `link_to_tool_docs` placeholders with relevant URLs to your internal scripts, EDR, SIEM, or other security tool documentation.
4.  **Populate Placeholders:** During an incident, replace variables like `{PHISHING_EMAIL_ID}`, `{RECIPIENT_EMAIL}`, `{MALICIOUS_URL}`, etc., with actual incident-specific data.
5.  **Train Your Team:** Ensure all incident responders are familiar with this playbook and the tools involved.
6.  **Regular Review:** Review and update this playbook periodically (e.g., quarterly, or after major incidents/tool changes) to ensure its accuracy and effectiveness.

## Disclaimer

This playbook is a template and should be adapted to your organization's specific environment, tools, policies, and risk tolerance. All automated actions should be thoroughly tested in a non-production environment before deployment. [Your Organization Name] is not liable for any damages or issues arising from the use or misuse of this playbook.

---

## Incident Details

*   **Incident Type:** Phishing Email with Malicious Link
*   **MITRE ATT&CK Techniques:** T1566.002 (Phishing: Spearphishing Link), T1078 (Valid Accounts), T1059 (Command and Scripting Interpreter)
*   **Targeted Assets:** End-user workstations, email accounts, network credentials, potentially enterprise network.

---

## 1. Severity and Priority Assessment

**Objective:** Rapidly categorize the incident to determine response urgency and resource allocation.

**Severity Criteria:**

*   **Critical:** Compromise confirmed, multiple users/endpoints affected, potential data exfiltration or credential theft.
*   **High:** Link clicked, user credentials entered on a malicious site, or attachment opened.
*   **Medium:** Link received, but no user interaction. Widespread distribution within the organization.
*   **Low:** Isolated incident, link blocked by email gateway, user reported without interaction.

**Automated Action:** Initial Severity Assignment (if integrated with SIEM/SOAR)
*   **Tool:** SIEM/SOAR Platform.
*   **Logic:**
    *   If `{User_Interaction_Confirmed}` = TRUE and `{Credential_Entry_Confirmed}` = TRUE: **CRITICAL**
    *   If `{User_Interaction_Confirmed}` = TRUE and `{Credential_Entry_Confirmed}` = FALSE: **HIGH**
    *   If `{Email_Distribution_Count}` > 50: **MEDIUM**
    *   Else: **LOW**
*   **Expected Output:** Incident Severity (`Critical`/`High`/`Medium`/`Low`).

---

## 2. Detection

**Objective:** Identify the source and initial indicators of the phishing incident.

**Detection Sources:**

*   **Email Security Gateway (ESG):** Blocks email and generates alert.
*   **Endpoint Detection and Response (EDR):** Detects malicious activity post-click (e.g., browser exploits, new processes, suspicious downloads).
*   **Security Information and Event Management (SIEM):** Correlates alerts from ESG, EDR, proxy logs, etc.
*   **User Report:** Employee reports suspicious email via security reporting tool (e.g., M365 Report Message button, dedicated email).
*   **Threat Intelligence (TI) Feeds:** Match identified URLs/IPs with known malicious indicators.
*   **AI-Driven Anomaly Detection:** Behavioral AI models flag unusual email patterns or user click behavior.

---

## 3. Initial Triage

**Objective:** Confirm the incident, gather initial context, and establish the immediate scope.

### Automated Actions (SOAR Playbook: `Phishing_Triage_v1.0`)
*(Executed automatically upon alert trigger from ESG, EDR, SIEM, or user report)*

1.  **Extract Indicators of Compromise (IOCs):**
    *   **Description:** Parse email content to extract sender address, recipient list, subject, email body, URLs (malicious, legitimate), and attachment hashes.
    *   **Tool:** SOAR Platform (integrates with Email Gateway API / EDR for email metadata).
    *   **Expected Output:** JSON object containing extracted IOCs.
2.  **Threat Intelligence Enrichment:**
    *   **Description:** Query internal and external TI feeds (e.g., VirusTotal, AbuseIPDB, internal reputation scores) for all extracted URLs and sender IPs.
    *   **Tool:** SOAR Platform (integrates with TI platforms).
    *   **Expected Output:** TI scores and context for each IOC. Flag any known malicious indicators.
3.  **Check User Interaction:**
    *   **Description:** Query proxy logs/EDR to determine if any recipient clicked the malicious URL. If clicked, check browser history for subsequent actions (e.g., credential entry page).
    *   **Tool:** SOAR Platform (integrates with Proxy Logs, EDR, Identity Provider (IdP)).
    *   **Expected Output:** Boolean `{User_Interaction_Confirmed}`, `{Credential_Entry_Confirmed}`, `{Click_Timestamp}`, `{Source_IP}`.
4.  **Internal Mailbox Scan:**
    *   **Description:** Search all organizational mailboxes for identical or similar emails.
    *   **Tool:** SOAR Platform (integrates with M365/Exchange API).
    *   **Expected Output:** List of `{Additional_Recipients}`.
5.  **Create Incident Ticket:**
    *   **Description:** Automatically create a detailed incident ticket in Jira or ServiceNow, populating it with all collected IOCs, user interaction status, and initial severity.
    *   **Tool:** Jira/ServiceNow API via SOAR.
    *   **Expected Output:** Jira ticket ID: `SEC-PHISH-{YYYYMMDD}-{#####}`.

### Manual Actions (by Incident Responder)

1.  **Review Automated Triage Results:** Examine the incident ticket `SEC-PHISH-{YYYYMMDD}-{#####}` and SOAR playbook execution logs. Verify the identified IOCs and user interaction status.
2.  **Initial Communication:** If user interaction is confirmed, immediately contact the affected user(s) via an alternative, secure channel (e.g., phone call) to gather more details and instruct them not to click any further links or delete emails.
3.  **Prioritize:** Based on confirmed user interaction, credential entry, and scope, re-evaluate initial severity and adjust as necessary.
4.  **Immediate Threat Assessment:**
    *   If `{Credential_Entry_Confirmed}` = TRUE, consider the user's account compromised. Proceed immediately to **Containment: User Account Remediation**.
    *   If `{User_Interaction_Confirmed}` = TRUE but no credential entry, focus on endpoint analysis. Proceed to **Containment: Endpoint Remediation**.

---

## 4. Containment

**Objective:** Limit the incident's scope and prevent further damage or propagation.

### Automated Actions (Triggered by SOAR or manual command)

1.  **Isolate Affected Endpoints:**
    *   **Description:** If user interaction with a malicious link is confirmed, automatically isolate the affected endpoint(s) from the network (except for security tools communication).
    *   **Tool:** EDR (e.g., CrowdStrike, SentinelOne) via API.
    *   **Command:** `[EDR_CLI_TOOL isolate_endpoint --agent-id {ENDPOINT_ID} --reason "Phishing Incident"]`
    *   **Expected Output:** Confirmation of endpoint isolation.
2.  **Block Malicious IOCs:**
    *   **Description:** Automatically push identified malicious URLs and IPs to network firewalls, web proxies, and email gateways.
    *   **Tool:** SOAR Platform (integrates with Firewall/Proxy/ESG APIs).
    *   **Command:** `[FIREWALL_API add_blacklist_entry {MALICIOUS_URL}, {MALICIOUS_IP}]`
    *   **Expected Output:** Confirmation of IOC blocking.
3.  **Email Quarantine/Deletion:**
    *   **Description:** Automatically quarantine or hard-delete all identified phishing emails from all internal mailboxes.
    *   **Tool:** SOAR Platform (integrates with M365/Exchange API).
    *   **Command:** `[M365_CMDLET search_and_delete -query {EMAIL_SUBJECT}, {SENDER_ADDRESS}]`
    *   **Expected Output:** Count of emails quarantined/deleted.
4.  **Disable Compromised Accounts:**
    *   **Description:** If `{Credential_Entry_Confirmed}` = TRUE, immediately disable the affected user's account in the Identity Provider (IdP) and Active Directory.
    *   **Tool:** SOAR Platform (integrates with IdP/AD APIs).
    *   **Command:** `[AD_CMDLET disable_user {USER_ACCOUNT_ID}]`
    *   **Expected Output:** Confirmation of account disablement.

### Manual Actions (by Incident Responder)

1.  **Verify Automated Containment:** Confirm endpoint isolation, IOC blocking, and email removal.
2.  **Network Segmentation:** For critical incidents, work with network operations to apply granular network segmentation or ACLs if automated tools are insufficient.
3.  **Review Logs for Lateral Movement:** Analyze SIEM and EDR logs for any signs of lateral movement or persistence attempts from isolated endpoints or compromised accounts *before* account disablement.
4.  **Alert Stakeholders:** Notify relevant internal teams (e.g., IT Operations, Legal, HR) about the incident and ongoing containment efforts, following the Communication Plan.

---

## 5. Eradication

**Objective:** Eliminate the root cause of the incident and remove all traces of the attacker's presence.

### Automated Actions (Triggered by SOAR or manual command)

1.  **Endpoint Scan & Remediation:**
    *   **Description:** Initiate a full, in-depth anti-malware scan on the isolated endpoint(s). Automatically remove any identified malware or suspicious files.
    *   **Tool:** EDR (e.g., CrowdStrike, SentinelOne) via API.
    *   **Command:** `[EDR_CLI_TOOL full_scan --agent-id {ENDPOINT_ID} --auto-remediate]`
    *   **Expected Output:** Scan results and remediation actions taken.
2.  **Remove Persistence (if identified):**
    *   **Description:** If specific persistence mechanisms (e.g., new registry keys, scheduled tasks) were identified in triage, automatically remove them.
    *   **Tool:** EDR / Remote Script Execution via SOAR.
    *   **Command:** `[EDR_CLI_TOOL delete_registry_key {REG_PATH}]`
    *   **Expected Output:** Confirmation of persistence removal.

### Manual Actions (by Incident Responder)

1.  **Thorough Forensics (if critical):** For critical incidents, initiate a full forensic analysis of the compromised endpoint(s) and accounts to ensure all aspects of compromise are understood and remediated.
2.  **Wipe and Reimage (if compromise is severe):** If compromise is deep or uncertain, recommend wiping and reimaging affected systems from a trusted source.
3.  **Credential Reset:** Force a password reset for all affected users (especially if credentials were stolen). Consider MFA reset for enhanced security.
4.  **Remove Unauthorized Access:** Review and remove any unauthorized access credentials, API keys, or backdoor accounts created by the attacker.

---

## 6. Recovery

**Objective:** Restore affected systems and services to normal operations securely.

### Automated Actions (Triggered by SOAR or manual command)

1.  **System Health Checks:**
    *   **Description:** Run automated health checks on recovered systems to ensure functionality and stability post-remediation.
    *   **Tool:** Monitoring System / EDR via API.
    *   **Expected Output:** "System Health Check Passed" status.
2.  **Vulnerability Scan:**
    *   **Description:** Initiate a post-remediation vulnerability scan on affected systems to ensure no new vulnerabilities were introduced and existing ones were resolved.
    *   **Tool:** Vulnerability Scanner via API.
    *   **Expected Output:** Scan report indicating no critical findings.
3.  **Re-enable Accounts/Endpoints:**
    *   **Description:** If all checks pass, automatically re-enable user accounts and rejoin isolated endpoints to the network.
    *   **Tool:** IdP/AD API, EDR API.
    *   **Command:** `[AD_CMDLET enable_user {USER_ACCOUNT_ID}]`, `[EDR_CLI_TOOL rejoin_endpoint --agent-id {ENDPOINT_ID}]`
    *   **Expected Output:** Confirmation of re-enablement.

### Manual Actions (by Incident Responder)

1.  **Verify Functionality:** Ensure business operations on affected systems are fully restored and functioning as expected.
2.  **User Education:** Provide targeted security awareness training to affected users, emphasizing the dangers of phishing and safe internet practices.
3.  **Continuous Monitoring:** Place affected systems and accounts under heightened monitoring for a defined period to detect any recurring or new suspicious activity.

---

## 7. Post-Incident Analysis (Lessons Learned)

**Objective:** Document the incident, identify root causes, and implement improvements.

### Automated Actions (Triggered by SOAR or manual command)

1.  **Generate Incident Report Draft:**
    *   **Description:** Automatically compile all data from the incident ticket, SOAR logs, and tool outputs into a draft post-incident report.
    *   **Tool:** SOAR Platform (integrates with reporting tools).
    *   **Expected Output:** Draft report document.
2.  **Update Threat Intelligence:**
    *   **Description:** Automatically ingest newly confirmed malicious IOCs into internal threat intelligence platforms.
    *   **Tool:** TI Platform API via SOAR.
    *   **Expected Output:** IOCs added to TI.
3.  **Log Retention:**
    *   **Description:** Ensure all relevant logs and evidence related to the incident are securely archived for audit and future analysis.
    *   **Tool:** SIEM/Log Management System.

### Manual Actions (by Incident Responder & Stakeholders)

1.  **Conduct Lessons Learned Meeting:**
    *   **Participants:** Incident responders, relevant IT/business stakeholders, management.
    *   **Agenda:** Review incident timeline, effectiveness of response, root cause analysis, identification of control failures, and improvement opportunities.
2.  **Update Playbook:** Based on lessons learned, update this playbook or create new ones if a novel incident type was encountered.
3.  **Enhance Controls:** Submit recommendations for improving preventative, detective, and corrective security controls (e.g., enhanced email filtering, new EDR rules, additional user training).
4.  **Management Reporting:** Finalize and present the post-incident report to executive leadership.

---

## 8. Communication Plan

**Objective:** Ensure timely and appropriate communication throughout the incident lifecycle.

### Automated Actions (Triggered by SOAR or manual command)

1.  **Initial Alert:**
    *   **Description:** Send immediate notification to SOC team via internal chat (e.g., Slack/Teams) and create a high-priority ticket.
    *   **Tool:** SOAR Platform.
    *   **Notification:** `@security-soc Alert: Phishing incident initiated by {DETECTION_SOURCE} - SEC-PHISH-{YYYYMMDD}-{#####}`
2.  **Severity Escalation:**
    *   **Description:** If severity is escalated to High or Critical, automatically notify management and relevant stakeholders via email/SMS.
    *   **Tool:** SOAR Platform.
    *   **Notification:** "Critical Phishing Alert: Incident SEC-PHISH-{YYYYMMDD}-{#####} affecting {IMPACTED_ASSETS}."
3.  **Status Updates:**
    *   **Description:** Automatically post regular status updates to incident communication channels (e.g., internal chat #incident-updates) at key milestones (Containment achieved, Eradication complete).
    *   **Tool:** SOAR Platform.

### Manual Actions (by Incident Commander/Lead Responder)

1.  **Affected User Communication:** Directly communicate with affected users to provide guidance, reassurance, and instructions.
2.  **Internal Stakeholder Updates:** Provide regular, tailored updates to IT leadership, business unit owners, legal, HR, and public relations, as appropriate for the incident's severity and impact.
3.  **External Communication (if necessary):** If data breach or regulatory notification is required, coordinate with Legal and PR teams for external communication.
4.  **Final Resolution:** Announce incident resolution and next steps to all relevant parties.

---

## 9. References & Tools

*   **Email Security Gateway (ESG):** [Link to ESG Documentation/Login]
*   **Endpoint Detection and Response (EDR):** [Link to EDR Documentation/Login]
*   **Security Information and Event Management (SIEM):** [Link to SIEM Documentation/Login]
*   **SOAR Platform:** [Link to SOAR Platform Login/Playbook Library]
    *   `Phishing_Triage_v1.0` Playbook: [Link to Phishing Triage Playbook Definition]
    *   `Endpoint_Isolation_v1.0` Playbook: [Link to Endpoint Isolation Playbook Definition]
*   **Threat Intelligence Platform:** [Link to TI Platform Login]
*   **Identity Provider (IdP) / Active Directory (AD):** [Link to IdP/AD Management Console]
*   **Jira / ServiceNow:** [Link to Incident Management System]
*   **Internal Security Policies:** [Link to Security Policy Document]
*   **Security Awareness Training Portal:** [Link to Training Portal]
*   **Python Automation Scripts:**
    *   `disable_ad_user.py`: [Link to `disable_ad_user.py` in Git Repo]
    *   `query_m365_logs.py`: [Link to `query_m365_logs.py` in Git Repo]
*   **MITRE ATT&CK Framework:** [https://attack.mitre.org/](https://attack.mitre.org/)

---
