# **Endpoint Threat Hunting Report**  
**Platform:** Elastic (Kibana)  
**Focus:** Detecting Persistence, Lateral Movement, and Credential Access  

---

## **1. Objective**
This report documents a focused endpoint threat hunting engagement designed to identify and analyze potential persistence, lateral movement, and credential access techniques within a Windows environment. The activity simulated realistic post-compromise behavior using only built-in system tools and no external malware. The goal was to mirror common living off the land tactics and evaluate detection coverage.

---

## **2. Methodology**

### **2.1 Tools and Data Sources**
- **Elastic Stack (Kibana):** log aggregation and visual hunting  
- **Sysmon + Elastic Agent/Filebeat:** endpoint telemetry collection  
- **Windows Event Logs:** validation and context enrichment  

### **2.2 Approach**
The hunting strategy aligned with the MITRE ATT&CK framework techniques listed below.

| Phase | Technique | MITRE ID |
|:------|:-----------|:---------|
| Persistence | Scheduled Task or Job | T1053 |
| Lateral Movement | PsExec Execution | T1570 |
| Credential Access | LSASS Memory Dumping | T1003 |

Each hypothesis was tested through targeted KQL queries and manual log review to trace possible attacker behaviors.

---

## **3. Findings**

### **3.1 Persistence via Scheduled Tasks**
**Rationale:** Schtasks.exe is a standard Windows utility that adversaries frequently abuse to achieve persistence across reboots.

**KQL Query**
```kql
process.name: "schtasks.exe"
```

**Observed Indicators**
- PowerShell commands embedded within scheduled task creation  
- Hidden execution flags such as `-WindowStyle Hidden`, `-ep bypass`, and `-nop`  
- Command lines suggesting potential script downloads or obfuscation  

**Interpretation:**  
The activity was consistent with MITRE T1053.003 behavior. It indicated a possible scheduled PowerShell payload used for recurring execution or maintaining control after reboot.

---

### **3.2 Lateral Movement via PsExec**
**Rationale:** PsExec is often used by attackers after stealing credentials to execute commands remotely while appearing as normal administrative activity.

**KQL Query**
```kql
process.name: "PsExec64.exe" OR process.name: "PsExec.exe"
```

**Observed Indicators**
- Execution with flags such as `-u`, `-p`, and `-s` showing credential use  
- Target hosts resembling internal domain systems like `\\dc01`  
- Parent process chains consistent with interactive command-line use  

**Visual Evidence**

![PsExec Execution Trace in Elastic](https://github.com/user-attachments/assets/518df23c-5246-4e59-9a36-f3db89b9de05)

**Interpretation:**  
The data indicated credential-based remote execution that aligned with MITRE T1570 (Lateral Tool Transfer). In a production environment this would justify credential audits and possible endpoint isolation.

---

### **3.3 Credential Access via LSASS**
**Rationale:** Accessing the LSASS process memory is a strong sign of credential dumping. Tools like Mimikatz or PowerShell injection methods often target LSASS to extract user logins.

**KQL Query**
```kql
winlog.channel: "Microsoft-Windows-Sysmon/Operational" 
AND event.code: "10" 
AND winlog.event_data.TargetImage: "*lsass.exe*"
```

**Observed Indicators**
- Non-system processes attempting handle access to LSASS  
- Parent process trees inconsistent with legitimate authentication flows  
- Binaries located in non-standard directories  

**Interpretation:**  
The event pattern matched MITRE T1003 for OS Credential Dumping. Memory forensics and endpoint isolation would be necessary to confirm and mitigate potential credential theft.

---

## **4. Analysis Summary**
| Stage | Technique | MITRE ID | Description |
|:-------|:-----------|:----------|:-------------|
| 1 | Scheduled Tasks | T1053 | Creation of recurring task for persistence |
| 2 | PsExec | T1570 | Remote execution using captured credentials |
| 3 | LSASS Access | T1003 | Memory access for credential harvesting |

The investigation proved that native Windows tools can be abused to achieve persistence, movement, and credential access without malware deployment.

---

## **5. Conclusions and Recommendations**

### **Key Takeaways**
- Behavioral analytics outperform signature-based detection when facing living off the land techniques.  
- Sysmon events provide the best process-level visibility for correlation.  
- Elastic dashboards simplify contextual log review across multiple attack stages.  

### **Recommended Actions**
1. Configure Elastic rules for common malicious command-line patterns.  
2. Limit administrative tool use to verified system accounts only.  
3. Enable Sysmon Event ID 10 monitoring across all hosts.  
4. Apply Endpoint Detection and Response (EDR) policies to prevent non-system processes from accessing LSASS.  
5. Continue building hunting playbooks to cover each MITRE ATT&CK tactic.  

---

## **6. Lessons Learned**
This hunt enhanced proficiency in KQL query writing, behavior correlation, and understanding of post-compromise activity stages. It also reinforced the value of log context and event sequence analysis. Effective detection depends not on isolated alerts but on how each event tells a coherent story.

---
