# Endpoint Threat Hunting – Detecting Persistence, Lateral Movement, and Credential Access

Threat actors don’t always use malware to compromise environments — sometimes, the tools are already there. This project walks through how I used Elastic (Kibana) to investigate suspicious endpoint behavior: scheduled tasks for persistence, PsExec for lateral movement, and process access to lsass.exe for potential credential dumping.

This was done as part of a threat hunting lab to simulate real-world techniques and sharpen detection skills.

---

🔍 **The Goal**  
Track the steps of an attacker after initial access:
- Did they create persistence mechanisms?
- Did they attempt to move laterally?
- Did they try to harvest credentials?

---

### 🧱 Toolset Used
- **Elastic Stack (Kibana)** for hunting and log review  
- **Sysmon + Filebeat/Elastic Agent** for endpoint telemetry  
- **Windows logs** for deep visibility into process execution and access  

---

## 🧪 Step 1: Scheduled Task – Persistence

### 🎯 Why I looked here  
Scheduled tasks are commonly used for persistence — they're stealthy and don’t need continuous access. If an attacker wants a payload to run quietly and repeatedly, this is one of the first places they'll go.

### 🔎 What I searched
I started by filtering for scheduled task execution via:
```
process.name: "schtasks.exe"
```

Then pulled in:
- `process.command_line`  
- Looked for signs of PowerShell usage  
- Flags like `-WindowStyle Hidden`, `-ep bypass`, `-nop`  
- Also watched for download activity (network calls)

---

## 🧪 Step 2: PsExec – Lateral Movement

### 🎯 Why I looked here  
Lateral movement typically follows initial compromise. Admin tools like PsExec are often used because they blend in with legitimate IT activity. If an attacker grabs credentials, PsExec might be how they escalate.

### 🔎 What I searched
To detect PsExec behavior:
```
process.name: "PsExec64.exe" OR process.name: "PsExec.exe"
```

Then added:
- `process.args` to see what switches were used  
- Looked for flags like `-u`, `-p`, `-s`, and any sign of target systems like `\dc01`

This helped me trace if credentials were passed and where access was attempted.
![image](https://github.com/user-attachments/assets/518df23c-5246-4e59-9a36-f3db89b9de05)

---

## 🧪 Step 3: Credential Access – Targeting LSASS

### 🎯 Why I looked here  
After landing on high-value machines (like domain controllers), attackers often try to dump credentials. Access to `lsass.exe` is a red flag. I focused on process access events that might show this happening.

### 🔎 What I searched
Using Sysmon’s Event ID 10 (process access):
```
winlog.channel: "Microsoft-Windows-Sysmon/Operational" AND event.code: "10" AND winlog.event_data.TargetImage: "*lsass.exe*"
```

From there, I traced:
- Which process touched LSASS  
- Who launched it  
- Where the binary was located

---

## 🧠 What I Learned

This hunt sharpened my ability to:
- Write tight KQL queries  
- Spot signs of post-exploitation using native tools  
- Map attacker behavior to MITRE ATT&CK tactics  
- Work through multi-stage activity across systems

---

✅ **Why this approach matters**
- Doesn’t rely on alerts — I hunted from raw logs  
- Showed how native Windows tools can be abused  
- Reinforced the importance of context and sequence  

Even without malware, the logs told a story.

