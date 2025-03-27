## **🎯Sudden Network Slowdowns Incident**

![image (6)](https://github.com/user-attachments/assets/13a2858a-3e92-43fe-9b05-1df1ac32d1ac)

# Incident Investigation Report

## 📚 **Scenario:**
I noticed a significant network performance degradation on some of the older devices attached to the network in the `10.0.0.0/16` network. After ruling out external DDoS attacks, the security team suspects something might be going on internally. All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.

---

## 📊 **Incident Summary and Findings**

Goal: Gather relevant data from logs, network traffic, and endpoints.
Consider inspecting the logs for excessive successful/failed connections from any devices.  If discovered, pivot and inspect those devices for any suspicious file or process events.
Activity: Ensure data is available from all key sources for analysis.
Ensure the relevant tables contain recent logs:
DeviceNetworkEvents
DeviceFileEvents
DeviceProcessEvents

```kql
DeviceFileEvents
| order by Timestamp desc 
| take 10

DeviceNetworkEvents
| order by Timestamp desc 
| take 10

DeviceProcessEvents
| order by Timestamp desc 
| take 10
```

### **Timeline Overview**
1. **🔍 Windows-target-1 was found failing several connection requests against itself and another host on the same network.**

   **Detection Query (KQL):**
   ```kql
   DeviceNetworkEvents
   | where ActionType == "ConnectionFailed"
   | summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
   | order by ConnectionCount
   ```

![Screenshot 2025-01-06 104150](https://github.com/user-attachments/assets/2eb708ed-7191-4219-b1a8-7fd416eee0c2)


2. **⚙️ Process Analysis:**
   - **Observed Behavior:** After observing failed connection requests from a suspected host (`10.0.0.5`) in chronological order, I noticed a port scan was taking place due to the sequential order of the ports. There were several port scans being conducted.

   **Detection Query (KQL):**
   ```kql
   let IPInQuestion = "10.0.0.5";
   DeviceNetworkEvents
   | where ActionType == "ConnectionFailed"
   | where LocalIP == IPInQuestion
   | order by Timestamp desc
   ```
![Screenshot 2025-01-06 110119](https://github.com/user-attachments/assets/0a413b76-a739-4779-ac8a-aa3cd4a8ff9e)

   

3. **🌐 Network Check:**
   - **Observed Behavior:** I pivoted to the `DeviceProcessEvents` table to see if we could see anything that was suspicious around the time the port scan started. We noticed a PowerShell script named `portscan.ps1` launched at `2025-01-06T06:37:00.774381Z`.

   **Detection Query (KQL):**
```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-01-06T06:37:00.774381Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
![Screenshot 2025-01-13 161326](https://github.com/user-attachments/assets/ad26dcfb-2c43-4674-8a14-f926415d9ee6)

5. **📝 Response:**
   - We observed the port scan script was launched by the SYSTEM account. This is not expected behavior and it is not something that was setup by the admins. I isolated the device and ran a malware scan. The malware scan produced no results, so out of caution, I kept the device isolated and put in a ticket to have it re-image/rebuilt. Shared findings with the manager, highlighting automated archive creation. Awaiting further instructions.
 

![Screenshot 2025-01-06 112548](https://github.com/user-attachments/assets/545363b9-cf69-4609-b40a-1af34c18c86e)


---

# MITRE ATT&CK Techniques for Incident Notes

| **Tactic**                | **Technique**                                                                                       | **ID**       | **Description**                                                                                                                                 |
|---------------------------|---------------------------------------------------------------------------------------------------|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| **Initial Access**         | [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)                     | T1210        | Failed connection attempts may indicate an attacker probing for open ports or exploitable services.                                            |
| **Discovery**              | [Network Service Scanning](https://attack.mitre.org/techniques/T1046/)                           | T1046        | Sequential port scans performed using a script (`portscan.ps1`) align with service discovery activity.                                         |
| **Execution**              | [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)  | T1059.001    | The use of PowerShell (`portscan.ps1`) for conducting network scanning demonstrates script-based execution.                                    |
| **Persistence**            | [Account Manipulation](https://attack.mitre.org/techniques/T1098/)                               | T1098        | Unauthorized use of the SYSTEM account to launch a script indicates potential persistence through credential manipulation.                     |
| **Privilege Escalation**   | [Valid Accounts](https://attack.mitre.org/techniques/T1078/)                                     | T1078        | SYSTEM account execution suggests privilege escalation by leveraging valid but unauthorized credentials.                                       |
| **Defense Evasion**        | [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)                    | T1027        | If `portscan.ps1` contained obfuscated commands, this technique may have been used to avoid detection.                                         |
| **Impact**                 | [Network Denial of Service](https://attack.mitre.org/techniques/T1498/)                          | T1498        | The significant network slowdown could be a side effect or an intentional impact of excessive scanning activity.                              |

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Created By:
- **Author Name**: Owen Kerrisk
- **Author Contact**: https://www.linkedin.com/in/trevinoparker/
- **Date**: Mar 2025

## Validated By:
- **Reviewer Name**: Josh Madakor
- **Reviewer Contact**: https://www.linkedin.com/in/joshmadakor/
- **Validation Date**: Mar 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `Mar 2025`  | `Owen Kerrisk`   
