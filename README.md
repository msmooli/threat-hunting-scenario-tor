

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/msmooli/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table to find ANY file’s named “tor” in it i discovered what looks like the user “nimbus” downloaded a tor installer did result in many tor files being installed and copied and the creation of file name called tor-shopping-list.txt on the desktop. 
These events began at: 2025-07-09T15:59:55.169749Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "nimbus"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-09T15:48:32.056018Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![Screenshot 2025-07-10 at 10 42 50 AM](https://github.com/user-attachments/assets/16f36ec4-8171-479f-b950-83be2780ecbf)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any  process command line that contained the string tor-browser-windows-x86_64-portable-14.5.4.exe. Based on the logs returned at 2025-07-09T15:50:26.5824949Z a user named account name “nimbus” on a device called threat-hunt-lab opened the Tor Browser file from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
![Screenshot 2025-07-10 at 10 53 11 AM](https://github.com/user-attachments/assets/e37e7507-8630-4d1e-acfb-e36bf7429732)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “nimbus” actually opened the tor browser. There was evidence that they did open it at 2025-07-09T15:54:17.9482317Z. There were several other instances of firefox.exe(Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
![Screenshot 2025-07-10 at 10 55 41 AM](https://github.com/user-attachments/assets/1f398515-53df-45b6-9627-5dd8f7c5ae88)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any tor ports at 2025-07-09T15:52:09.1764086Z, the user nimbus opened Firefox from the folder c:\users\nimbus\desktop\tor browser\browser\, and the browser successfully connected to the local IP address 217.160.247.34 on port 9001, which is used by Tor to manage anonymous internet traffic.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort,RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
![Screenshot 2025-07-10 at 10 57 27 AM](https://github.com/user-attachments/assets/bf260d25-7676-416b-88b5-2ac178820eca)

---

Chronological Events

Here's a detailed timeline report of the Tor browser usage and threat hunt steps, followed by a summary of events:

Timeline Report: Tor Browser Usage on "threat-hunt-lab" by User "nimbus"
All timestamps are in Coordinated Universal Time (UTC).

2025-07-09T15:50:26.5824949Z - Tor Browser Installer Execution (Silent Installation)
Action: User "nimbus" on device "threat-hunt-lab" opened the Tor Browser installer from their Downloads folder.
Details: The process command line contained "tor-browser-windows-x86_64-portable-14.5.4.exe", indicating a silent installation was triggered.
Source: DeviceProcessEvents

2025-07-09T15:52:09.1764086Z - Tor Browser Network Connection Established
Action: User "nimbus" opened Firefox (from c:\users\nimbus\desktop\tor browser\browser\) which successfully connected to a Tor network.
Details: The connection was established to the remote IP address 217.160.247.34 on port 9001, a known Tor port for managing anonymous internet traffic.
Source: DeviceNetworkEvents

2025-07-09T15:54:17.9482317Z - Tor Browser Application Launched
Action: User "nimbus" opened the Tor browser.
Details: Evidence shows "firefox.exe" (identified as Tor) was launched, followed by several other instances of "firefox.exe" (Tor) and "tor.exe" being spawned.
Source: DeviceProcessEvents
2025-07-09T15:59:55.169749Z - Tor File Installation and Creation of "tor-shopping-list.txt"
Action: Numerous Tor-related files were installed and copied, and a file named "tor-shopping-list.txt" was created on the user's desktop.
Details: This indicates the successful installation of Tor and the creation of a user-specific file potentially related to Tor activities.
Source: DeviceFileEvents

Summary of Events:
On July 9, 2025, at approximately 15:50 UTC, the user "nimbus" on the "threat-hunt-lab" device initiated a silent installation of the Tor Browser. Shortly after, at 15:52 UTC, the Tor Browser (Firefox) established a network connection to a known Tor relay on port 9001, indicating active usage of the anonymity network. By 15:54 UTC, the Tor Browser application was fully launched, with multiple related processes appearing in the system logs. The installation process also resulted in the creation of numerous Tor-related files and, notably, a file named "tor-shopping-list.txt" on the user's desktop at 15:59 UTC, suggesting potential illicit or unauthorized activities.

Response Taken

TOR usage was confirmed on endpoint threat-hunt-lab by the user nimbus. The device was isolated and the user's direct manager was notified.

---
