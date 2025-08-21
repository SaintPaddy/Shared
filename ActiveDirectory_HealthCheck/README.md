# ActiveDirectory_HealthCheck

One-click **read-only** health check for Active Directory.

## What this does

- Runs a battery of **AD/DNS/replication/time/RID/SPN/trusts** checks.
- Collects outputs per command and **echoes the exact command** at the top of each file.
- Saves everything to:  
  `C:\temp_ad_health_log\AD-Health_<YYYY-MM-DD__HH-mm>\`
- Creates a ZIP for easy emailing:  
  `C:\temp_ad_health_log\AD-Health_<YYYY-MM-DD__HH-mm>.zip`
- Generates a **manifest.csv** + **console_transcript.txt** so you can see what ran and where.

> ✅ The script is **read-only**. It does not change AD or server settings.

---

## Files in this folder

- `ad_health.ps1` – the main PowerShell script (run as admin).
- `ad_health.cmd` – double-click launcher that elevates PowerShell and runs the script.
- `README.md` – this file.

---

## Quick Start (for admins)

1. **Copy files to C:\**
   - Place `ad_health.ps1` and `ad_health.cmd` in `C:\` (the C-drive root) on **one** domain controller.

2. **Run it**
   - Double-click `C:\ad_health.cmd`.
   - Click **Yes** on the admin/UAC prompt.

3. **Send the results**
   - When it finishes, open `C:\temp_ad_health_log\`.
   - Email the **ZIP** named like `AD-Health_YYYY-MM-DD__HH-mm.zip` to the requester.

That’s it.

---

## What gets collected (high level)

- **Domain/forest & FSMO**: `Get-ADDomain`, `Get-ADForest`, `netdom query fsmo`
- **Replication**: `repadmin /replsummary`, `repadmin /showrepl`, `Get-ADReplication*`
- **DNS health**: `dcdiag /test:DNS`, SRV lookups, DNS zone/scavenging (if DNS tools installed)
- **SYSVOL/DFSR**: `dfsrmig /GetGlobalState`, `dfsrdiag ReplicationState`
- **Time service**: `w32tm /monitor`, `w32tm /query /status`
- **RID health**: `dcdiag /test:ridmanager /v`
- **Duplicate SPNs**: `setspn -X`
- **Sites/Subnets/GC coverage**
- **Trusts overview**
- **Event logs (last 7 days, errors)**: Directory Service, DFS Replication, DNS Server
- **Per-DC network config**: `ipconfig /all` + DNS client server list
- **Port reachability matrix**: LDAP/LDAPS/Kerberos/GC/DNS/NTP
- **NTDS storage headroom**: DIT/logs path & disk free space
- **NLTEST DC list**: `nltest /dclist:<domain>`

Each text file starts with a header showing the **command** and **target**. Check `manifest.csv` to map commands → files.

---

## Requirements

- Run **on a domain controller**.
- Launch as **Administrator** (the `.cmd` does this for you).
- Windows Server 2012 R2 or newer is fine.
- Recommended (but not mandatory) features:
  - **RSAT: Active Directory module** (`ActiveDirectory` PowerShell module)
  - **DNS Server tools** (`DnsServer` module) for extra DNS details
- **PowerShell Remoting** (WinRM) optional:
  - Enables remote `ipconfig /all` and secure-channel checks on *other* DCs.
  - If disabled, the script logs a warning and continues.

> The script is built to **keep going** even if some tools/modules are missing. It logs any gaps.

---

## How to run (alternate methods)

If double-click doesn’t work or you prefer the console:

**Elevated PowerShell**
```powershell
PowerShell -NoProfile -ExecutionPolicy Bypass -File C:\ad_health.ps1
```
**Elevated CMD**
```bat
powershell -NoProfile -ExecutionPolicy Bypass -File C:\ad_health.ps1
```

---

## Output locations

- Folder: `C:\temp_ad_health_log\AD-Health_<YYYY-MM-DD__HH-mm>\`
- ZIP: `C:\temp_ad_health_log\AD-Health_<YYYY-MM-DD__HH-mm>.zip`
- Key files inside the folder:
  - `manifest.csv` – map of Command → Output file → Target → Status
  - `console_transcript.txt` – everything printed to the console
  - `dcdiag_*.txt`, `repadmin_*.txt`, `replication_*.csv`
  - `ipconfig_all_<DCNAME>.txt`, `dns_server_list_<DCNAME>.txt`
  - `events_*.txt`, `dns_*.txt`, `dfsr_*.txt`, `time_*.txt`, etc.

---

## Troubleshooting (common hiccups)

- **“running scripts is disabled on this system”**  
  Use the launcher (`ad_health.cmd`) or run with `-ExecutionPolicy Bypass` as shown above.

- **UAC prompt didn’t appear / Access denied**  
  Right-click the CMD file → **Run as administrator**.

- **Remoting warnings in logs**  
  That’s fine. To enable later:  
  `Enable-PSRemoting -Force` (run elevated).  
  The script works without it; remote checks just become local-only.

- **Missing AD/DNS modules**  
  The script logs what’s missing and skips those extras. (Optional to install RSAT.)

---

## Safety / privacy

- **Read-only**: no changes to AD, DNS, or services.
- Outputs may include **server names, IPs, and DNS info**. Send only to approved recipients.

---

## Repository structure

```
ActiveDirectory_HealthCheck/
├── README.md
├── ad_health.ps1
└── ad_health.cmd
```
