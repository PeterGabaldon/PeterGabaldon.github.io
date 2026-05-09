---
layout: page
title: CVEs
icon: fas fa-bug
order: 1
---

This is the full list of CVEs that I have discovered and that have been published.

| CVE ID | Date | Short Description | Exploit Links |
|---|---|---|---|
| [CVE-2024-3704](https://www.cve.org/CVERecord?id=CVE-2024-3704) | 2024-04-11 | SQL Injection Vulnerability has been found on OpenGnsys product affecting version 1.1.1d (Espeto). This vulnerability allows an attacker to inject malicious SQL code into login page to bypass it or even retrieve all the information stored in the database. | |
| [CVE-2024-3705](https://www.cve.org/CVERecord?id=CVE-2024-3705) | 2024-04-11 | Unrestricted file upload vulnerability in OpenGnsys affecting version 1.1.1d (Espeto). This vulnerability allows an attacker to send a POST request to the endpoint '/opengnsys/images/M_Icons.php' modifying the file extension, due to lack of file extension verification, resulting in a webshell injection. | |
| [CVE-2024-3706](https://www.cve.org/CVERecord?id=CVE-2024-3706) | 2024-04-11 | Information exposure vulnerability in OpenGnsys affecting version 1.1.1d (Espeto). This vulnerability allows an attacker to view a php backup file (controlaccess.php-LAST) where database credentials are stored. | |
| [CVE-2024-3707](https://www.cve.org/CVERecord?id=CVE-2024-3707) | 2024-04-11 | Information exposure vulnerability in OpenGnsys affecting version 1.1.1d (Espeto). This vulnerability allows an attacker to enumerate all files in the web tree by accessing a php file. | |
| [CVE-2024-1343](https://www.cve.org/CVERecord?id=CVE-2024-1343) | 2024-02-19 | A weak permission was found in the backup directory in LaborOfficeFree affecting version 19.10. This vulnerability allows any authenticated user to read backup files in the directory '%programfiles(x86)% LaborOfficeFree BackUp'. | |
| [CVE-2024-1344](https://www.cve.org/CVERecord?id=CVE-2024-1344) | 2024-02-19 | Encrypted database credentials in LaborOfficeFree affecting version 19.10. This vulnerability allows an attacker to read and extract the username and password from the database of 'LOF_service.exe' and 'LaborOfficeFree.exe' located in the '%programfiles(x86)%\LaborOfficeFree\' directory. This user can log in remotely and has root-like privileges. | |
| [CVE-2024-1345](https://www.cve.org/CVERecord?id=CVE-2024-1345) | 2024-02-19 | Weak MySQL database root password in LaborOfficeFree affects version 19.10. This vulnerability allows an attacker to perform a brute force attack and easily discover the root password. | |
| [CVE-2024-1346](https://www.cve.org/CVERecord?id=CVE-2024-1346) | 2024-02-19 | Weak MySQL database root password in LaborOfficeFree affects version 19.10. This vulnerability allows an attacker to calculate the root password of the MySQL database used by LaborOfficeFree using two constants. | |
| [CVE-2024-7481](https://www.cve.org/CVERecord?id=CVE-2024-7481)<br>[ZDI-24-1290](https://www.zerodayinitiative.com/advisories/ZDI-24-1290/) | 2024-08-20 | Improper verification of cryptographic signature during installation of a Printer driver via the TeamViewer_service.exe component of TeamViewer Remote Clients prior version 15.58.4 for Windows allows an attacker with local unprivileged access on a Windows system to elevate their privileges and install drivers. | |
| [CVE-2024-7479](https://www.cve.org/CVERecord?id=CVE-2024-7479)<br>[ZDI-24-1289](https://www.zerodayinitiative.com/advisories/ZDI-24-1289/) | 2024-08-20 | Improper verification of cryptographic signature during installation of a VPN driver via the TeamViewer_service.exe component of TeamViewer Remote Clients prior version 15.58.4 for Windows allows an attacker with local unprivileged access on a Windows system to elevate their privileges and install drivers. | |
| [CVE-2025-40678](https://www.cve.org/CVERecord?id=CVE-2025-40678) | 2025-08-02 | FortiGate VPN SSL Honeypot Information Disclosure | |
| [CVE-2025-40677](https://www.cve.org/CVERecord?id=CVE-2025-40677) | 2025-10-10 | FortiGate Symlink Attack leading to Arbitrary File Write | |
| [CVE-2025-68686](https://www.cve.org/CVERecord?id=CVE-2025-68686) | 2025-12-01 | TeamViewer Unquoted Service Path Local Privilege Escalation | |
| [CVE-2026-8076](https://www.cve.org/CVERecord?id=CVE-2026-8076) | 2026-02-15 | Azure Admin Approval Mode Bypass via Enumeration | |
| [CVE-2026-8077](https://www.cve.org/CVERecord?id=CVE-2026-8077) | 2026-04-20 | Windows Diamond and Sapphire Tickets Privilege Escalation | |
