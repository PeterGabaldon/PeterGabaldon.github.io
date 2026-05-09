---
layout: page
title: CVEs
icon: fas fa-bug
order: 1
---

<style>
.cve-table {
  width: 100%;
  table-layout: fixed;
}

.cve-table th,
.cve-table td {
  text-align: center;
  vertical-align: middle;
  overflow-wrap: break-word;
}

/* CVE ID */
.cve-table th:nth-child(1),
.cve-table td:nth-child(1) {
  width: 14%;
}

/* Date */
.cve-table th:nth-child(2),
.cve-table td:nth-child(2) {
  width: 10%;
}

/* Description */
.cve-table th:nth-child(3),
.cve-table td:nth-child(3) {
  width: 70%;
  white-space: normal;
  text-align: left;
  overflow-wrap: break-word;
}

/* Exploit Link */
.cve-table th:nth-child(4),
.cve-table td:nth-child(4) {
  width: 15%;
  white-space: normal;
}

/* Blog Link  */
.cve-table th:nth-child(5),
.cve-table td:nth-child(5) {
  width: 15%;
  white-space: normal;
}
</style>

<div class="cve-table" markdown="1">

This is the full list of CVEs that I have discovered and that have been published.

| CVE ID | Date | Description | Exploit Link | Blog Link |
|---|---|---|---|---|
| [CVE-2024-3704](https://www.cve.org/CVERecord?id=CVE-2024-3704) | 2024-04-11 | SQL injection in OpenGnsys 1.1.1d allowing login bypass and database access. | — | [INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-opengnsys)<br><br>[OpenGnsys patch](https://opengnsys.es/web/parche-de-seguridad-cve-2024-370x) |
| [CVE-2024-3705](https://www.cve.org/CVERecord?id=CVE-2024-3705) | 2024-04-11 | Unrestricted file upload in OpenGnsys 1.1.1d allowing webshell upload. | — | [INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-opengnsys)<br><br>[OpenGnsys patch](https://opengnsys.es/web/parche-de-seguridad-cve-2024-370x) |
| [CVE-2024-3706](https://www.cve.org/CVERecord?id=CVE-2024-3706) | 2024-04-11 | Information exposure in OpenGnsys 1.1.1d leaking database credentials. | — | [INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-opengnsys)<br><br>[OpenGnsys patch](https://opengnsys.es/web/parche-de-seguridad-cve-2024-370x) |
| [CVE-2024-3707](https://www.cve.org/CVERecord?id=CVE-2024-3707) | 2024-04-11 | Information exposure in OpenGnsys 1.1.1d allowing web-tree file enumeration. | — | [INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-opengnsys)<br><br>[OpenGnsys patch](https://opengnsys.es/web/parche-de-seguridad-cve-2024-370x) |
| [CVE-2024-1343](https://www.cve.org/CVERecord?id=CVE-2024-1343) | 2024-02-19 | Weak backup directory permissions in LaborOfficeFree 19.10 allowing backup file access. | — | [INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-laborofficefree) |
| [CVE-2024-1344](https://www.cve.org/CVERecord?id=CVE-2024-1344) | 2024-02-19 | Recoverable database credentials in LaborOfficeFree 19.10 enabling privileged database access. | — | [INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-laborofficefree) |
| [CVE-2024-1345](https://www.cve.org/CVERecord?id=CVE-2024-1345) | 2024-02-19 | Weak MySQL root password in LaborOfficeFree 19.10 vulnerable to brute force. | — | [INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-laborofficefree) |
| [CVE-2024-1346](https://www.cve.org/CVERecord?id=CVE-2024-1346) | 2024-02-19 | Predictable MySQL root password in LaborOfficeFree 19.10 derived from constants. | [GitHub PoC](https://github.com/PeterGabaldon/CVE-2024-1346)<br><br>[Exploit-DB](https://www.exploit-db.com/exploits/51894) | [INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-laborofficefree) |
| [CVE-2024-7481](https://www.cve.org/CVERecord?id=CVE-2024-7481)<br><br>[ZDI-24-1290](https://www.zerodayinitiative.com/advisories/ZDI-24-1290/) | 2024-08-20 | TeamViewer driver signature verification flaw allowing local privilege escalation via printer driver installation. | [GitHub PoC](https://github.com/PeterGabaldon/CVE-2024-7479_CVE-2024-7481) | [Finding TeamViewer 0days - Part III](https://pgj11.com/posts/Finding-TeamViewer-0days-Part-3/)<br><br>[ZDI-24-1290](https://www.zerodayinitiative.com/advisories/ZDI-24-1290/)<br><br>[TeamViewer bulletin](https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2024-1006/) |
| [CVE-2024-7479](https://www.cve.org/CVERecord?id=CVE-2024-7479)<br><br>[ZDI-24-1289](https://www.zerodayinitiative.com/advisories/ZDI-24-1289/) | 2024-08-20 | TeamViewer driver signature verification flaw allowing local privilege escalation via VPN driver installation. | [GitHub PoC](https://github.com/PeterGabaldon/CVE-2024-7479_CVE-2024-7481) | [Finding TeamViewer 0days - Part III](https://pgj11.com/posts/Finding-TeamViewer-0days-Part-3/)<br><br>[ZDI-24-1289](https://www.zerodayinitiative.com/advisories/ZDI-24-1289/)<br><br>[TeamViewer bulletin](https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2024-1006/) |
| [CVE-2025-40678](https://www.cve.org/CVERecord?id=CVE-2025-40678) | 2025-08-02 | Dangerous file upload in Summar Portal del Empleado via the absence attachment endpoint. | — | [INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-summar-software-employee-portal)<br><br>[GitHub advisory](https://github.com/advisories/GHSA-8xh2-xr8x-3g8x) |
| [CVE-2025-40677](https://www.cve.org/CVERecord?id=CVE-2025-40677) | 2025-10-10 | SQL injection in Summar Portal del Empleado allowing database read/write operations. | [GitHub PoC](https://github.com/PeterGabaldon/CVE-2025-40677)<br><br>[Exploit-DB](https://www.exploit-db.com/exploits/52462) | [INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-summar-software-employee-portal) |
| [CVE-2025-68686](https://www.cve.org/CVERecord?id=CVE-2025-68686) | 2025-12-01 | FortiOS information exposure allowing bypass of the symbolic-link persistence patch after prior compromise. | [Checker Tool - GitHub](https://github.com/I3IT/Fortigate.Symlink.Persistence.Checker) | [FortiGate Symlink Persistence Method](https://pgj11.com/posts/FortiGate-Symlink-Attack/)<br><br>[ITRES patch-bypass writeup](https://labs.itresit.es/2026/02/11/fortigate-symlink-persistence-method-patch-bypass-cve-2025-68686/)<br><br>[Fortinet PSIRT](https://fortiguard.fortinet.com/psirt/FG-IR-25-934) |
| [CVE-2026-8076](https://www.cve.org/CVERecord?id=CVE-2026-8076) | 2026-02-15 | Weak PIN-based credentials in CashDro 3 enabling brute-force access to administration. | — | [Cashdro Vulnerabilities: From Pentest to Stealing Money](https://labs.itresit.es/2026/05/07/cashdro-vulnerabilities-from-pentest-to-stealing-money/)<br><br>[INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-cashdro-3) |
| [CVE-2026-8077](https://www.cve.org/CVERecord?id=CVE-2026-8077) | 2026-04-20 | Missing backend authorization in CashDro 3 allowing privilege escalation to administrator. | — | [Cashdro Vulnerabilities: From Pentest to Stealing Money](https://labs.itresit.es/2026/05/07/cashdro-vulnerabilities-from-pentest-to-stealing-money/)<br><br>[INCIBE advisory](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-cashdro-3) |

</div>