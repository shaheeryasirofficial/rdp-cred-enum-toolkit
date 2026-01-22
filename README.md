<h1 align="center">RDP-Cred-Enum-Toolkit</h1>

<p align="center">
  <strong>Lightweight • Menu-Driven • RDP-Optimized Credential Enumeration</strong><br>
  Post-exploitation credential harvesting toolkit for Windows systems accessed via RDP.
</p>

<p align="center">
  <a href="https://github.com/shaheeryasiofficial/rdp-cred-enum-toolkit/stargazers">
    <img src="https://img.shields.io/github/stars/shaheeryasiofficial/rdp-cred-enum-toolkit?style=for-the-badge&logo=github&color=yellow" alt="GitHub stars">
  </a>
  <a href="https://github.com/shaheeryasiofficial/rdp-cred-enum-toolkit/issues">
    <img src="https://img.shields.io/github/issues/shaheeryasiofficial/rdp-cred-enum-toolkit?style=for-the-badge&logo=github&color=red" alt="GitHub issues">
  </a>
  <a href="https://github.com/shaheeryasiofficial/rdp-cred-enum-toolkit/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/shaheeryasiofficial/rdp-cred-enum-toolkit?style=for-the-badge&logo=opensourceinitiative&color=green" alt="License">
  </a>
  <br>
  <img src="https://img.shields.io/badge/PowerShell-5.1+-blue?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell">
  <img src="https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-important?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/Red%20Team-Post%20Exploitation-orange?style=for-the-badge" alt="Red Team">
</p>

<div align="center">
  <br>
  🔴 Lightweight • Living-off-the-land • Minimal footprint • Menu-driven
  <br><br>
</div>

---

### ✨ Features

- Interactive menu run single modules or everything at once (`A`)
- Basic AMSI bypass via reflection (included at the top)
- Privilege escalation attempt (UAC fallback when not elevated)
- All sensitive output files are XOR-encoded (key 0x42) + Base64 → `.xor64`
- No binaries dropped uses only native Windows commands & PowerShell
- Designed for interactive RDP sessions (user or elevated context)
- Timestamped loot folder created on Desktop

### 🛠️ Enumeration Modules

| #  | Module                                      | Admin?       | Main Output File(s)                          | Purpose / Typical Value                   |
|----|---------------------------------------------|--------------|----------------------------------------------|-------------------------------------------|
| 1  | Windows Credential Manager                  | Sometimes    | `credman_all.csv.xor64`                      | Vault, generic, domain, web creds         |
| 2  | cmdkey stored credentials                   | No           | `cmdkey_list.txt.xor64`                      | Network shares, RDP, WinRM saved logins   |
| 3  | Wi-Fi profiles & passwords                  | No           | `wifi_passwords.csv.xor64`                   | Cleartext Wi-Fi keys                      |
| 4  | Saved RDP connections & credential blobs    | No           | `cred_blobs.csv.xor64`, `rdp_servers.reg.txt.xor64` | RDP history & targets              |
| 5  | Browser saved passwords                     | No           | `Chrome_creds.sqlite.xor64` etc.             | Chrome / Edge / Firefox login data        |
| 6  | LAPS local admin passwords                  | AD rights    | `laps.txt.xor64`                             | ms-Mcs-AdmPwd attribute                   |
| 7  | IE / legacy Edge IntelliForms               | No           | `ie_intelliforms.reg.txt.xor64`              | Legacy saved form data                    |
| 8  | Unattended / sysprep / setup files          | No           | `unattend_*.xml / .txt.xor64`                | Plaintext creds from deployment remnants  |
| 9  | Recent files, RunMRU, PowerShell history    | No           | `recent.csv.xor64`, `ps_history.txt.xor64`   | User activity & command traces             |
| 10 | SAM / SYSTEM / SECURITY hives               | Yes + priv   | `SAM.xor64`, `SYSTEM.xor64`, `SECURITY.xor64`| NTLM hashes (offline cracking)            |
| A  | Run **ALL** modules                         | Varies       | All files above                              | Complete credential sweep                 |
| 0  | Exit                                        | —            | —                                            | —                                         |

### Quick Start

**Method 1 Paste & Execute** (recommended in RDP)

1. Open PowerShell (preferably as administrator)
2. Copy the full script from [`rdp-cred-enum-toolkit.ps1`](rdp-cred-enum-toolkit.ps1)
3. Paste into the PowerShell window and press Enter
4. Select module(s) by number or `A` for all
