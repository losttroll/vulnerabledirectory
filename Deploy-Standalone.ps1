##System Configuration

$hostname = "vulnwin"
$insecure = $false  #Set to $true to bypass SSL Verification
$folder = "c:\temp"

##Account Lockout
$lockout_duration = 5 #minutes
$lockout_threshold = 15 #0 will disabled threshold

##Working Directory
if (Test-Path $folder) {
   Set-Location $folder
} else { 
    Write-Host "[*] Creating $folder"
    mkdir $folder
    Set-Location $folder
    }

##Bypass SSL Verify
if ($insecure -eq $true) {
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
    
##Setup host

if ((Test-Path C:\tools\PsExec.exe) -eq $false) {
   write-host "[*] Downloading PSTools"

    $pstoolslink = "https://download.sysinternals.com/files/PSTools.zip" 
    invoke-webrequest -uri $pstoolslink -outfile pstools.zip

    
    Expand-Archive -Path pstools.zip -DestinationPath c:/tools/ -Force
    }


## Dowlnload Latest Repo - Using HTTP so that git.exe won't be a dependency
$repo = "https://github.com/losttroll/vulnerabledirectory/archive/refs/heads/main.zip"
write-host "[*] Downloading Vulnerable Directory"
invoke-webrequest -uri $repo -outfile main.zip
Expand-Archive -Path main.zip -DestinationPath ./vulndfile/ -Force


#Warning

$warning_title = "WARNING!!!"
$warning_message = "Do not expose this system to public networks, it has been configured to be VERY insecure.  This should only be deployed on private networks."

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "legalnoticecaption" -Value $warning_title
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "legalnoticetext" -Value $warning_message

#hostname
if (([System.Net.Dns]::GetHostName()) -ne $hostname) {
    write-host "[*] Setting hostname to: $hostname"
    try {
        Rename-Computer -NewName $hostname
        write-host "[*] A reboot is required to take effect"
    } catch {
        write-host "[*] Unable to set hostname, re-run as Administrator"
    }
}


## Create Users
foreach ($user in @("lowpriv", "highpriv") ) {
    $password = "vunwin1!"
    
    $not_so_secure_pass= ConvertTo-SecureString $password -AsPlainText -Force

    ## Check if user exists
    if ((Get-LocalUser -Name $user -ErrorAction SilentlyContinue ) -ne $null) {
        continue   
    }

    #Create User
    New-LocalUser -Name $user -Description "User created for testing" -PasswordNeverExpires -Password $not_so_secure_pass

    #Create Profile
    C:\tools\PsExec.exe -accepteula -u $user -p $password cmd.exe /c exit

    #Populate files
    Expand-Archive -Path c:/temp/vulndfile/vulnerabledirectory-main/desktop_files.zip -DestinationPath "c:\users\$user\desktop\" -Force
    Expand-Archive -Path c:/temp/vulndfile/vulnerabledirectory-main/documents.zip -DestinationPath "c:\users\$user\documents\" -Force

    if ($user -eq "highpriv") {
        write-host "[*] Created admin user - $user`:$password"
        Add-LocalGroupMember -name "administrators" -member $user
                }
    else {
        write-host "[*] Created non-admin user - $user`:$password"
    }
}

## Set Account Lockout Thresholds
write-host "[*] Setting Lockout Duration to: $lockout_duration"
cmd /c "net accounts /lockoutduration:$lockout_duration"

write-host "[*] Setting Lockout Threshold to: $lockout_threshold"
cmd /c "net accounts /lockoutthreshold:$lockout_threshold"

## Create defender Exceptions
$folders = @("c:\temp\unsafe", "c:\users\lowpriv\desktop\unsafe", "c:\users\highpriv\desktop\unsafe")
foreach ($folder in $folders) {
    write-host "[*] Creating AV Exception for: $folder"
    Add-MpPreference -ExclusionPath “$folder”
    }

## Enable RDP
$check_rdp = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections

if ($check_rdp -eq 1) {
    write-host "[*] Enabling RDP"
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name "fDenyTSConnections" -value 0
}



##Install or Upgrade Sysmon


## Check for Sysmon
if (Get-Service Sysmon -ErrorAction Ignore | Select Status) {

    Write-Host "[*] Sysmon already installed, updating config"
    cmd /c "c:\tools\Sysmon.exe -c c:\temp\vulndfile\vulnerabledirectory-main\sysmon.conf"
    } else {
    write-host "[*] Downloading Sysmon"
    $sysmonurl = "https://download.sysinternals.com/files/Sysmon.zip"

    invoke-webrequest -uri $sysmonurl -outfile sysmon.zip

    Expand-Archive -Path sysmon.zip -DestinationPath c:\tools\ -Force

    write-host "[*] Installing Sysmon"

    cmd /c "c:\tools\Sysmon.exe -accepteula -i c:\temp\vulndfile\vulnerabledirectory-main\sysmon.conf"
    }

## Common tools downloads     
$tools = @(
    "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.2/npp.8.2.Installer.x64.exe|npp.8.2.Installer.x64.exe",
    "https://www.baremetalsoft.com/baretail/download.php?p=m|beartail.exe",
    "https://github.com/Seabreg/Regshot/archive/refs/heads/master.zip|regshot.zip",
    "https://nmap.org/dist/nmap-7.92-setup.exe|nmap-7.92-setup.exe",
    "https://1.na.dl.wireshark.org/win64/Wireshark-win64-3.6.1.exe|Wireshark-win64-3.6.1.exe",
    "https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe|python-3.10.0-amd64.exe"
    )

    foreach ($tool in $tools) {

        $url = ($tool -split "\|")[0]
        $name = ($tool -split "\|")[1]

        $filepath = "c:\tools\$name"
        if (Test-Path $filepath) {
            write-host "[*] The file $name is already downloaded"
            continue
        }

        write-host "[*] Downloading $name"
        Invoke-WebRequest -Uri $url -OutFile $filepath

    }
