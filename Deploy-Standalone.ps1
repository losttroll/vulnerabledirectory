##System Configuration

$hostname = "vulnwin"

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

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Current Version\Policies\System\" -Name "legalnoticecaption" -Value $warning_message
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Current Version\Policies\System\" -Name "legalnoticetext" -Value $warning_message

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

## Create defender Exceptions
$folders = @("c:\temp\unsafe", "c:\users\lowpriv\desktop\unsafe", "c:\users\highpriv\desktop\unsafe")
foreach ($folder in $folders) {
    write-host "[*] Creating AV Exception for: $folder"
    Add-MpPreference -ExclusionPath “$folder”
    }




##Install or Upgrade Sysmon


## Check for Sysmon
if ( (Get-ItemProperty -Path  "HKCU:\Software\Sysinternals\System Monitor" -ErrorAction Ignore) -eq $null) {
    write-host "[*] Downloading Sysmon"
    $sysmonurl = "https://download.sysinternals.com/files/Sysmon.zip"

    invoke-webrequest -uri $sysmonurl -outfile sysmon.zip

    Expand-Archive -Path sysmon.zip -DestinationPath c:\tools\ -Force

    write-host "[*] Installing Sysmon"

    cmd /c "c:\tools\Sysmon.exe -accepteula -i c:\temp\vulndfile\vulnerabledirectory-main\sysmon.conf"
    }
 else {
     Write-Host "[*] Sysmon already installed, updating config"
     cmd /c "c:\tools\Sysmon.exe -c c:\temp\vulndfile\vulnerabledirectory-main\sysmon.conf"  }
