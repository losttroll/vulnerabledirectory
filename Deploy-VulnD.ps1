. "C:\Users\Administrator\vulnerabledirectory\Create-Accounts.ps1"

function Set-RunOnce
  
{
    [CmdletBinding()]
    param
    (
         #Command to run
        [string]
        $Path
  
    ) 
    $KeyName = 'Run'
    $Command = "%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -executionpolicy bypass -file $Path"
    echo $Command
    if (-not ((Get-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce).$KeyName ))
    {
        New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name $KeyName -Value $Command -PropertyType ExpandString
    }
    else
    {
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name $KeyName -Value $Command -PropertyType ExpandString
    }

    shutdown -r -t 00
    break
}

function Do-Reboot {
    write-host "[!] Reboot Required, doing that now"
    Set-RunOnce -Path C:\Users\Administrator\vulnerabledirectory\Deploy-VulnD.ps1
    
}

function install-sysmon {
    if (Get-Service Sysmon -ErrorAction Ignore | Select Status) {

        Write-Host "[*] Sysmon already installed, updating config"
        cmd /c "c:\tools\Sysmon.exe -c sysmon.conf"
        } else {
        write-host "[*] Downloading Sysmon"

        $sysmonurl = "https://download.sysinternals.com/files/Sysmon.zip"

        invoke-webrequest -uri $sysmonurl -outfile sysmon.zip

        Expand-Archive -Path sysmon.zip -DestinationPath c:\tools\ -Force

        write-host "[*] Installing Sysmon"

        cmd /c "c:\tools\Sysmon.exe -accepteula -i sysmon.conf"
    }


}


function do-install {
param(
       [string]$hostname,
       [string]$domain,
       [string]$safemodepassword
       )

#Base DN

$dc1 = ($domain -split "\.")[0]
$dc2 = ($domain -split "\.")[1]
$basedn = "dc=$dc1,dc=$dc2"


write-host "[*] Installing VulnD"

##Tool Path
$folder = "c:\tools"
if (-not (Test-Path -Path $folder)) {
    Write-Host "[*] Creating tools folder: $folder"
    mkdir $folder -InformationAction SilentlyContinue -WarningAction SilentlyContinue
    }
    

## Set Hostname
if ( $(hostname) -ne $hostname ) {
    write-host "[*] Setting hostname to $hostname"
    Rename-Computer $hostname -InformationAction SilentlyContinue -WarningAction SilentlyContinue
    write-host "[!] Hostname will appy after reboot"
    Do-Reboot
    }

## Check if AD-Domain-Services is installed
$ads_service_installed = Get-WindowsFeature -Name AD-Domain-Services -InformationAction SilentlyContinue -WarningAction SilentlyContinue

if ( $ads_service_installed.Installed ) {
    write-host "[*] AD Domain Services already installed"
} else {
    write-host "[*] Installing AD Domain Services"
    Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools -InformationAction SilentlyContinue -WarningAction SilentlyContinue
    }

## Create domain
if ((gwmi win32_computersystem).partofdomain -eq $true) {
    write-host "[*] Domain joined"
} else {
    write-host "[*] Not Domain Joined, creating DC"
    #Create 
    $supersecurepassword = ConvertTo-SecureString $safemodepassword -AsPlainText -Force
    Invoke-Command {  
        Install-ADDSForest -DomainName $domain -InstallDns -SafeModeAdministratorPassword $supersecurepassword -Force -InformationAction SilentlyContinue -WarningAction SilentlyContinue
        }
    Do-Reboot
}

## Import GPOs

#Export GPO - "Backup-GPO -Guid 37B982DA-FD56-446C-9EC1-A6F712E934FC -Path C:\Users\Administrator\vulnerabledirectory\GPOs\"

write-host "[*] Importing Default GPOs"

$gpos = @(
    @( "WeakPasswordPolicy", $basedn ),
    @( "AuditLoggingPolicy", $basedn ),
    @( "SecurityBannerPolicy", $basedn)
    
     )

$newgp = $false

foreach ($gpo in $gpos ) {
    #$values = $gpo -split "|"
    $name = $gpo[0]
    $target = $gpo[1]
    
    #write-host $name, $target
 

    if (-not (Get-GPO -Name $name)) {
    New-GPO -Name $name
    Import-GPO -Path C:\Users\Administrator\vulnerabledirectory\GPOs\ -BackupGpoName $name -TargetName $name 
    New-GPLink -Name $name -Target $target -LinkEnabled Yes
    $newgp = $true
        }

    }
if ($newgp -eq $true) {
    Invoke-GPUpdate
    }

## Add Users
$totalusers = (Get-ADUser -Filter * )
if ($totalusers.Count -lt 5) {
    write-host "[*] Creating User Accounts"
    Creates-Users
}

} # do-install



function invoke-vulnd {

    param(
    [switch]$install,
    [switch]$sysmon,
    [string]$hostname = "dc",
    [string]$domain = "vuln.d",
    [string]$safemodepassword = "Saf3vulnd-p4ssw!"
    )

    write-host "[*] Starting Vulnerable Directory"

    if ($install) { do-install -hostname $hostname -domain $domain -safemodepassword $safemodepassword}
    elseif ($sysmon) {install-sysmon}

    
} # invoke-vulnd

invoke-vulnd -install
