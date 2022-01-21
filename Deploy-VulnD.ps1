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

write-host "[*] Installing VulnD"

##Tool Path
$folder = "c:\tools"
Write-Host "[*] Creating $folder"
mkdir $folder



## Set Hostname
if ( $(hostname) -ne $hostname ) {
    write-host "[*] Setting hostname to $hostname"
    Rename-Computer $hostname -WarningAction SilentlyContinue
    write-host "[!] Hostname will appy after reboot"
    }

## Check if AD-Domain-Services is installed
$ads_service_installed = Get-WindowsFeature -Name AD-Domain-Services

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
        Install-ADDSForest -DomainName $domain -InstallDns -SafeModeAdministratorPassword $supersecurepassword -Force -InformationAction SilentlyContinue
        }
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