function do-install {
param(
       [string]$hostname,
       [string]$domain,
       [string]$safemodepassword
       )

write-host "[*] Installing VulnD"

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
    [string]$hostname = "dc",
    [string]$domain = "vuln.d",
    [string]$safemodepassword = "safevulnd"
    )

    write-host "[*] Starting Vulnerable Directory"

    if ($install) { do-install -hostname $hostname -domain $domain -safemodepassword $safemodepassword}

} # invoke-vulnd