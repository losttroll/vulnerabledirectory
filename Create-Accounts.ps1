function Generate-Password {
    param ([string]$num)
    if ( $num -eq "random") {
        $number = Get-Random -Maximum 100
        } else {
         $number = $num
       }
    #write-host $number

    #PW for seaons & year

    if ($number -lt 10) {

        $y = (Get-Date).Year
        $y1 = $y - 1
        $y2 = $y - 2
        $years = @($y, $y1, $y2)
        $seasons = @("Winter!", "Spring!", "Summer!")
     
        $year = Get-Random -InputObject $years
        $season = Get-Random -InputObject $seasons

        $pass = $season + $year

    #Create company 'secret password'
    } elseif ($number -lt 20) {
        $pass = "vulndirectory1!"

    #Catchall
    } else {
        $length = 15
        $space = ( ( (0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) ) )
        $pass = Write-Output ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count $length  | % {[char]$_}) )


    }


   return $pass
} #Generate-Password


function Generate-Name {
    
    ## Create Last Name
    $lastname = Get-Random -InputObject (get-content .\lastnames.txt)
    
    ## Create First Name
    $firstname = Get-Random -InputObject (get-content .\firstnames.txt)

    ## Create User Name
    $un = ($firstname + "." + $lastname).ToLower()

    ## Lookup for duplicates - In Progress
    $filter = "SamAccountName -like `'$un`'"
    #
    #$lookup = (Get-ADUser -Filter $filter | Select-Object Name).count
    #echo $lookup
    #if ( $lookup -gt 0 ) {
    #  echo $un
    #  }
    

    #Return array with generated ifno
    return @($firstname, $lastname, $un)
} #Create-User

function Add-DomUser {
    param([int]$number)
    
   
    ### Password Vulnerabilies ####
    if ("defaultpass" -in $vulns) {
        $passnum = 15
    } else {
        $passnum = "random"
        }
    ### Set User Password ###
    $pass = Generate-Password -num $passnum
    $password = ConvertTo-SecureString $pass -AsPlainText -Force

    ### Create User Account ###
    $user_details = Generate-Name
    $firstname = $user_details[0]
    $lastname = $user_details[1]
    $name = "$firstname $lastname"
    $userid = $user_details[2]

    New-ADUser -SamAccountName $userid -Surname $lasnname -Name $name -AccountPassword $password -Enabled $true
    #write-host $pass
    
    ### Assign Privileges ###
    if ($number -lt 5) {
         Add-ADGroupMember -Identity "Domain Admins" -Members $userid
    }
    
    if ($number -eq 5) {
         Add-ADGroupMember -Identity "Administrators" -Members $userid
    }
   
    return
    #$password = ConvertTo-SecureString $pw -AsPlainText -Force
    #write-host $password
    #New-ADUser
}




function Creates-Users {

    foreach ($n in 1..100) {
        Add-DomUser -number $n
    }
}
