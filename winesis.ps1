$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    msg $ENV:Username The scorebot has failed due to insufficient permissions. Please contact your training lead or restart the script running as an administrator.
    Exit
}
Write-Output "
__          _ ______ _   _ ______  _____ _____  _____ 
\ \        / |_   _| \ | |  ____|/ ____|_   _|/ ____|
 \ \  /\  / /  | | |  \| | |__   |(___   | |  |(___  
  \ \/  \/ /   | | | .   |  __|  \___ \  | |  \___ \ 
   \  /\  /   _| |_| |\  | |____ ____)| _| |_ ____)|
    \/  \/   |_____|_| \_|______|_____/|_____|_____/"

Write-Output " "
Write-Output "Winesis Scorebot v1`n"
Write-Output "NOTE: Please allow up to 5 minutes for scorebot updates & injects.`n"
Write-Output "Injects: NO" # Modify this if you run an inject
$global:score = 0 #make sure your total points add up to 100

Function Solved {
    param(
        [String]$vuln_name,
        [Int]$points
    )
    $global:score += $points
    Write-Output "Vulnerability fixed: $vuln_name [$points points]"
}

#under-the-hood function to handle checking text in a file
Function TextExists {
    param(
        [String]$file,
        [String]$text
    )
    try {
        if (Get-Content $file -ErrorAction Stop | Select-String -Pattern ($text)) {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
        return $null
    }
}

# Function to check if text exists in a file
Function CheckTextExists {
    param(
        [String]$file,
        [String]$text,
        [String]$vuln_name,
        [Int]$points
    )
    $Exists = TextExists -file $file -text $text
    if ($null -eq $Exists) {
        Write-Output "Unsolved Vuln"
        return
    }
    if ($Exists) {
        Solved -vuln_name $vuln_name -points $points
    }
    else {
        Write-Output "Unsolved Vuln"
    }
}

#Function to check if text does not exist in a file
Function CheckTextNotExists {
    param(
        [String]$file,
        [String]$text,
        [String]$vuln_name,
        [Int]$points
    )
    $Exists = TextExists -file $file -text $text
    if ($null -eq $Exists) {
        Write-Output "Unsolved Vuln"
        return
    }
    if (-not $Exists) {
        Solved -vuln_name $vuln_name -points $points
    }
    else {
        Write-Output "Unsolved Vuln"
    }

}

# Function to check if a file exists
Function CheckFileExists {
    param(
        [String]$file,
        [String]$vuln_name,
        [Int]$points
    )
    if (Test-Path -Path $file) {
        Solved -vuln_name $vuln_name -points $points
    }
    else {
        Write-Output "Unsolved Vuln"
    }
}

Function CheckFileDeleted {
    param(
        [String]$file,
        [String]$vuln_name,
        [Int]$points
    )
    
    if (-not (Test-Path -Path $file)) {
        Solved -vuln_name $vuln_name -points $points
    }
    else {
        Write-Output "Unsolved Vuln"
    }
}

Function CheckRegistryKey {
    param(
        [String]$path,
        [String]$key,
        [String]$expected_value,
        [String]$vuln_name,
        [Int]$points
    )
    try {
        $property = Get-ItemProperty -Path $path -Name $key -ErrorAction Stop
        $actual_value = $property.$key #not sure if this will work
        if ($expected_value -eq $actual_value) {
            Solved -vuln_name $vuln_name -points $points
        }
        else {
            Write-Output "Unsolved Vuln"
        }
    }
    catch {
        Write-Output "Unsolved Vuln"
    }
}

Function RegistryKeyDeleted {
    param(
        [String]$path,
        [String]$key,
        [String]$vuln_name,
        [Int]$points
    )
    try {
        ($value = Get-ItemProperty -Path $path -Name $key -ErrorAction Stop) | Out-Null
        if ($value -eq $value) {$value = $value} #simply to ease my peace of mind and stop my IDE from complaining that I never use $value
        Write-Output "Unsolved Vuln"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Solved -vuln_name $vuln_name -points $points
    }
    catch {
        Write-Output "Unsolved Vuln"
    }
}

Function CheckService {
    param(
        [String]$name,
        [Boolean]$is_running,
        [String]$vuln_name,
        [Int]$points
    )
    try {
        $service = Get-Service -Name $name -ErrorAction Stop
    }
    catch {
        Write-Output "Unsolved Vuln"
        return
    }

    if ($is_running) {
        if ($service.Status -eq 'Running') {
            Solved -vuln_name $vuln_name -points $points
        }
        else {
            Write-Output "Unsolved Vuln"
        }
    }
    else {
        if ($service.Status -eq 'Stopped') {
            Solved -vuln_name $vuln_name -points $points
        }
        else {
            Write-Output "Unsolved Vuln"
        }
    }
}
Function CheckGroupPolicy {
    params(
        [String]$secstring,
        [String]$vuln_name,
        [Int]$points
    )
    $exPath = "C:\temp.cfg"
    try {
        secedit /export /cfg $exPath
        if (TextExists -file $exPath -text $secstring) {
            Solved -vuln_name $vuln_name -points $points
        }
        else {
            Write-Output "Unsolved Vuln"
        }
    }
    catch {
        Write-Output "Unsolved Vuln"
    }
}


Write-Output " "
Write-Output ">> Insert image name here <<"
Write-Output " "

# spot to put your vulns begins here

# CheckTextExists -file 'C:\Users\Cyber\Desktop\FQ1' -text "SpavisComputer" -vuln_name "Forensics 1" -points 5
CheckFileDeleted -file 'C:\Users\Cyber\AppData\Local\Discord\app.ico' -vuln_name "Removed Unwanted Software" -points 5
# CheckRegistryKey -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -key ConsentPromptBehaviorAdmin -expected_value "2" -vuln_name "User Account Control Configured" -points 5
# CheckRegistryKey -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -key EnableFirewall -expected_value "1" -vuln_name "Firewall Configured" -points 5
# CheckRegistryKey -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" -key fAllowToGetHelp -expected_value "0" -vuln_name "Disabled Remote Assistance" -points 5
# CheckRegistryKey -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" -key fDenyTSConnections -expected_value "1" -vuln_name "Disabled Remote Desktop" -points 5
# CheckRegistryKey -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -key RPSessionInterval -expected_value "1" -vuln_name "Turned on System Protection" -points 5
# CheckRegistryKey -Path "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\New Windows" -key PopupMgr -expected_value "1" -vuln_name "Enabled Pop-Up Blocker" -points 5
# CheckRegistryKey -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -key EnableHttp1_1 -expected_value "0" -vuln_name "Disabled HTTP 1.1" -points 5
# CheckRegistryKey -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -key EnableHttp2 -expected_value "1" -vuln_name "Disabled HTTP 1.1" -points 5
# CheckRegistryKey -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -key ProxyHttp1.1 -expected_value "0" -vuln_name "Disabled HTTP 1.1 through proxy connections" -points 5
# CheckRegistryKey -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -key DisableAutoplay -expected_value "1" -vuln_name "Disabled AutoPlay" -points 5
# CheckFileDeleted -Path 'C:\Windows\System32\TFTP.EXE' -vuln_name "Uninstalled TFTP" -points 5


# $adapterName = "Ethernet0"
# $ipv6Binding = Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object { $_.Name -eq $adapterName }

# if ($ipv6Binding -and $ipv6Binding.Disabled -eq $true) {
#     Solved -vuln_name "Disable IPv6" -points 5
# }

# # Define the name of the adapter you want to check (Ethernet0)
# $adapterName = "Ethernet0"

# # Check if the adapter exists
# $adapter = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue

# if ($adapter) {
#     # Check if LLTDIO (Link-Layer Topology Discovery Mapper I/O Driver) is enabled
#     $bindingStatus = Get-NetAdapterBinding -Name $adapterName -ComponentID ms_lltdio

#     if ($bindingStatus.Enabled) {
        
#     } else {
#         Solved -vuln_name "Disabled Link-Layer Topology Discovery Mapper I/O Driver" -points 5
#     }
# } else {

# }

# # Define the registry path for Internet Explorer security zones
# $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones"

# # Function to get the security level for a given zone
# function Get-SecurityZoneLevel {
#     param (
#         [int]$zoneId
#     )

#     # Define the registry key path for the specified zone
#     $regKey = "$regPath\$zoneId"

#     if (Test-Path $regKey) {
#         # Read the security level value from the registry
#         $zoneSettings = Get-ItemProperty -Path $regKey
#         if ($zoneSettings.PSObject.Properties.Match("1001")) {
#             # 1001 is the key for the Security Level
#             return $zoneSettings."1001"
#         } else {
#             return "Security level not found for zone ID $zoneId."
#         }
#     } else {
#         return "Zone $zoneId not found."
#     }
# }

# # Check the Internet zone (zone ID 3)
# $internetZoneId = 3
# $securityLevel = Get-SecurityZoneLevel -zoneId $internetZoneId

# # Output the security level and print "yay" if the level is 3
# if ($securityLevel -eq 3) {
#     Solved -vuln_name "Security Zone Set to 3" -points 5
# } else {
# }





# spot to put your vulns ends here


Write-Output "Total Score: $score/100"
