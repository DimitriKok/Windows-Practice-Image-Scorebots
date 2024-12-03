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

# Define the registry path and key name
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$keyName = "VMware Profile Settings"

# Check if the registry key exists
if (Get-ItemProperty -Path $regPath -Name $keyName -ErrorAction SilentlyContinue) {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "Deleted Malicious Run Key"
}

# Define the registry path and key name
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$keyName = "VMware"

# Check if the registry key exists
if (Get-ItemProperty -Path $regPath -Name $keyName -ErrorAction SilentlyContinue) {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "removed Malicious Run Once Key" -points 5
}

# Define the registry path and value name
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "DisableTaskMgr"

# Check if the registry key exists and get its value
try {
    $value = Get-ItemPropertyValue -Path $regPath -Name $valueName -ErrorAction Stop
} catch {
    # If the value does not exist, treat it as 0 (Task Manager is enabled)
    Write-Output "True"
    exit
}

# Evaluate the value
if ($value -eq 1) {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "Fixed Task Manager" -points 5
}

# Define the registry path and value name
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoControlPanel"

# Check if the registry key exists and get its value
try {
    $value = Get-ItemPropertyValue -Path $regPath -Name $valueName -ErrorAction Stop
} catch {
    # If the value does not exist, treat it as 0 (Control Panel is enabled)
    Write-Output "True"
    exit
}

# Evaluate the value
if ($value -eq 1) {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "Fixed Control Panel" -points 5
}

# Define the registry path and value name
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoViewContextMenu"

# Check if the registry key exists and get its value
try {
    $value = Get-ItemPropertyValue -Path $regPath -Name $valueName -ErrorAction Stop
} catch {
    # If the value does not exist, treat it as 0 (Context menu is enabled)
    Write-Output "True"
    exit
}

# Evaluate the value
if ($value -eq 1) {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "Fixed Right Click" -points 5
}

# Define the registry path and value name
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$valueName = "AutoAdminLogon"

# Check if the registry key exists and get its value
try {
    $value = Get-ItemPropertyValue -Path $regPath -Name $valueName -ErrorAction Stop
} catch {
    # If the value does not exist, treat it as 0 (AutoAdminLogon is not enabled)
    Write-Output "True"
    exit
}

# Evaluate the value
if ($value -eq "1") {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "Disabled AutoAdminLogon"
}

# Define the registry path and value name
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$valueName = "AlwaysInstallElevated"

# Check if the registry key exists and get its value
try {
    $value = Get-ItemPropertyValue -Path $regPath -Name $valueName -ErrorAction Stop
} catch {
    # If the value does not exist, treat it as 0 (AlwaysInstallElevated is not enabled)
    Write-Output "True"
    exit
}

# Evaluate the value
if ($value -eq 1) {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "Fixed Malicious Reg Key AlwatsInstallElevated" -points 5
}

# Define the registry path and value name
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
$valueName = "DisableScheduledScans"

# Check if the registry key exists and get its value
try {
    $value = Get-ItemPropertyValue -Path $regPath -Name $valueName -ErrorAction Stop
} catch {
    # If the value does not exist, treat it as 0 (Scheduled scans are enabled)
    Write-Output "True"
    exit
}

# Evaluate the value
if ($value -eq 1) {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "Fixed one part of defender" -points 5
}

# Define the registry path and value name
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
$valueName = "DisableRealtimeMonitoring"

# Check if the registry key exists and get its value
try {
    $value = Get-ItemPropertyValue -Path $regPath -Name $valueName -ErrorAction Stop
} catch {
    # If the value does not exist, treat it as 0 (Real-time monitoring is enabled)
    Write-Output "True"
    exit
}

# Evaluate the value
if ($value -eq 1) {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "Fixed one part of defender" -points 5
}

# Define the registry path
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv"

# Get the ACL for the registry key
$acl = Get-Acl -Path $regPath

# Check if any access rule denies Full Control for any user or group
$denyFullControl = $acl.Access | Where-Object { 
    $_.AccessControlType -eq 'Deny' -and 
    $_.RegistryRights -eq 'FullControl'
}

# Print True if "Deny" is NOT checked for Full Control, otherwise print False
if ($denyFullControl) {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "Fixed Windows Update" -points 5
}

# Define the registry path for the Dhcp service
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dhcp"

# Check if the DependOnService value exists
try {
    $dependOnService = Get-ItemPropertyValue -Path $regPath -Name "DependOnService" -ErrorAction Stop
} catch {
    # If the value does not exist, print True (no dependencies)
    Write-Output "True"
    exit
}

# Check if PlugPlay is in the dependencies
if ($dependOnService -notcontains "PlugPlay") {
    Solved -vuln_name "Fixed DHCP" -points 5
} else {
    Write-Output "Unsolved Vuln"
}




# spot to put your vulns ends here


Write-Output "Total Score: $score/55"
