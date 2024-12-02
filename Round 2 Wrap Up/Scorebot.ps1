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

# Define the policy registry key path and value name
$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$valueName = "LimitBlankPasswordUse"

# Check if the registry value exists
if (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue) {
    $value = (Get-ItemProperty -Path $keyPath).$valueName
    # If the value is 0, the policy is disabled
    if ($value -eq 0) {
        Solved -vuln_name "Account: Limit local use of blank paswords [enabled]" -points 5
    } else {
        Write-Output "Unsolved Vuln"
    }
} else {
    Write-Output "Unsolved Vuln"
}


# Define the registry key path and value name for the Guest account
$keyPath = "HKLM:\SAM\SAM\Domains\Account\Users\Names"
$guestAccountName = "Guest"

# Check if the Guest account exists and if it is enabled
$guestAccount = Get-LocalUser -Name $guestAccountName -ErrorAction SilentlyContinue

if ($guestAccount) {
    # Check if the Guest account is enabled
    if ($guestAccount.Enabled) {
        Write-Output "Unsolved Vuln"
    } else {
        Solved -vuln_name "Account: Guest status [disabled]" -points 5
    }
} else {
    Write-Output "Unsolved Vuln"
}


CheckFileDeleted -file "C:\Program Files\Npcap\NPFInstall.exe" -vuln_name "Removed Npcap" -points 5
CheckFileDeleted -file "C:\Users\Cyber\AppData\Local\Programs\Python\Python313\python.exe" -vuln_name "Removed python" -points 5
CheckFileDeleted -file "C:\Users\Billy\Documents\Shellshock.py" -vuln_name "Removed Shellshock expoit script" -points 5


# Get the audit policy for Logoff events
$auditPolicy = auditpol /get /category:"Logon/Logoff" | Where-Object { $_ -match "Logoff" }

# Check if Failure auditing is enabled for Logoff
if ($auditPolicy -match "Failure") {
    Solved -vuln_name "Audit Logoff [s/f]" -points 5
} else {
    Write-Output "Unsolved Vuln"
}


# Check if USERS$ share exists
$shareName = "USERS$"
$shareExists = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue

if ($shareExists) {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "File sharing disabled for the user's directory" -points 5
}

# Check if DNS Server service is installed
$serviceName = "DNS"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($service) {
    Solved -vuln_name "DNS Server service has been installed" -points 5
} else {
    Write-Output "Unsolved Vuln"
}

# Define the service name
$serviceName = "RemoteRegistry"

# Get the service status
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($service) {
    if ($service.StartType -eq 'Disabled') {
        Solved -vuln_name "Remote Registry Service has been stopped and disabled" -points 5
    } else {
        Write-Output "Unsolved Vuln"
    }
} else {
    Write-Output "Unsolved Vuln"
}


# Function to extract the installed 7-Zip version
function Get-7ZipInstalledVersion {
    try {
        # Path to 7-Zip executable (change if installed in a different location)
        $7zipPath = "C:\Program Files\7-Zip\7z.exe"
        
        if (Test-Path -Path $7zipPath) {
            # Retrieve the version information
            $versionInfo = (Get-Command $7zipPath).FileVersionInfo.FileVersion
            return $versionInfo
        } else {
            Write-Output "7-Zip is not installed."
            return $null
        }
    } catch {
        Write-Output "Error retrieving 7-Zip version: $_"
        return $null
    }
}

# Function to get the latest version of 7-Zip from the official website
function Get-Latest7ZipVersion {
    try {
        $url = "https://www.7-zip.org/download.html"
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing
        $latestVersion = $response.Content -match 'Download 7-Zip ([\d.]+)' | Out-Null
        return $matches[1]
    } catch {
        Write-Output "Error retrieving the latest version from the website: $_"
        return $null
    }
}

# Compare installed version with the latest version
$installedVersion = Get-7ZipInstalledVersion
$latestVersion = Get-Latest7ZipVersion

if ($installedVersion -and $latestVersion) {
    Write-Output "Installed version: $installedVersion"
    Write-Output "Latest version: $latestVersion"
    
    if ($installedVersion -eq $latestVersion) {
        Solved -vuln_name "7-zip has been updated" -points 5
    } else {
        Write-Output "Unsolved Vuln"
    }
}

# Function to get all Firefox profile directories
function Get-FirefoxProfilePaths {
    $appDataPath = [System.Environment]::GetFolderPath('ApplicationData')
    $firefoxProfilePath = Join-Path $appDataPath "Mozilla\Firefox\Profiles"
    
    if (Test-Path $firefoxProfilePath) {
        $profileDirs = Get-ChildItem -Path $firefoxProfilePath -Directory
        return $profileDirs
    } else {
        Write-Output "Firefox profile directory not found."
        return @()  # Return empty array if no profile folder found
    }
}

# Function to check if Firefox Strict Browser Privacy (ETP) is enabled
function Check-FirefoxStrictPrivacy {
    $profileDirs = Get-FirefoxProfilePaths

    if ($profileDirs.Count -eq 0) {
        Write-Output "No Firefox profiles found."
        return
    }

    foreach ($profile in $profileDirs) {
        $prefsFilePath = Join-Path $profile.FullName "prefs.js"
        
        if (Test-Path $prefsFilePath) {

            # Read the prefs.js file to check the setting for ETP
            $prefs = Get-Content $prefsFilePath

            # Check if Enhanced Tracking Protection is enabled
            $etpEnabled = $prefs -match 'user_pref\("privacy.trackingprotection.enabled", true\)'

            if ($etpEnabled) {
                Solved -vuln_name "Firefox Safe Browsing is enabled" -points 5
            } else {
                Write-Output "unsolved vuln"
            }
        } else {
            Write-Output ""
        }
    }
}

# Run the function to check Firefox's Strict Browser Privacy setting
Check-FirefoxStrictPrivacy


# Function to get the current Windows version
function Get-CurrentWindowsVersion {
    $osVersion = Get-CimInstance -ClassName Win32_OperatingSystem
    return $osVersion.Version
}

# Function to get the latest Windows version available from Windows Update
function Get-LatestWindowsVersion {
    try {
        # Use the Windows Update API to get the latest version
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0")

        # Filter the results to find major updates (Windows version updates)
        $latestUpdate = $searchResult.Updates | Where-Object { $_.Title -match "Windows 11" }

        if ($latestUpdate) {
            return $latestUpdate[0].Title
        } else {
            Write-Output "No Windows 11 version update found from Windows Update."
            return $null
        }
    } catch {
        Write-Output "Error checking for the latest Windows version: $_"
        return $null
    }
}

# Check the current Windows version and compare to the latest version
$currentVersion = Get-CurrentWindowsVersion
$latestVersionInfo = Get-LatestWindowsVersion

if ($currentVersion -and $latestVersionInfo) {

    if ($currentVersion -eq $latestVersionInfo) {
        Solved -vuln_name "Majority of Windows Updates are installed" -points 5
    } else {
        Write-Output "Unsolved Vuln"
    }
}





# spot to put your vulns ends here


Write-Output "Total Score: $score/60"
