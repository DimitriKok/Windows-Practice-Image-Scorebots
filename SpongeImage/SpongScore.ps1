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

# Define the username to check
$usernameO = "Plankton"  # Replace with the username you want to check

# Get the local user account
$user = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $usernameO }

# Check if the user exists and if they are disabled
if ($user) {
    if ($user.Disabled -eq $true) {
        Solved -vuln_name "Disabled User Plankton" -points 5
    } else {
        Write-Output "Unsolved vuln"
    }
} 





# Define the username to check
$usernameR = "Larry"  # Replace with the username you want to check

# Get the local user account
$user = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $usernameR }

# Check if the user exists and if they are disabled
if ($user) {
    if ($user.Disabled -eq $true) {
        Write-Output "Unsolved vuln"
    } else {
        Solved -vuln_name "Created User Larry" -points 5
    }
} 





# Define the group name to check
$groupName = "The Krusty Krab"

# Get the local groups
$group = Get-WmiObject -Class Win32_Group | Where-Object { $_.Name -eq $groupName }

# Check if the group exists
if ($group) {
    Solved -vuln_name "Created Group The Krusty Krab" -points 5
} else {
    Write-Output "Unsolved vuln"
}




# Define the username to check
$usernameA = "Spongebob"  # Replace with the username you want to check

# Define the group name
$groupName = "The Krusty Krab"

# Get the group members
$group = Get-WmiObject -Class Win32_Group | Where-Object { $_.Name -eq $groupName }

# Check if the group exists
if ($group) {
    $members = $group.GetRelated("Win32_UserAccount")
    $userExists = $members | Where-Object { $_.Name -eq $usernameA }

    if ($userExists) {
        Solved -vuln_name "Added user Spongebob to group The Krusty Krab" -points 5
    } else {
        Write-Output "Unsolved vuln"
    }
} else {
    Write-Output "Unsolved Vuln"
}


# Define the username to check
$usernameA = "Squidward"  # Replace with the username you want to check

# Define the group name
$groupName = "The Krusty Krab"

# Get the group members
$group = Get-WmiObject -Class Win32_Group | Where-Object { $_.Name -eq $groupName }

# Check if the group exists
if ($group) {
    $members = $group.GetRelated("Win32_UserAccount")
    $userExists = $members | Where-Object { $_.Name -eq $usernameA }

    if ($userExists) {
        Solved -vuln_name "Added user Squidward to group The Krusty Krab" -points 5
    } else {
        Write-Output "Unsolved vuln"
    }
} else {
    Write-Output "Unsolved Vuln"
}


# Define the username to check
$usernameA = "Mr. Krabs"  # Replace with the username you want to check

# Define the group name
$groupName = "The Krusty Krab"

# Get the group members
$group = Get-WmiObject -Class Win32_Group | Where-Object { $_.Name -eq $groupName }

# Check if the group exists
if ($group) {
    $members = $group.GetRelated("Win32_UserAccount")
    $userExists = $members | Where-Object { $_.Name -eq $usernameA }

    if ($userExists) {
        Solved -vuln_name "Added user Mr. Krabs to group The Krusty Krab" -points 5
    } else {
        Write-Output "Unsolved vuln"
    }
} else {
    Write-Output "Unsolved Vuln"
}


# Define the username to check
$usernameA = "Squidward"  # Replace with the username you want to check

# Define the group name
$groupName = "Administrators"

# Get the group members
$group = Get-WmiObject -Class Win32_Group | Where-Object { $_.Name -eq $groupName }

# Check if the group exists
if ($group) {
    $members = $group.GetRelated("Win32_UserAccount")
    $userExists = $members | Where-Object { $_.Name -eq $usernameA }

    if ($userExists) {
        Solved -vuln_name "User Squidward is an Administrator" -points 5
    } else {
        Write-Output "Unsolved vuln"
    }
} else {
    Write-Output "Unsolved Vuln"
}

# Define the username to check
$usernameA = "Plankton"  # Replace with the username you want to check

# Define the group name
$groupName = "Administrators"

# Get the group members
$group = Get-WmiObject -Class Win32_Group | Where-Object { $_.Name -eq $groupName }

# Check if the group exists
if ($group) {
    $members = $group.GetRelated("Win32_UserAccount")
    $userExists = $members | Where-Object { $_.Name -eq $usernameA }

    if ($userExists) {
        Write-Output "Unsolved Vuln"
    } else {
        Solved -vuln_name "User Plankton is not an Administrator" -points 5
    }
} else {
    Write-Output "Unsolved Vuln"
}


# Define the username to check
$userV = "Sandy"

# Get the user account information
$userAccount = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $userV }

# Check if the "PasswordNeverExpires" flag is enabled (Value: 65536)
if ($userAccount.PasswordExpires -eq $false) {
    Write-Output "Unsolved Vuln"
} else {
    Solved -vuln_name "User Sandy's password expires" -points 5
}




CheckTextExists -file "C:\Users\Cyber\Desktop\Forensics Question 1.txt" -text "5a1d20c5151a44c33e34be67fdad1d60" -vuln_name "Forensics Question 1 Solved" -points 10




# spot to put your vulns ends here


Write-Output "Total Score: $score/55"