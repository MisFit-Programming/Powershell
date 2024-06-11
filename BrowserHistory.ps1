<#
.SYNOPSIS
    Extracts browsing history from Chrome, Firefox, and Edge browsers for all user profiles on a Windows machine.

.DESCRIPTION
    This script checks and installs sqlite3 if not already present. It then retrieves browsing history from Chrome, Firefox, and Edge browsers
    for all user profiles and exports the history to a CSV file.

.NOTES
    Author: Philip Stacy
    Date: 2024-06-11
#>

# Define the working directory
$workingDirectory = "C:\temp"

# Create the working directory if it doesn't exist
if (-Not (Test-Path -Path $workingDirectory)) {
    New-Item -Path $workingDirectory -ItemType Directory | Out-Null
}

function Install-SQLite3 {
    <#
    .SYNOPSIS
        Installs sqlite3 if not already installed.
    .DESCRIPTION
        Downloads and installs sqlite3.exe in the specified working directory if it is not already present.
    #>
    $sqlitePath = "$workingDirectory\sqlite3.exe"
    if (-Not (Test-Path $sqlitePath)) {
        Write-Host "sqlite3.exe not found. Downloading sqlite3..."
        $sqliteUrl = "https://sqlite.org/2023/sqlite-tools-win32-x86-3420000.zip"
        $zipFile = "$workingDirectory\sqlite-tools.zip"
        $sqliteDir = "$workingDirectory\sqlite-tools"

        Invoke-WebRequest -Uri $sqliteUrl -OutFile $zipFile
        Expand-Archive -Path $zipFile -DestinationPath $sqliteDir

        Copy-Item "$sqliteDir\sqlite-tools-win32-x86-3420000\sqlite3.exe" $sqlitePath
        Remove-Item $zipFile
        Remove-Item -Recurse $sqliteDir

        Write-Host "sqlite3.exe installed."
    } else {
        Write-Host "sqlite3.exe is already installed."
    }
}

function Get-UserProfiles {
    <#
    .SYNOPSIS
        Gets user profiles on the system.
    .DESCRIPTION
        Retrieves all user profiles except for "Public" and "Default".
    #>
    $usersPath = 'C:\Users'
    Get-ChildItem -Path $usersPath -Directory | Where-Object { 
        $_.Name -ne "Public" -and $_.Name -ne "Default" 
    }
}

function Get-ChromeHistory {
    param (
        [string]$profilePath,
        [string]$sqlitePath
    )
    <#
    .SYNOPSIS
        Gets browsing history from Chrome.
    .PARAMETER profilePath
        The path to the user profile.
    .PARAMETER sqlitePath
        The path to the sqlite3 executable.
    #>
    $chromeHistoryPath = "$profilePath\AppData\Local\Google\Chrome\User Data\Default\History"
    if (Test-Path $chromeHistoryPath) {
        $query = "SELECT datetime((visits.visit_time/1000000)-11644473600,'unixepoch') as visit_time, urls.url, urls.title FROM urls, visits WHERE urls.id = visits.url ORDER BY visit_time DESC"
        $data = & $sqlitePath $chromeHistoryPath $query
        return $data
    }
}

function Get-FirefoxHistory {
    param (
        [string]$profilePath,
        [string]$sqlitePath
    )
    <#
    .SYNOPSIS
        Gets browsing history from Firefox.
    .PARAMETER profilePath
        The path to the user profile.
    .PARAMETER sqlitePath
        The path to the sqlite3 executable.
    #>
    $firefoxProfilesPath = "$profilePath\AppData\Roaming\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfilesPath) {
        Get-ChildItem -Path $firefoxProfilesPath -Directory | ForEach-Object {
            $placesPath = "$($_.FullName)\places.sqlite"
            if (Test-Path $placesPath) {
                $query = "SELECT datetime((visit_date/1000000),'unixepoch') as visit_time, url FROM moz_places ORDER BY visit_date DESC"
                $data = & $sqlitePath $placesPath $query
                return $data
            }
        }
    }
}

function Get-EdgeHistory {
    param (
        [string]$profilePath,
        [string]$sqlitePath
    )
    <#
    .SYNOPSIS
        Gets browsing history from Edge.
    .PARAMETER profilePath
        The path to the user profile.
    .PARAMETER sqlitePath
        The path to the sqlite3 executable.
    #>
    $edgeHistoryPath = "$profilePath\AppData\Local\Microsoft\Edge\User Data\Default\History"
    if (Test-Path $edgeHistoryPath) {
        $query = "SELECT datetime((visits.visit_time/1000000)-11644473600,'unixepoch') as visit_time, urls.url, urls.title FROM urls, visits WHERE urls.id = visits.url ORDER BY visit_time DESC"
        $data = & $sqlitePath $edgeHistoryPath $query
        return $data
    }
}

# Main script execution
Install-SQLite3

# Get the path to sqlite3
$sqlitePath = "$workingDirectory\sqlite3.exe"

# Get all user profiles
$userProfiles = Get-UserProfiles

# Initialize an array to store history
$allHistory = @()

foreach ($profile in $userProfiles) {
    $userName = $profile.Name
    $profilePath = $profile.FullName
    
    # Get Chrome History
    $chromeHistory = Get-ChromeHistory -profilePath $profilePath -sqlitePath $sqlitePath
    if ($chromeHistory) {
        $chromeHistory | ForEach-Object {
            Write-Host "Raw Chrome Entry: $_"
            # Manually parse each line of the output
            $fields = $_ -split '\|'
            $entry = [PSCustomObject]@{
                visit_time = $fields[0]
                url        = $fields[1]
                title      = $fields[2]
                User       = $userName
                Browser    = "Chrome"
            }
            $allHistory += $entry
        }
    }
    
    # Get Firefox History
    $firefoxHistory = Get-FirefoxHistory -profilePath $profilePath -sqlitePath $sqlitePath
    if ($firefoxHistory) {
        $firefoxHistory | ForEach-Object {
            Write-Host "Raw Firefox Entry: $_"
            # Manually parse each line of the output
            $fields = $_ -split '\|'
            $entry = [PSCustomObject]@{
                visit_time = $fields[0]
                url        = $fields[1]
                title      = $null
                User       = $userName
                Browser    = "Firefox"
            }
            $allHistory += $entry
        }
    }
    
    # Get Edge History
    $edgeHistory = Get-EdgeHistory -profilePath $profilePath -sqlitePath $sqlitePath
    if ($edgeHistory) {
        $edgeHistory | ForEach-Object {
            Write-Host "Raw Edge Entry: $_"
            # Manually parse each line of the output
            $fields = $_ -split '\|'
            $entry = [PSCustomObject]@{
                visit_time = $fields[0]
                url        = $fields[1]
                title      = $fields[2]
                User       = $userName
                Browser    = "Edge"
            }
            $allHistory += $entry
        }
    }
}

# Output the parsed results
$allHistory | ForEach-Object {
    Write-Host "Parsed Entry: $_"
}

# Ensure $allHistory contains entries
Write-Host "Total Entries: $($allHistory.Count)"

# Convert to PST and Export to CSV
$allHistory | ForEach-Object {
    $visitTime = $_.visit_time
    Write-Host "Raw visit_time: $visitTime"

    # Try to convert to DateTime
    try {
        $convertedTime = [DateTime]::ParseExact($visitTime, 'yyyy-MM-dd HH:mm:ss', $null)
        $_.visit_time = [TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($convertedTime, 'Pacific Standard Time')
        Write-Host "Converted visit_time: $($_.visit_time)"
    } catch {
        Write-Warning "Failed to parse visit_time for entry: $visitTime"
    }
}

# Export the data to CSV
$csvPath = "$workingDirectory\BrowsingHistory.csv"
$allHistory | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "Browsing history has been exported to $csvPath"
