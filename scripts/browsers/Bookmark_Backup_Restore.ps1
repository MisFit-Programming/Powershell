# Define parameters
$operationMode = "backup" # Change this to "restore" to switch modes
$documentsFolder = [System.Environment]::GetFolderPath('MyDocuments')
$backupRootPath = "$documentsFolder\BrowserBackups"
$backupPath = "$backupRootPath\$(Get-Date -Format 'yyyyMMdd')"
$logFile = "$backupPath\BookmarkBackupRestore.log"

# Ensure backup root path exists
if (-not (Test-Path -Path $backupRootPath)) {
    New-Item -Path $backupRootPath -ItemType Directory -Force
}

# Ensure today's backup path exists
if (-not (Test-Path -Path $backupPath)) {
    New-Item -Path $backupPath -ItemType Directory -Force
}

# Create log function
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Add-Content -Path $logFile -Value $logEntry
    Manage-LogSize
}

# Manage log size function
function Manage-LogSize {
    $maxLines = 50
    if ((Get-Content -Path $logFile).Count -gt $maxLines) {
        $lines = Get-Content -Path $logFile
        $lines = $lines[-$maxLines..-1]
        Set-Content -Path $logFile -Value $lines
    }
}

# Create MD5 hash function
function Get-FileHashMD5 {
    param (
        [string]$filePath
    )
    $hash = Get-FileHash -Path $filePath -Algorithm MD5
    return $hash.Hash
}

# Clean up old backups (older than 30 days)
function Clean-OldBackups {
    $now = Get-Date
    $threshold = $now.AddDays(-30)
    Get-ChildItem -Path $backupRootPath -Directory | Where-Object { $_.LastWriteTime -lt $threshold } | Remove-Item -Recurse -Force
}

# Check if browsers are running and close them
function Close-Browsers {
    $browsers = @("msedge", "chrome", "firefox")
    foreach ($browser in $browsers) {
        $process = Get-Process -Name $browser -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "Closing $browser..."
            Stop-Process -Name $browser -Force
            Log-Message "$browser closed."
        }
    }
}

# Define browser paths
$edgePaths = @{
    Bookmarks = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
    Passwords = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
}
$chromePaths = @{
    Bookmarks = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
    Passwords = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data"
}
$firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"

# Function to backup bookmarks and passwords
function Backup-Data {
    Log-Message "Starting backup process..."
    
    $browsers = @{
        Edge = $edgePaths
        Chrome = $chromePaths
    }

    # Handle Firefox separately due to potential path issues
    if (Test-Path -Path $firefoxProfilePath) {
        $firefoxProfiles = Get-ChildItem -Path $firefoxProfilePath -Directory
        if ($firefoxProfiles.Count -gt 0) {
            foreach ($profile in $firefoxProfiles) {
                $bookmarkBackupPath = "$profile\bookmarkbackups"
                $passwordBackupPath = "$profile\logins.json"
                if (Test-Path -Path $bookmarkBackupPath) {
                    $browsers["Firefox_$($profile.Name)"] = @{
                        Bookmarks = $bookmarkBackupPath
                        Passwords = $passwordBackupPath
                    }
                } else {
                    Log-Message "No bookmark backups found in Firefox profile: $profile"
                }
            }
        } else {
            Log-Message "No Firefox profiles found."
        }
    } else {
        Log-Message "Firefox profiles path not found: $firefoxProfilePath"
    }

    foreach ($browser in $browsers.GetEnumerator()) {
        $browserName = $browser.Key
        $browserPaths = $browser.Value

        foreach ($type in $browserPaths.Keys) {
            $path = $browserPaths[$type]
            if (Test-Path -Path $path) {
                $backupFile = "$backupPath\$browserName-$type.json"
                Copy-Item -Path $path -Destination $backupFile -Force
                $hash = Get-FileHashMD5 -filePath $backupFile
                Log-Message "$browserName $type backed up. MD5: $hash"
            } else {
                Log-Message "No $type found for $browserName at $path"
            }
        }
    }
    Log-Message "Backup process completed."
}

# Function to restore bookmarks and passwords
function Restore-Data {
    Log-Message "Starting restore process..."
    if (-not (Test-Path -Path $backupPath)) {
        Log-Message "Backup path not found: $backupPath"
        return
    }

    $browsers = @{
        Edge = $edgePaths
        Chrome = $chromePaths
    }

    # Handle Firefox separately due to potential path issues
    if (Test-Path -Path $firefoxProfilePath) {
        $firefoxProfiles = Get-ChildItem -Path $firefoxProfilePath -Directory
        if ($firefoxProfiles.Count -gt 0) {
            foreach ($profile in $firefoxProfiles) {
                $bookmarkBackupPath = "$profile\bookmarkbackups"
                $passwordBackupPath = "$profile\logins.json"
                if (Test-Path -Path $bookmarkBackupPath) {
                    $browsers["Firefox_$($profile.Name)"] = @{
                        Bookmarks = $bookmarkBackupPath
                        Passwords = $passwordBackupPath
                    }
                } else {
                    Log-Message "No bookmark backups found in Firefox profile: $profile"
                }
            }
        } else {
            Log-Message "No Firefox profiles found."
        }
    } else {
        Log-Message "Firefox profiles path not found: $firefoxProfilePath"
    }

    foreach ($browser in $browsers.GetEnumerator()) {
        $browserName = $browser.Key
        $browserPaths = $browser.Value

        foreach ($type in $browserPaths.Keys) {
            $path = $browserPaths[$type]
            $backupFile = "$backupPath\$browserName-$type.json"
            if (Test-Path -Path $backupFile) {
                Copy-Item -Path $backupFile -Destination $path -Force
                $hash = Get-FileHashMD5 -filePath $path
                Log-Message "$browserName $type restored. MD5: $hash"
            } else {
                Log-Message "No backup file found for $browserName $type at $backupFile"
            }
        }
    }
    Log-Message "Restore process completed."
}

# Main execution logic
try {
    Clean-OldBackups
    Close-Browsers
    if ($operationMode -eq "backup") {
        Backup-Data
    } elseif ($operationMode -eq "restore") {
        Restore-Data
    } else {
        Log-Message "Invalid operation mode specified. Use 'backup' or 'restore'."
    }
} catch {
    Log-Message "An error occurred: $_"
}
