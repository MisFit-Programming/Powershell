# Computer Setup Script
# 
# Description:
# This script performs the following tasks on a new computer:
# 1. Runs all available updates.
# 2. Renames the computer.
# 3. Joins the computer to a specified domain.
#
# Usage:
# Run this script with administrative privileges.
# Example: .\SetupComputer.ps1 -ComputerName "NewComputerName" -DomainName "example.com" -DomainUser "domainuser" -DomainPassword "password"
#
# Author: <Your Name>
# Date: <Date>
# Version: <Version>
# License: <License>

# --------------------
# PARAMETERS
# --------------------
param (
    [string]$ComputerName, 
    [string]$DomainName,
    [string]$DomainUser,
    [string]$DomainPassword
)

# --------------------
# FUNCTIONS
# --------------------

# Function to run all updates
function Run-WindowsUpdate {
    # Description: This function runs all available Windows updates.
    # Usage: Run-WindowsUpdate

    Write-Host "Running Windows Updates..."
    
    Install-Module PSWindowsUpdate -Force -Scope CurrentUser
    Import-Module PSWindowsUpdate
    Get-WindowsUpdate -Install -AcceptAll -AutoReboot
}

# Function to rename the computer
function Rename-ComputerName {
    param (
        [string]$NewName
    )
    
    # Description: This function renames the computer.
    # Usage: Rename-ComputerName -NewName "<NewComputerName>"

    Write-Host "Renaming computer to $NewName..."
    
    Rename-Computer -NewName $NewName -Force
    Restart-Computer -Force
}

# Function to join the computer to a domain
function Join-Domain {
    param (
        [string]$Domain,
        [string]$User,
        [string]$Password
    )
    
    # Description: This function joins the computer to the specified domain.
    # Usage: Join-Domain -Domain "<DomainName>" -User "<DomainUser>" -Password "<DomainPassword>"

    Write-Host "Joining computer to domain $Domain..."
    
    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    Add-Computer -DomainName $Domain -Credential (New-Object System.Management.Automation.PSCredential ($User, $securePassword)) -Force
    Restart-Computer -Force
}

# --------------------
# MAIN SCRIPT LOGIC
# --------------------

# Run updates
Run-WindowsUpdate

# Rename the computer
Rename-ComputerName -NewName $ComputerName

# Join the computer to the domain
Join-Domain -Domain $DomainName -User $DomainUser -Password $DomainPassword

# --------------------
# EXAMPLES
# --------------------
# Example 1: Running the script with all parameters
# .\SetupComputer.ps1 -ComputerName "NewComputerName" -DomainName "example.com" -DomainUser "domainuser" -DomainPassword "password"

# --------------------
# NOTES
# --------------------
# Ensure you have the necessary permissions to execute the script.
# This script requires PowerShell version 5.1 or later.
# The computer will reboot multiple times during the execution of this script.

# End of script
