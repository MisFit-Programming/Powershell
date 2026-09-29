$outputDirectory = "C:\Temp"
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory
}

$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Device Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .collapsible { background-color: #f2f2f2; cursor: pointer; padding: 10px; width: 100%; border: none; text-align: left; outline: none; font-size: 15px; }
        .active, .collapsible:hover { background-color: #ccc; }
        .content { padding: 0 18px; display: none; overflow: hidden; background-color: #f9f9f9; }
    </style>
</head>
<body>
<h1>Device Report</h1>
"@

# Device Name
$deviceName = $env:COMPUTERNAME
$html += "<h2>Device Name: $deviceName</h2>"

# Function to create collapsible sections
function Add-CollapsibleSection {
    param (
        [string]$title,
        [string]$content
    )
    $html += "<button class='collapsible'>$title</button><div class='content'>$content</div>"
}

# Roles
$roles = Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" } | Select-Object -ExpandProperty Name
if ($roles) {
    $rolesContent = "<table><tr><th>Role</th></tr>"
    foreach ($role in $roles) {
        $rolesContent += "<tr><td>$role</td></tr>"
    }
    $rolesContent += "</table>"
} else {
    $rolesContent = "<p>No roles installed.</p>"
}
Add-CollapsibleSection -title "Roles" -content $rolesContent

# AD Information
try {
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $dc = $domain.FindDomainController()

    $adContent = "<table><tr><th>Name</th><th>Site</th></tr><tr><td>$($dc.Name)</td><td>$($dc.SiteName)</td></tr></table>"
    $adContent += "<h3>Forest Functional Level</h3><p>$($forest.ForestMode)</p>"
    $adContent += "<h3>Domain Functional Level</h3><p>$($domain.DomainMode)</p>"

    # OU Layout
    $ouContent = "<ul>"
    function Get-OU {
        param (
            [string]$ou
        )
        $ous = Get-ADOrganizationalUnit -Filter { Name -like "*" } -SearchBase $ou
        $content = ""
        foreach ($ou in $ous) {
            $content += "<li><b>$($ou.Name)</b> ($($ou.DistinguishedName))"
            $content += "<ul>"
            $content += Get-OU -ou $ou.DistinguishedName
            $content += "</ul></li>"
        }
        return $content
    }
    $ouContent += Get-OU -ou $domain.GetDirectoryEntry().DistinguishedName
    $ouContent += "</ul>"
    $adContent += "<h3>OU Layout</h3><button class='collapsible'>Organizational Units</button><div class='content'>$ouContent</div>"

    # FSMO Roles
    $fsmoRoles = @{
        SchemaMaster = $forest.SchemaMaster
        DomainNamingMaster = $forest.DomainNamingMaster
        PDCEmulator = $domain.PDCEmulator
        RIDMaster = $domain.RIDMaster
        InfrastructureMaster = $domain.InfrastructureMaster
    }
    $fsmoContent = "<table><tr><th>Role</th><th>Owner</th></tr>"
    foreach ($role in $fsmoRoles.GetEnumerator()) {
        $fsmoContent += "<tr><td>$($role.Key)</td><td>$($role.Value)</td></tr>"
    }
    $fsmoContent += "</table>"
    $adContent += "<h3>FSMO Roles</h3>$fsmoContent"
} catch {
    $adContent = "<p>AD Information not available.</p>"
}
Add-CollapsibleSection -title "AD Information" -content $adContent

# Share Information
$shares = Get-WmiObject -Class Win32_Share
if ($shares) {
    $shareContent = "<table><tr><th>Share Name</th><th>Share Path</th><th>Local Path</th><th>Description</th><th>NTFS Permissions</th></tr>"
    foreach ($share in $shares) {
        $shareName = $share.Name
        $sharePath = $share.Path
        $localPath = $share.LocalPath
        $description = $share.Description
        if (-not [string]::IsNullOrEmpty($sharePath) -and (Test-Path -Path $sharePath)) {
            $ntfsPermissions = Get-Acl -Path $sharePath | Select-Object -ExpandProperty AccessToString
        } else {
            $ntfsPermissions = "Path not found or invalid"
        }
        $shareContent += "<tr><td>$shareName</td><td>$sharePath</td><td>$localPath</td><td>$description</td><td>$ntfsPermissions</td></tr>"
    }
    $shareContent += "</table>"
} else {
    $shareContent = "<p>No shares found.</p>"
}
Add-CollapsibleSection -title "Share Information" -content $shareContent

# DNS Information
$dnsZones = Get-DnsServerZone
if ($dnsZones) {
    $dnsContent = "<table><tr><th>Zone Name</th><th>Zone Type</th><th>Record</th><th>Type</th><th>Data</th></tr>"
    foreach ($zone in $dnsZones) {
        $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName
        foreach ($record in $records) {
            $recordData = $null
            switch ($record.RecordType) {
                "A" { $recordData = $record.RecordData.IPv4Address }
                "CNAME" { $recordData = $record.RecordData.HostNameAlias }
                "MX" { $recordData = $record.RecordData.MailExchange }
                "NS" { $recordData = $record.RecordData.NameServer }
                "PTR" { $recordData = $record.RecordData.PtrDomainName }
                "TXT" { $recordData = $record.RecordData.Text }
            }
            $dnsContent += "<tr><td>$($zone.ZoneName)</td><td>$($zone.ZoneType)</td><td>$($record.HostName)</td><td>$($record.RecordType)</td><td>$recordData</td></tr>"
        }
    }
    $dnsContent += "</table>"
} else {
    $dnsContent = "<p>No DNS zones found.</p>"
}
Add-CollapsibleSection -title "DNS Information" -content $dnsContent

# DHCP Information
$dhcpScopes = Get-DhcpServerv4Scope
if ($dhcpScopes) {
    $dhcpContent = "<table><tr><th>Scope Name</th><th>Start IP</th><th>End IP</th><th>Subnet Mask</th><th>Lease Duration</th></tr>"
    foreach ($scope in $dhcpScopes) {
        $dhcpContent += "<tr><td>$($scope.Name)</td><td>$($scope.StartRange)</td><td>$($scope.EndRange)</td><td>$($scope.SubnetMask)</td><td>$($scope.LeaseDuration)</td></tr>"
    }
    $dhcpContent += "</table>"
} else {
    $dhcpContent = "<p>No DHCP scopes found.</p>"
}
Add-CollapsibleSection -title "DHCP Information" -content $dhcpContent

# Users and Groups
$users = Get-ADUser -Filter * -Property DisplayName, LastLogonDate, Enabled, LockedOut
$groups = Get-ADGroup -Filter *
if ($users -or $groups) {
    $userGroupContent = "<table><tr><th>Username</th><th>Last Logged In</th><th>Status</th></tr>"
    foreach ($user in $users) {
        $status = if ($user.Enabled) { "Enabled" } else { "Disabled" }
        if ($user.LockedOut) { $status += ", Locked Out" }
        $userGroupContent += "<tr><td>$($user.SamAccountName)</td><td>$($user.LastLogonDate)</td><td>$status</td></tr>"
    }
    $userGroupContent += "</table><h3>Groups</h3><table><tr><th>Group Name</th><th>Members</th></tr>"
    foreach ($group in $groups) {
        $members = Get-ADGroupMember -Identity $group | Select-Object -ExpandProperty Name
        $userGroupContent += "<tr><td>$($group.Name)</td><td>$($members -join ", ")</td></tr>"
    }
    $userGroupContent += "</table>"
} else {
    $userGroupContent = "<p>No users or groups found.</p>"
}
Add-CollapsibleSection -title "Users and Groups" -content $userGroupContent

# Hardware Configuration
$compSys = Get-WmiObject -Class Win32_ComputerSystem
$proc = Get-WmiObject -Class Win32_Processor
$memory = Get-WmiObject -Class Win32_PhysicalMemory
$drives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"

$hwContent = "<table><tr><th>Manufacturer</th><th>Model</th><th>Processor</th><th>RAM (GB)</th><th>Drives</th></tr>"
$hwContent += "<tr><td>$($compSys.Manufacturer)</td><td>$($compSys.Model)</td><td>$($proc.Name)</td><td>$([math]::round(($memory.Capacity | Measure-Object -Sum).Sum/1GB, 2))</td><td>"
foreach ($drive in $drives) {
    $usedSpace = [math]::round(($drive.Size - $drive.FreeSpace) / 1GB, 2)
    $hwContent += "Drive $($drive.DeviceID): $([math]::round($drive.Size/1GB, 2)) GB (Used: $usedSpace GB)<br>"
}
$hwContent += "</td></tr></table>"
Add-CollapsibleSection -title "Hardware Configuration" -content $hwContent

# Software Configuration
$software = Get-WmiObject -Class Win32_Product
if ($software) {
    $softwareContent = "<table><tr><th>Software Name</th><th>Version</th><th>Vendor</th></tr>"
    foreach ($app in $software) {
        $softwareContent += "<tr><td>$($app.Name)</td><td>$($app.Version)</td><td>$($app.Vendor)</td></tr>"
    }
    $softwareContent += "</table>"
} else {
    $softwareContent = "<p>No software found.</p>"
}
Add-CollapsibleSection -title "Software Configuration" -content $softwareContent

# Networking Information
$networkAdapters = Get-NetAdapter
$networkContent = "<table><tr><th>Name</th><th>Status</th><th>MAC Address</th><th>IP Address</th><th>Subnet</th><th>DNS</th><th>DHCP Enabled</th></tr>"
foreach ($adapter in $networkAdapters) {
    $ipConfig = Get-NetIPAddress -InterfaceAlias $adapter.Name | Where-Object { $_.AddressFamily -eq "IPv4" }
    $dnsServers = Get-DnsClientServerAddress -InterfaceAlias $adapter.Name | Select-Object -ExpandProperty ServerAddresses
    $networkContent += "<tr><td>$($adapter.Name)</td><td>$($adapter.Status)</td><td>$($adapter.MacAddress)</td><td>$($ipConfig.IPAddress)</td><td>$($ipConfig.PrefixLength)</td><td>$($dnsServers -join ", ")</td><td>$($adapter.DhcpEnabled)</td></tr>"
}
$networkContent += "</table>"
Add-CollapsibleSection -title "Networking Information" -content $networkContent

# Open Ports
$openPorts = Get-NetTCPConnection -State Listen
$openPortContent = "<table><tr><th>Port</th><th>Process Name</th></tr>"
foreach ($port in $openPorts) {
    $proc = Get-Process -Id $port.OwningProcess | Select-Object -ExpandProperty ProcessName
    $openPortContent += "<tr><td>$($port.LocalPort)</td><td>$proc</td></tr>"
}
$openPortContent += "</table>"
Add-CollapsibleSection -title "Open Ports" -content $openPortContent

# ARP Table
$arpTable = Get-NetNeighbor
$arpContent = "<table><tr><th>IPAddress</th><th>MACAddress</th><th>State</th></tr>"
foreach ($arp in $arpTable) {
    $arpContent += "<tr><td>$($arp.IPAddress)</td><td>$($arp.MacAddress)</td><td>$($arp.State)</td></tr>"
}
$arpContent += "</table>"
Add-CollapsibleSection -title "ARP Table" -content $arpContent

# Route Table
$routeTable = Get-NetRoute
$routeContent = "<table><tr><th>Destination</th><th>Mask</th><th>Gateway</th><th>Interface</th><th>Metric</th></tr>"
foreach ($route in $routeTable) {
    $routeContent += "<tr><td>$($route.DestinationPrefix)</td><td>$($route.PrefixLength)</td><td>$($route.NextHop)</td><td>$($route.InterfaceAlias)</td><td>$($route.RouteMetric)</td></tr>"
}
$routeContent += "</table>"
Add-CollapsibleSection -title "Route Table" -content $routeContent

# Printers
$printers = Get-WmiObject -Query "SELECT * FROM Win32_Printer"
if ($printers) {
    $printerContent = "<table><tr><th>Printer Name</th><th>IP Address</th><th>Driver</th><th>Share Name</th></tr>"
    foreach ($printer in $printers) {
        if ($printer.PortName -match '\d+\.\d+\.\d+\.\d+') {
            $printerIP = $matches[0]
        } else {
            $printerIP = "N/A"
        }
        $printerShare = if ($printer.Shared) { $printer.ShareName } else { "Not Shared" }
        $printerContent += "<tr><td>$($printer.Name)</td><td>$printerIP</td><td>$($printer.DriverName)</td><td>$printerShare</td></tr>"
    }
    $printerContent += "</table>"
} else {
    $printerContent = "<p>No printers found.</p>"
}
Add-CollapsibleSection -title "Printers" -content $printerContent

$html += @"
<script>
    var coll = document.getElementsByClassName('collapsible');
    for (var i = 0; i < coll.length; i++) {
        coll[i].addEventListener('click', function() {
            this.classList.toggle('active');
            var content = this.nextElementSibling;
            if (content.style.display === 'block') {
                content.style.display = 'none';
            } else {
                content.style.display = 'block';
            }
        });
    }
</script>
</body>
</html>
"@

$reportPath = Join-Path -Path $outputDirectory -ChildPath "DeviceReport.html"
$html | Out-File -FilePath $reportPath

Write-Output "Report generated at $reportPath"
