# Define the URL and the session key
$url = ""
$sessionKey = ""

# Validate session key
if (-not $sessionKey) {
    Write-Host "Session key is missing. Please provide a valid session key."
    exit 1
}

# Set the headers as a dictionary
$headers = @{
    "Accept" = "application/json"
    "Cookie" = "sessionKey=$sessionKey"
}

# Print URL and headers for debugging
Write-Host "URL: $url"
Write-Host "Headers:"
$headers.GetEnumerator() | ForEach-Object { Write-Host "$($_.Key): $($_.Value)" }

# Perform the GET request with detailed response
try {
    $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction Stop
    Write-Host "Organizations retrieved successfully."
    
    # Print the raw response for debugging
    Write-Host "Response Content:"
    $response | ConvertTo-Json -Depth 3
    
    # Display the organization details
    $response | ForEach-Object {
        Write-Host "Name: $($_.name)"
        Write-Host "Node Approval Mode: $($_.nodeApprovalMode)"
        Write-Host "ID: $($_.id)"
        Write-Host "-------------------------"
    }
} catch {
    # Handle HTTP errors and general errors
    Write-Host "An error occurred: $_.Exception.Message"

    if ($_.Exception.Response -ne $null) {
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $errorResponse = $streamReader.ReadToEnd()
        Write-Host "Error Response Content: $errorResponse"
    } else {
        Write-Host "No additional error response content available."
    }

    # Additional error details
    if ($_.ErrorDetails) {
        Write-Host "Error Details: $($_.ErrorDetails)"
    }

    exit 1
}
