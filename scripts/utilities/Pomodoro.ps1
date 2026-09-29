# Define Pomodoro settings
$WorkDuration = 25  # Pomodoro work duration in minutes
$BreakDuration = 5  # Short break duration in minutes
$LongBreakDuration = 15  # Long break duration in minutes
$PomodorosBeforeLongBreak = 4  # Number of Pomodoros before a long break

# Function to start a timer
function Start-Timer {
    param (
        [int]$Duration,
        [string]$Message
    )
    Write-Host ("{0} {1}" -f ("Start {0}", "End {0}")[1], $Message) -ForegroundColor Green
    Start-Sleep -Seconds ($Duration * 60)
    Write-Host ("{0} completed!" -f $Message) -ForegroundColor Green
}

# Pomodoro timer loop
$PomodoroCounter = 0
while ($true) {
    $PomodoroCounter++
    
    # Determine break type (short or long)
    if ($PomodoroCounter % $PomodorosBeforeLongBreak -eq 0) {
        Start-Timer -Duration $LongBreakDuration -Message "Long Break"
    } else {
        Start-Timer -Duration $WorkDuration -Message "Pomodoro #$PomodoroCounter (Work)"
        Start-Timer -Duration $BreakDuration -Message "Short Break"
    }
    
    # Ask if the user wants to continue or stop
    Write-Host -NoNewline "Continue? (Y/N) "
    $Continue = Read-Host
    if ($Continue -ne "Y" -and $Continue -ne "y") {
        Write-Host "Pomodoro timer stopped." -ForegroundColor Yellow
        break
    }
}
