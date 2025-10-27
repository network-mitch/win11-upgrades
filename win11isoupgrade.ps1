<# Upgrade Windows 11 with ISO by Isaac Good
Notes:
    - Microsoft servers are very limiting about downloads so for best results host your own
      copy of the ISO on your website or a storage bucket like Wasabi that has free egress.
    - Some machines will just exit Setup after a few seconds so I created an optional fallback of
      running as the logged in user, elevating them temporarily to admin if needed. Sometimes
      even that fails. Would love to have a better solution, please share your ideas.
    - Read all the variables and make sure they're set appropriately for your environment!
    - Make sure to increase the script timeout in Syncro to longer than your
      $TimeToWaitForCompletion + typical download time or you won't get full output in logs.

Changelog:
1.2.0 / 2025-09-28
        Changed - Variable-ized 'Disable Privacy Settings Experience'
        Changed - Registry changes now use PS commands in a function instead of reg.exe commands
        Added - Option to skip hardware compatibility checks like TPM & CPU (CAUTION: future build upgrades will have to be done with this script/via ISO or device will be stuck on EOL build forever)
        Added - Remove folders from previous Windows upgrades to free up space and start fresh
        Fixed - Now dismounts image if upgrade fails
        Fixed - $DriveLetter was undefined, changed to $env:SystemDrive
1.1.2 / 2024-12-12
        Changed - ISO is no longer deleted if upgrade fails (avoids excessive bandwidth use/retry time)
        Added - $ProvidedURLARM64 if you want to provide your own ISO for ARM64
        Note - Fido now detects ARM64 and downloads the appropriate ISO
1.1.1 / 2023-11-01
        Fixed - Since the Net command doesn't show local computer name as part of username,
                the script tried to give admin to users that already were admin, then removed it.
  1.1 / 2023-10-20
        Changed - Variable-ized some parameters, general cleanup & optimization
        Added - Error catching/handling for key functions
        Added - Option to provide your own ISO download URL to avoid rate limiting
        Added - Option to upgrade Windows 10 to 11
        Added - Option to temporarily elevate current user to Administrators group if needed
        Added - Option to extend rollback period
        Added - Alternate method of starting setup when running under SYSTEM fails (no idea why)
        Added - Folder exclusion to prevent Windows Defender from interfering
        Fixed - Replaced deprecated Get-WMIObject with Get-CIMInstance
  1.0 / 2023-10-08 - Original script provided by Doc in Syncro forums: https://community.syncromsp.com/t/windows-11-feature-update-script-to-22h2/9538/12
#>

# Install Variables
# Reference: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-command-line-options?view=windows-11
$TargetFolder = "$env:Temp\Windows11Upgrade"
$ISOFilePath = "$TargetFolder\Windows.iso"
$WindowsSetupArguments = "/Auto Upgrade /BitLocker TryKeepActive /Compat IgnoreWarning /CopyLogs $TargetFolder /DynamicUpdate Enable /Eula Accept /MigrateDrivers All /NoReboot /Quiet /ShowOOBE None /Telemetry Disable"
$RequiredSpaceInGB = '40'
$UpgradeWindows10 = $true
$RebootAfterSetup = $false
$ElevateUserIfNeeded = $true # Temporarily adds user to Administrators group if needed, there is a brief window where script could be interrupted and user would stay admin!
$TimeToWaitForCompletion = '180' # In minutes. Depending on the machine can take 20mins up to several hours
$DaysToAllowRollback = '7' # Min 2, Max 60, Windows default is 10. If devices are tight for space you may want to reduce this

# Fido is used to retrieve Microsoft's ISO file URL https://github.com/pbatard/Fido/tree/master
# These settings don't matter if you're providing your own ISO URL
$FidoURL = "https://raw.githubusercontent.com/network-mitch/win11-upgrades/refs/heads/main/Fido.ps1"
$TargetVersion = 'Latest' # Example: '22H2' or 'Latest'
$Language = 'English'

# Provide your own ISO download URL
# If you do so, $TargetVersion and $Language above will be ignored
$ProvidedURL = ''
$ProvidedURLARM64 = ''

# Skip hardware compatibility checks like TPM & CPU
# CAUTION: Upgrading incompatible hardware means you will have to use this ISO upgrade method for every new feature update on that machine or be stuck on EOL build forever
$SkipHardwareChecks = $true

# Disable Privacy Settings Experience at first sign-in so users aren't prompted
$DisablePrivacyExperience = $true

##### END OF VARIABLES #####

function Exit-WithError {
    param ($Text)
    Write-Output $Text
    if (Get-Module | Where-Object { $_.ModuleBase -match 'Syncro' }) {
        Rmm-Alert -Category "Windows 11 ISO Upgrade" -Body $Text
    }
    # Pause # Uncomment for interactive troubleshooting
    SchTasks /delete /tn "Windows Setup" /f
    Get-DiskImage -ImagePath "$ISOFilePath" -ErrorAction SilentlyContinue | Dismount-DiskImage | Out-Null
    Start-Sleep 10
    exit 1
}

function Get-Download {
    param ($URL, $TargetFolder, $FileName)
    $DownloadSize = (Invoke-WebRequest $URL -Method Head -UseBasicParsing).Headers.'Content-Length'
    Write-Output "Downloading: $URL ($([math]::round($DownloadSize/1GB, 1)) GB)`nDestination: $TargetFolder\$FileName"
    # Check if file already exists
    if ($DownloadSize -ne (Get-ItemProperty $TargetFolder\$FileName -ErrorAction SilentlyContinue).Length) {
        Invoke-WebRequest -Uri $URL -OutFile $TargetFolder\$FileName -UseBasicParsing
        # Verify download success
        $DownloadSizeOnDisk = (Get-ItemProperty $TargetFolder\$FileName -ErrorAction SilentlyContinue).Length
        if ($DownloadSize -ne $DownloadSizeOnDisk) {
            Remove-Item $TargetFolder\$FileName
            Exit-WithError "Download size ($DownloadSize) and size on disk ($DownloadSizeOnDisk) do not match, download failed."
        }
    } else { Write-Output 'File with same size already exists at download target.' }
}

function Start-Cleanup {
    Write-Output "Cleaning up..."
    SchTasks /delete /tn "Windows Setup" /f
    while ((Test-Path $ISOFilePath) -and $CleanupAttempts -lt 10) {
        Get-DiskImage -ImagePath "$ISOFilePath" -ErrorAction SilentlyContinue | Dismount-DiskImage | Out-Null
        Start-Sleep 5
        Remove-Item "$ISOFilePath" -ErrorAction SilentlyContinue
        $CleanupAttempts = $CleanupAttempts + 1
    }
}

function Set-RegistryValueForced {
    param ([string]$Path, [string]$Name, [string]$Type, [object]$Value)
    try {
        if (-not (Test-Path -Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
    } catch {
        Write-Output "Failed to set $Name in ${Path}: $($_.Exception.Message)"
    }
}

# Check upgrade eligibility
$OS = (Get-CimInstance Win32_OperatingSystem).Name
if ($OS -notmatch "Windows 11" -and $UpgradeWindows10 -eq $false) {
    Write-Output "Device is not running Windows 11 and Windows 10 upgrade variable is $false, exiting."
    exit
} elseif ($OS -notmatch "Windows 10" -and (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'DisplayVersion').DisplayVersion -eq "$TargetVersion") {
    Write-Output "Already running Windows 11 $TargetVersion, exiting."
    exit
}

# Change registry settings to skip hardware compatibility checks
if ($SkipHardwareChecks -eq $true) {
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\CompatMarkers" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Shared" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators" -Recurse -Force -ErrorAction SilentlyContinue
    Set-RegistryValueForced -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\HwReqChk" -Name "HwReqChkVars" -Type MultiString -Value @("SQ_SecureBootCapable=TRUE", "SQ_SecureBootEnabled=TRUE", "SQ_TpmVersion=2", "SQ_RamMB=8192")
    Set-RegistryValueForced -Path "HKLM:\SYSTEM\Setup\MoSetup" -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -Type DWord -Value 1
    Set-RegistryValueForced -Path "HKCU:\Software\Microsoft\PCHC" -Name "UpgradeEligibility" -Type DWord -Value 1
}

# Disable Privacy Settings Experience at first sign-in
if ($DisablePrivacyExperience -eq $true) {
    Set-RegistryValueForced "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Type DWord -Value 1
}

# Remove folders from previous Windows upgrades to free up space and start fresh
Remove-Item "$env:SystemDrive\Windows.old" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item "$env:SystemDrive\`$GetCurrent\" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item "$env:SystemDrive\`$WINDOWS.~*\" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

# Check disk free space
$Disk = Get-CimInstance -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
$FreeSpaceInGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
if ($FreeSpaceInGB -lt $RequiredSpaceInGB) {
    Exit-WithError "Drive $env:SystemDrive has only $FreeSpaceInGB GB free of the required $RequiredSpaceInGB GB, exiting."
}

# Create the $TargetFolder directory if it doesn't exist and switch to it
if (-not (Test-Path -Path "$TargetFolder" -PathType Container)) {
    New-Item -Path "$TargetFolder" -ItemType Directory | Out-Null
}
Set-Location $TargetFolder

# Set how long to allow rollback
DISM /Online /Set-OSUninstallWindow /Value:$DaysToAllowRollback | Out-Null

# Add folder exclusion so Windows Defender doesn't freak out about mounting a downloaded ISO
Add-MpPreference -ExclusionPath $TargetFolder -ErrorAction SilentlyContinue

# Download the ISO
if ((Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Architecture) -eq 12) {
    $ProvidedURL = $ProvidedURLARM64
}
$ProgressPreference = "SilentlyContinue" # avoid slowdown from displaying progress
if (-not $ProvidedURL) {
    try { Get-Download -URL $FidoURL -TargetFolder $TargetFolder -FileName 'Fido.ps1' }
    catch { Exit-WithError "Fido script download error: $($_.Exception.Message)" }
    # Set execution policy to allow Fido.ps1 to run
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    $ProvidedURL = &".\Fido.ps1" -Win 11 -Lang $Language -Rel $TargetVersion -GetURL
    Remove-Item "$TargetFolder\Fido.ps1"
    if (-not $ProvidedURL) {
        Exit-WithError "Fido script did not return a download URL. Likely blocked by MS, see script log to confirm."
    }
}
try { Get-Download -URL $ProvidedURL -TargetFolder $TargetFolder -FileName 'Windows.iso' }
catch { Exit-WithError "Windows ISO download error: $($_.Exception.Message)" }

Write-Output "Mounting the ISO..."
try { $MountResult = Mount-DiskImage -ImagePath $ISOFilePath -ErrorAction Stop }
catch { Exit-WithError "Windows ISO mount error: $($_.Exception.Message)" }

Write-Output "Starting Windows Setup..."
$BeginTime = Get-Date
$MountedDrive = ($MountResult | Get-Volume).DriveLetter
$process = Start-Process -FilePath "${MountedDrive}:\setup.exe" -ArgumentList $WindowsSetupArguments -Wait -PassThru
Write-Output "Setup exit code: $($process.ExitCode)"
if ($process.ExitCode -eq '-2147024769' -or $process.ExitCode -eq '-1073741502') {
    $CurrentUser = Get-CimInstance -class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
    # If CurrentUser is a non-domain user, trim down to just the username as Net command doesn't show computer name in username
    if ($CurrentUser -Like "$env:ComputerName\*") { $CurrentUser = $CurrentUser | Split-Path -Leaf }
    if ($CurrentUser) {
        Write-Output "Running setup under SYSTEM failed, trying to run as the currently logged in user instead."
        if ((Net LocalGroup Administrators) -NotContains $CurrentUser -and $ElevateUserIfNeeded -eq $true) {
            Write-Output "$CurrentUser is not in the Administrators group, adding them temporarily."
            Net LocalGroup Administrators $CurrentUser /Add
            $SetUserAsAdmin = $true
        } elseif ((Net LocalGroup Administrators) -NotContains $CurrentUser -and $ElevateUserIfNeeded -eq $false) {
            Exit-WithError "Running setup under SYSTEM failed, $CurrentUser is not in the Administrators group and ElevateUserToAdmin is off so scheduled task method also failed."
        }
        $StartTime = ((Get-Date).AddMinutes(2)).ToString('HH:mm')
        SchTasks /Create /TN "Windows Setup" /SC Once /ST $StartTime /TR "${MountedDrive}:\setup.exe $WindowsSetupArguments" /RU $CurrentUser /RL Highest /F
    } else {
        Exit-WithError "Running setup under SYSTEM failed and there was no logged in user so scheduled task method also failed."
    }
} elseif ($process.ExitCode -eq '-1047526912') {
    Exit-WithError "Setup exited because the device does not meet the minimum requirements to upgrade Windows."
} elseif ($process.ExitCode -eq '-2147024680') {
    Exit-WithError "Device may be running an ARM processor which MS doesn't provide an ISO for, you can generate your own using uupdump.net or use the Windows Update GUI."
}
 
Write-Output "Waiting for upgrade to complete..."
if ($SetUserAsAdmin) {
    Start-Sleep 140
    Write-Output "While the upgrade is running we can remove $CurrentUser from the Administrators group."
    Net LocalGroup Administrators $CurrentUser /Delete
    if (-not (Get-Process | Select-Object Path | Where-Object { $_.Path -like "${MountedDrive}:\*" })) {
        Exit-WithError "Setup isn't running, scheduled task method must have also failed. Try upgrading this machine manually."
    }
}
while ((Get-EventLog -Log 'Application' -Source 'System Restore' -EntryType 'Information' -InstanceId '8198' -After $BeginTime -ErrorAction SilentlyContinue).Count -eq 0 -and $minutes -lt $TimeToWaitForCompletion) {
    Start-Sleep 60
    $minutes = $minutes + 1
}

if ($minutes -eq $TimeToWaitForCompletion) {
    Exit-WithError "It's been over $TimeToWaitForCompletion minutes, something probably went wrong, check logs for details."
} else {
    Write-Output "Event ID 8198 found, indicating setup has completed and is ready to restart. Cleaning up."
    Start-Cleanup
    if ($RebootAfterSetup) {
        'Rebooting...'
        shutdown /r /f
    }
}
