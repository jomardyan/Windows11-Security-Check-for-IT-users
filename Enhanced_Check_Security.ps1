<#
.SYNOPSIS
    Comprehensive security checks for Windows 10 and Windows 11 systems, including domain-specific assessments.

.DESCRIPTION
    This script performs an extensive set of security checks on a Windows 10 or Windows 11 system, covering various aspects
    such as firewall status, antivirus status, system updates, account policies, audit policies, services,
    network settings, firewall rules, administrative shares, installed software vulnerabilities, drive encryption,
    browser security settings, antivirus definitions, and additional domain-specific security checks if the system is joined to a domain.
    It displays the results with color-coded statuses, summarizes them, provides final notes for failed tests,
    and optionally saves the results to a specified disk location.

.PARAMETER OutputPath
    (Optional) The disk location where the results should be saved as a text file.

.EXAMPLE
    .\Check-WinSecurity.ps1
    Performs security checks and displays the results.

.EXAMPLE
    .\Check-WinSecurity.ps1 -OutputPath "C:\SecurityReports\SecurityReport.txt"
    Performs security checks and saves the results to the specified text file.
#>

[CmdletBinding()]
param (
    [Parameter(Position=0, Mandatory=$false, HelpMessage="Specify the output path for the results file.")]
    [string]$OutputPath
)

# Initialize an array to store the results
$script:Results = @()

# Function to add result to the Results array
function Add-Result {
    param (
        [string]$TestName,
        [string]$Status,
        [string]$Message
    )
    $script:Results += [PSCustomObject]@{
        Test    = $TestName
        Status  = $Status
        Message = $Message
    }
}

# Function to interpret the productState value for Antivirus
function Get-AntivirusStatus {
    param (
        [int]$ProductState
    )

    # Decode the productState bitmask
    $currentState = $ProductState -band 0xFF
    $definitionState = ($ProductState -band 0xFF00) -shr 8
    $onAccessProtection = ($ProductState -band 0xFF0000) -shr 16

    # Determine current state
    switch ($currentState) {
        0 { $status = "OFF" }
        1 { $status = "SUSPENDED" }
        10 { $status = "RUNNING" }
        11 { $status = "OFFLINE" }
        default { $status = "UNKNOWN" }
    }

    # Determine definition state
    switch ($definitionState) {
        0 { $defState = "UNKNOWN" }
        1 { $defState = "OUT-OF-DATE" }
        2 { $defState = "UPDATED" }
        default { $defState = "UNKNOWN" }
    }

    # Determine on-access protection
    switch ($onAccessProtection) {
        0 { $onAccess = "OFF" }
        1 { $onAccess = "ON" }
        default { $onAccess = "UNKNOWN" }
    }

    return @{
        Status             = $status
        DefinitionStatus   = $defState
        OnAccessProtection = $onAccess
    }
}

# Function to detect if the system is domain-joined
function Is-DomainJoined {
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        return $computerSystem.PartOfDomain
    }
    catch {
        return $false
    }
}

# Function to perform domain-specific checks
function Perform-DomainChecks {
    Write-Output "Performing Domain-Specific Security Checks..."

    ### 1. Check Connectivity to Domain Controllers ###
    try {
        Write-Output "Checking connectivity to Domain Controllers..."
        $domain = try {
            ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
        }
        catch {
            throw "Unable to retrieve the current domain. Ensure the system is properly joined to the domain."
        }

        $domainControllers = try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindAllDomainControllers()
        }
        catch {
            throw "Unable to retrieve domain controllers for the domain '$domain'."
        }

        $reachableDCs = @()

        foreach ($dc in $domainControllers) {
            if (Test-Connection -ComputerName $dc.Name -Count 1 -Quiet) {
                $reachableDCs += $dc.Name
            }
        }

        if ($reachableDCs.Count -eq $domainControllers.Count) {
            Add-Result -TestName "Domain Controller Connectivity" -Status "Passed" -Message "All domain controllers are reachable."
        }
        elseif ($reachableDCs.Count -gt 0) {
            Add-Result -TestName "Domain Controller Connectivity" -Status "Info" -Message "$($reachableDCs.Count) out of $($domainControllers.Count) domain controllers are reachable."
        }
        else {
            Add-Result -TestName "Domain Controller Connectivity" -Status "Failed" -Message "No domain controllers are reachable."
        }
        Write-Output "Domain Controller Connectivity Check Completed.`n"
    }
    catch {
        Add-Result -TestName "Domain Controller Connectivity" -Status "Error" -Message $_.Exception.Message
        Write-Output "Error checking Domain Controller Connectivity: $_.Exception.Message`n"
    }

    ### 2. Check Group Policy Compliance ###
    try {
        Write-Output "Checking Group Policy Compliance..."
        # Example: Verify that specific group policies are enforced
        # This can be expanded based on company-specific policies

        # Check if specific registry keys are set as per Group Policies
        # Example: Ensure that Windows Firewall is configured via Group Policy
        $firewallPolicy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
        if ($firewallPolicy -and $firewallPolicy.EnableFirewall -eq 1) {
            Add-Result -TestName "Group Policy: Windows Firewall" -Status "Passed" -Message "Windows Firewall is enabled via Group Policy."
        }
        else {
            Add-Result -TestName "Group Policy: Windows Firewall" -Status "Failed" -Message "Windows Firewall is not enabled via Group Policy."
        }

        # Add more group policy checks as required by your organization

        Write-Output "Group Policy Compliance Check Completed.`n"
    }
    catch {
        Add-Result -TestName "Group Policy Compliance" -Status "Error" -Message $_.Exception.Message
        Write-Output "Error checking Group Policy Compliance: $_.Exception.Message`n"
    }

    ### 3. Check VPN Connection ###
    try {
        Write-Output "Checking VPN Connection Status..."
        # Example: Check if VPN is connected
        $vpnConnections = Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue
        if ($vpnConnections) {
            foreach ($vpn in $vpnConnections) {
                if ($vpn.ConnectionStatus -eq "Connected") {
                    Add-Result -TestName "VPN Connection ($($vpn.Name))" -Status "Passed" -Message "VPN connection '$($vpn.Name)' is active."
                }
                else {
                    Add-Result -TestName "VPN Connection ($($vpn.Name))" -Status "Info" -Message "VPN connection '$($vpn.Name)' is not active."
                }
            }
        }
        else {
            Add-Result -TestName "VPN Connection" -Status "Info" -Message "No VPN connections configured."
        }
        Write-Output "VPN Connection Status Check Completed.`n"
    }
    catch {
        Add-Result -TestName "VPN Connection" -Status "Error" -Message $_.Exception.Message
        Write-Output "Error checking VPN Connection: $_.Exception.Message`n"
    }

    ### 4. Check Network Share Permissions ###
    try {
        Write-Output "Checking Network Share Permissions..."
        # Example: Verify access to specific network shares
        # Replace '\\CompanyShare\Folder' with actual share paths
        $networkShares = @("\\CompanyShare\Folder1", "\\CompanyShare\Folder2")
        foreach ($share in $networkShares) {
            if (Test-Path $share) {
                Add-Result -TestName "Network Share Access ($share)" -Status "Passed" -Message "Access to '$share' is available."
            }
            else {
                Add-Result -TestName "Network Share Access ($share)" -Status "Failed" -Message "Cannot access '$share'. Ensure you have the necessary permissions and connectivity."
            }
        }
        Write-Output "Network Share Permissions Check Completed.`n"
    }
    catch {
        Add-Result -TestName "Network Share Permissions" -Status "Error" -Message $_.Exception.Message
        Write-Output "Error checking Network Share Permissions: $_.Exception.Message`n"
    }

    ### 5. Check for Required Domain Software ###
    try {
        Write-Output "Checking for Required Domain Software..."
        # Example: Ensure that domain-specific applications are installed
        $requiredSoftware = @("CompanyVPN", "CompanyEndpointProtection", "CompanyComplianceAgent")
        $installedSoftware = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
            Select-Object DisplayName, DisplayVersion | 
            Where-Object { $_.DisplayName -and ($requiredSoftware -contains $_.DisplayName) }

        foreach ($software in $requiredSoftware) {
            if ($installedSoftware.DisplayName -contains $software) {
                Add-Result -TestName "Required Software ($software)" -Status "Passed" -Message "$software is installed."
            }
            else {
                Add-Result -TestName "Required Software ($software)" -Status "Failed" -Message "$software is not installed. Please install it to comply with company policies."
            }
        }
        Write-Output "Required Domain Software Check Completed.`n"
    }
    catch {
        Add-Result -TestName "Required Domain Software" -Status "Error" -Message $_.Exception.Message
        Write-Output "Error checking Required Domain Software: $_.Exception.Message`n"
    }

    # Additional domain-specific checks can be added here based on organizational requirements
}

Write-Output "Starting Windows Security Comprehensive Checks..."
Write-Output "---------------------------------------------------`n"

### 1. Check Windows Firewall Status ###
try {
    Write-Output "Checking Windows Firewall Status..."
    $firewallStatus = Get-NetFirewallProfile | Select-Object Name, Enabled
    foreach ($profile in $firewallStatus) {
        if ($profile.Enabled) {
            Add-Result -TestName "Windows Firewall ($($profile.Name))" -Status "Passed" -Message "Firewall is enabled."
        }
        else {
            Add-Result -TestName "Windows Firewall ($($profile.Name))" -Status "Failed" -Message "Firewall is disabled."
        }
    }
    Write-Output "Windows Firewall Status Check Completed.`n"
}
catch {
    Add-Result -TestName "Windows Firewall Status" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Windows Firewall: $_.Exception.Message`n"
}

### 2. Check Antivirus Status ###
try {
    Write-Output "Checking Antivirus Status..."
    $antivirusProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct

    if ($antivirusProducts) {
        foreach ($av in $antivirusProducts) {
            $statusInfo = Get-AntivirusStatus -ProductState $av.productState
            if ($statusInfo.Status -eq "RUNNING" -and $statusInfo.DefinitionStatus -eq "UPDATED" -and $statusInfo.OnAccessProtection -eq "ON") {
                Add-Result -TestName "Antivirus ($($av.displayName))" -Status "Passed" -Message "Antivirus is enabled, up-to-date, and real-time protection is active."
            }
            else {
                Add-Result -TestName "Antivirus ($($av.displayName))" -Status "Failed" -Message "Antivirus is not fully active. Status: $($statusInfo.Status), Definitions: $($statusInfo.DefinitionStatus), Real-Time Protection: $($statusInfo.OnAccessProtection)."
            }
        }
    }
    else {
        Add-Result -TestName "Antivirus Status" -Status "Failed" -Message "No antivirus product found."
    }
    Write-Output "Antivirus Status Check Completed.`n"
}
catch {
    Add-Result -TestName "Antivirus Status" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Antivirus Status: $_.Exception.Message`n"
}

### 3. Check Windows Update Service Status ###
try {
    Write-Output "Checking Windows Update Service Status..."
    $wuSettings = Get-Service -Name wuauserv -ErrorAction Stop
    if ($wuSettings.Status -eq 'Running') {
        Add-Result -TestName "Windows Update Service" -Status "Passed" -Message "Windows Update service is running."
    }
    else {
        Add-Result -TestName "Windows Update Service" -Status "Failed" -Message "Windows Update service is not running."
    }
    Write-Output "Windows Update Service Status Check Completed.`n"
}
catch {
    Add-Result -TestName "Windows Update Status" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Windows Update Status: $_.Exception.Message`n"
}

### 4. Check Pending Windows Updates ###
try {
    Write-Output "Checking for Pending Windows Updates..."
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    if ($searchResult.Updates.Count -gt 0) {
        Add-Result -TestName "Pending Windows Updates" -Status "Failed" -Message "$($searchResult.Updates.Count) pending updates found."
    }
    else {
        Add-Result -TestName "Pending Windows Updates" -Status "Passed" -Message "No pending updates."
    }
    Write-Output "Pending Windows Updates Check Completed.`n"
}
catch {
    Add-Result -TestName "Pending Windows Updates" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Pending Windows Updates: $_.Exception.Message`n"
}

### 5. Check Account Lockout Policies ###
try {
    Write-Output "Checking Account Lockout Policies..."

    # Account Lockout Threshold
    $lockoutThreshold = try {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutThreshold" -ErrorAction Stop).LockoutThreshold
    }
    catch {
        $null
    }

    # Account Lockout Duration
    $lockoutDuration = try {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutDuration" -ErrorAction Stop).LockoutDuration / 60
    }
    catch {
        $null
    }

    # Reset Account Lockout Counter After
    $resetCounter = try {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutObservationWindow" -ErrorAction Stop).LockoutObservationWindow / 60
    }
    catch {
        $null
    }

    # Define acceptable policies
    $acceptableThreshold = 5
    $acceptableDuration = 15
    $acceptableReset = 15

    if (($lockoutThreshold -le $acceptableThreshold) -and ($lockoutDuration -ge $acceptableDuration) -and ($resetCounter -ge $acceptableReset)) {
        Add-Result -TestName "Account Lockout Policy" -Status "Passed" -Message "Account lockout policies are appropriately configured. Threshold: $lockoutThreshold, Duration: $lockoutDuration minutes, Reset Counter: $resetCounter minutes."
    }
    else {
        Add-Result -TestName "Account Lockout Policy" -Status "Failed" -Message "Account lockout policies need adjustment. Threshold: $lockoutThreshold, Duration: $lockoutDuration minutes, Reset Counter: $resetCounter minutes."
    }
    Write-Output "Account Lockout Policies Check Completed.`n"
}
catch {
    Add-Result -TestName "Account Lockout Policies" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Account Lockout Policies: $_.Exception.Message`n"
}

### 6. Check Password Complexity and Length Policies ###
try {
    Write-Output "Checking Password Complexity and Length Policies..."

    # Minimum Password Length
    $passwordLength = try {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "MinimumPasswordLength" -ErrorAction Stop).MinimumPasswordLength
    }
    catch {
        $null
    }

    # Enforce Password History
    $passwordHistory = try {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordHistorySize" -ErrorAction Stop).PasswordHistorySize
    }
    catch {
        $null
    }

    # Password Must Meet Complexity Requirements
    $passwordComplexity = try {
        (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PasswordComplexity" -ErrorAction Stop).PasswordComplexity
    }
    catch {
        $null
    }

    # Define acceptable policies
    $acceptableLength = 12
    $acceptableHistory = 24

    if (($passwordLength -ge $acceptableLength) -and ($passwordHistory -ge $acceptableHistory) -and ($passwordComplexity -eq 1)) {
        Add-Result -TestName "Password Policy" -Status "Passed" -Message "Password policies meet the recommended standards. Minimum Length: $passwordLength, Password History: $passwordHistory, Complexity Required: Enabled."
    }
    else {
        $complexityStatus = if ($passwordComplexity -eq 1) { "Enabled" } else { "Disabled" }
        Add-Result -TestName "Password Policy" -Status "Failed" -Message "Password policies need enhancement. Minimum Length: $passwordLength, Password History: $passwordHistory, Complexity Required: $complexityStatus."
    }
    Write-Output "Password Complexity and Length Policies Check Completed.`n"
}
catch {
    Add-Result -TestName "Password Complexity and Length Policies" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Password Policies: $_.Exception.Message`n"
}

### 7. Check Audit Policies ###
try {
    Write-Output "Checking Audit Policies..."

    # Audit Logon Events
    $auditLogon = try {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditBaseObjects" -ErrorAction Stop).AuditBaseObjects
    }
    catch {
        $null
    }

    # Audit Object Access
    $auditObjectAccess = try {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "CategoryCount" -ErrorAction Stop).CategoryCount
    }
    catch {
        $null
    }

    # Audit Privilege Use
    $auditPrivilegeUse = try {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "CategoryCount" -ErrorAction Stop).CategoryCount
    }
    catch {
        $null
    }

    # Since precise audit policies are complex to retrieve via registry, we'll simplify
    # and assume that certain keys being set indicates enabled policies.

    # For a more accurate check, consider using the `AuditPol` cmdlet where available.

    $auditLogonEnabled = $false
    $auditObjectAccessEnabled = $false
    $auditPrivilegeUseEnabled = $false

    # Using AuditPol if available
    if (Get-Command AuditPol -ErrorAction SilentlyContinue) {
        $logon = AuditPol /get /category:"Logon/Logoff" | Select-String "Audit Logon"
        $objectAccess = AuditPol /get /category:"Object Access" | Select-String "Audit Object Access"
        $privilegeUse = AuditPol /get /category:"Privilege Use" | Select-String "Audit Privilege Use"

        $auditLogonEnabled = $logon -and $logon.Line -match "Success and Failure"
        $auditObjectAccessEnabled = $objectAccess -and $objectAccess.Line -match "Success and Failure"
        $auditPrivilegeUseEnabled = $privilegeUse -and $privilegeUse.Line -match "Success and Failure"
    }

    if ($auditLogonEnabled -and $auditObjectAccessEnabled -and $auditPrivilegeUseEnabled) {
        Add-Result -TestName "Audit Policies" -Status "Passed" -Message "Audit policies are enabled."
    }
    else {
        Add-Result -TestName "Audit Policies" -Status "Failed" -Message "Audit policies are not fully enabled. Logon Events: $auditLogonEnabled, Object Access: $auditObjectAccessEnabled, Privilege Use: $auditPrivilegeUseEnabled."
    }
    Write-Output "Audit Policies Check Completed.`n"
}
catch {
    Add-Result -TestName "Audit Policies" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Audit Policies: $_.Exception.Message`n"
}

### 8. Check Unnecessary Services ###
try {
    Write-Output "Checking Unnecessary Services..."
    # Define a list of unnecessary services to check
    $unnecessaryServices = @("Telnet", "RemoteRegistry", "Fax", "WMPNetworkSvc")
    $serviceStatus = @()

    foreach ($service in $unnecessaryServices) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne 'Stopped') {
                Add-Result -TestName "Service ($service)" -Status "Failed" -Message "Service '$service' is running and may be unnecessary."
            }
            else {
                Add-Result -TestName "Service ($service)" -Status "Passed" -Message "Service '$service' is stopped."
            }
        }
        else {
            Add-Result -TestName "Service ($service)" -Status "Info" -Message "Service '$service' is not installed."
        }
    }
    Write-Output "Unnecessary Services Check Completed.`n"
}
catch {
    Add-Result -TestName "Unnecessary Services" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Unnecessary Services: $_.Exception.Message`n"
}

### 9. Check Network Security Settings ###
try {
    Write-Output "Checking Network Security Settings..."
    # Check SMBv1 is disabled
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq "Disabled") {
        Add-Result -TestName "SMBv1 Protocol" -Status "Passed" -Message "SMBv1 is disabled."
    }
    else {
        Add-Result -TestName "SMBv1 Protocol" -Status "Failed" -Message "SMBv1 is enabled. It is recommended to disable it."
    }

    # Check Remote Desktop is disabled if not needed
    $rdp = Get-Service -Name TermService -ErrorAction SilentlyContinue
    if ($rdp) {
        if ($rdp.Status -eq 'Running') {
            Add-Result -TestName "Remote Desktop Service" -Status "Info" -Message "Remote Desktop service is running. Ensure it is required and properly secured."
        }
        else {
            Add-Result -TestName "Remote Desktop Service" -Status "Passed" -Message "Remote Desktop service is stopped."
        }
    }
    else {
        Add-Result -TestName "Remote Desktop Service" -Status "Info" -Message "Remote Desktop service is not installed."
    }

    # Check if WinRM is configured securely
    $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($winrm) {
        if ($winrm.StartType -eq 'Automatic' -and $winrm.Status -eq 'Running') {
            Add-Result -TestName "Windows Remote Management (WinRM)" -Status "Info" -Message "WinRM is running. Ensure it is secured properly."
        }
        else {
            Add-Result -TestName "Windows Remote Management (WinRM)" -Status "Passed" -Message "WinRM is not running."
        }
    }
    else {
        Add-Result -TestName "Windows Remote Management (WinRM)" -Status "Info" -Message "WinRM is not installed."
    }

    Write-Output "Network Security Settings Check Completed.`n"
}
catch {
    Add-Result -TestName "Network Security Settings" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Network Security Settings: $_.Exception.Message`n"
}

### 10. Check Firewall Rules ###
try {
    Write-Output "Checking Firewall Rules..."
    # Check for default deny inbound and outbound rules
    $defaultInbound = Get-NetFirewallRule -Direction Inbound -Action Allow | Measure-Object
    $defaultOutbound = Get-NetFirewallRule -Direction Outbound -Action Allow | Measure-Object

    if ($defaultInbound.Count -eq 0 -and $defaultOutbound.Count -eq 0) {
        Add-Result -TestName "Default Firewall Rules" -Status "Passed" -Message "Default deny inbound and outbound rules are in place."
    }
    else {
        Add-Result -TestName "Default Firewall Rules" -Status "Failed" -Message "There are allow rules present. Review firewall rules to ensure they follow the principle of least privilege."
    }

    Write-Output "Firewall Rules Check Completed.`n"
}
catch {
    Add-Result -TestName "Firewall Rules" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Firewall Rules: $_.Exception.Message`n"
}

### 11. Check Administrative Shares ###
try {
    Write-Output "Checking Administrative Shares..."
    $adminShares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Name -match '^\w+\$$' }
    if ($adminShares.Count -gt 0) {
        foreach ($share in $adminShares) {
            Add-Result -TestName "Administrative Share ($($share.Name))" -Status "Info" -Message "Administrative share '$($share.Name)' is present."
        }
    }
    else {
        Add-Result -TestName "Administrative Shares" -Status "Passed" -Message "No administrative shares found."
    }
    Write-Output "Administrative Shares Check Completed.`n"
}
catch {
    Add-Result -TestName "Administrative Shares" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Administrative Shares: $_.Exception.Message`n"
}

### 12. Check Installed Software Vulnerabilities ###
try {
    Write-Output "Checking Installed Software for Known Vulnerabilities..."
    # List of commonly vulnerable software. This list can be expanded as needed.
    $vulnerableSoftware = @("Adobe Acrobat Reader", "Java SE", "Mozilla Firefox", "Google Chrome", "Skype", "WinRAR", "7-Zip", "CompanyVPN", "CompanyEndpointProtection", "CompanyComplianceAgent")
    $installedSoftware = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
        Where-Object { $_.DisplayName -and ($vulnerableSoftware -contains $_.DisplayName) }

    if ($installedSoftware) {
        foreach ($app in $installedSoftware) {
            Add-Result -TestName "Installed Software ($($app.DisplayName))" -Status "Failed" -Message "Installed version: $($app.DisplayVersion). Consider updating to the latest version."
        }
    }
    else {
        Add-Result -TestName "Installed Software Vulnerabilities" -Status "Passed" -Message "No commonly vulnerable software detected."
    }
    Write-Output "Installed Software Vulnerabilities Check Completed.`n"
}
catch {
    Add-Result -TestName "Installed Software Vulnerabilities" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Installed Software: $_.Exception.Message`n"
}

### 13. Check Drive Encryption ###
try {
    Write-Output "Checking Drive Encryption Status..."
    # Use BitLocker cmdlets to check encryption status
    $bitLockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bitLockerVolumes) {
        foreach ($vol in $bitLockerVolumes) {
            if ($vol.VolumeStatus -eq 'FullyEncrypted') {
                Add-Result -TestName "BitLocker ($($vol.MountPoint))" -Status "Passed" -Message "BitLocker is enabled and fully encrypted."
            }
            elseif ($vol.VolumeStatus -eq 'EncryptionInProgress') {
                Add-Result -TestName "BitLocker ($($vol.MountPoint))" -Status "Failed" -Message "BitLocker encryption is in progress."
            }
            else {
                Add-Result -TestName "BitLocker ($($vol.MountPoint))" -Status "Failed" -Message "BitLocker is not enabled or not fully encrypted."
            }
        }
    }
    else {
        # Check Device Encryption for devices not using BitLocker
        $deviceEncryption = try {
            Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess" -Name "DeviceEncryptionEnabled" -ErrorAction Stop
        }
        catch {
            $null
        }

        if ($deviceEncryption) {
            if ($deviceEncryption.DeviceEncryptionEnabled -eq 1) {
                Add-Result -TestName "Device Encryption" -Status "Passed" -Message "Device encryption is enabled."
            }
            else {
                Add-Result -TestName "Device Encryption" -Status "Failed" -Message "Device encryption is disabled."
            }
        }
        else {
            Add-Result -TestName "Drive Encryption" -Status "Info" -Message "Drive encryption status could not be determined or not applicable."
        }
    }
    Write-Output "Drive Encryption Status Check Completed.`n"
}
catch {
    Add-Result -TestName "Drive Encryption" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Drive Encryption Status: $_.Exception.Message`n"
}

### 14. Check Browser Security Settings ###
try {
    Write-Output "Checking Browser Security Settings..."
    # Example check: Ensure SmartScreen is enabled in Edge
    $edgeSettingsPath = "HKCU:\Software\Microsoft\Edge\Main"
    if (Test-Path $edgeSettingsPath) {
        $smartScreen = Get-ItemProperty -Path $edgeSettingsPath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
        if ($smartScreen -and $smartScreen.SmartScreenEnabled -eq "Require") {
            Add-Result -TestName "Edge SmartScreen" -Status "Passed" -Message "Edge SmartScreen is enabled."
        }
        else {
            Add-Result -TestName "Edge SmartScreen" -Status "Failed" -Message "Edge SmartScreen is not enabled."
        }
    }
    else {
        Add-Result -TestName "Edge SmartScreen" -Status "Info" -Message "Edge SmartScreen settings not found."
    }

    Write-Output "Browser Security Settings Check Completed.`n"
}
catch {
    Add-Result -TestName "Browser Security Settings" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Browser Security Settings: $_.Exception.Message`n"
}

### 15. Check Antivirus Definitions ###
try {
    Write-Output "Checking Antivirus Definitions..."
    $antivirusDefinitions = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct

    if ($antivirusDefinitions) {
        foreach ($av in $antivirusDefinitions) {
            try {
                $lastUpdate = [Management.ManagementDateTimeConverter]::ToDateTime($av.Timestamp)
                $daysSinceUpdate = (New-TimeSpan -Start $lastUpdate -End (Get-Date)).Days
                if ($daysSinceUpdate -le 7) {
                    Add-Result -TestName "Antivirus Definitions ($($av.displayName))" -Status "Passed" -Message "Antivirus definitions are up-to-date. Last update: $lastUpdate."
                }
                else {
                    Add-Result -TestName "Antivirus Definitions ($($av.displayName))" -Status "Failed" -Message "Antivirus definitions are outdated by $daysSinceUpdate days. Last update: $lastUpdate."
                }
            }
            catch {
                Add-Result -TestName "Antivirus Definitions ($($av.displayName))" -Status "Failed" -Message "Could not determine the last update date for antivirus definitions."
            }
        }
    }
    else {
        Add-Result -TestName "Antivirus Definitions" -Status "Failed" -Message "No antivirus product found."
    }
    Write-Output "Antivirus Definitions Check Completed.`n"
}
catch {
    Add-Result -TestName "Antivirus Definitions" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Antivirus Definitions: $_.Exception.Message`n"
}

### 16. Check Domain Membership and Perform Domain-Specific Checks ###
try {
    Write-Output "Checking Domain Membership..."
    if (Is-DomainJoined) {
        Add-Result -TestName "Domain Membership" -Status "Passed" -Message "System is joined to the domain."
        Write-Output "System is joined to a domain. Proceeding with domain-specific checks.`n"
        Perform-DomainChecks
    }
    else {
        Add-Result -TestName "Domain Membership" -Status "Info" -Message "System is not joined to any domain."
        Write-Output "System is not joined to any domain. Skipping domain-specific checks.`n"
    }
}
catch {
    Add-Result -TestName "Domain Membership" -Status "Error" -Message $_.Exception.Message
    Write-Output "Error checking Domain Membership: $_.Exception.Message`n"
}

# Function to display results with colored statuses
function Display-Results {
    param (
        [array]$ResultsArray
    )

    Write-Output "`nDisplaying Security Check Results:`n"

    # Define table headers
    $header = "{0,-60} {1,-10} {2}" -f "Test", "Status", "Message"
    Write-Host $header -ForegroundColor Cyan
    Write-Host ("-" * 100) -ForegroundColor Cyan

    foreach ($result in $ResultsArray) {
        # Determine the color based on the status
        switch ($result.Status) {
            "Passed" { $statusColor = "Green" }
            "Failed" { $statusColor = "Red" }
            "Error"  { $statusColor = "Yellow" }
            "Info"   { $statusColor = "Magenta" }
            default  { $statusColor = "White" }
        }

        # Format each row with colored status
        $testName = "{0,-60}" -f $result.Test
        $status = "{0,-10}" -f $result.Status
        $message = $result.Message

        # Write the test name
        Write-Host -NoNewline $testName + " "

        # Write the status with color
        Write-Host -NoNewline $status -ForegroundColor $statusColor + " "

        # Write the message
        Write-Host $message
    }
}

# Display the results with colors
Display-Results -ResultsArray $Results

# Summarize the results with colored output
$passed = $Results | Where-Object { $_.Status -eq "Passed" } | Measure-Object | Select-Object -ExpandProperty Count
$failed = $Results | Where-Object { $_.Status -eq "Failed" } | Measure-Object | Select-Object -ExpandProperty Count
$errors = $Results | Where-Object { $_.Status -eq "Error" } | Measure-Object | Select-Object -ExpandProperty Count
$info = $Results | Where-Object { $_.Status -eq "Info" } | Measure-Object | Select-Object -ExpandProperty Count

Write-Output "`n----------------------------------------"

# Define summary lines with colors
if ($passed -gt 0) {
    $summaryPassed = "Passed Tests       : $passed"
    Write-Host $summaryPassed -ForegroundColor Green
}
if ($failed -gt 0) {
    $summaryFailed = "Failed Tests       : $failed"
    Write-Host $summaryFailed -ForegroundColor Red
}
if ($errors -gt 0) {
    $summaryErrors = "Errors Encountered : $errors"
    Write-Host $summaryErrors -ForegroundColor Yellow
}
if ($info -gt 0) {
    $summaryInfo = "Information Notes  : $info"
    Write-Host $summaryInfo -ForegroundColor Magenta
}
Write-Host "----------------------------------------"

# Function to provide final notes based on results
function Provide-FinalNotes {
    param (
        [int]$FailedCount,
        [int]$ErrorCount,
        [int]$InfoCount
    )

    if ($FailedCount -gt 0 -or $ErrorCount -gt 0) {
        Write-Host "`nFinal Notes:" -ForegroundColor Cyan
        Write-Host "----------------------------------------" -ForegroundColor Cyan

        if ($FailedCount -gt 0) {
            Write-Host "Some security checks have failed. Please review the failed tests above and take the necessary actions to address them." -ForegroundColor Red
            Write-Host "Here are some general recommendations:" -ForegroundColor Yellow
            Write-Host "- **Firewall**: Ensure that Windows Firewall is enabled for all profiles. If it's disabled, consider enabling it or configuring a third-party firewall." -ForegroundColor White
            Write-Host "- **Antivirus**: Make sure that your antivirus software is active, up-to-date, and real-time protection is enabled. If no antivirus is found, install a reputable antivirus solution." -ForegroundColor White
            Write-Host "- **Windows Update**: Ensure that the Windows Update service is running and that all pending updates are installed to receive the latest security patches." -ForegroundColor White
            Write-Host "- **Account Lockout Policies**: Adjust account lockout settings to enforce thresholds and durations that prevent brute-force attacks." -ForegroundColor White
            Write-Host "- **Password Policy**: Enhance password policies by increasing minimum length and enforcing complexity requirements." -ForegroundColor White
            Write-Host "- **Audit Policies**: Enable necessary audit policies to monitor and log critical security events." -ForegroundColor White
            Write-Host "- **Unnecessary Services**: Disable unnecessary services to reduce the attack surface." -ForegroundColor White
            Write-Host "- **Network Security**: Secure network settings by disabling outdated protocols and ensuring remote services are properly secured or disabled." -ForegroundColor White
            Write-Host "- **Firewall Rules**: Review existing firewall allow rules to ensure they adhere to the principle of least privilege." -ForegroundColor White
            Write-Host "- **Administrative Shares**: Remove or secure administrative shares if they are not required." -ForegroundColor White
            Write-Host "- **Installed Software**: Update or remove vulnerable or unnecessary installed software to minimize security risks." -ForegroundColor White
            Write-Host "- **Drive Encryption**: Enable BitLocker or Device Encryption to protect sensitive data from unauthorized access." -ForegroundColor White
            Write-Host "- **Browser Security**: Enable features like SmartScreen in browsers to protect against web-based threats." -ForegroundColor White
            Write-Host "- **Domain-Specific Policies**: Ensure compliance with domain-specific security policies such as group policies, VPN usage, and required software installations." -ForegroundColor White
        }

        if ($ErrorCount -gt 0) {
            Write-Host "`nAdditionally, some checks encountered errors. Please review the error messages above for more details and take appropriate actions." -ForegroundColor Yellow
        }

        if ($InfoCount -gt 0) {
            Write-Host "`nSome information notes were detected. Please review them above for additional context." -ForegroundColor Magenta
        }

        Write-Host "`nFor more detailed information, refer to the saved security report at the specified output path." -ForegroundColor Cyan
        Write-Host "----------------------------------------" -ForegroundColor Cyan
    }
    else {
        Write-Host "`nAll security checks passed successfully. Your system meets the recommended security standards." -ForegroundColor Green
        Write-Host "----------------------------------------" -ForegroundColor Cyan
    }
}

# Provide final notes based on the results
Provide-FinalNotes -FailedCount $failed -ErrorCount $errors -InfoCount $info
######################################################################
# If OutputPath is provided, save the results to a text file
if ($PSBoundParameters.ContainsKey('OutputPath')) {
    try {
        Write-Output "`nSaving results to the specified path..."
        $outputDir = Split-Path -Path $OutputPath -Parent
        if (!(Test-Path -Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        }

        # Prepare the report content
        $reportContent = @"
Windows Security Comprehensive Check Report
Date: $(Get-Date)

----------------------------------------
Security Check Results:
"@

        foreach ($result in $Results) {
            $reportContent += "{0,-60} {1,-10} {2}`n" -f $result.Test, $result.Status, $result.Message
        }

        $reportContent += @"
----------------------------------------
Summary of Security Checks:
Passed Tests       : $passed
Failed Tests       : $failed
Errors Encountered : $errors
Information Notes  : $info
----------------------------------------
"@

        # Add final notes to the report
        if ($failed -gt 0 -or $errors -gt 0 -or $info -gt 0) {
            $reportContent += @"
Final Notes:
----------------------------------------
"@

            if ($failed -gt 0) {
                $reportContent += @"
Some security checks have failed. Please review the failed tests above and take the necessary actions to address them. Here are some general recommendations:
- **Firewall**: Ensure that Windows Firewall is enabled for all profiles. If it's disabled, consider enabling it or configuring a third-party firewall.
- **Antivirus**: Make sure that your antivirus software is active, up-to-date, and real-time protection is enabled. If no antivirus is found, install a reputable antivirus solution.
- **Windows Update**: Ensure that the Windows Update service is running and that all pending updates are installed to receive the latest security patches.
- **Account Lockout Policies**: Adjust account lockout settings to enforce thresholds and durations that prevent brute-force attacks.
- **Password Policy**: Enhance password policies by increasing minimum length and enforcing complexity requirements.
- **Audit Policies**: Enable necessary audit policies to monitor and log critical security events.
- **Unnecessary Services**: Disable unnecessary services to reduce the attack surface.
- **Network Security**: Secure network settings by disabling outdated protocols and ensuring remote services are properly secured or disabled.
- **Firewall Rules**: Review existing firewall allow rules to ensure they adhere to the principle of least privilege.
- **Administrative Shares**: Remove or secure administrative shares if they are not required.
- **Installed Software**: Update or remove vulnerable or unnecessary installed software to minimize security risks.
- **Drive Encryption**: Enable BitLocker or Device Encryption to protect sensitive data from unauthorized access.
- **Browser Security**: Enable features like SmartScreen in browsers to protect against web-based threats.
- **Domain-Specific Policies**: Ensure compliance with domain-specific security policies such as group policies, VPN usage, and required software installations.
"@
            }

            if ($errors -gt 0) {
                $reportContent += @"
Additionally, some checks encountered errors. Please review the error messages above for more details and take appropriate actions.
"@
            }

            if ($info -gt 0) {
                $reportContent += @"
Some information notes were detected. Please review them above for additional context.
"@
            }

            $reportContent += @"
For more detailed information, refer to this report.
----------------------------------------
"@
        }
        else {
            $reportContent += @"
All security checks passed successfully. Your system meets the recommended security standards.
----------------------------------------
"@
        }

        # Write the content to the file
        $reportContent | Out-File -FilePath $OutputPath -Encoding UTF8

        Write-Output "Results have been saved to $OutputPath"
    }
    catch {
        Write-Output "Failed to save results to the specified path. Error: $_.Exception.Message"
    }
} else {
    Write-Output "No output path specified."
}
