<# 
   Updated VaultNamespacesMounts.ps1
   - Adds more verbosity and trace for all web calls.
   - Allows for insecure TLS in the web calls.
   This script lists all HashiCorp Vault namespaces (Vault 1.16.x) and, for each namespace,
   retrieves all mount points – both secret mounts (e.g. cubbyhole, kv, etc.) and auth mounts (e.g. aws, oidc, jwt, k8, approle, etc.).
   For each mount point, it writes a record into a CSV file that includes the namespace, mount path, and mount type.
#>

# ----- Allow Insecure TLS (if enabled) -----
$AllowInsecureTLS = $true
if ($AllowInsecureTLS) {
    Write-Host "WARNING: Insecure TLS is enabled. Certificate validation will be skipped." -ForegroundColor Yellow
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
}

# ----- Step 1: Select Target Environment -----
Write-Host "Select target environment:" -ForegroundColor Cyan
Write-Host "1: https://prod.vaultserver.com"
Write-Host "2: https://dev.vaultserver.com"
Write-Host "3: https://test.vaultserver.com"
$envChoice = Read-Host "Enter option (1-3)"
switch ($envChoice) {
    "1" { $vaultUrl = "https://prod.vaultserver.com" }
    "2" { $vaultUrl = "https://dev.vaultserver.com" }
    "3" { $vaultUrl = "https://test.vaultserver.com" }
    default {
        Write-Host "Invalid option. Exiting." -ForegroundColor Red
        exit 1
    }
}

# ----- Step 2: Collect Additional Information -----
$vaultNamespace = Read-Host "Enter target HashiCorp Vault namespace (e.g. 'my-namespace')"
$awsRegion      = Read-Host "Enter target AWS region (e.g. 'us-east-1')"

# ----- Step 3: Retrieve Vault Token -----
function Get-VaultToken {
    if (Test-Path ".vault-token") {
        $token = Get-Content ".vault-token" | Out-String
        Write-Host "Using token from .vault-token file."
        return $token.Trim()
    }
    else {
        $secureToken = Read-Host "Enter your Vault token" -AsSecureString
        $token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
                 )
        return $token
    }
}

# ----- Step 4: Validate Vault Token -----
function Validate-VaultToken {
    param(
        [string]$Token,
        [string]$VaultAddr,
        [string]$Namespace
    )
    try {
        $headers = @{
            "X-Vault-Token"     = $Token
            "X-Vault-Namespace" = $Namespace
        }
        $uri = "$VaultAddr/v1/auth/token/lookup-self"
        Write-Verbose "Validating Vault token with URI: $uri"
        Write-Verbose "Headers: $(ConvertTo-Json $headers -Compress)"
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
        Write-Verbose "Vault token validated successfully."
        return $response
    }
    catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 403) {
            Write-Host "Authentication failed (403 Forbidden)."
            return $null
        }
        else {
            Write-Error "Error during token validation: $($_.Exception.Message)"
            throw $_
        }
    }
}

$vaultToken = Get-VaultToken
$vaultResponse = Validate-VaultToken -Token $vaultToken -VaultAddr $vaultUrl -Namespace $vaultNamespace

while (-not $vaultResponse) {
    $secureToken = Read-Host "Vault token invalid. Please enter a valid Vault token:" -AsSecureString
    $vaultToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
                  )
    $vaultResponse = Validate-VaultToken -Token $vaultToken -VaultAddr $vaultUrl -Namespace $vaultNamespace
}

# Set default headers for subsequent Vault API calls.
$vaultHeaders = @{
    "X-Vault-Token"     = $vaultToken
    "X-Vault-Namespace" = $vaultNamespace
}

# ----- Step 5: Retrieve KV Mounts -----
Write-Host "Retrieving mounts from Vault..."
$mountsUri = "$vaultUrl/v1/sys/mounts"
Write-Verbose "Retrieving mounts using URI: $mountsUri"
Write-Verbose "Headers: $(ConvertTo-Json $vaultHeaders -Compress)"
$mountsResponse = Invoke-RestMethod -Method GET -Uri $mountsUri -Headers $vaultHeaders

$kvMounts = @()
foreach ($mount in $mountsResponse.PSObject.Properties) {
    if ($mount.Value.type -eq "kv") {
        # Remove any trailing slash from the mount name.
        $mountName = $mount.Name.TrimEnd("/")
        $kvMounts += $mountName
        Write-Verbose "KV mount found: $mountName"
    }
}

if ($kvMounts.Count -eq 0) {
    Write-Host "No KV mounts found in the specified namespace."
    exit
}

# ----- Step 6: Function to Recursively Retrieve Secrets -----
function Get-SecretsRecursively {
    param(
        [string]$VaultAddr,
        [string]$MountPath,
        [string]$SubPath = "",
        [hashtable]$Headers
    )
    if ($SubPath -ne "") {
        $trimmedPath = $SubPath.TrimEnd("/")
        $uri = "$VaultAddr/v1/$MountPath/metadata/$trimmedPath?list=true"
    }
    else {
        $uri = "$VaultAddr/v1/$MountPath/metadata?list=true"
    }
    Write-Verbose "Listing secrets with URI: $uri"
    try {
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $Headers
        Write-Verbose "Received response: $(ConvertTo-Json $response -Compress)"
    }
    catch {
        Write-Verbose "No keys found or error occurred at URI: $uri. Returning empty list."
        return @()
    }
    $secrets = @()
    foreach ($key in $response.data.keys) {
        if ($key.EndsWith("/")) {
            # It's a folder; call recursively.
            $folderPath = if ($SubPath -ne "") { "$SubPath$key" } else { $key }
            Write-Verbose "Entering folder: $folderPath"
            $secrets += Get-SecretsRecursively -VaultAddr $VaultAddr -MountPath $MountPath -SubPath $folderPath -Headers $Headers
        }
        else {
            $secretPath = if ($SubPath -ne "") { "$SubPath$key" } else { $key }
            Write-Verbose "Secret found: $secretPath"
            $secrets += $secretPath
        }
    }
    return $secrets
}

# ----- Step 7: Process Each KV Mount and Create Secrets in AWS Secrets Manager -----
foreach ($mount in $kvMounts) {
    Write-Host "`nProcessing mount: $mount"
    
    # Recursively get all secret keys from this mount.
    $secretsList = Get-SecretsRecursively -VaultAddr $vaultUrl -MountPath $mount -Headers $vaultHeaders
    if ($secretsList.Count -eq 0) {
        Write-Host "No secrets found under mount $mount."
        continue
    }
    
    foreach ($secret in $secretsList) {
        # Construct the AWS Secrets Manager secret name: {namespace}/{mount}/{secret-path}
        $awsSecretName = "$vaultNamespace/$mount/$secret"
        Write-Host "`nProcessing secret: $awsSecretName"
        
        # Retrieve the secret value from Vault using the KV v2 data endpoint.
        $vaultDataUri = "$vaultUrl/v1/$mount/data/$secret"
        Write-Verbose "Retrieving secret value from Vault using URI: $vaultDataUri"
        try {
            $secretValueResponse = Invoke-RestMethod -Method GET -Uri $vaultDataUri -Headers $vaultHeaders
            Write-Verbose "Secret value response: $(ConvertTo-Json $secretValueResponse -Compress)"
            # Assuming the secret data is in $secretValueResponse.data.data, convert it to a compact JSON string.
            $secretValue = $secretValueResponse.data.data | ConvertTo-Json -Compress
        }
        catch {
            Write-Warning "Failed to retrieve secret value for '$awsSecretName'. Skipping this secret. Error details: $($_.Exception.Message)"
            continue
        }
        
        # Create the secret in AWS Secrets Manager.
        try {
            Write-Verbose "Creating AWS secret '$awsSecretName' in region '$awsRegion'"
            Write-Host "Creating AWS secret '$awsSecretName' ..."
            New-SECSecret -Name $awsSecretName -SecretString $secretValue -Region $awsRegion -Force -ErrorAction Stop
            Write-Host "Secret '$awsSecretName' created successfully in AWS Secrets Manager."
        }
        catch {
            Write-Error "Error creating AWS secret '$awsSecretName'. Detailed error: $($_.Exception.Message)"
        }
    }
}

Write-Host "`nAll secrets processed."
