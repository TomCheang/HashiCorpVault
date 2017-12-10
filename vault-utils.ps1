function Get-VaultAuthToken {
  <#
  .SYNOPSIS
     work interactively with Vault secrets.  interacts with vault svr via
        REST calls.  This function does not persist token to a file on disk.
  .DESCRIPTION
   Currently, this function authenticates a user and stores token in a variable
   named 'vault_token' in the Global scope.  Var is avaiable new spawned child
   scopes but will not persists to other powershell sessions.

   To auth by machine certificate, please make use of vault.exe.

   To send request to a test machine, specify value for $VaultHostName
   .EXAMPLE
      Get-VaultAuthToken

      token saved to var name vault_token in Global scope ($Global:vault_token)
  .EXAMPLE
     $auth = Get-VaultAuthToken -MFA lhbdejrclvndicknbrhclvefitrtguhb

     You can then use auth token by calling $auth.client_token.
  .INPUTS
     MFA (yubikey), you'll also be prompted for your network password
  .OUTPUTS
     This function returns the response from the Vault server.  The auth token
     is stored in the client_token property
  .NOTES
     TODO:
       Auth via machine impersonation.  will require local admin rights.
  .FUNCTIONALITY
     Authenticate against Vault server and receive an auth token.
  #>
  [CmdletBinding(
    HelpUri = 'https://redacted'
  )]
  Param (
    # specify your test instance otherwise will default to Vault svr
    [string]$VaultHostName
  )
  #clear vault token for reauth scenario
  if ($global:vault_token) {
    Remove-Variable -Name vault_token -Scope Global -ErrorAction Ignore
  }

  $VaultUri = New-Object System.UriBuilder('https', $VaultHostName)
  $VaultUri.Path = ('v1/auth/ldap/login/' + $env:UserName)

  # If TLS1.2 not supported, temporarily add to session
  $OrigSecProtocols = [System.Net.ServicePointManager]::SecurityProtocol
  if ($OrigSecProtocols.ToString() -notlike '*Tls12*') {
    [Net.ServicePointManager]::SecurityProtocol =
      [Net.SecurityProtocolType]::Tls12
  }
  $User = '-- Duo Token Here --'
     $msg = "2Fac Auth Required:    Duo Auth and Network Pwd`r`n`r`n" +
            "          Valid Input:`r`n" +
            "                               " +
            " yubikey / 'push' /  Duo code (6 digit)"

  $p = Get-Credential -Message $msg -UserName $User
  Try {
    if ($p.UserName -eq '-- Duo Token Here --' -or $p.UserName -eq 'push') {
      Write-Verbose 'Awaiting Duo Push response...'
      $data = @{
        password = $p.GetNetworkCredential().Password
      } | ConvertTo-JSON -Compress

    }
    else {
      $data = @{
        passcode = $p.UserName
        password = $p.GetNetworkCredential().Password
      } | ConvertTo-JSON -Compress
    }
    $splGetAuthToken = @{
      Uri = $VaultUri.ToString()
      Method = 'Post'
      Body = $data
      ErrorAction = 'Stop'
    }
    $response = Invoke-WebRequest @splGetAuthToken
    Clear-Variable p, data, MFA, splGetAuthToken -ErrorAction Ignore
    if ($response.StatusCode -eq '200') {
      $auth_response = $response.Content | ConvertFrom-Json
      $Policies = $auth_response.auth.policies -join ', '
      $reauth_msg = 'Successfully authenticated.  To reauth, ' +
        'run "Get-VaultAuthToken"'
      Write-Verbose $reauth_msg
      Write-Verbose "your policies: $Policies"
      $splVaultToken = @{
        Name = 'vault_token'
        Scope = 'Global'
        Value = $auth_response.auth.client_token
      }
      Set-Variable @splVaultToken
    }
    else {
      Write-Error "No vault auth token returned by server."
      Write-Error "Status Code: $($response.StatusCode)"
      if ($response.errors) {
        Write-Error $response.errors
      }
    }
  }
  Catch {
    Write-Warning "Issue authenticating to Vault server:"
    Write-Warning $_.Exception.Message
    Write-Warning $_.ErrorDetails.Message
  }
  Finally {
    # Restore original security protocol settings if changed
    if (-Not [System.Net.ServicePointManager]::SecurityProtocol.Equals($OrigSecProtocols)) {
      [Net.ServicePointManager]::SecurityProtocol = $OrigSecProtocols
    }
    Clear-Variable response, auth_response -ErrorAction Ignore
  }
}

function Read-VaultSecret {
  <#
  .SYNOPSIS
     Read Vault secret providing in vault_token.
  .DESCRIPTION
     Read Vault secret with the vault token obtained from using
     Get-VaultAuthToken.  Specify secret to be read by supplying full path to
     secret, Security Group + secret or by Tier + secret.  Function returns
     secret as custom psObject.

     To send request to a test machine, specify value for $VaultHostName
  .EXAMPLE
     $auth = Get-VaultAuthToken -MFA lhbdejrclvndicknbrhclvefitrtguhb
     $secret = Read-VaultSecret -Auth_Token $auth.client_token -SecretsPath `
       'secret/infral2admins/my_secret'
  .EXAMPLE
      $secret = Read-VaultSecret -Auth_Token $auth.client_token `
          -SecretsPath 'secret/tier/mytier/mysecrets
      Prompt for auth will occurs if not done previously in current session.
  .NOTES
     TODO:
       function that lists available secrets in secrets path
  #>
  [CmdletBinding(
    HelpUri = 'https://redacted')]
  Param (
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Auth_Token,
    # ex.  secret/tier/my_tier/my_secret
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SecretsPath,
    #List avaiable secrets/keys in given path
    [switch]$ListAvailable,
    # specify your test instance otherwise will default to Vault svr
    [string]$VaultHostName
  )
  Begin {
    $VaultUri = New-Object System.UriBuilder('https', $VaultHostName)
    if ($ListAvailable) {
      $VaultUri.Path += ('v1/' + $SecretsPath + '/')
      $VaultUri.Query = 'list=true'
    }
    else {
      $VaultUri.Path += 'v1/' + $SecretsPath
    }

    # If TLS1.2 not supported, temporarily add to session
    $OrigSecProtocols = [System.Net.ServicePointManager]::SecurityProtocol
    if ($OrigSecProtocols.ToString() -notlike '*Tls12*') {
      [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12
    }
  }
  Process {
    if ($Auth_Token) {
        $token = $Auth_Token
    }
    elseif ($Global:vault_token) {
      $token = $Global:vault_token
    }
    else {
      Get-VaultAuthToken
      $token = $Global:vault_token
    }

    $splReadSecret =  @{
      Method = 'Get'
      Uri = $VaultUri.ToString()
      Headers = @{'X-Vault-Token' = $token}
      ContentType = 'application/json'
      ErrorAction = 'Stop'
    }
    Try {
      $response = Invoke-RestMethod @splReadSecret

      if ($response.data) {
        if ($ListAvailable) {
          $List = $response.data.keys -Join "`r`n"
          Write-Verbose "Available secrets at $SecretsPath`: `r`n$List"
        }
        return $response.data
      }
      else {
       Write-Verbose 'No value for secrets path provided.'
       return $response
      }
    }
    Catch {
      Write-Verbose "Issue with request to Vault server:"
      Write-Verbose $_.Exception.Message

      Write-Verbose "To reauth, run Get-VaultAuthToken"
      Return $Error[0].Exception.Response.StatusCode.value__
    }
    Finally {
      # Restore original security protocol settings if changed
      $SecProtocols = [Net.ServicePointManager]::SecurityProtocol

      if (-Not $SecProtocols.Equals($OrigSecProtocols)) {
      [Net.ServicePointManager]::SecurityProtocol = $OrigSecProtocols
      }
    }
  }
  End {
     Clear-Variable token, data, MFA, response -ErrorAction Ignore
  }
}

function Write-VaultSecret {
  <#
  .SYNOPSIS
     Write Vault secret with in vault_token.  To write additional values to
     the secret, run command again and provide a separate key and value.
  .DESCRIPTION
     Write Vault secret with the vault token obtained from using
     Get-VaultAuthToken.  Specify secret to be written by supplying full path
     to secret, Security Group + secret or by Tier + secret.

     To send request to a test machine, specify value for $VaultHostName

  .EXAMPLE

      $SecretHash = @{key1='value1';key2='value2'}

      Write-VaultSecret -SecretsHashTable $SecretHash `
          -SecretsPath 'secret/tier/mytier/mysecrets

      Prompt for auth will occurs if not done previously in current session.

  #>
  [CmdletBinding(
    HelpUri = 'https://redacted')]
  Param (
    [Parameter(Mandatory=$False, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$Auth_Token,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SecretsPath,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [hashtable]$SecretsHashTable,
    # specify your test instance otherwise will default to Vault svr
    [string]$VaultHostName
  )
  Begin {
    $VaultUri = New-Object System.UriBuilder('https', $VaultHostName)
    $VaultUri.Path = 'v1/' + $SecretsPath

    # If TLS1.2 not supported, temporarily add to session
    $OrigSecProtocols = [System.Net.ServicePointManager]::SecurityProtocol
    if ($OrigSecProtocols.ToString() -notlike '*Tls12*') {
      [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12
    }
  }
  Process {
    if ($Auth_Token) {
        $token = $Auth_Token
    }
    elseif ($Global:vault_token) {
      $token = $Global:vault_token
    }
    else {
      Get-VaultAuthToken
      $token = $Global:vault_token
    }

    $secret = $SecretsHashTable | ConvertTo-Json -Compress

    $splWriteSecret =  @{
      Method = 'Post'
      Uri = $VaultUri.ToString()
      Headers = @{'X-Vault-Token' = $token}
      ContentType = 'application/json'
      Body = $secret
      ErrorAction = 'Stop'
    }
    Try {
      $response = Invoke-RestMethod @splWriteSecret
      Write-Verbose "secret `($SecretsPath`) has been written"
      return $response
    }
    Catch {
      $msg = $_.Exception.Message
      Write-Verbose "Could not write secret: $SecretsPath"
      Write-Verbose $msg

      Write-Verbose "To reauth, run Get-VaultAuthToken"
      return $_.Exception.Response.StatusCode.value__
    }
    Finally {
      # Restore original security protocol settings if changed
      $SecProtocols = [Net.ServicePointManager]::SecurityProtocol

      if (-Not $SecProtocols.Equals($OrigSecProtocols)) {
        [Net.ServicePointManager]::SecurityProtocol = $OrigSecProtocols
      }
    }
  }
  End {
     Clear-Variable token, data, MFA, response -ErrorAction SilentlyContinue
  }
}

function Remove-VaultSecret {
  <#
  .SYNOPSIS
     Deletes Vault secret.
  .DESCRIPTION
    Deletes Vault secret with given vault_token and path.

     To send request to a test machine, specify value for $VaultHostName

  .EXAMPLE
      Remove-VaultSecret -SecretsPath 'secret/tier/mytier/mysecrets `
        -Confirm:$false

      Prompt for auth will occurs if not done previously in current session.

  #>
  [CmdletBinding(
    HelpUri = 'https://fburl.com/Vault_posh')]
  Param (
    [Parameter(Mandatory=$False, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$Auth_Token,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SecretsPath,
    # specify your test instance otherwise will default to Vault svr
    [string]$VaultHostName,
    [bool]$Confirm = $true
  )
  Begin {
    $VaultUri = New-Object System.UriBuilder('https', $VaultHostName)
    $VaultUri.Path = 'v1/' + $SecretsPath

    # If TLS1.2 not supported, temporarily add to session
    $OrigSecProtocols = [System.Net.ServicePointManager]::SecurityProtocol
    if ($OrigSecProtocols.ToString() -notlike '*Tls12*') {
      [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12
    }
  }
  Process {
    if ($Auth_Token) {
        $token = $Auth_Token
    }
    elseif ($Global:vault_token) {
      $token = $Global:vault_token
    }
    else {
      Get-VaultAuthToken
      $token = $Global:vault_token
    }

    $splRemoveSecret =  @{
      Method = 'Delete'
      Uri = $VaultUri.ToString()
      Headers = @{'X-Vault-Token' = $token}
      ContentType = 'application/json'
      ErrorAction = 'Stop'
    }
    Try {
      if ($Confirm) {
      # Trigger confirmation prompt
      $Title = "Vault Secret Removal"
      $message = "Permanently delete the stored secret at: `r`n    $SecretsPath"

      $Y = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes'
      $N = New-Object System.Management.Automation.Host.ChoiceDescription '&No'
      $options = [System.Management.Automation.Host.ChoiceDescription[]]($Y, $N)
      $UserConfirm = $host.ui.PromptForChoice($title, $message, $options, 0)
      }
      else {
        $UserConfirm = '0'
      }
      if ($UserConfirm -eq '0') {
        $response = Invoke-RestMethod @splRemoveSecret
        Write-Verbose "secret `($SecretsPath`) has been REMOVED"
        return $response
      }
      else {
        Write-Verbose 'you have have elected not to remove the secret'
        return
      }
    }
    Catch {
      $msg = $_.Exception.Message
      Write-Verbose "Could not Delete secret: $SecretsPath"
      Write-Verbose $msg

      Write-Verbose "To reauth, run Get-VaultAuthToken"
      return $_.Exception.Response.StatusCode.value__
    }
    Finally {
      # Restore original security protocol settings if changed
      $SecProtocols = [Net.ServicePointManager]::SecurityProtocol

      if (-Not $SecProtocols.Equals($OrigSecProtocols)) {
      [Net.ServicePointManager]::SecurityProtocol = $OrigSecProtocols
      }
    }
  }
  End {
     Clear-Variable token, data, MFA, response -ErrorAction Ignore
  }
}
