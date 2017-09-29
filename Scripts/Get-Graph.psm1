<#
.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.
#>
#region Authentication
####################################################
function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string]$User
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-verbose "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable


    if ($null -eq $AadModule) {
        Write-Output ""
        Write-OutPut "AzureAD Powershell module not installed..." 
        Write-OutPut "Install by running 'Install-Module AzureAD' from an elevated PowerShell prompt" 
        Write-OutPut "Script can't continue..."
        Write-OutPut ""
        break
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]

        $aadModule = $AadModule | Where-Object { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | Select-Object -Unique

            }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
#
$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
#
$resourceAppIdURI = "https://graph.microsoft.com"
#
$authority = "https://login.windows.net/$Tenant"
#
    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {
            Write-OutPut "Authorization Access Token is null, please re-run authentication..."
            Write-Output ""
            break
        }

    }

    catch {
        Write-Output $_.Exception.Message
        Write-Output $_.Exception.ItemName
        Write-Output ""
        break
    }

}
##################################################################################
Function CheckAuthorisation(){

<#
.SYNOPSIS
This function is used to get AAD Groups from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Groups registered with AAD
.EXAMPLE
Get-AADGroup
Returns all users registered with Azure AD
.NOTES
NAME: Get-AADGroup
#>

    try {
            # Checking if authToken exists before running authentication
            if($Global:authToken){
              # Setting DateTime to Universal time to work in all timezones
              $DateTime = (Get-Date).ToUniversalTime()
              # If the authToken exists checking when it expires
              $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
              if($TokenExpires -le 0){
                Write-Output "Azure Authentication Token expired $($TokenExpires) minutes ago" 
                Write-Output ""
                # Defining User Principal Name if not present
                if($null -eq $User -or $User -eq ""){
                    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                    Write-Output ""
                }
                $Global:authToken = Get-AuthToken -User $User
              }
            }
            # Authentication doesn't exist, calling Get-AuthToken function
            else {
                write-Output "Azure Authentication Token does not exit." 
                write-Output ""
                if($Null -eq $User -or $User -eq ""){
                    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                    write-Output ""
                }
                # Getting the authorization token
                $Global:authToken = Get-AuthToken -User $User
            }
        }
    catch {
        $_.Exception
        break
    }
}
##################################################################################
#endregion
function Trace-Error{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Message,

        [switch]
        $NonTerminating
    )

    $Message += $(Get-PSCallStack | Select-Object -skip 1 | Out-String)

    if ($NonTerminating) {
        Write-Error $Message
    } 
    else {
        throw $Message
    }
}
##################################################################################
Function Trace-Execution {
    [CmdletBinding()]
    param (
        [string]
        $Message
    )

    Write-Verbose $Message -Verbose
}
##################################################################################
Function JSONGet {

[CmdletBinding()]

    param(
        [Parameter(mandatory=$True)]
        [String] $path,

        [Parameter(Mandatory=$False)]
        [string]$graphApiVersion = "Beta",
        [Switch] $WaitForUpdate,
        $Silent = $True

    )


    $uriRoot = "https://graph.microsoft.com"

    $method = "Get"
    $uri = $uriRoot+"/"+$graphApiVersion+"/"+$($path)

    
    if (!$Silent) {
        Trace-Execution "JSON Get [$path]"
    }

    try {
        $NotFinished = $true
        do {
            $result = Invoke-WebRequest -Headers $authToken -Method $method -Uri $uri
            if($null -eq $result) {
                return $null    
            }
            
            $toplevel = convertfrom-json $result.Content
            if ($null -eq $toplevel.value)
            {
                $obj = $toplevel
            } 
            else 
            {
                $obj = $toplevel.value
            }

            if ($WaitForUpdate.IsPresent) {
                if ($obj.properties.provisioningState -eq "Updating")
                {
                    Trace-Execution "JSONGet: the object's provisioningState is Updating. Wait 1 second and check again."
                    Start-Sleep 1 #then retry
                }
                else
                {
                    $NotFinished = $false
                }
            }
            else
            {
                $notFinished = $false
            }
      } while ($NotFinished)

      if ($obj.properties.provisioningState -eq "Failed") {
         Trace-Error ("Provisioning failed: {0}`nReturned Object: {1}`nObject properties: {2}" -f @($uri, $obj, $obj.properties))
      }
      return $obj
    }
    catch
    {
        Trace-Execution "GET Exception: $_"
        Trace-Execution "GET Exception: $($_.Exception.Response)"
        Trace-Execution "GET Exception: $($_.Exception.Response.GetResponseStream())"
        return $null
    }
}
##################################################################################
Function Get-IntuneManagedAppPolicy(){

<#
.SYNOPSIS
This function is used to get managed app policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any managed app policies
.EXAMPLE
Get-IntuneManagedAppPolicy
Returns any managed app policies configured in Intune
.NOTES
NAME: Get-IntuneManagedAppPolicy
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "Beta",

    [Parameter(Mandatory=$false)]
    [string]$Name
)
    #
    CheckAuthorisation
    #
    $Resource = "deviceAppManagement/managedAppPolicies"

    #
    if($Name)
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion| Where-Object { ($_.'displayName').contains("$Name")}
    }
    Else
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion
    }
}
##################################################################################
Function Get-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to get Device Configuration policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface
.EXAMPLE
Get-DeviceConfigurationPolicy
Returns any managed app policies configured in Intune
.NOTES
NAME: Get-DeviceConfigurationPolicy
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "Beta",

    [Parameter(Mandatory=$false)]
    [string]$Name
)
    #
    CheckAuthorisation
    #
    $Resource = "deviceManagement/deviceConfigurations"

    #
    if($Name)
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion| Where-Object { ($_.'displayName').contains("$Name")}
    }
    Else
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion
    }
}
####################################################
Function Get-AADGroup(){

<#

.SYNOPSIS
This function is used to get AAD Groups from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Groups registered with AAD
.EXAMPLE
Get-AADGroup
Returns all users registered with Azure AD
.NOTES
NAME: Get-AADGroup
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "v1.0",
    $GroupName,
    $id,
    [switch]$Members
)
#
CheckAuthorisation
#
# Defining Variables 
$Group_resource = "groups"
    if($id){
        $uri = "$($Group_resource)?`$filter=id eq '$id'"
        JSONGet -path $uri -graphApiVersion $graphApiVersion
    }
    #
    elseif(($GroupName -eq "") -or ($Null -eq $GroupName)){
        $uri = "$($Group_resource)"
        JSONGet -path $uri -graphApiVersion $graphApiVersion
    }
    else {
        if(!($Members.IsPresent)){
            $uri = "$($Group_resource)?`$filter=displayname eq '$GroupName'"
            JSONGet -path $uri -graphApiVersion $graphApiVersion
        }
        elseif($Members.IsPresent){
            $uri = "$($Group_resource)?`$filter=displayname eq '$GroupName'"
            $Group = JSONGet -path $uri -graphApiVersion $graphApiVersion
                if($Group){
                    $GID = $Group.id
                    $Group.displayName
                    Write-Output ""
                    $uri = "$($Group_resource)/$GID/Members?`$top=999"
                    JSONGet -path $uri -graphApiVersion $graphApiVersion
                }
            }
        }
}

##################################################################################
Function Get-defaultDeviceEnrollmentLimit(){

<#
.SYNOPSIS
This function is used to get the defaultDeviceEnrollmentLimit from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface
.EXAMPLE
(Get-IntuneOrganization).id | Get-defaultDeviceEnrollmentLimit
Returns "int"
.NOTES
NAME: Get-defaultDeviceEnrollmentLimit
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "beta",

    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    $id
)

    #
    CheckAuthorisation
    $Resource = "organization/$id/defaultDeviceEnrollmentLimit"

    if(!$id){
        Trace-Execution "Organization Id hasn't been specified, please specify Id..."
        break
    }
    else {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion
    }
}
##################################################################################
Function Get-mobileDeviceManagementAuthority(){

<#
.SYNOPSIS
This function is used to get the MobileDeviceManagementAuthority from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any MAM applications
.EXAMPLE
Get-mobileDeviceManagementAuthority
Returns "unknown, intune, sccm, office365."
.NOTES
NAME: Get-mobileDeviceManagementAuthority
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "Beta",

    [Parameter(Mandatory=$false)]
    [string]$Name
)
    #
    CheckAuthorisation
    #
    $Resource = "organization('$OrgId')?`$select=mobiledevicemanagementauthority"

    #
    JSONGet -path $Resource -graphApiVersion $graphApiVersion
}
##################################################################################
Function Get-IntuneMAMApplication(){

<#
.SYNOPSIS
This function is used to get MAM applications from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any MAM applications
.EXAMPLE
Get-IntuneMAMApplication
Returns any MAM applications configured in Intune
.NOTES
NAME: Get-IntuneMAMApplication
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "Beta",

    [Parameter(Mandatory=$false)]
    [string]$Name
)
    #
    CheckAuthorisation
    #
    $Resource = "deviceAppManagement/mobileApps"

    #
    if($Name)
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion| Where-Object { ($_.'displayName').contains("$Name")}
    }
    Else
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion | Where-Object { ($_.'@odata.type').Contains("managed") }
    }
}

##################################################################################
Function Get-IntuneOrganization(){

<#
.SYNOPSIS
This function is used to get the Organization intune resource from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets the Organization Intune Resource
.EXAMPLE
Get-IntuneOrganization
Returns the Organization resource configured in Intune
.NOTES
NAME: Get-IntuneOrganization
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "Beta"
)
    #
    CheckAuthorisation
    #
    $Resource = "organization"

    #
    JSONGet -path $Resource -graphApiVersion $graphApiVersion
}

####################################################
Function Get-AADUser(){

<#
.SYNOPSIS
This function is used to get AAD Users from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any users registered with AAD
.EXAMPLE
Get-AADUser
Returns all users registered with Azure AD
.EXAMPLE
Get-AADUser -userPrincipleName user@domain.com
Returns specific user by UserPrincipalName registered with Azure AD
.NOTES
NAME: Get-AADUser
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "v1.0",
    $userPrincipalName,
    $Property
)

    #
    CheckAuthorisation
    #
    # Defining Variables
    $User_resource = "users"
    
    if($userPrincipalName -eq "" -or $null -eq $userPrincipalName){
        $uri = "$($User_resource)?`$top=999"
        JSONGet -path $uri -graphApiVersion $graphApiVersion
    }

    else {
        if($Property -eq "" -or $null -eq $Property){
            $uri = "$($User_resource)/$userPrincipalName"
            JSONGet -path $uri -graphApiVersion $graphApiVersion
        }
        else {
            $uri = "$($User_resource)/$userPrincipalName/$Property"
            JSONGet -path $uri -graphApiVersion $graphApiVersion
        }
    }
}
##################################################################################
Function Get-AADUserDevice(){
<#
.SYNOPSIS
This function is used to get an AAD User Devices from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a users devices registered with Intune MAM
.EXAMPLE
Get-AADUserDevice -UserID $UserID
(Get-AADUser -userPrincipalName UserPrincipalName).id | Get-AADUserDevice
Returns all user devices registered in Intune MDM
.NOTES
NAME: Get-AADUserDevice
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "beta",

    [Parameter(Mandatory=$true,ValueFromPipeLine=$True,HelpMessage="UserID (guid) for the user you want to take action on must be specified:")]
    $UserID
)
#
    CheckAuthorisation
    #
    # Defining Variables
    $Resource = "users/$UserID/registeredDevices"
    #
    if($UserID -eq "" -or $null -eq $UserID){
        Trace-Execution "UserID (guid) for the user you want to take action on must be specified"
        break
    }
    Else
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion
    }
}

##################################################################################
Function Get-RBACRole(){

<#
.SYNOPSIS
This function is used to get RBAC Role Definitions from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any RBAC Role Definitions
.EXAMPLE
Get-RBACRole
Returns any RBAC Role Definitions configured in Intune
.NOTES
NAME: Get-RBACRole
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "Beta",
    [string]$Name 
)

    #
    CheckAuthorisation
    #
    $Resource = "deviceManagement/roleDefinitions"

    #
    if($Name)
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion| Where-Object { ($_.'displayName').contains("$Name") -and $_.isBuiltInRoleDefinition -eq $false }
    }
    Else
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion
    }
}

##################################################################################
Function Get-subscribedSku(){
<#
.SYNOPSIS
This function is used to get RBAC Role Definitions from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any RBAC Role Definitions
.EXAMPLE
Get-subscribedSku
Returns any RBAC Role Definitions configured in Intune
.NOTES
NAME: Get-subscribedSku
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "beta",

    [Parameter(Mandatory=$False)]
    [string]$Name 
)

    #
    CheckAuthorisation
    #
    $Resource = "subscribedSkus"

    if($Name){
        JSONGet -path $Resource -graphApiVersion $graphApiVersion | Where-Object { ($_.'skuPartNumber').contains("$Name")}
    }
    else
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion
    }
}
##################################################################################
Function Get-termsAndConditions(){
<#
.SYNOPSIS
This function is used to get termsAndConditions from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface
.EXAMPLE
Get-termsAndConditions
Returns any termsAndConditions configured in Intune
.NOTES
NAME: Get-termsAndConditions
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "beta",

    [Parameter(Mandatory=$False)]
    [string]$Name 
)

    #
    CheckAuthorisation
    #
    $Resource = "deviceManagement/termsAndConditions"

    if($Name){
        JSONGet -path $Resource -graphApiVersion $graphApiVersion | Where-Object { ($_.'displayName').contains("$Name")}
    }
    else
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion
    }
}
##################################################################################
Function Get-AADDomain(){

<#
.SYNOPSIS
This function is used to get RBAC Role Definitions from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any RBAC Role Definitions
.EXAMPLE
Get-AADDomain
Returns any Domains configured in AAD
.NOTES
NAME: Get-AADDomain
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "beta",
    [string]$Name,
    [switch]$DNSRecords
)

    #
    CheckAuthorisation
    #
    $Resource = "domains"

    if($Name){
        JSONGet -path $Resource -graphApiVersion $graphApiVersion | Where-Object { ($_.'id').contains("$Name")}
        If ($DNSRecords){
            $Resources = "$($Resource)/$Name/verificationDnsRecords"
            JSONGet -path $Resources -graphApiVersion $graphApiVersion
        }
    }
    else
    {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion
    }
}
##################################################################################
Function Get-IntuneDeviceEnrollmentRestriction(){

<#
.SYNOPSIS
This function is used to get device enrollment restrictions resource from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets the device enrollment restrictions Resource
.EXAMPLE
    Get-IntuneDeviceEnrollmentRestriction -id $id
    (Get-IntuneOrganization).id | Get-IntuneDeviceEnrollmentRestriction
Returns device enrollment restrictions configured in Intune
.NOTES
NAME: Get-IntuneDeviceEnrollmentRestriction
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "beta",

    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    $id
)

    #
    CheckAuthorisation
    $Resource = "organization/$id/defaultDeviceEnrollmentRestrictions"

    if(!$id){
        Trace-Execution "Organization Id hasn't been specified, please specify Id..."
        break
    }
    else {
        JSONGet -path $Resource -graphApiVersion $graphApiVersion
    }
}
##################################################################################
Function Get-AADGroupMembership(){
<#

#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$True)]
    $GroupName,
    [Parameter(Mandatory=$False)]
    [string]$graphApiVersion = "beta",
    [switch]$MissingOnly
    
)
    CheckAuthorisation

    $Results = @()
    write-verbose ""
    write-verbose "Getting List of Users who already part of the Group"
    $Group_Users = Get-AADGroup -graphApiVersion $graphApiVersion -GroupName $GroupName -Member

    If ($IsNull -eq $Group_Users){Write-Output "The Group:$($GroupName) is either empty or does not exist"; break}

    write-verbose ""
    write-verbose "Getting the list of users present in the Tenant"
    $Tenant_Users = Get-AADUser -graphApiVersion $graphApiVersion 
    If ($MissingOnly.IsPresent){
        $Differences  = Compare-Object -ReferenceObject $($Tenant_Users.DisplayName) -DifferenceObject $($Group_Users.DisplayName)
    }
    Else{
        $Differences  = Compare-Object -ReferenceObject $($Tenant_Users.DisplayName) -DifferenceObject $($Group_Users.DisplayName) -IncludeEqual
    }
    
    ForEach ($Difference in $Differences) {
        $Result = New-Object PSObject
        $Result | Add-Member -type 'NoteProperty' -name UserName -value $Difference.InputObject
        
        If (($Difference.SideIndicator).ToLower().Contains("<=".ToLower())) {
            $Result | Add-Member -Type 'NoteProperty' -name GroupName -Value $GroupName
            $Result | Add-Member -Type 'NoteProperty' -Name GroupMemberShip -Value "NotInGroup"
        }
        Else {
            $Result | Add-Member -Type 'NoteProperty' -Name GroupName -Value $GroupName
            $Result | Add-Member -Type 'NoteProperty' -Name GroupMemberShip -Value "MemberOf"
        }        
        $Results += $Result
    }
    Return $Results
#
}
##################################################################################
Export-ModuleMember -Function Get-IntuneManagedAppPolicy,`
                              Get-IntuneMAMApplication,`
                              Get-IntuneOrganization,`
                              Get-IntuneBrand,`
                              Get-AADUser,`
                              Get-AADGroup,`
                              Get-AADUserDevice,`
                              Get-subscribedSku,`
                              Get-AADDomain, `
                              Get-RBACRole, `
                              Get-mobileDeviceManagementAuthority,`
                              Get-IntuneDeviceEnrollmentRestriction, `
                              Get-defaultDeviceEnrollmentLimit, `
                              Get-termsAndConditions, `
                              Get-DeviceConfigurationPolicy, `
                              Get-AADGroupMembership