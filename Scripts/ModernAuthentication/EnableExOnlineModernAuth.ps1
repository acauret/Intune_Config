
#Requires -Version 3

If (!(Get-PSSession).ConfigurationName -eq "Microsoft.Exchange"){
    $UserCredential = $host.ui.PromptForCredential("Office 365 Tenant Admin Account", "Please enter the user name and password with Tenant Administrative privileges", "", "")
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange  -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic  -AllowRedirection
    $Null = Import-PSSession $Session -AllowClobber -DisableNameChecking
}
#
Write-Output ""
$GetAuth = Get-OrganizationConfig
Write-Output "Current modern authentication setting:`n`tName:[$($GetAuth.Name)]`n`tOAuth2ClientProfileEnabled:[$($GetAuth.OAuth2ClientProfileEnabled)]"
If(!$GetAuth.OAuth2ClientProfileEnabled){
    Write-Output "Modern Authentication is Not enabled - Enabling it"
    Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
    $GetAuth = Get-OrganizationConfig
    Write-Output "Modern authentication setting changed to:`n`tName:[$($GetAuth.Name)]`n`tOAuth2ClientProfileEnabled:[$($GetAuth.OAuth2ClientProfileEnabled)]"
}
Else{Write-OutPut "No Change needed since modern authentication is already enabled for this tenant!"}
#Remove Any PSSessions
Get-PSSession | Remove-PSSession
