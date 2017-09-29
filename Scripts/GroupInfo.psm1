function MSOLConnected {
    Get-MsolGroup -ErrorAction SilentlyContinue
    $result = $?
    return $result
}



Function Get-LicenseInfo(){

<#

#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$False)]
    $GroupName,
    [switch]$Members
)
#
If (!(MSOLConnected)) {
    Connect-MsolService
}
#
    If (!($GroupName)){
        Get-MsolGroup -All | Where-Object {$_.Licenses}  | ForEach-Object {
        $groupId = $_.ObjectId;
        $groupName = $_.DisplayName;
        $groupLicenses = $_.Licenses | Select-Object -ExpandProperty SkuPartNumber
        $totalCount = 0;
        $licenseAssignedCount = 0;
        $licenseErrorCount = 0;

        Get-MsolGroupMember -All -GroupObjectId $groupId |
        #get full info about each user in the group
        Get-MsolUser -ObjectId {$_.ObjectId} | 
        ForEach-Object {
            $user = $_;
            If ($Members){
                $Users = $user
                Write-Output $Users
            }
            $totalCount++

            #check if any licenses are assigned via this group
            if($user.Licenses | Where-Object {$_.GroupsAssigningLicense -ieq $groupId })
            {
                $licenseAssignedCount++
            }
            #check if user has any licenses that failed to be assigned from this group
            if ($user.IndirectLicenseErrors | ? {$_.ReferencedObjectId -ieq $groupId })
            {
                $licenseErrorCount++
            }     
        }

        #aggregate results for this group
        New-Object Object |
        Add-Member -NotePropertyName GroupName -NotePropertyValue $groupName -PassThru |
        Add-Member -NotePropertyName GroupId -NotePropertyValue $groupId -PassThru |
        Add-Member -NotePropertyName GroupLicenses -NotePropertyValue $groupLicenses -PassThru |
        Add-Member -NotePropertyName TotalUserCount -NotePropertyValue $totalCount -PassThru |
        Add-Member -NotePropertyName LicensedUserCount -NotePropertyValue $licenseAssignedCount -PassThru |
        Add-Member -NotePropertyName LicenseErrorCount -NotePropertyValue $licenseErrorCount -PassThru
        Write-Output "--------------------------------------------------------------------------------------------------------------------------------"
        } | Format-Table
        
    }
    #
    Else{
        Get-MsolGroup | Where-Object {$_.DisplayName -eq $GroupName -and $_.licenses} | ForEach-Object {
            $groupId = $_.ObjectId;
            $groupName = $_.DisplayName;
            $groupLicenses = $_.Licenses | Select-Object -ExpandProperty SkuPartNumber
            $totalCount = 0;
            $licenseAssignedCount = 0;
            $licenseErrorCount = 0;

            Get-MsolGroupMember -All -GroupObjectId $groupId |
            #get full info about each user in the group
            Get-MsolUser -ObjectId {$_.ObjectId}| 
            ForEach-Object {
                $user = $_;            $totalCount++

                #check if any licenses are assigned via this group
                if($user.Licenses | Where-Object {$_.GroupsAssigningLicense -ieq $groupId })
                {
                    $licenseAssignedCount++
                }
                #check if user has any licenses that failed to be assigned from this group
                if ($user.IndirectLicenseErrors | ? {$_.ReferencedObjectId -ieq $groupId })
                {
                    $licenseErrorCount++
                }     
            }

            #aggregate results for this group
            New-Object Object |
            Add-Member -NotePropertyName GroupName -NotePropertyValue $groupName -PassThru |
            Add-Member -NotePropertyName GroupId -NotePropertyValue $groupId -PassThru |
            Add-Member -NotePropertyName GroupLicenses -NotePropertyValue $groupLicenses -PassThru |
            Add-Member -NotePropertyName TotalUserCount -NotePropertyValue $totalCount -PassThru |
            Add-Member -NotePropertyName LicensedUserCount -NotePropertyValue $licenseAssignedCount -PassThru |
            Add-Member -NotePropertyName LicenseErrorCount -NotePropertyValue $licenseErrorCount -PassThru | Format-List

            If ($Members){
                $Users = Get-MsolGroupMember -All -GroupObjectId $groupId | Sort-Object -Property DisplayName | Get-MsolUser -ObjectId {$_.ObjectId} | Format-Table
                Write-Output $Users
            }
        } 
    }
}
#
Function Get-GroupInfo(){

<#

#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$True)]
    $GroupName,
    [Parameter(Mandatory=$False)]
    [switch]$Membership
)
#
If (!(MSOLConnected)) {
    Connect-MsolService
}
#
    If ($Membership){
        Get-MsolGroup | Where-Object {$_.DisplayName -eq $GroupName} | ForEach-Object {
            $groupId = $_.ObjectId;
            $groupName = $_.DisplayName;
            $totalCount = 0;
            #
            Get-MsolGroupMember -All -GroupObjectId $groupId |
            #get full info about each user in the group
            Get-MsolUser -ObjectId {$_.ObjectId}| 
            ForEach-Object {
                $user = $_;
                $totalCount++
            }
            #
            Get-MsolGroupMember -All -GroupObjectId $groupId | Get-MsolUser -ObjectId {$_.ObjectId} | Select-Object DisplayName, UserPrincipalName
        } 
    }
    Else{
        Get-MsolGroup | Where-Object {$_.DisplayName -eq $GroupName} | ForEach-Object {
        $groupId = $_.ObjectId;
        $groupName = $_.DisplayName;
        $totalCount = 0;

        Get-MsolGroupMember -All -GroupObjectId $groupId |
        #get full info about each user in the group
        Get-MsolUser -ObjectId {$_.ObjectId}| 
        ForEach-Object {
            $user = $_;
            $totalCount++
        }

        #aggregate results for this group
        New-Object Object |
            Add-Member -NotePropertyName GroupName -NotePropertyValue $groupName -PassThru |
            Add-Member -NotePropertyName GroupId -NotePropertyValue $groupId -PassThru |
            Add-Member -NotePropertyName TotalUserCount -NotePropertyValue $totalCount -PassThru | Format-List
                        
        } 
    }

}
#
Function Get-GroupMembership(){
<#

#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$True)]
    $GroupName,
    [Parameter(Mandatory=$False)]
    [switch]$MissingOnly
    
)
If (!(MSOLConnected)) {
    Connect-MsolService
}

    $Results = @()
    write-verbose ""
    write-verbose "Getting List of Users who already part of the Group"
    $Group_Users = Get-GroupInfo -GroupName $GroupName -Membership | Sort-Object -Property DisplayName | Select-Object displayname, UserPrincpalName
    If ($IsNull -eq $Group_Users){Write-Output "The Group:$($GroupName) is either empty or does not exist"; break}

    write-verbose ""
    write-verbose "Geting the list of users present in the Tenant"
    $Tenant_Users = Get-MsolUser -all | Sort-Object -Property  displayname| Select-Object DisplayName, UserPrincpalName
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
Export-ModuleMember -Function Get-LicenseInfo,`
                              Get-GroupInfo, `
                              Get-GroupMembership




