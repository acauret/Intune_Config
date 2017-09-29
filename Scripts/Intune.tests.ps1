#requires -Modules Pester
#requires -version 4.0

#################################################################################################################################
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module $scriptRoot\Get-Graph.psm1 -Force
#
Describe -Tag "O365" "Office 365 Tests" {
    If (!(Get-PSSession).ConfigurationName -eq "Microsoft.Exchange"){
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange  -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic  -AllowRedirection
        $Null = Import-PSSession $Session -AllowClobber -DisableNameChecking
    }
    #
    Context "Modern Authentication"{
        It -name "Check Modern Authentication is Enabled " {
            (Get-OrganizationConfig).OAuth2ClientProfileEnabled| Should Be $true
        }
    }
}
#
Describe -Tag "MDM" "Mobile Device Management Tests"{
    Context -Name "Mobile device management Authority"{
        It "has the Mobile device management authority set to Intune"{
            (Get-mobileDeviceManagementAuthority).mobileDeviceManagementAuthority | Should BeExactly "intune"
        }
    }
    Context -Name "Enrollment restrictions - Device Type Restrictions"{
        It "has Android platform Enrollment: 'Allowed'"{
            (((Get-IntuneOrganization).id | Get-IntuneDeviceEnrollmentRestriction).androidRestrictions).Platformblocked | Should Be $false
        }
        It "has Android platform Enrollment: osMinimumVersion= '5.1'"{
            (((Get-IntuneOrganization).id | Get-IntuneDeviceEnrollmentRestriction).androidRestrictions).osMinimumVersion | Should Be "5.1"
        }
        It "has Android 'Personally Owned Devices' Enrollment: 'Blocked'"{
            (((Get-IntuneOrganization).id | Get-IntuneDeviceEnrollmentRestriction).androidRestrictions).personalDeviceEnrollmentBlocked | Should Be $True
        }
        It "has iOS platform Enrollment: 'Blocked'"{
            (((Get-IntuneOrganization).id | Get-IntuneDeviceEnrollmentRestriction).iosRestrictions).Platformblocked | Should Be $true
        }
        It "has macOS platform Enrollment: 'Blocked'"{
            (((Get-IntuneOrganization).id | Get-IntuneDeviceEnrollmentRestriction).macRestrictions).Platformblocked | Should Be $true
        }
        It "has Windows (8.1+) platform Enrollment: 'Blocked'"{
            (((Get-IntuneOrganization).id | Get-IntuneDeviceEnrollmentRestriction).windowsRestrictions).Platformblocked | Should Be $true
        }
        It "has Windows Mobile platform Enrollment: 'Blocked'"{
            (((Get-IntuneOrganization).id | Get-IntuneDeviceEnrollmentRestriction).windowsMobileRestrictions).Platformblocked | Should Be $true
        }
    }
    Context -Name "Enrollment restrictions - Device Limit Restrictions"{
        It "has maximum number of devices a user can enroll set as '1' "{
            (Get-IntuneOrganization).id | Get-defaultDeviceEnrollmentLimit | Should Be 1
        }
    }
    Context -Name "Terms and conditions"{
        It "has at least one 'Term and Condition' set" -skip:$true{
            Get-termsAndConditions | Should Not Be $null
        }
    }
}
Describe -Tag "License" "License Tests"{
#
    $AADdomain     = Get-AADDomain
    $Organization  = Get-IntuneOrganization
    $subscribedSku = Get-subscribedSku
#
    #
    Context -Name "Product checks "{
        #It "Contains the Correct skuPartNumber - EMSPREMIUM"{$subscribedSku.skupartnumber.Contains("EMSPREMIUM") | Should be $True}
        It "contains the correct skuPartNumber - AAD_PREMIUM_P2"{
            $subscribedSku.skupartnumber.Contains("AAD_PREMIUM_P2") | Should be $True
        }
        It "contains the correct skuPartNumber - INTUNE_A"{
            $subscribedSku.skupartnumber.Contains("INTUNE_A") | Should be $True
        }
    }
    #
    foreach ($sku in $subscribedSku){
        <#
        If($sku.skuPartNumber -eq "EMSPREMIUM") {
            Context -Name "Licence checks - $($sku.skuPartNumber)"{
                It "has the correct licence type of AAD_PREMIUM_P2 assigned"{
                    $sku.servicePlans.serviceplanname.Contains("AAD_PREMIUM_P2") | Should Be $True
                }
                It "has the correct licence type of INTUNE_A assigned"{
                    $sku.servicePlans.serviceplanname.Contains("INTUNE_A") | Should Be $True
                }
                It "has capabilityStatus set to ENABLED"{
                    $sku.capabilityStatus | Should Be "Enabled"
                }
            }
        }
        #>
        If($sku.skuPartNumber -eq "INTUNE_A") {
            Context -Name "Licence checks - $($sku.skuPartNumber)"{
                It "has the correct licence type of 'Intune A Direct' assigned"{
                    $sku.servicePlans.serviceplanname.Contains("INTUNE_A") | Should Be $True
                }
                It "has capabilityStatus set to ENABLED"{
                    $sku.capabilityStatus | Should Be "Enabled"
                }
                It "has the correct amount of licences assigned"{
                    $sku.prepaidUnits.enabled | Should Be 376
                }
            }
        }
        If($sku.skuPartNumber -eq "AAD_PREMIUM_P2") {
            Context -Name "Licence checks - $($sku.skuPartNumber)"{
                It "has the correct licence type of 'Azure Active Directory Premium P2' assigned"{
                    $sku.servicePlans.serviceplanname.Contains("AAD_PREMIUM_P2") | Should Be $True
                }
                It "has the correct licence type of 'Azure Active Directory Premium Plan 1' assigned"{
                    $sku.servicePlans.serviceplanname.Contains("AAD_PREMIUM") | Should Be $True
                }
                It "has the correct licence type of 'Azure Multi-Factor Authentication' assigned"{
                    $sku.servicePlans.serviceplanname.Contains("MFA_PREMIUM") | Should Be $True
                }
                It "has capabilityStatus set to ENABLED"{
                    $sku.capabilityStatus | Should Be "Enabled"
                }
                It "has the correct amount of licences assigned"{
                    $sku.prepaidUnits.enabled | Should Be 375
                }
            }
        }
    }
}

Describe -Tag "Policy" "Intune Application Protection Policy Checks"{
$Policy = Get-IntuneManagedAppPolicy
$PolData = Get-Content -Raw -Path (join-path $scriptRoot "MAM_Policy.json") | ConvertFrom-Json
$iOSPolicy_JSON = $PolData.Value | Where-Object { ($_.'@odata.type').Contains("iosManagedAppProtection") }
$AndroidPolicy_JSON = $PolData.Value | Where-Object { ($_.'@odata.type').Contains("androidManagedAppProtection") }

    Context -Name "iOS Application Protection Policy checks"{
        It "contains at least 1 iOS Managed AppProtection policy"{
            $Policy.'@odata.type'.Contains("#microsoft.graph.iosManagedAppProtection") | Should Be $true
        }
        If ($Policy.'@odata.type'.Contains("#microsoft.graph.iosManagedAppProtection")){
            $iOSPolicy = Get-IntuneManagedAppPolicy | Where-Object { ($_.'@odata.type').Contains("iosManagedAppProtection") }
            It "Prevent iTunes and iCloud backups [Value = $($iOSPolicy.dataBackupBlocked)] "{
                $iOSPolicy.dataBackupBlocked | should BeExactly $iOSPolicy_JSON.dataBackupBlocked
            } 
            It "Allow app to transfer data to other apps [Value = $($iOSPolicy.allowedInboundDataTransferSources)]"{
                $iOSPolicy.allowedInboundDataTransferSources | should BeExactly $iOSPolicy_JSON.allowedInboundDataTransferSources
            } 
            It "Allow app to receive data from other apps [Value = $($iOSPolicy.allowedOutboundDataTransferDestinations)]"{
                $iOSPolicy.allowedOutboundDataTransferDestinations | should BeExactly $iOSPolicy_JSON.allowedOutboundDataTransferDestinations
            } 
            It "Prevent 'Save As' [Value = $($iOSPolicy.saveAsBlocked)]"{
                $iOSPolicy.saveAsBlocked | should BeExactly $iOSPolicy_JSON.saveAsBlocked
            } 
            It "Select which storage service corporate data can be saved to [Value = $($iOSPolicy.allowedDataStorageLocations)]"{
                $iOSPolicy.allowedDataStorageLocations | should Be $Null
            } 
            It "Restrict cut, copy, and paste with other app [Value = $($iOSPolicy.allowedOutboundClipboardSharingLevel)]"{
                $iOSPolicy.allowedOutboundClipboardSharingLevel | should BeExactly $iOSPolicy_JSON.allowedOutboundClipboardSharingLevel
            } 
            It "Restrict web content to display in the Managed Browser [Value = $($iOSPolicy.managedBrowserToOpenLinksRequired)]"{
                $iOSPolicy.managedBrowserToOpenLinksRequired | should BeExactly $iOSPolicy_JSON.managedBrowserToOpenLinksRequired
            } 
            It "Encrypt app data [Value = $($iOSPolicy.appDataEncryptionType)]"{
                $iOSPolicy.appDataEncryptionType | should BeExactly $iOSPolicy_JSON.appDataEncryptionType
            } 
            It "Disable contacts sync [Value = $($iOSPolicy.contactSyncBlocked)]"{
                $iOSPolicy.contactSyncBlocked | should BeExactly $iOSPolicy_JSON.contactSyncBlocked
            } 
            It "Disable printing [Value = $($iOSPolicy.printBlocked)]"{
                $iOSPolicy.printBlocked | should BeExactly $iOSPolicy_JSON.printBlocked
            } 
            It "Require PIN for access [Value = $($iOSPolicy.pinRequired)]"{
                $iOSPolicy.pinRequired | should BeExactly $iOSPolicy_JSON.pinRequired
            } 
            It "Allow simple PIN [Value = $($iOSPolicy.simplePinBlocked)]"{
                $iOSPolicy.simplePinBlocked | should BeExactly $iOSPolicy_JSON.simplePinBlocked
            } 
            It "PIN length [Value = $($iOSPolicy.minimumPinLength)]"{
                $iOSPolicy.minimumPinLength | should BeExactly $iOSPolicy_JSON.minimumPinLength
            } 
            It "Allow fingerprint instead of PIN [Value = $($iOSPolicy.fingerprintBlocked)]"{
                $iOSPolicy.fingerprintBlocked | should BeExactly $iOSPolicy_JSON.fingerprintBlocked
            } 
            It "Disable app PIN when device PIN is managed [Value = $($iOSPolicy.disableAppPinIfDevicePinIsSet)]"{
                $iOSPolicy.disableAppPinIfDevicePinIsSet | should BeExactly $iOSPolicy_JSON.disableAppPinIfDevicePinIsSet
            } 
            It "Require corporate credentials for access [Value = $($iOSPolicy.organizationalCredentialsRequired)]"{
                $iOSPolicy.organizationalCredentialsRequired | should BeExactly $iOSPolicy_JSON.organizationalCredentialsRequired
            } 
            It "Recheck the access interval requirements after (minutes) - Timeout [Value = $($iOSPolicy.periodOnlineBeforeAccessCheck)]"{
                $iOSPolicy.periodOnlineBeforeAccessCheck | should BeExactly $iOSPolicy_JSON.periodOnlineBeforeAccessCheck
            } 
            It "Recheck the access interval requirements after (minutes) - Offline grace period [Value = $($iOSPolicy.periodOfflineBeforeAccessCheck)]"{
                $iOSPolicy.periodOfflineBeforeAccessCheck | should BeExactly $iOSPolicy_JSON.periodOfflineBeforeAccessCheck
            } 
            It "Offline interval before app data is wiped (days) [Value = $($iOSPolicy.periodOfflineBeforeWipeIsEnforced)]"{
                $iOSPolicy.periodOfflineBeforeWipeIsEnforced | should BeExactly $iOSPolicy_JSON.periodOfflineBeforeWipeIsEnforced
            } 
            It "Require minimum iOS operating system [Value = $($iOSPolicy.minimumRequiredOsVersion)]"{
                $iOSPolicy.minimumRequiredOsVersion | should BeExactly $iOSPolicy_JSON.minimumRequiredOsVersion
            } 
            It "Targeted Security Group count [Value = $($iOSPolicy.targetedSecurityGroupsCount)]"{
                $iOSPolicy.targetedSecurityGroupsCount | should BeExactly $iOSPolicy_JSON.targetedSecurityGroupsCount
            } 
        }
    }

        Context -Name "Android Application Protection Policy checks"{
        It "contains at least 1 Android Managed AppProtection policy"{
            $Policy.'@odata.type'.Contains("#microsoft.graph.androidManagedAppProtection") | Should Be $true
        }
        If ($Policy.'@odata.type'.Contains("#microsoft.graph.androidManagedAppProtection")){
            $AndroidPolicy = Get-IntuneManagedAppPolicy | Where-Object { ($_.'@odata.type').Contains("androidManagedAppProtection") }
            It "Prevent Android backups [Value = $($AndroidPolicy.dataBackupBlocked)]"{
                $AndroidPolicy.dataBackupBlocked | should BeExactly $AndroidPolicy_JSON.dataBackupBlocked
            } 
            It "Allow app to transfer data to other apps [Value = $($AndroidPolicy.allowedInboundDataTransferSources)]"{
                $AndroidPolicy.allowedInboundDataTransferSources | should BeExactly $AndroidPolicy_JSON.allowedInboundDataTransferSources
            } 
            It "Allow app to receive data from other apps [Value = $($AndroidPolicy.allowedOutboundDataTransferDestinations)]"{
                $AndroidPolicy.allowedOutboundDataTransferDestinations | should BeExactly $AndroidPolicy_JSON.allowedOutboundDataTransferDestinations
            } 
            It "Prevent 'Save As' [Value = $($AndroidPolicy.saveAsBlocked)]"{
                $AndroidPolicy.saveAsBlocked | should BeExactly $AndroidPolicy_JSON.saveAsBlocked
            } 
            It "Select which storage service corporate data can be saved to [Value = $($AndroidPolicy.allowedDataStorageLocations)]"{
                $AndroidPolicy.allowedDataStorageLocations | should Be $Null
            } 
            It "Restrict cut, copy, and paste with other app [Value = $($AndroidPolicy.allowedOutboundClipboardSharingLevel)]"{
                $AndroidPolicy.allowedOutboundClipboardSharingLevel | should BeExactly $AndroidPolicy_JSON.allowedOutboundClipboardSharingLevel
            } 
            It "Restrict web content to display in the Managed Browser [Value = $($AndroidPolicy.managedBrowserToOpenLinksRequired)]"{
                $AndroidPolicy.managedBrowserToOpenLinksRequired | should BeExactly $AndroidPolicy_JSON.managedBrowserToOpenLinksRequired
            } 
            It "Encrypt app data [Value = $($AndroidPolicy.encryptAppData)]"{
                $AndroidPolicy.encryptAppData | should BeExactly $AndroidPolicy_JSON.encryptAppData
            } 
            It "Disable contacts sync [Value = $($AndroidPolicy.contactSyncBlocked)]"{
                $AndroidPolicy.contactSyncBlocked | should BeExactly $AndroidPolicy_JSON.contactSyncBlocked
            } 
            It "Disable printing [Value = $($AndroidPolicy.printBlocked)]"{
                $AndroidPolicy.printBlocked | should BeExactly $AndroidPolicy_JSON.printBlocked
            } 
            It "Require PIN for access [Value = $($AndroidPolicy.pinRequired)]"{
                $AndroidPolicy.pinRequired | should BeExactly $AndroidPolicy_JSON.pinRequired
            } 
            It "Allow simple PIN [Value = $($AndroidPolicy.simplePinBlocked)]"{
                $AndroidPolicy.simplePinBlocked | should BeExactly $AndroidPolicy_JSON.simplePinBlocked
            } 
            It "PIN length [Value = $($AndroidPolicy.minimumPinLength)]"{
                $AndroidPolicy.minimumPinLength | should BeExactly $AndroidPolicy_JSON.minimumPinLength
            } 
            It "Allow fingerprint instead of PIN [Value = $($AndroidPolicy.fingerprintBlocked)]"{
                $AndroidPolicy.fingerprintBlocked | should BeExactly $AndroidPolicy_JSON.fingerprintBlocked
            } 
            It "Disable app PIN when device PIN is managed [Value = $($AndroidPolicy.disableAppPinIfDevicePinIsSet)]"{
                $AndroidPolicy.disableAppPinIfDevicePinIsSet | should BeExactly $AndroidPolicy_JSON.disableAppPinIfDevicePinIsSet
            } 
            It "Require corporate credentials for access [Value = $($AndroidPolicy.organizationalCredentialsRequired)]"{
                $AndroidPolicy.organizationalCredentialsRequired | should BeExactly $AndroidPolicy_JSON.organizationalCredentialsRequired
            } 
            It "Recheck the access interval requirements after (minutes) - Timeout [Value = $($AndroidPolicy.periodOnlineBeforeAccessCheck)]"{
                $AndroidPolicy.periodOnlineBeforeAccessCheck | should BeExactly $AndroidPolicy_JSON.periodOnlineBeforeAccessCheck
            } 
            It "Recheck the access interval requirements after (minutes) - Offline grace period [Value = $($AndroidPolicy.periodOfflineBeforeAccessCheck)]"{
                $AndroidPolicy.periodOfflineBeforeAccessCheck | should BeExactly $AndroidPolicy_JSON.periodOfflineBeforeAccessCheck
            } 
            It "Offline interval before app data is wiped (days) [Value = $($AndroidPolicy.periodOfflineBeforeWipeIsEnforced)]"{
                $AndroidPolicy.periodOfflineBeforeWipeIsEnforced | should BeExactly $AndroidPolicy_JSON.periodOfflineBeforeWipeIsEnforced
            } 
            It "Require minimum Android operating system [Value = $($AndroidPolicy.minimumRequiredOsVersion)]"{
                $AndroidPolicy.minimumRequiredOsVersion | should BeExactly $AndroidPolicy_JSON.minimumRequiredOsVersion
            } 
            It "Targeted Security Group count [Value = $($AndroidPolicy.targetedSecurityGroupsCount)]"{
                $AndroidPolicy.targetedSecurityGroupsCount | should BeExactly $AndroidPolicy_JSON.targetedSecurityGroupsCount
            } 
        }
    }

}
Describe -Tag "MDM" "Intune Mobile Device Managment Policy Checks"{
$Policy = Get-DeviceConfigurationPolicy
$PolData = Get-Content -Raw -Path (join-path $scriptRoot "MDM_Policy.json") | ConvertFrom-Json
$MDM_Policy_JSON = $PolData.Value
 Context -Name "Android Device Restrictions checks "{
    It "'Minimum password length' is correct: [Value = $($Policy.passwordMinimumLength)]"{
        $Policy.passwordMinimumLength | should BeExactly $MDM_Policy_JSON.passwordMinimumLength
    } 
    It "'Password requirement' is set correctly. [Value = $($Policy.passwordRequired)]"{
        $Policy.passwordRequired | should BeExactly $MDM_Policy_JSON.passwordRequired
    } 
    It "'Number of sign-in failures before wiping device' is set correctly. [Value = $($Policy.passwordSignInFailureCountBeforeFactoryReset)]"{
        $Policy.passwordSignInFailureCountBeforeFactoryReset | should BeExactly $MDM_Policy_JSON.passwordSignInFailureCountBeforeFactoryReset
    } 
 }
}




