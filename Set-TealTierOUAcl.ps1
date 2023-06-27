# Set-TealTierOUAcl.ps1

<#
.SYNOPSIS
   Applies a pre-defined ACL to an organizational unit and removes all non-inherited permissions from all subordinate OUs.
.PARAMETER OUDistinguishedName
   Specifies the distinguished name of the organizational unit.
.PARAMETER ProtectedFromAccidentalDeletion
   Specifies whether to add a Deny ACE to prevent the specified OU from being deleted. This deny access rule will be added to all OUs underneath the specified OU.
.PARAMETER RemoveNonInheritedAccessRules
   Specifies whether non-inherited access rules are removed from all AD objects underneath the specified organizational unit. The default is 'true'.
.EXAMPLE
   Set-TealTierOUAcl.ps1 -OUDistinguishedName 'OU=Tier0,DC=contoso,DC=local'
   Applies the pre-defined ACL to the OU 'OU=Tier0,DC=contoso,DC=local' and removes all non-inherited access rules from all AD objects underneath the specified organizational unit.
.NOTES
    This script is published under the "MIT No Attribution License" (MIT-0) license.

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so.

    THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>

#Requires -Version 4.0
#Requires -Modules ActiveDirectory

[CmdletBinding(SupportsShouldProcess=$true)]
Param
(
    [Parameter(Mandatory=$true,Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$OUDistinguishedName,

    [Parameter(Mandatory=$false)]
    [bool]$ProtectedFromAccidentalDeletion = $true,

    [Parameter(Mandatory=$false)]
    [bool]$RemoveNonInheritedAccessRules = $true
)

Set-StrictMode -Version Latest

try {
    $AdObject = Get-ADObject -Identity $OUDistinguishedName -ErrorAction Stop
    if ($AdObject.ObjectClass -ne 'organizationalUnit') {
        throw "Base object must be of class organizationalUnit."
    }

    # Determine the SID of the forest root domain
    $Forest = Get-ADForest -ErrorAction Stop
    $RootDomainSID = Get-ADDomain -Identity $Forest.RootDomain | Select-Object -ExpandProperty DomainSID

    # Build the ACL
    # This ACL includes all access rules with well-known security identifiers and no environment-specific IDs
    $AclSddl  = 'O:DA'                                                       # setting owner to Domain Admins
    $AclSddl += 'G:DA'                                                       # setting the primary group to Domain Admins (only applies to the POSIX subsystem)
    $AclSddl += 'D:PAI'                                                      # setting the flags SE_DACL_PROTECTED and SE_DACL_AUTO_INHERITED 
    $AclSddl += '(A;CI;LCRPWPRC;;;ED)'                                       # access rule for Enterprise Domain Controllers
    $AclSddl += '(A;CI;LCRPRC;;;AU)'                                         # access rule for Authenticated Users
    $AclSddl += '(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)'                     # access rule for SYSTEM
    $AclSddl += '(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)'                     # access rule for Administrators
    $AclSddl += '(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)'                     # access rule for Domain Admins
    $AclSddl += '(OA;CIIO;LCRPRC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)'  # access rule for Pre–Windows 2000 Compatible Access
    $AclSddl += '(OA;CIIO;LCRPRC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)'  # access rule for Pre–Windows 2000 Compatible Access
    $AclSddl += 'S:PAI(AU;CISA;CCDCSWWPDTCRSDWDWO;;;WD)'                     # audit rule for everyone

    # Creating the ACL using the SDDL string built previously
    $Acl = New-Object -TypeName 'System.DirectoryServices.ActiveDirectorySecurity'
    $Acl.SetSecurityDescriptorSddlForm($AclSddl)

    # The Enterprise Admins group includes the SID of the forest root domain
    # therefore the access rules needs to be built dynamically
    $EnterpriseAdminsId = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountEnterpriseAdminsSid, $RootDomainSID)
    $Arguments = $EnterpriseAdminsId, [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, [System.Security.AccessControl.AccessControlType]::Allow, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    $AccessRule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $Arguments
   
    # Add access rule for Enterprise Admins to existing ACL
    $Acl.AddAccessRule($AccessRule)

    # Create a deny rule for everyone to prevent accidental deletion of OUs
    # this rule will be applied to OUs if $ProtectedFromAccidentalDeletion -eq $true
    $EveryoneId = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    $Arguments = $EveryoneId, ([System.DirectoryServices.ActiveDirectoryRights]::Delete, [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree), [System.Security.AccessControl.AccessControlType]::Deny, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    $EveryoneDenyDeleteRule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $Arguments
    
    # Set ACL on specified OU
    if ($PSCmdlet.ShouldProcess($AdObject.DistinguishedName, 'Set-Acl')) {
        if ($ProtectedFromAccidentalDeletion) {
            # Add deny rule for Everyone if $ProtectedFromAccidentalDeletion = $true (like the UI would do)
            $Acl.AddAccessRule($EveryoneDenyDeleteRule)
        }
        # Apply the ACL
        Set-Acl -Path "AD:$($AdObject.DistinguishedName)" -AclObject $Acl
    }

    Get-ADObject -Filter * -SearchBase $OUDistinguishedName -SearchScope Subtree | ForEach-Object {
        if ($_.ObjectClass -eq 'organizationalUnit' -and $_.DistinguishedName -eq $OUDistinguishedName) {
            # Skipping root OU since inheritance has been disabled for this OU in the previous step
            # and this OU will only include non-inherited ACEs
        }
        else {
            $Acl = Get-Acl -Path "AD:$($_.DistinguishedName)"
                
            # Remove non-inherited access rules
            if ($RemoveNonInheritedAccessRules) {
                $Acl | Select-Object -ExpandProperty Access | ForEach-Object {
                    if (-not $_.IsInherited) {
                        if ($PSCmdlet.ShouldProcess($Acl.Path, "Remove-Ace for identity $($_.IdentityReference) (IsInherited: $($_.IsInherited))")) {
                            $Result = $Acl.RemoveAccessRule($_)
                        }
                    }
                }
            }
                
            # Add deny rule for everyone to prevent accidental deletion of OUs
            if ($ProtectedFromAccidentalDeletion -and $_.ObjectClass -eq 'organizationalUnit') {
                $Acl.AddAccessRule($EveryoneDenyDeleteRule)
            }
                
            # Write ACL back to the AD object
            if ($PSCmdlet.ShouldProcess($_, 'Set-Acl')) {
                # allow inheritance
                $Acl.SetAccessRuleProtection($false, $true)
                Set-Acl -Path $Acl.Path -AclObject $Acl
            }
        }
    }
}
catch {
    Write-Error $_
}
