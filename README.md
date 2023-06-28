# 1. Set-TealTierOUAcl
The PowerShell script **Set-TealTierOUAcl.ps1** sets a pre-defined ACL to an organizational unit and removes all non-inherited permissions from all subordinate OUs.

## 1.1. Parameters
**OUDistinguishedName**: Specifies the distinguished name of the organizational unit.

**ProtectedFromAccidentalDeletion**: Specifies whether to add a Deny ACE to prevent the specified OU from being deleted. This deny access rule will be added to all OUs underneath the specified OU.

**RemoveNonInheritedAccessRules**: Specifies whether non-inherited access rules are removed from all AD objects underneath the specified organizational unit. The default is 'true'.

## 1.2. Example

   Applies the pre-defined ACL to the OU 'OU=Tier0,DC=contoso,DC=local' and removes all non-inherited access rules from all AD objects underneath the specified organizational unit.
   
        Set-TealTierOUAcl.ps1 -OUDistinguishedName 'OU=Tier0,DC=contoso,DC=local'
