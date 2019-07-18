<#

.SYNOPSIS

Created by: https://ingogegenwarth.wordpress.com/
Version:    42 ("What do you get if you multiply six by nine?")
Changed:    22.05.2019

.LINK
https://ingogegenwarth.wordpress.com/2019/05/22/tombstoned-accessrights/

.DESCRIPTION

The purpose of the script is to retrieve mailbox permission from AD attribute msexchmailboxsecuritydescriptor

.PARAMETER SamaccountName

SamaccountName of the mailboxes for querying

.EXAMPLE

Get-ADUser -SearchBase 'OU=Resources,DC=contoso,DC=local' -Filter {homemdb -like '*'} | .\Get-MBSecurityDescriptor.ps1 -Verbose

.NOTES
#>

[CmdletBinding()]
param(
    [parameter( ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$true,Mandatory=$false, Position=0)]
    [System.String[]]$SamaccountName
)
Begin
{
    # retrieve SDDL from AD attribute sexchmailboxsecuritydescriptor
    function Get-msExchMailboxSecurityDescriptor
    {
        param(
            $SamaccountName
        )
        $User = ([ADSISearcher]"(SamAccountName=$SamaccountName)").FindOne().Properties
        if (-not [System.String]::IsNullOrWhiteSpace($User.msexchmailboxsecuritydescriptor))
        {
            [System.Byte[]]$DaclByte = $User.msexchmailboxsecuritydescriptor[0]
            $adDACL = new-object System.DirectoryServices.ActiveDirectorySecurity
            $adDACL.SetSecurityDescriptorBinaryForm($DaclByte)
            $adDACL
        }
    }

    # convert SDDL to readable form from attribute msexchmailboxsecuritydescriptor
    function Get-SIDfromDescriptor
    {
        param(
            $SamaccountName
        )
        $SDDescriptor = Get-msExchMailboxSecurityDescriptor $SamaccountName
        if ($SDDescriptor)
        {
            $temp = $SDDescriptor.Sddl.Split("(") | foreach{$_.Trim(")")} |
            select @{l='RightsRaw'; e={$_.Split(';')[2]}}, @{l='SID';e={$_.Split(';')[5]}}, @{l='ACEType';e={$_.Split(';')[0] | Where-Object {($_ -eq 'D') -or ($_ -eq 'A')}}}
            $temp
        }
    }

    # map permission to readable Exchange permission
    function TranslateSDDL
    {
        param (
            [System.String]$SDDL
        )
        $temp = $SDDL -split '(?<=\G\w{2})(?=\w{2})'
        # WD = ChangePermission
        # WO = ChangeOwner
        # SD = DeleteItem
        # LC = ExternalAccount
        # CC = FullAccess
        # RC = ReadPermission
        # SendAS is an AD-permission
        [System.String]$TranslatedRights = ''
        ForEach ($right in $temp) {
            switch ($right) {
                "WD" {$TranslatedRights += "ChangePermission,"}
                "WO" {$TranslatedRights += "ChangeOwner,"}
                "SD" {$TranslatedRights += "DeleteItem,"}
                "LC" {$TranslatedRights += "ExternalAccount,"}
                "CC" {$TranslatedRights += "FullAccess,"}
                "RC" {$TranslatedRights += "ReadPermission,"}
                default {"Unkown $($right)"}
            }
        }
        $TranslatedRights.Trim(',')
    }

    # resolve a user for a given SID
    function Get-UserForSID
    {
        param (
            [parameter( Mandatory=$true, Position=0)]
            [System.String]$SID
        )
        try
        {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier("$SID")
            $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
            $objUser.Value
        }
        catch
        {
            #$_.Exception.Message
            return "N/A"
        }
    }

    # create variables
    $result = @()
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
}

Process
{
    ForEach ($SAM in $SamAccountName)
    {
        Write-Verbose "Processing $($SAM) processing time:$($timer.Elapsed.ToString())"
        $SIDEntrys = Get-SIDfromDescriptor $SAM | Where-Object {$_.SID -match 'S-1'}
        If ($SIDEntrys)
        {
            $objcol = @()
            ForEach ($SIDEntry in $SIDEntrys) {
                $data = new-object PSObject
                $data | add-member -type NoteProperty -Name Mailbox -Value $SAM
                $data | add-member -type NoteProperty -Name SID -Value $SIDEntry.SID
                $data | add-member -type NoteProperty -Name RightsRaw -Value $SIDEntry.RightsRaw
                $data | add-member -type NoteProperty -Name RightsTranslated -Value $(TranslateSDDL $SIDEntry.RightsRaw)
                $data | add-member -type NoteProperty -Name UserID -Value $((Get-UserForSID $SIDEntry.SID).Split('\')[1])
                $data | add-member -type NoteProperty -Name Domain -Value $((Get-UserForSID $SIDEntry.SID).Split('\')[0])
                $data | add-member -type NoteProperty -Name ACE -Value $SIDEntry.ACEType
                $objcol += $data
            }
            $result += $objcol
        }
    }
}

End
{
    $result
    $timer.Stop()
    Write-Verbose "ScriptRuntime:$($timer.Elapsed.ToString())"
}