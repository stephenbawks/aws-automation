# Import-Module -Name AWSPowerShell.NetCore


# PowerShell script file to be executed as a AWS Lambda function.
#
# When executing in Lambda the following variables will be predefined.
#   $LambdaInput - A PSObject that contains the Lambda function input data.
#   $LambdaContext - An Amazon.Lambda.Core.ILambdaContext object that contains information about the currently running Lambda environment.
#
# The last item in the PowerShell pipeline will be returned as the result of the Lambda function.
#
# To include PowerShell modules with your Lambda function, like the AWSPowerShell.NetCore module, add a "#Requires" statement
# indicating the module and version.

#Requires -Modules @{ModuleName='AWSPowerShell.NetCore';ModuleVersion='3.3.422.0'}

# Documentation
# https://docs.aws.amazon.com/organizations/latest/APIReference/API_CreateAccount.html
# https://docs.aws.amazon.com/powershell/latest/reference/Index.html



function Get-TimeStamp {
    # function to attach a timestamp to the logs
    # mainly for troubleshooting
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)

}



function post_to_teams {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $process,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $status,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $details
    )

    # this will pull from the environmental values on the lambda
    # this should be the webhook address that the function will post to
    # disabling for the moment until deployed, testing still

    $uri = (Get-SSMParameterValue -Name "/kraken/prod-aws/$app_id/teams_uri_address" –WithDecryption $true).Parameters

    # these values would be retrieved from or set by an application
    # $status = 'success'
    $pass_fail_image = $null

    if ($status -eq "Success") {
        $pass_fail_image = 'https://cdn3.iconfinder.com/data/icons/flat-actions-icons-9/792/Tick_Mark_Dark-512.png'
    }
    elseif ($status -eq "Failure") {
        $pass_fail_image = 'https://www.iconsdb.com/icons/preview/red/x-mark-xxl.png'
    }

    $body = ConvertTo-Json -Depth 4 @{
        title    = 'AWS Account Automation Notification'
        text     = "$process completed with status $status"
        sections = @(
            @{
                activityTitle    = 'AWS Account Automation'
                activitySubtitle = 'Automated Account Creation Platform'
                activityText     = 'A change was evaluated and new results are available.'
                activityImage    = $pass_fail_image
            },
            @{
                title = 'Details'
                facts = @(
                    @{
                        name  = 'Account Creation Step'
                        value = $process
                    },
                    @{
                        name  = 'Details'
                        value = $details
                    }
                )
            }
        )
    }

    Invoke-RestMethod -uri $uri -Method Post -body $body -ContentType 'application/json'
}




function add_account_to_hal {

    <#
    .SYNOPSIS
        Attempts to add the new aws account to HAL
    .DESCRIPTION
        Some Description goes here
    #>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $account_alias,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $new_account_id,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $org_role_name
    )

    Write-Host "Checking the current IAM Account Alias...."


}




function add_account_to_redlock {

    <#
    .SYNOPSIS
        Attempts to add the new aws account to redlock
    .DESCRIPTION
        Some Description goes here
    #>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $account_alias,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $new_account_id,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $org_role_name
    )

    Write-Host "Checking the current IAM Account Alias...."


}



function create_org_ou {

    <#
    .SYNOPSIS
        Attempts to create a new organization ou.
    .DESCRIPTION
        Some Description goes here
        https://docs.aws.amazon.com/powershell/latest/reference/Index.html
    #>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $account_alias,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $new_account_id,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $release_train
    )

    # Write-Host "Checking to see if Parent OU exists...."
    # $org_root = (Get-ORGRoot -Region 'us-east-2')
    # Get-ORGOrganizationalUnitList -ParentId $org_root.id -Region 'us-east-2'

    # Get-ORGOrganizationalUnit -OrganizationalUnitId <String> -Region 'us-east-2'

    # New-ORGOrganizationalUnit -Name <String> -ParentId $release_train -Force <SwitchParameter>



}



function setup_guard_duty {

    <#
    .SYNOPSIS
        Attempts to add the new account to guard duty.
    .DESCRIPTION
        Will add the new account to guard duty.  This requires the new account to be invited from the
        master account.  Once the invite has been sent, the function will then assume a role into the
        new account and then accept the invitation.
        https://docs.aws.amazon.com/powershell/latest/reference/Index.html
    #>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $org_role_name,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $new_account_id,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $email_address
    )

    # Write-Host "Checking to see if Parent OU exists...."

    $role = "arn:aws:iam::" + $new_account_id + ":role/" + $org_role_name
    $detector_id = "3eb6b2bf5301fe24f8501dc3153ee838"

    # $AccountDetails = @{
    #     AccountId = "648242967050"
    #     Email     = "paulwiles@quickenloans.com"
    # }

    # $us_regions = "us-east-2","us-east-1","us-west-1","us-west-2"

    $AccountDetails = @{
        AccountId = $new_account_id
        Email     = $email_address
    }

    $regions = @(
        @{
            "region" = "us-east-2"
            "detectorid" = "acb0ea346465917edef83687b7dfe06d"
        },
        @{
            "region"    = "us-east-1"
            "detectorid" = "0cb0f0c874d250b10e1dcee4cd168ffa"
        },
        @{
            "region"    = "us-west-2"
            "detectorid" = "deb0f1128a7c3e07e95961c01fa4c60e"
        },
        @{
            "region"    = "us-west-1"
            "detectorid" = "f4b100fe156d7207770c7bcc3268c3d5"
        }
    )

    $regions | ForEach-Object -Process {
        New-GDMember -AccountDetail $AccountDetails -Region $_.regions -DetectorId $_.detectorid -ProfileName testorganization
        Send-GDMemberInvitation -AccountId $new_account_id -Region $_.regions -DetectorId $_.detectorid -DisableEmailNotification $true -ProfileName testorganization

        $Response = (Use-STSRole -RoleArn $role -RoleSessionName "assumedrole" -Region $_.regions -ProfileName testorganization).Credentials
        $Credentials = New-AWSCredentials -AccessKey $Response.AccessKeyId -SecretKey $Response.SecretAccessKey -SessionToken $Response.SessionToken

        # this creates a detector in the child/member account.  there needs to be
        # a detector before you can accept an invitiation
        $member_detector = New-GDDetector -Enable $true -Credential $Credentials -Region $_.regions

        # this will retrieve the inivitiation from the master account
        $invite = Get-GDInvitationList -Credential $Credentials -Region $_.regions

        # will confirm the invit
        Confirm-GDInvitation -DetectorId $member_detector -InvitationId $invite.InvitationId -MasterId $invite.AccountId -Credential $Credentials -Region $_.regions
    }

}


function delete_default_vpc {

    <#
    .SYNOPSIS
        Attempts to create a new organization ou.
    .DESCRIPTION
        Some Description goes here
        https://docs.aws.amazon.com/powershell/latest/reference/Index.html
    #>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $org_role_name,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $new_account_id
    )

    # Write-Host "Checking to see if Parent OU exists...."
    # $org_root = (Get-ORGRoot -Region 'us-east-2')
    # Get-ORGOrganizationalUnitList -ParentId $org_root.id -Region 'us-east-2'

    # Get-ORGOrganizationalUnit -OrganizationalUnitId <String> -Region 'us-east-2'

    # New-ORGOrganizationalUnit -Name <String> -ParentId $release_train -Force <SwitchParameter>

    Write-Host "Checking the current VPC's...."

    $role = "arn:aws:iam::" + $new_account_id + ":role/" + $org_role_name

    $Response = (Use-STSRole -Region us-east-2 -RoleArn $role -RoleSessionName "assumedrole" -ProfileName testorganization).Credentials
    $Credentials = New-AWSCredentials -AccessKey $Response.AccessKeyId -SecretKey $Response.SecretAccessKey -SessionToken $Response.SessionToken

    $regions = Get-AWSRegion

    $region | ForEach-Object -Process {
        $vpc = Get-EC2Vpc -Region $_.Region -Credential $Credentials -Filter @{Name = "isDefault"; Value = "true"} #| Select-Object -Property VpcId,CidrBlock
        # Write-Host $vpc $_.Region
        Remove-EC2Vpc -VpcId $vpc.VpcId -Region $_.Region -Credential $Credentials -WhatIf
        # $vpc | ForEach-Object -Process {
        #     Remove-EC2Vpc -VpcId $_.VpcId -Region $_.Region -Credential $Credentials -WhatIf
        # }
    }



}









function update_account_alias {

    <#
    .SYNOPSIS
        Attempts to assume into new organization account to change IAM Account Alias
    .DESCRIPTION
        This function is meant to update the account alias in a newly created organization account.
        Will attempt to assume the organization role in the new account to change the account alias.
        It first checks current status to compare to new alias.  If there is a difference it
        creates the new account alias to be what is passed in to the function.
    #>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $account_alias,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $new_account_id,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $org_role_name
    )

    Write-Host "Checking the current IAM Account Alias...."

    $role = "arn:aws:iam::" + $new_account_id + ":role/" + $org_role_name

    $Response = (Use-STSRole -Region us-east-2 -RoleArn $role -RoleSessionName "assumedrole" -ProfileName testorganization).Credentials
    $Credentials = New-AWSCredentials -AccessKey $Response.AccessKeyId -SecretKey $Response.SecretAccessKey -SessionToken $Response.SessionToken

    # check the current iam account alias
    $current_account_alias = Get-IAMAccountAlias -Credential $Credentials
    if ($current_account_alias -ne $account_alias) {
        Write-Host "------------------------------"
        Write-Host "Changing IAM Account Alias...."
        Write-Host "------------------------------"
        Write-Host ""
        New-IAMAccountAlias -AccountAlias $account_alias -Credential $Credentials

        # check to see if the iam account alias was succesfully updated
        $new_account_alias = Get-IAMAccountAlias -Credential $Credentials
        if ($new_account_alias -eq $account_alias) {
            Write-Host "--------------- IAM Alias creation Successful -----------------------"
            Write-Host "IAM Sign-In URL: https://$account_alias.signin.aws.amazon.com/console"
            Write-Host "---------------------------------------------------------------------"
            Write-Host ""
        }
    }
    elseif ($current_account_alias -eq $account_alias) {
        # current iam account alias is already set up to match
        Write-Host "----------------------------------------------"
        Write-Host "IAM Account is already correct. Nothing to do."
        Write-Host "----------------------------------------------"
        Write-Host ""
    }

    Write-Host "----------------------------------------"
    Write-Host "Changing IAM Account Password Policy...."
    Write-Host "----------------------------------------"
    Write-Host ""

    Try {
        Update-IAMAccountPasswordPolicy -MaxPasswordAge 90 -PasswordReusePrevention 6 -RequireLowercaseCharacter $true -RequireNumber $true -RequireSymbol $true -RequireUppercaseCharacter $true -Credential $Credentials
        $password_policy = Get-IAMAccountPasswordPolicy -Credential $Credentials

        Write-Host ($password_policy | ConvertTo-Json)
        Write-Host "------------------------------------------------"
        Write-Host "---- IAM Account Password Policy Successful ----"

        $password_policy = $password_policy | ConvertTo-Json | ConvertFrom-Json
        Write-Host "------------------------------------------------"
        post_to_teams -process "IAM Account Password Policy" -status "Success" -details $password_policy
    }
    Catch {
        Write-Host "An error occurred: " + $error[0].Exception.message -ForegroundColor Green
        post_to_teams -process "IAM Account Password Policy" -status "Failure" -details $error[0].Exception.message
    }

}






function update_saml_identity_provider {

    <#
    .SYNOPSIS
        Updates SAML Provider in account.
    .DESCRIPTION
        Assumes a role in the newly created account and creates a SAML Identity Provider.
    #>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $new_account_id,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $org_role_name
    )

    # $saml_64 = (Get-SSMParameterValue -Name "/kraken/prod-aws/$app_id/saml_64" –WithDecryption $true).Parameters
    $saml_64 = "PG1kOkVudGl0eURlc2NyaXB0b3IgSUQ9IlZjd3pWaFJJY2REMmZrdGl4aFh1N1hISk92RyIgY2FjaGVEdXJhdGlvbj0iUFQxNDQwTSIgZW50aXR5SUQ9Imh0dHBzOi8vc3NvLnJvY2tmaW4uY29tIiB4bWxuczptZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm1ldGFkYXRhIj48bWQ6SURQU1NPRGVzY3JpcHRvciBwcm90b2NvbFN1cHBvcnRFbnVtZXJhdGlvbj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBXYW50QXV0aG5SZXF1ZXN0c1NpZ25lZD0iZmFsc2UiPjxtZDpLZXlEZXNjcmlwdG9yIHVzZT0ic2lnbmluZyI+PGRzOktleUluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUM1RENDQWN5Z0F3SUJBZ0lHQVV0NTQ0bmNNQTBHQ1NxR1NJYjNEUUVCQlFVQU1ETXhDekFKQmdOVkJBWVRBbFZUTVJZd0ZBWURWUVFLRXcxUmRXbGphMlZ1SUV4dllXNXpNUXd3Q2dZRFZRUURFd05CVjFNd0hoY05NVFV3TWpFeE1UZ3lOVE13V2hjTk1qQXdNakV3TVRneU5UTXdXakF6TVFzd0NRWURWUVFHRXdKVlV6RVdNQlFHQTFVRUNoTU5VWFZwWTJ0bGJpQk1iMkZ1Y3pFTU1Bb0dBMVVFQXhNRFFWZFRNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQW1wYW9Tb1VXd0ZrZklmUnA3cWxsUTFnNkd3NHFKNXNFQW54RTZ1QkJaelU3c3ltSndscjhKVk1wSlJ1RHAzQU5GTzBmZGZVdGM4bnUxdWVUb2NrQzVkb2FVeEY0c2lUS3dOL1BFNkl6S21aa1BMWDNuVW5hN0M3Ymx6anNvdjc5bHhOUElJZ09rdXBUMldiRk52dUtOUGRhaytJUVBkZno3M1daV0g5dHVXbDZjNHRZZ1B3VGVCNFJ0am1JY3FNSWxEeGhVd2tzY1llcHNkb01BbUkxYUZoOHNZK2Uwd2hQK1dQQlVlOWpRWjl3b2wwK2FxbjcvWFRxL3plOXRpZUVjZzEvZVltalZoR0RPS2k3WU56VGtuRzdSWWJPem9WTEg0MW12U2hMYUc5Wm1nMnNYdW1hMzdqdUxWOHd2VXJrblpsSC81UGE0c3F1Y0ZkRThmMDBYd0lEQVFBQk1BMEdDU3FHU0liM0RRRUJCUVVBQTRJQkFRQWtCd2pETFY1RzExZ2ZqQ1U1N2NyUERBanAwc0VuZGV2ZTRlTms5NFNwbldhcmxMVE9PcHNUc29pWWtPdU9OMEg1Vk1OSXpVeVJiNE5kWDJoWHhaSGRhODh0NXlxYXFmbTJLVWFEaWtqR1c5TzlHeFMxK0tlSGRicVZBbnhxZE9leXdjSjZzS3MzMVRsU1NuTWRQT0UrdDY5L1ZQa2g5TVU5OFBFdmM1ZlNhS1lyM0xFS2kxNXBEanlKNGliMHRudVA4c2xkcWh5eStaalVGUERra3R6T2I3Q2lFOHl0bkNhdzhZM0VxS3ZkRXErOUtJTzBYMmJ1QTlSVHhJMzNENGpqYTlqVGpVdkJLbGN1RlB4TlV1ZWUvYTFBdDVxZHlpZWlDQ2xRZk5wZGw3S1ZoekRVaitxMUwxSnJpUmhBR2tBdHhaVENwS0xvdUl6U0N3MElwQkNiPC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9tZDpLZXlEZXNjcmlwdG9yPjxtZDpOYW1lSURGb3JtYXQ+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6dW5zcGVjaWZpZWQ8L21kOk5hbWVJREZvcm1hdD48bWQ6U2luZ2xlU2lnbk9uU2VydmljZSBCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBMb2NhdGlvbj0iaHR0cHM6Ly9zc28ucm9ja2Zpbi5jb20vaWRwL1NTTy5zYW1sMiIvPjxtZDpTaW5nbGVTaWduT25TZXJ2aWNlIEJpbmRpbmc9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpiaW5kaW5nczpIVFRQLVJlZGlyZWN0IiBMb2NhdGlvbj0iaHR0cHM6Ly9zc28ucm9ja2Zpbi5jb20vaWRwL1NTTy5zYW1sMiIvPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlU2Vzc2lvbk5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iLz48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cHM6Ly9hd3MuYW1hem9uLmNvbS9TQU1ML0F0dHJpYnV0ZXMvUm9sZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIvPjwvbWQ6SURQU1NPRGVzY3JpcHRvcj48bWQ6Q29udGFjdFBlcnNvbiBjb250YWN0VHlwZT0iYWRtaW5pc3RyYXRpdmUiPjxtZDpDb21wYW55PlF1aWNrZW4gTG9hbnM8L21kOkNvbXBhbnk+PC9tZDpDb250YWN0UGVyc29uPjwvbWQ6RW50aXR5RGVzY3JpcHRvcj4="
    $saml = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($saml_64))

    Write-Host "Checking the current IAM SAML Provider...."

    # AWSControlTowerExecution
    $role = "arn:aws:iam::" + $new_account_id + ":role/" + $org_role_name

    $Response = (Use-STSRole -Region us-east-2 -RoleArn $role -RoleSessionName "assumedrole" -ProfileName testorganization).Credentials #dont forget to comment out the organiazation profile here
    $Credentials = New-AWSCredentials -AccessKey $Response.AccessKeyId -SecretKey $Response.SecretAccessKey -SessionToken $Response.SessionToken

    Try {
        # $saml = Get-content -Path "./saml/saml.xml"

        $calculated_saml_arn = "arn:aws:iam::" + $new_account_id + ":saml-provider/QL-Ping-Prod"
        $response_saml = New-IAMSAMLProvider -Name "QL-Ping-Prod" -SAMLMetadataDocument $saml -Credential $Credentials

        if ($calculated_saml_arn -eq $response_saml) {
            Write-Host "Checking SAML IAM Provider...."
            Write-Host "------------------------------"
            Write-Host "SAML IAM creation Successful  "

            post_to_teams -process "Account SAML Provider" -status "Success" -details $response_saml
        }

    }
    Catch {
        Write-Host "An error occurred: " + $error[0].Exception.message -ForegroundColor Green
        post_to_teams -process "Account SAML Provider" -status "Failure" -details $error[0].Exception.message
    }

}


function add_account_to_grafana {

    <#
    .SYNOPSIS
        Will reach out to Grafana and add new account as a data source
    .DESCRIPTION
        Does some stuff, need to figure it out.
    #>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $new_account_id,
        # [Parameter(Mandatory = $true, Position = 1)]
        # [string] $org_role_name,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $account_name
    )

    Write-Host "Attempting to add new AWS account to Grafana...."

    $grafana_url = (Get-SSMParameterValue -Name "/kraken/prod-aws/$app_id/grafana_url" –WithDecryption $true).Parameters
    $grafana_token = (Get-SSMParameterValue -Name "/kraken/prod-aws/$app_id/grafana_token" –WithDecryption $true).Parameters

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('Content-Type', 'application/json')
    $headers.Add('Authorization', 'Bearer ' + $grafana_token)

    $body = ConvertTo-Json -Compress -Depth 2 @{
        name     = $account_name
        type     = 'cloudwatch'
        url      = 'http://monitoring.us-east-2.amazonaws.com'
        access   = 'proxy'
        jsondata = @{
            authType      = 'arn'
            defaultRegion = 'us-east-2'
            assumeRoleArn = "arn:aws:iam::" + $new_account_id + ":role/QL-Base-Account-Grafana-Assume-Cloudwatch-Role"
        }
    }

    $response = Invoke-RestMethod -Uri $grafana_url -Method 'POST' -Headers $headers  -Body $body -ContentType 'application/json'

    Write-Host ($response | ConvertTo-Json)

}


##################################################################################
<#
.SYNOPSIS
    Creates a new AWS Account in an Organization
.DESCRIPTION
    This will attempt to create a new account.  Kicks off the process by
    creating a new account.  After the account is created it will then
    run numerous functions that all provide additional value.
#>
##################################################################################


##################################################################################
# Lambda Environment Variables
# app id 203880
# Pulls app_id from the lambda environment variable

$app_id = $ENV:app_id

##################################################################################


# Start of the acccount creation process
Write-Host (ConvertTo-Json -InputObject $LambdaInput -Compress -Depth 5)
$account_to_create_name = $LambdaInput.AccountName
$account_to_create_email = $LambdaInput.Email
$account_to_create_billing = $LambdaInput.IamUserAccessToBilling
$account_to_create_role = $LambdaInput.RoleName

Write-Host "Creating a new AWS Account...."
Write-Host "------------------------------"
Write-Host "App ID:" $app_id
Write-Host "Account Name:" $account_to_create_name
Write-Host "Account Email:" $account_to_create_email
Write-Host ""

Try {
    $create_account = New-ORGAccount -AccountName $account_to_create_name -Email $account_to_create_email -IamUserAccessToBilling $account_to_create_billing -RoleName $account_to_create_role -Region us-east-2

    $check_status = Get-ORGAccountCreationStatus -Region us-east-2 -CreateAccountRequestId $create_account.Id

    Do {
        Write-Host "$(Get-TimeStamp) - Waiting for account to finish creating...."
        Start-Sleep -Seconds 1
        $check_status = Get-ORGAccountCreationStatus -Region us-east-2 -CreateAccountRequestId $create_account.Id
        if ($check_status.State.Value -eq "SUCCEEDED") {
            $new_account = Get-ORGAccount -region us-east-2 -AccountId $check_status.AccountId
            Write-Host "$(Get-TimeStamp) ---- Account Creation Successful ----"
            Write-Host "Account ID:    " $new_account.Id
            Write-Host "Account Name:  " $new_account.Name
            Write-Host "Account Email: " $new_account.Email

            $new_account_id = "Account Number: " + $new_account.Id
            # post message to teams channel on success
            post_to_teams -process "Account Creation" -status "Success" -details $new_account_id
        }
        ElseIf ($check_status.State.Value -eq "FAILED" -and $check_status.FailureReason.Value -eq "EMAIL_ALREADY_EXISTS") {
            Write-Host "$(Get-TimeStamp) ---- Account Creation Failed ----"
            Write-Host "Failure Reason: Email Address is in use by another account in the Organization. Needs to be unique."
            Write-Host "Request ID:    " $check_status.Id
            Write-Host "Request Time:  " $check_status.RequestedTimestamp

            # post message to teams channel on failure
            post_to_teams -process "Account Creation" -status "Failure" -details "Email address is already in use for another account in the Organization."
        }
    } While ($check_status.State.Value -eq "IN_PROGRESS")
}
Catch {
    Write-Host "An error occurred:"
    Write-Host $_
    Break
}
