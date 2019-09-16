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



$LambdaInput = '{
   "AccountName": "stufffordoingthings",
   "Email": "stephenbawks@quickenloans.com",
   "IamUserAccessToBilling": "ALLOW",
   "RoleName": "QLPayerAcctRole"
}'

# Uncomment to send the input event to CloudWatch Logs
Write-Host (ConvertTo-Json -InputObject $LambdaInput -Compress)


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
    # $uri = $ENV:uri_address
    $uri = 'https://outlook.office.com/webhook/99a6affa-0a11-4a95-a7e0-b05bfbae281e@e58c8e81-abd8-48a8-929d-eb67611b83bd/IncomingWebhook/249e9c03ce1641b081191e5caee13dd4/7d92650b-7e73-4619-b445-5ddd6890cf73'

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

    $Response = (Use-STSRole -Region us-east-2 -RoleArn $role -RoleSessionName "assumedrole").Credentials
    $Credentials = New-AWSCredentials -AccessKey $Response.AccessKeyId -SecretKey $Response.SecretAccessKey -SessionToken $Response.SessionToken

    # check the current iam account alias
    $current_account_alias = Get-IAMAccountAlias -Credential $Credentials
    if ($current_account_alias -ne $account_alias) {
        Write-Host "Changing IAM Account Alias...."
        Write-Host "------------------------------"
        New-IAMAccountAlias -AccountAlias $account_alias -Credential $Credentials

        # check to see if the iam account alias was succesfully updated
        $new_account_alias = Get-IAMAccountAlias -Credential $Credentials
        if ($new_account_alias -eq $account_alias) {
            Write-Host "---- IAM Alias creation Successful ----"
            Write-Host "IAM Sign-In URL: https://$account_alias.signin.aws.amazon.com/console"
        }
    }
    elseif ($current_account_alias -eq $account_alias) {
        # current iam account alias is already set up to match
        Write-Host "IAM Account is already correct. Nothing to do."
        Write-Host "----------------------------------------------"
    }

    Try {
        Update-IAMAccountPasswordPolicy -MaxPasswordAge 90 -PasswordReusePrevention 6 -RequireLowercaseCharacter $true -RequireNumber $true -RequireSymbol $true -RequireUppercaseCharacter $true -Credential $Credentials
        $password_policy = Get-IAMAccountPasswordPolicy -Credential $Credentials | ConvertTo-Json | ConvertFrom-Json

        post_to_teams -process "IAM Account Password Policy" -status "Success" -details $password_policy
    } Catch {
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

    Write-Host "Checking the current IAM SAML Provider...."

    # AWSControlTowerExecution
    $role = "arn:aws:iam::" + $new_account_id + ":role/" + $org_role_name

    $Response = (Use-STSRole -Region us-east-2 -RoleArn $role -RoleSessionName "assumedrole" -ProfileName testorganization).Credentials #dont forget to comment out the organiazation profile here
    $Credentials = New-AWSCredentials -AccessKey $Response.AccessKeyId -SecretKey $Response.SecretAccessKey -SessionToken $Response.SessionToken

    Try {
        $saml = Get-content -Path "./saml/saml.xml"

        $calculated_saml_arn = "arn:aws:iam::" + $new_account_id + ":saml-provider/QL-Ping-Prod"
        $response_saml = New-IAMSAMLProvider -Name "QL-Ping-Prod" -SAMLMetadataDocument $saml -Credential $Credentials

        if ($calculated_saml_arn -eq $response_saml) {
            Write-Host "Checking SAML IAM Provider...."
            Write-Host "------------------------------"
            Write-Host "SAML IAM creation Successful  "

            post_to_teams -process "Account SAML Provider" -status "Success" -details $response_saml
        }

    } Catch {
        Write-Host "An error occurred: " + $error[0].Exception.message -ForegroundColor Green
        post_to_teams -process "Account SAML Provider" -status "Failure" -details $error[0].Exception.message
    }

}










$account_to_create = ConvertFrom-Json -InputObject $LambdaInput
Write-Host $account_to_create

# $nl = [Environment]::NewLine

Try {
    $create_account = New-ORGAccount -AccountName $account_to_create.AccountName -Email $account_to_create.Email -IamUserAccessToBilling $account_to_create.IamUserAccessToBilling -RoleName $account_to_create.RoleName -Region us-east-2

    $check_status = Get-ORGAccountCreationStatus -Region us-east-2 -CreateAccountRequestId $create_account.Id

    Do {
        Write-Host "Waiting for account to finish creating...."
        Start-Sleep -Seconds 2
        $check_status = Get-ORGAccountCreationStatus -Region us-east-2 -CreateAccountRequestId $create_account.Id
        if ($check_status.State.Value -eq "SUCCEEDED") {
            $new_account = Get-ORGAccount -region us-east-2 -AccountId $check_status.AccountId
            Write-Host "---- Account Creation Successful ----"
            Write-Host "Account ID:    " $new_account.Id
            Write-Host "Account Name:  " $new_account.Name
            Write-Host "Account Email: " $new_account.Email

            $new_account_id = "Account Number: " + $new_account.Id
            # post message to teams channel on success
            post_to_teams -process "Account Creation" -status "Success" -details $new_account_id
        }
        ElseIf ($check_status.State.Value -eq "FAILED" -and $check_status.FailureReason.Value -eq "EMAIL_ALREADY_EXISTS") {
            Write-Host "---- Account Creation Failed ----"
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
