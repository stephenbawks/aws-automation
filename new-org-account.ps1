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

# Requires -Modules @{ModuleName='AWSPowerShell.NetCore';ModuleVersion='4.0.4.0'}
#Requires -Modules @{ModuleName = 'AWS.Tools.AWSSupport'; ModuleVersion = '4.0.4.0' }
#Requires -Modules @{ModuleName = 'AWS.Tools.CloudFormation'; ModuleVersion = '4.0.4.0' }
#Requires -Modules @{ModuleName = 'AWS.Tools.EC2'; ModuleVersion = '4.0.4.0' }
#Requires -Modules @{ModuleName = 'AWS.Tools.GuardDuty'; ModuleVersion = '4.0.4.0' }
#Requires -Modules @{ModuleName = 'AWS.Tools.IdentityManagement'; ModuleVersion = '4.0.4.0' }
#Requires -Modules @{ModuleName = 'AWS.Tools.KeyManagementService'; ModuleVersion = '4.0.4.0' }
#Requires -Modules @{ModuleName = 'AWS.Tools.Lambda'; ModuleVersion = '4.0.4.0' }
#Requires -Modules @{ModuleName = 'AWS.Tools.Organizations'; ModuleVersion = '4.0.4.0' }
#Requires -Modules @{ModuleName = 'AWS.Tools.SecurityToken'; ModuleVersion = '4.0.4.0' }
#Requires -Modules @{ModuleName = 'AWS.Tools.SimpleNotificationService'; ModuleVersion = '4.0.4.0' }
#Requires -Modules @{ModuleName = 'AWS.Tools.SimpleSystemsManagement'; ModuleVersion = '4.0.4.0' }

# AWS Documentation
# https://docs.aws.amazon.com/powershell/latest/reference/
# https://docs.aws.amazon.com/organizations/latest/APIReference/API_CreateAccount.html
# https://docs.aws.amazon.com/powershell/latest/reference/Index.html

# Powershell Documentation
# https://www.powershellgallery.com/packages/AWSPowerShell


function org_account_assume_credentials {

    <#
    .SYNOPSIS
        Creates a set of credentials into the child account from the master organization account.
    .DESCRIPTION
        This is the set of credentials that will be used by many of the functions to run code against the new child account
        these credentials are from.
    #>

    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $new_account_id
    )

    Write-Host "Creating set of Credentials in new Child Account....."

    $organization_role = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/organization_role" –WithDecryption $true).Parameters.Value
    $assume_role = "arn:aws:iam::" + $new_account_id + ":role/" + $organization_role

    Write-Host "Assuming into Child Account ID: " $new_account_id
    Write-Host "Assuming with Role ARN: " $assume_role

    $wait_time = 10
    $retry_limit = 3
    $Stoploop = $false
    [int]$Retrycount = "0"

    do {
        try {
            # Scripts Commands here
            Write-Host "Attempt Number: $Retrycount"
            $Response = (Use-STSRole -RoleArn $assume_role -RoleSessionName "orgaccountassume").Credentials
            $Credentials = New-AWSCredentials -AccessKey $Response.AccessKeyId -SecretKey $Response.SecretAccessKey -SessionToken $Response.SessionToken

            return $Credentials
            $Stoploop = $true
        }
        catch {
            if ($Retrycount -gt $retry_limit) {
                Write-Host "Could not Assume Role after $retry_limit attempts."
                $Stoploop = $true
            }
            else {
                Write-Host "Waiting $wait_time seconds and retrying..."
                Start-Sleep -Seconds $wait_time
                $Retrycount = $Retrycount + 1
            }
        }
    }
    While ($Stoploop -eq $false)
}


function guard_duty_master_account_assume_credentials {

    <#
    .SYNOPSIS
        Creates a set of credentials into the Guard Duty Master account.
    .DESCRIPTION
        This is the set of credentials that will be used by Guard Duty function to add new accounts to Guard Duty Master.
    #>

    $organization_role = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/organization_role" -WithDecryption $true).Parameters.Value
    $guard_duty_master = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/guard_duty_master_account" -WithDecryption $true).Parameters.Value
    $assume_role = "arn:aws:iam::" + $guard_duty_master + ":role/" + $organization_role

    Write-Host "Assuming into Guard Duty Master Account ID: " $guard_duty_master
    Write-Host "Assuming with Role ARN: " $assume_role

    $Stoploop = $false
    [int]$Retrycount = "0"

    do {
        try {
            # Scripts Commands here
            Write-Host "Attempt Number: $Retrycount"
            $Response = (Use-STSRole -RoleArn $assume_role -RoleSessionName "guard-duty-master-account").Credentials
            $Credentials = New-AWSCredentials -AccessKey $Response.AccessKeyId -SecretKey $Response.SecretAccessKey -SessionToken $Response.SessionToken

            return $Credentials
            $Stoploop = $true
        }
        catch {
            if ($Retrycount -gt 3) {
                Write-Host "Could not Assume Role after $Retrycount attempts."
                $Stoploop = $true
            }
            else {
                Write-Host "Waiting 10 seconds and retrying..."
                Start-Sleep -Seconds 10
                $Retrycount = $Retrycount + 1
            }
        }
    }
    While ($Stoploop -eq $false)

}


function post_to_teams {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $process,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $status,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $details
    )

    # this will pull from the environmental values on the lambda
    # this should be the webhook address that the function will post to
    # disabling for the moment until deployed, testing still

    $uri = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/teams_uri_address" –WithDecryption $true).Parameters.Value

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
                facts = $notification
            }
        )
    }

    $method = 'POST'
    $content_type = 'application/json'
    Invoke-RestMethod -uri $uri -Method $method -body $body -ContentType $content_type
}


function create_stackset_exec_role {

    <#
    .SYNOPSIS
        Adds the StackSet Execution Role.
    .DESCRIPTION
        This is the role that is requires for StackSets to assume into the account from the top account that holds these stack sets.
    #>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $new_account_id
    )

    $get_organization = Get-ORGOrganization
    $organization_master_id = $get_organization.MasterAccountId

    $role_tags = @( @{key = "app-id"; value = $app_id }, @{key = "product-id"; value = "000000" }, @{key = "iac"; value = "cloudformation" } )

    $stackset_role_name = "AWSCloudFormationStackSetExecutionRole"
    $stackset_role_desc = "Stack Set Role to push StackSets from the Org"
    $stackset_role_trust_policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal": {"AWS": "arn:aws:iam::' + $organization_master_id + ':root"},"Action":"sts:AssumeRole"}]}'


    Write-Host "----------------------------------------------"
    Write-Host "Creating StackSet Execution Role"
    Write-Host "Role Name:" $stackset_role_name
    Write-Host "Master Organization ID: $organization_master_id"
    Write-Host "Policy: $stackset_role_trust_policy"
    Write-Host "----------------------------------------------"

    try {
        New-IAMRole -RoleName $stackset_role_name -AssumeRolePolicyDocument $stackset_role_trust_policy -Description $stackset_role_desc -Tag $role_tags -Credential $org_account_Credentials
        Write-Host "Waiting 5 seconds for IAM role to be ready..."
        Start-Sleep -Seconds 5
        Register-IAMRolePolicy -RoleName $stackset_role_name -PolicyArn 'arn:aws:iam::aws:policy/AdministratorAccess' -Credential $org_account_Credentials
        Write-Host "$stackset_role_name has been created."

        $stack_set_role_details = @{
            name  = 'Stack Set Role Creation'
            value = 'Success'
        }
        $notification.Add($stack_set_role_details)
    }
    catch [Amazon.IdentityManagement.Model.EntityAlreadyExistsException] {
        Write-Host "$stackset_role_name role already exists.  Nothing to do here."

        $stack_set_role_details = @{
            name  = 'Stack Set Role Creation'
            value = 'Success'
        }
        $notification.Add($stack_set_role_details)
    }
    catch {
        Write-Host "Failed to create StackSet Execution Role."
        Write-Host $_.Exception.Message
        $stack_set_role_details = @{
            name  = 'Stack Set Role Creation'
            value = 'Failure'
        }
        $notification.Add($stack_set_role_details)
    }


}


function add_account_stackset {

    <#
    .SYNOPSIS
        Attempts to add the new aws account Cloudformation StackSets
    .DESCRIPTION
        Some Description goes here
    #>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $new_account_id,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $environment,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $foc
    )

    # Grab accounts in a particular StackSet
    $base_roles_stackset = Get-CFNStackInstanceList -StackSetName "base-account-role-policy-$environment" -Region "us-east-1"

    # Check to see if the new account exists in the array
    if ($base_roles_stackset.Account -contains $new_account_id) {
        Write-Host "Account $new_account_id is already in the Base Account Roles StackSet. Nothing to do here."
    }
    elseif ($base_roles_stackset.Account -notcontains $new_account_id) {
        Write-Host "Account $new_account_id is not in the Base Account Roles StackSet and will be added. Creating Stack Instance."
        New-CFNStackInstance -StackSetName "base-account-role-policy-$environment" -Account $new_account_id -StackInstanceRegion "us-east-2" -Region "us-east-1"
    }

    $aws_hal_stackset = Get-CFNStackInstanceList -StackSetName "base-account-setup-hal-role-child-account-$environment" -Region "us-east-1"

    # Check to see if the new account exists in the array
    $aws_hal_stackset_regions = 'us-east-2', 'us-east-1', 'us-west-2', 'us-west-1'
    $operation_preference = '{"RegionOrder":["us-east-2","us-east-1","us-west-2","us-west-1"]}' | ConvertFrom-Json

    #need to double check this if statement.  want to make sure that each region is in the stackset for the new account
    if ($aws_hal_stackset.Account -contains $new_account_id) {
        Write-Host "Account $new_account_id is already in the Base Account HAL Roles Child StackSet. Nothing to do here."
    }
    elseif ($aws_hal_stackset.Account -notcontains $new_account_id) {
        Write-Host "Account $new_account_id is not in the Base Account Roles StackSet and will be added. Creating Stack Instance."
        New-CFNStackInstance -StackSetName "base-account-setup-hal-role-child-account-$environment" -Account $new_account_id -StackInstanceRegion $aws_hal_stackset_regions -OperationPreference $operation_preference -Region "us-east-1"
    }

    $aws_cloudtrail_stackset = Get-CFNStackInstanceList -StackSetName "base-account-setup-cloudtrail-$environment" -Region "us-east-1"

    if ($aws_cloudtrail_stackset.Account -contains $new_account_id) {
        Write-Host "Account $new_account_id is already in the Base Account Cloudtrai StackSet. Nothing to do here."
    }
    elseif ($aws_cloudtrail_stackset.Account -notcontains $new_account_id) {
        Write-Host "Account $new_account_id is not in the Base Account Roles StackSet and will be added. Creating Stack Instance."
        New-CFNStackInstance -StackSetName "base-account-setup-cloudtrail-$environment" -Account $new_account_id -StackInstanceRegion "us-east-2" -Region "us-east-1"
    }


    $aws_config_stackset = Get-CFNStackInstanceList -StackSetName "base-account-setup-aws-config-$environment" -Region "us-east-1"

    $config_regions = "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-north-1", "eu-west-3", "sa-east-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2"
    $config_operation_preference = '{"RegionOrder":["us-east-2","us-east-1","us-west-1","us-west-2","ap-northeast-1","ap-northeast-2","ap-south-1","ap-southeast-1","ap-southeast-2","ca-central-1","eu-central-1","eu-west-1","eu-west-2","eu-west-3","sa-east-1"]}' | ConvertFrom-Json
    if ($aws_config_stackset.Account -contains $new_account_id) {
        Write-Host "Account $new_account_id is already in the Base Account Config StackSet. Nothing to do here."
    }
    elseif ($aws_config_stackset.Account -notcontains $new_account_id) {
        Write-Host "Account $new_account_id is not in the Base Account Config StackSet and will be added. Creating Stack Instance."
        New-CFNStackInstance -StackSetName "base-account-setup-aws-config-$environment" -Account $new_account_id -StackInstanceRegion $config_regions -OperationPreference $config_operation_preference -Region "us-east-1"
        # -ProfileName prodorganization
    }

    $aws_governance_stackset = Get-CFNStackInstanceList -StackSetName "base-account-setup-governance-$foc-$environment" -Region "us-east-2"

    if ($aws_governance_stackset.Account -contains $new_account_id) {
        Write-Host "Account $new_account_id is already in the Base Account Governance StackSet. Nothing to do here."
    }
    elseif ($aws_governance_stackset.Account -notcontains $new_account_id) {
        Write-Host "Account $new_account_id is not in the Base Account Governance StackSet and will be added. Creating Stack Instance."
        New-CFNStackInstance -StackSetName "base-account-setup-governance-ql-$environment" -Account $new_account_id -StackInstanceRegion "us-east-2" -Region "us-east-2"
    }
}


function add_account_to_hal {

    <#
.SYNOPSIS
    Attempts to add the new aws account to HAL
.DESCRIPTION
    Sends a SNS message to a Topic ARN in the HAL account with the details of the account that is being added/modified/deleted.
#>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $new_account_id,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $environment,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $account_alias,
        [Parameter(Mandatory = $true, Position = 3)]
        [string] $release_train,
        [Parameter(Mandatory = $true, Position = 4)]
        [string] $stream,
        [Parameter(Mandatory = $true, Position = 5)]
        [string] $action
    )

    # Values that will work for Action are: create/update/delete
    $body = ConvertTo-Json -Compress @{
        account_id    = $new_account_id
        environment   = $environment
        alias         = $account_alias
        release_train = $release_train
        stream        = $stream
        action        = $action
    }

    Write-Host "Adding new Account to HAL. Publising a message to SNS Topic....."

    $topic_arn = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/hal_new_account_sns_topic" -WithDecryption $true).Parameters.Value

    try {
        Publish-SNSMessage -TopicArn $topic_arn -Subject "New Account - $new_account_id" -Message $body -Region "us-east-1"

        $hal_details = @{
            name  = 'HAL9000 Notification'
            value = 'Success'
        }
        $notification.Add($hal_details)

        Write-Host "Adding new Account to HAL has been successful."

    }
    catch [Amazon.SimpleNotificationService.Model.AuthorizationErrorException] {
        Write-Host "Failed to post to HAL SNS Topic because of missing IAM permissions."
        $hal_details = @{
            name  = 'HAL9000 Notification'
            value = 'Failure - Missing IAM Permissions on SNS Topic'
        }
        $notification.Add($hal_details)
    }
    finally {
        Write-Host "Failed to post to HAL SNS Topic."
        $hal_details = @{
            name  = 'HAL9000 Notification'
            value = 'Failure'
        }
        $notification.Add($hal_details)
    }

}




function add_account_to_account_governance {

    <#
.SYNOPSIS
    Attempts to add the new AWS Account tool that is used for AWS Governance and Compliance
.DESCRIPTION
    This will invoke another Lambda function to have it create the appropiate actions for adding the new account to the tool we use for AWS Governance and Compliance.
#>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $new_account_id,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $account_name,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $account_environment,
        [Parameter(Mandatory = $true, Position = 3)]
        [string] $release_train,
        [Parameter(Mandatory = $true, Position = 4)]
        [string] $stream
    )

    # Values that will work for Environment: sandbox/nonprod/prod
    $body = ConvertTo-Json -Compress @{
        type           = "aws"
        action         = "create"
        name           = $account_name
        aws_account_id = $new_account_id
        environment    = $account_environment
        release_train  = $release_train
        stream         = $stream
    }

    $topic_arn = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/prisma_sns_topic" -WithDecryption $true).Parameters.Value

    try {
        Publish-SNSMessage -TopicArn $topic_arn -Subject "New Account - $new_account_id" -Message $body -Region "us-east-2"

        $prisma_details = @{
            name  = 'Prisma Notification'
            value = 'Success'
        }
        $notification.Add($prisma_details)

    }
    catch [Amazon.SimpleNotificationService.Model.AuthorizationErrorException] {

        Write-Host "Failed to post to Prisma SNS Topic because of missing IAM permissions."

        $prisma_details = @{
            name  = 'Prisma Notification'
            value = 'Failure - Missing IAM Permissions on SNS Topic'
        }
        $notification.Add($prisma_details)
    }
    finally {
        Write-Host "Failed to post to HAL SNS Topic."
        $prisma_details = @{
            name  = 'Prisma Notification'
            value = 'Failure'
        }
        $notification.Add($prisma_details)
    }
}

function add_account_ent_support {

    <#
.SYNOPSIS
    Creates a AWS Support Case to add account to our Enterprise Support.
.DESCRIPTION
    Creates a support case to add to your enterprise support agreement.
    This has to run in us-east-1 region as it is considered a global service and only has one
    endpoint and that is us-east-1.  Creates the case and is using a Teams email address for
    general notifications.
    https://docs.aws.amazon.com/powershell/latest/reference/Index.html
#>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $new_account_id
    )

    try {
        $email_address = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/email_for_notifications" –WithDecryption $true).Parameters.Value
        New-ASACase -Subject "New Account - Add to Enterprise Support" -IssueType "customer-service" -ServiceCode "account-management" -CategoryCode "billing" -SeverityCode "low" -CommunicationBody "Can you please add $new_account_id to our Enterprise Support agreement?" -CcEmailAddress $email_address -Region "us-east-1"

        $support_details = @{
            name  = 'Enterprise Support'
            value = 'Success - Ticket Created'
        }
        $notification.Add($support_details)
    }
    catch {
        $error_message = $error[0].Exception.message
        Write-Host "An error occurred: " + $error_message
        $support_details = @{
            name  = 'Enterprise Support'
            value = 'Failed - Could not create Support Ticket'
        }
        $notification.Add($support_details)
    }
    finally {
        Write-Host 'Failed to create Enterprise Support Case.'
        $prisma_details = @{
            name  = 'Enterprise Support'
            value = 'Failed - Could not create Support Ticket'
        }
        $notification.Add($prisma_details)
    }

}


function create_org_ou {

    <#
.SYNOPSIS
    Attempts to create a new organization ou.
.DESCRIPTION
    Some Description goes here
    https://docs.aws.amazon.com/powershell/latest/reference/Index.html
#>


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
        [string] $new_account_id,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $email_address
    )

    $guard_duty_master = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/guard_duty_master_account" –WithDecryption $true).Parameters.Value

    if ($guard_duty_master -eq "503012327073") {
        Write-Host "Guard Duty Environment: Prod Organization"
        Write-Host "Guard Duty Master Account: 503012327073"

        $guard_duty_parameters = @(
            @{
                "Region"     = "us-east-2"
                "DetectorId" = "acb0ea346465917edef83687b7dfe06d"
            },
            @{
                "Region"     = "us-east-1"
                "DetectorId" = "0cb0f0c874d250b10e1dcee4cd168ffa"
            },
            @{
                "Region"     = "us-west-2"
                "DetectorId" = "deb0f1128a7c3e07e95961c01fa4c60e"
            },
            @{
                "Region"     = "us-west-1"
                "DetectorId" = "f4b100fe156d7207770c7bcc3268c3d5"
            }
        )
    }
    elseif ($guard_duty_master -eq "267798967938") {
        Write-Host "Guard Duty Environment: NonProd Organization"
        Write-Host "Guard Duty Master Account: 267798967938"

        $guard_duty_parameters = @(
            @{
                "Region"     = "us-east-2"
                "DetectorId" = "aeb70c9c10f806005070a90f001c9597"
            },
            @{
                "Region"     = "us-east-1"
                "DetectorId" = "46b70c9dd9e919af91469795b4967540"
            },
            @{
                "Region"     = "us-west-2"
                "DetectorId" = "9ab70c9dfaf3bcfdab82e2a867d41691"
            },
            @{
                "Region"     = "us-west-1"
                "DetectorId" = "4eb70c9deb465e0a53b373b270c012b8"
            }
        )
    }


    $AccountDetails = @{
        AccountId = $new_account_id
        Email     = $email_address
    }

    $guard_duty_parameters | ForEach-Object -Process {
        $detectorId = $_.DetectorId
        $detectorRegion = $_.Region
        Write-Host "Region: " $detectorRegion
        Write-Host "Guard Duty Master Detector: " $detectorId

        $wait_time = 5
        $retry_limit = 3
        $Stoploop = $false
        [int]$Retrycount = "0"

        do {
            try {
                # Scripts Commands here
                Write-Host "Attempt Number: $Retrycount"
                $new_member_detector = New-GDDetector -Enable $true -Region $detectorRegion -Credential $org_account_Credentials

                $Stoploop = $true
            }
            catch {
                if ($Retrycount -gt $retry_limit) {
                    Write-Host "Could not Create a new Detector after $Retrycount attempts."
                    $Stoploop = $true
                }
                else {
                    Write-Host "Waiting $wait_time seconds and retrying to create the Detector..."
                    Start-Sleep -Seconds $wait_time
                    $Retrycount = $Retrycount + 1
                }
            }
        }
        While ($Stoploop -eq $false)

        Write-Host "Member Account Detector:" $new_member_detector
        Write-Host "Member Account Region:" $detectorRegion

        New-GDMember -AccountDetail $AccountDetails -Region $detectorRegion -DetectorId $detectorId -Credential $gd_master_Credentials
        # Start-Sleep -Seconds 2
        Send-GDMemberInvitation -AccountId $new_account_id -Region $detectorRegion -DetectorId $detectorId -Credential $gd_master_Credentials -DisableEmailNotification $true

        do {
            try {
                # this will retrieve the inivitiation from the master account
                # putting this in a while loop because it sometimes take a few seconds for the invite to show up
                Write-Host "Attempt Number: $Retrycount"
                Write-Host "Getting Guard Duty Invitation from Child Accound: " $new_account_id
                $invite = Get-GDInvitationList -Region $detectorRegion -Credential $org_account_Credentials

                # $invite_id = $invite.InvitationId
                # $invite_master_acct_id = $invite.AccountId
                Write-Host "Member Account Invitation:" $invite.InvitationId
                Write-Host "Guard Duty Master Account:" $invite.AccountId

                # will confirm the invite in the member account from the master guard duty account
                Confirm-GDInvitation -DetectorId $new_member_detector -InvitationId $invite.InvitationId -MasterId $invite.AccountId -Region $detectorRegion -Credential $org_account_Credentials

                $Stoploop = $true
            }
            catch {
                if ($Retrycount -gt $retry_limit) {
                    Write-Host "Could not find the Invitation after $Retrycount attempts."

                    $guard_duty_details = @{
                        name  = 'GuardDuty Setup'
                        value = 'Failed'
                    }
                    $notification.Add($guard_duty_details)

                    $Stoploop = $true
                }
                else {
                    Write-Host "Waiting $wait_time seconds and retrying to find the invitation..."
                    Start-Sleep -Seconds $wait_time
                    $Retrycount = $Retrycount + 1
                }
            }
        }
        While ($Stoploop -eq $false)

        $guard_duty_details = @{
            name  = "GuardDuty: $detectorRegion"
            value = 'Success'
        }
        $notification.Add($guard_duty_details)

    }

}


function delete_default_vpc {

    <#
.SYNOPSIS
    Checks for Default VPCs in all regions.
.DESCRIPTION
    If there are default VPCs, this function will attempt to remove them.  It will first
    grab all the VPCs.  It will then pull any InternetGateways attached to those VPCs as
    well as any subnets.  It will them attempt to detach and remove the Internet Gateways
    and then remove the subnets as well from the VPC.  Once those have all been removed
    it will then remove the default VPC.  It does this for all the regions.
    https://docs.aws.amazon.com/powershell/latest/reference/Index.html
#>

    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $new_account_id
    )

    Write-Host "Checking the current VPC's...."

    $vpc_regions = "us-east-1", "us-east-2", "us-west-1", "us-west-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", "sa-east-1"
    $regions_count = $vpc_regions.count

    Write-Host "----------------------------------------------"
    Write-Host "Checking for Default VPCs in" $regions_count "regions."
    Write-Host "----------------------------------------------"

    $vpc_delete_count = 0

    $vpc_regions | ForEach-Object -Process {
        $current_region = $_
        $current_account = Get-STSCallerIdentity -Credential $org_account_Credentials

        Write-Host "----------------------------------------------"
        Write-Host "Current Account:" $current_account.Account
        Write-Host "Current Region:" $current_region
        Write-Host "----------------------------------------------"

        $wait_time = 10
        $retry_limit = 7
        $Stoploop = $false
        [int]$Retrycount = "0"

        do {
            try {
                # Scripts Commands here
                Write-Host "Attempt Number: $Retrycount"
                Write-Host "Looking up VPC in the reigon."
                $vpc = Get-EC2Vpc -Region $current_region -Credential $org_account_Credentials -Filter @{Name = "isDefault"; Values = "true" }

                if ($vpc.count -eq 0) {
                    Write-Host " --- There are no Default VPCs in" $current_region -ForegroundColor Yellow
                }
                elseif ($vpc.count -gt 0) {
                    Write-Host "Tring to find Internet Gateway for VPC: " $vpc.VpcId
                    $igw = Get-EC2InternetGateway -Region $current_region -Credential $org_account_Credentials -Filter @{Name = "attachment.vpc-id"; Values = $vpc.VpcId }
                    if ($igw) {
                        Write-Host " ---- Attempting to dismount" $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Yellow
                        Dismount-EC2InternetGateway -Region $current_region -Credential $org_account_Credentials -VpcId $vpc.VpcId -InternetGatewayId $igw.InternetGatewayId
                        if ($? -eq $true) {
                            Write-Host " ---- Succesfully dismounted" $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Green
                        }
                        elseif ($? -eq $false) {
                            Write-Host " ---- Failed to dismount" $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Red
                        }
                        Write-Host " ---- Attempting to remove" $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Yellow
                        Remove-EC2InternetGateway -Region $current_region -Credential $org_account_Credentials -InternetGatewayId $igw.InternetGatewayId -Force
                        if ($? -eq $true) {
                            Write-Host " ---- Succesfully removed" $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Green
                        }
                        elseif ($? -eq $false) {
                            Write-Host " ---- Failed to remove" $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Red
                        }
                    }
                    elseif ($null -eq $igw) {
                        Write-Host " ---- There are no Internet Gateways attached to VPC" $vpc.VpcId -ForegroundColor Yellow
                    }

                    $subnets = Get-EC2Subnet -Region $current_region -Credential $org_account_Credentials -Filter @{Name = "vpc-id"; Values = $vpc.VpcId }
                    if ($subnets) {
                        Write-Host ""
                        Write-Host " ---- Attempting to remove subnets from Default VPC" $vpc.VpcId -ForegroundColor Yellow
                        $subnets | ForEach-Object -Process {
                            # Write-Host $current_region
                            Write-Host " ---- Removing Subnet:" $_.SubnetId -ForegroundColor Red
                            Remove-EC2Subnet -SubnetId $_.SubnetId -Region $current_region -Credential $org_account_Credentials -Force
                            if ($? -eq $true) {
                                Write-Host " ---- Succesfully removed" $_.SubnetId "from VPC" $vpc.VpcId -ForegroundColor Green
                            }
                            elseif ($? -eq $false) {
                                Write-Host " ---- Failed to remove" $_.SubnetId "from VPC" $vpc.VpcId -ForegroundColor Red
                            }
                        }
                    }
                    elseif ($null -eq $subnets) {
                        Write-Host " ---- There are no subnets in the VPC" $vpc.VpcId -ForegroundColor Yellow
                    }
                    Write-Host " ---- Attempting to remove Default VPC" $vpc.VpcId -ForegroundColor Yellow
                    Remove-EC2Vpc -VpcId $vpc.VpcId -Region $current_region -Credential $org_account_Credentials -Force

                    $vpc_delete_count++

                    if ($? -eq $true) {
                        Write-Host " ---- Succesfully removed Default VPC" $vpc.VpcId -ForegroundColor Green
                    }
                    elseif ($? -eq $false) {
                        Write-Host " ---- Failed to remove Default VPC" $vpc.VpcId -ForegroundColor Red
                    }

                }
                $Stoploop = $true
            }
            catch {
                if ($Retrycount -gt $retry_limit) {
                    Write-Host "Could not get VPC Information after $retry_limit attempts."
                    $Stoploop = $true
                }
                else {
                    Write-Host "Waiting $wait_time seconds and retrying..."
                    Start-Sleep -Seconds $wait_time
                    $Retrycount = $Retrycount + 1
                }
            }
        }
        While ($Stoploop -eq $false)

        $vpc_cleanup_details = @{
            name  = "Default VPC: $current_region"
            value = 'Success - Deleted'
        }
        $notification.Add($vpc_cleanup_details)

    }

    $vpc_cleanup_total = @{
        name  = "Default VPCs"
        value = "Deleted $vpc_delete_count out of $regions_count"
    }
    $notification.Add($vpc_cleanup_total)

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
        [string] $new_account_id
    )

    Write-Host "Checking the current IAM Account Alias...."

    # check the current iam account alias
    $current_account_alias = Get-IAMAccountAlias -Credential $org_account_Credentials
    if ($current_account_alias -ne $account_alias) {
        Write-Host "------------------------------------------------------------------------------------------"
        Write-Host "Changing IAM Account Alias...."

        New-IAMAccountAlias -AccountAlias $account_alias -Credential $org_account_Credentials

        # check to see if the iam account alias was succesfully updated
        $new_account_alias = Get-IAMAccountAlias -Credential $org_account_Credentials
        if ($new_account_alias -eq $account_alias) {
            Write-Host "IAM Alias Successfully Created"
            Write-Host "IAM Sign-In URL: https://$account_alias.signin.aws.amazon.com/console"
            Write-Host "------------------------------------------------------------------------------------------"
            Write-Host ""
        }
    }
    elseif ($current_account_alias -eq $account_alias) {
        # current iam account alias is already set up to match
        Write-Host "IAM Account is already correct. Nothing to do."
        Write-Host "------------------------------------------------------------------------------------------"
        Write-Host ""
    }

    Write-Host "------------------------------------------------------------------------------------------"
    Write-Host "Changing IAM Account Password Policy...."

    Try {
        Update-IAMAccountPasswordPolicy -MaxPasswordAge 90 -PasswordReusePrevention 6 -RequireLowercaseCharacter $true -RequireNumber $true -RequireSymbol $true -RequireUppercaseCharacter $true -Credential $org_account_Credentials
        $password_policy = Get-IAMAccountPasswordPolicy -Credential $org_account_Credentials

        Write-Host ($password_policy | ConvertTo-Json)
        Write-Host "IAM Account Password Policy Successfully Updated"

        $password_policy = $password_policy | ConvertTo-Json | ConvertFrom-Json
        Write-Host "------------------------------------------------------------------------------------------"

        $iamurldetails = @{
            name  = 'IAM Console URL'
            value = "https://$account_alias.signin.aws.amazon.com/console"
        }
        $notification.Add($iamurldetails)

        # post_to_teams -process "IAM Account Password Policy" -status "Success" -details $password_policy
    }
    Catch {
        $error_message = $error[0].Exception.message
        Write-Host "An error occurred: " + $error_message

        $iamurldetails = @{
            name  = 'IAM Console Alias'
            value = "Failed - $error_message"
        }
        $notification.Add($iamurldetails)

        # post_to_teams -process "IAM Account Password Policy" -status "Failure" -details $error[0].Exception.message
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
        [string] $new_account_id
    )

    $saml_64 = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/saml_64" –WithDecryption $true).Parameters.Value
    $saml = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($saml_64))

    Write-Host "Checking the current IAM SAML Provider...."

    Try {

        $calculated_saml_arn = "arn:aws:iam::" + $new_account_id + ":saml-provider/QL-Ping-Prod"
        $response_saml = New-IAMSAMLProvider -Name "QL-Ping-Prod" -SAMLMetadataDocument $saml -Credential $org_account_Credentials

        if ($calculated_saml_arn -eq $response_saml) {
            Write-Host "------------------------------------------------------------------------------------------"
            Write-Host "Checking SAML IAM Provider...."
            Write-Host "SAML IAM Provider Successfully created"
            Write-Host "------------------------------------------------------------------------------------------"

            $iamsaml = @{
                name  = 'SAML Provider Creation'
                value = 'Success'
            }
            $notification.Add($iamsaml)
        }

    }
    Catch {
        $error_message = $error[0].Exception.message
        Write-Host "An error occurred: " + $error_message

        $iamsaml = @{
            name  = 'SAML Provider Creation'
            value = "Failure - $error_message"
        }
        $notification.Add($iamsaml)
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
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $account_name
    )

    Write-Host "Attempting to add new AWS account to Grafana...."

    $grafana_url = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/$" –WithDecryption $true).Parameters.Value
    # -ProfileName prodorganization
    $grafana_token = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/grafana_token" –WithDecryption $true).Parameters.Value
    # -ProfileName prodorganization

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('Content-Type', 'application/json')
    $headers.Add('Authorization', 'Bearer ' + $grafana_token)

    $body = ConvertTo-Json -Compress @{
        name     = $account_name
        type     = 'cloudwatch'
        url      = 'http://monitoring.us-east-2.amazonaws.com'
        access   = 'proxy'
        jsondata = @{
            authType      = 'arn'
            defaultRegion = 'us-east-2'
            assumeRoleArn = 'arn:aws:iam::' + $new_account_id + ':role/QL-Base-Account-Grafana-Assume-Cloudwatch-Role'
        }
    }

    try {
        $method = 'POST'
        $content_type = 'application/json'
        $response = Invoke-RestMethod -Uri $grafana_url -Method $method -Headers $headers -Body $body -ContentType $content_type
        Write-Host ($response | ConvertTo-Json)

        $grafana_detail = @{
            name  = 'Grafana'
            value = 'Success'
        }
        $notification.Add($grafana_detail)

    }
    catch {
        $error_message = $_
        Write-Host "An error occurred: " + $error_message

        $iamsaml = @{
            name  = 'Grafana'
            value = "Failure - $error_message"
        }
        $notification.Add($iamsaml)
    }

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

$app_id = $ENV:APP_ID
$kraken_env = $ENV:KRAKEN_ENV

# $LambdaInput = '{"AccountName":"Data Operations","FOC":"QL","Stream":"somestream","ReleaseTrain":"releasetrain","Environment":"Prod"}'
# ,"Email":"AWS-QLDataOperations-Prod-Root@quickenloans.com"
##################################################################################


# Start of the acccount creation process
Write-Host (ConvertTo-Json -InputObject $LambdaInput -Compress -Depth 5)
$account_to_create_name = "[" + $LambdaInput.FOC + "]" + " " + $LambdaInput.AccountName + " " + $LambdaInput.Environment
$account_to_create_email = "AWS-DL-" + $LambdaInput.FOC + ($LambdaInput.AccountName -replace '\s', '') + "-" + $LambdaInput.Environment + "-Root@quickenloans.com"
# $LambdaInput.Email
$account_to_create_billing = "ALLOW"
$account_environment = ($LambdaInput.Environment).tolower()
$account_stream = $LambdaInput.Stream
$account_release_train = $LambdaInput.ReleaseTrain
$account_foc = $LambdaInput.FOC

$organization_role = (Get-SSMParameterValue -Name "/kraken/$kraken_env/$app_id/organization_role" –WithDecryption $true).Parameters.Value

Write-Host "Creating a new AWS Account...."
Write-Host "------------------------------"
Write-Host "App ID:" $app_id
Write-Host "Account Name:" $account_to_create_name
Write-Host "Account Email:" $account_to_create_email
Write-Host "IAM Assume Role:" $organization_role
Write-Host ""

Try {
    $create_account = New-ORGAccount -AccountName $account_to_create_name -Email $account_to_create_email -IamUserAccessToBilling $account_to_create_billing -RoleName $organization_role -Region "us-east-2"

    $check_status = Get-ORGAccountCreationStatus -Region "us-east-2" -CreateAccountRequestId $create_account.Id

    #Start to build notification, need to add additional stuff to this from other functions
    $notification = New-Object 'System.Collections.Generic.List[System.Object]'

    Do {
        Write-Host "Waiting for account to finish creating...."
        Start-Sleep -Seconds 1
        $check_status = Get-ORGAccountCreationStatus -Region us-east-2 -CreateAccountRequestId $create_account.Id
        if ($check_status.State.Value -eq "SUCCEEDED") {

            $new_account = Get-ORGAccount -region "us-east-2" -AccountId $check_status.AccountId
            $account_tags = @(@{key = "app-id"; value = $app_id }, @{key = "product-id"; value = "000000" }, @{key = "iac"; value = "serverless" }, @{key = "environment"; value = $account_environment }, @{key = "release-train"; value = $account_release_train }, @{key = "stream"; value = $account_stream })

            Add-ORGResourceTag -ResourceId $new_account.Id -Tag $account_tags

            Write-Host "---- Account Creation Successful ----"
            Write-Host "Account ID:    " $new_account.Id
            Write-Host "Account Name:  " $new_account.Name
            Write-Host "Account Email: " $new_account.Email

            $account_name_details = @{
                name  = "Account Name"
                value = $account_to_create_name
            }
            $notification.Add($account_name_details)

            $account_detail = @{
                name  = "Account ID"
                value = $new_account.Id
            }
            $notification.Add($account_detail)

            $org_account_Credentials = org_account_assume_credentials -new_account_id $new_account.Id

            $new_account_name_alias = ($new_account.Name).tolower() -replace "((?![a-z0-9\-]).)", ""

            add_account_to_hal -new_account_id $new_account.Id -environment $account_environment -alias $new_account_name_alias -release_train $release_train -stream $stream -action $action

            Write-Host "IAM Account Alias:" $new_account_name_alias
            update_account_alias -account_alias $new_account_name_alias -new_account_id $new_account.Id
            update_saml_identity_provider -new_account_id $new_account.Id

            create_stackset_exec_role -new_account_id $new_account.Id
            # add_account_stackset -new_account_id $new_account.Id -environment $account_environment -foc $account_foc

            delete_default_vpc -new_account_id $new_account.Id

            if ($account_environment -eq "prod") {
                add_account_ent_support -new_account_id $new_account.Id
                add_account_to_account_governance -new_account_id $new_account.Id -account_name $account_to_create_name -account_environment $account_environment -release_train $release_train -stream $stream
                $grafana_account_format = $account_to_create_name + " (" + $new_account.Id + ")"
                add_account_to_grafana -new_account_id $new_account.Id -account_name $grafana_account_format
            }

            Write-Host "Creating set of Credentials in Guard Duty Master Account....."
            $gd_master_Credentials = guard_duty_master_account_assume_credentials
            setup_guard_duty -new_account_id $new_account.Id -email_address $account_to_create_email

            post_to_teams -process "Account Creation" -status "Success" -details $notification

        }
        elseIf ($check_status.State.Value -eq "FAILED" -and $check_status.FailureReason.Value -eq "EMAIL_ALREADY_EXISTS") {
            Write-Host "---- Account Creation Failed ----"
            Write-Host "Failure Reason: Email Address is in use by another account in the Organization. Needs to be unique."
            Write-Host "Request ID:    " $check_status.Id
            Write-Host "Request Time:  " $check_status.RequestedTimestamp

            # post message to teams channel on failure
            $account_detail = @{
                name  = 'Account Creation Failed'
                value = "Email address is already in use for another account in the Organization."
            }
            $notification.Add($account_detail)

            $account_detail_request = @{
                name  = "Account Requested"
                value = $account_to_create_name
            }
            $notification.Add($account_detail_request)

            post_to_teams -process "Account Creation" -status "Failure" -details $notification
        }
    } While ($check_status.State.Value -eq "IN_PROGRESS")
}
Catch {
    $error_message = $error[0].Exception.message
    Write-Host "An error occurred: " + $error_message
    Break
}
