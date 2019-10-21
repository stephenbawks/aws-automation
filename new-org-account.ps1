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

#Requires -Modules @{ModuleName='AWSPowerShell.NetCore';ModuleVersion='3.3.604.0'}

# AWS Documentation
# https://docs.aws.amazon.com/organizations/latest/APIReference/API_CreateAccount.html
# https://docs.aws.amazon.com/powershell/latest/reference/Index.html

# Powershell Documentation
# https://www.powershellgallery.com/packages/AWSPowerShell



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
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $details
    )

    # this will pull from the environmental values on the lambda
    # this should be the webhook address that the function will post to
    # disabling for the moment until deployed, testing still

    $uri = (Get-SSMParameterValue -Name "/kraken/prod-aws/$app_id/teams_uri_address" –WithDecryption $true).Parameters.Value

    # these values would be retrieved from or set by an application
    # $status = 'success'
    $pass_fail_image = $null

    if ($status -eq "Success") {
        $pass_fail_image = 'https://cdn3.iconfinder.com/data/icons/flat-actions-icons-9/792/Tick_Mark_Dark-512.png'
    } elseif ($status -eq "Failure") {
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
        [string] $org_role_name,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $new_account_id
    )

    $role = "arn:aws:iam::" + $new_account_id + ":role/" + $org_role_name

    $org_account_id = (Get-SSMParameterValue -Name "/kraken/prod-aws/$app_id/org_account_id" –WithDecryption $true -profilename prodorganization).Parameters.Value

    $role_tags = @( @{key = "app-id"; value = "203880" }, @{key = "product-id"; value = "000000" }, @{key = "iac"; value = "cloudformation" } )

    $Response = (Use-STSRole -Region us-east-2 -RoleArn $role -RoleSessionName "assumedrole" -ProfileName prodorganization).Credentials
    $Credentials = New-AWSCredentials -AccessKey $Response.AccessKeyId -SecretKey $Response.SecretAccessKey -SessionToken $Response.SessionToken

    $stackset_role_name = "AWSCloudFormationStackSetExecutionRole"
    $stackset_role_desc = "Stack Set Role to push StackSets from the Org"
    $stackset_role_trust_policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal": {"AWS": "arn:aws:iam::' + $org_account_id + ':root"},"Action":"sts:AssumeRole"}]}'

    New-IAMRole -RoleName $stackset_role_name -AssumeRolePolicyDocument $stackset_role_trust_policy -Description $stackset_role_desc -Tag $role_tags -Credential $Credentials

    Register-IAMRolePolicy -RoleName $stackset_role_name -PolicyArn "arn:aws:iam::aws:policy/AdministratorAccess" -Credential $Credentials
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
        [string] $environment
    )

    # Grab accounts in a particular StackSet
    $base_roles_stackset = Get-CFNStackInstanceList -StackSetName "base-account-role-policy-$environment" -Region "us-east-1" -profilename prodorganization
    # Check to see if the new account exists in the array
    if ($base_roles_stackset.Account -contains $new_account_id) {
        Write-Host "Account $new_account_id is already in the Base Account Roles StackSet. Nothing to do here."
    } elseif ($base_roles_stackset.Account -notcontains $new_account_id) {
        Write-Host "Account $new_account_id is not in the Base Account Roles StackSet and will be added. Creating Stack Instance."
        New-CFNStackInstance -StackSetName "base-account-role-policy-$environment" -Account $new_account_id -StackInstanceRegion "us-east-2" -Region "us-east-1" -ProfileName prodorganization
        # Update-CFNStackInstance -StackSetName "base-account-role-policy-$environment" -Account $new_account_id -StackInstanceRegion "us-east-2" -ProfileName testorganization
    }

    $aws_hal_stackset = Get-CFNStackInstanceList -StackSetName "base-account-setup-hal-role-child-account-$environment" -Region "us-east-1" -profilename prodorganization
    # Check to see if the new account exists in the array
    $aws_hal_stackset_regions = 'us-east-2','us-east-1','us-west-2','us-west-1'
    $operation_preference = '{"RegionOrder":["us-east-2","us-east-1","us-west-2","us-west-1"]}' | ConvertFrom-Json

    #need to double check this if statement.  want to make sure that each region is in the stackset for the new account
    if ($aws_hal_stackset.Account -contains $new_account_id) {
        Write-Host "Account $new_account_id is already in the Base Account HAL Roles Child StackSet. Nothing to do here."
    } elseif ($aws_hal_stackset.Account -notcontains $new_account_id) {
        Write-Host "Account $new_account_id is not in the Base Account Roles StackSet and will be added. Creating Stack Instance."
        New-CFNStackInstance -StackSetName "base-account-setup-hal-role-child-account-$environment" -Account $new_account_id -StackInstanceRegion $aws_hal_stackset_regions -OperationPreference $operation_preference -Region "us-east-1" -ProfileName prodorganization
        # Update-CFNStackInstance -StackSetName "base-account-setup-hal-role-child-account-$environment" -Account $new_account_id -StackInstanceRegion $aws_hal_stackset_regions -OperationPreference $operation_preference -ProfileName testorganization
    }

    $aws_cloudtrail_stackset = Get-CFNStackInstanceList -StackSetName "base-account-setup-cloudtrail-$environment" -Region "us-east-1" -profilename prodorganization
    if ($aws_cloudtrail_stackset.Account -contains $new_account_id) {
        Write-Host "Account $new_account_id is already in the Base Account Cloudtrai StackSet. Nothing to do here."
    } elseif ($aws_cloudtrail_stackset.Account -notcontains $new_account_id) {
        Write-Host "Account $new_account_id is not in the Base Account Roles StackSet and will be added. Creating Stack Instance."
        New-CFNStackInstance -StackSetName "base-account-setup-cloudtrail-$environment" -Account $new_account_id -StackInstanceRegion "us-east-2" -Region "us-east-1" -ProfileName prodorganization
    }


    $aws_config_stackset = Get-CFNStackInstanceList -StackSetName "base-account-setup-aws-config-$environment" -Region "us-east-1" -profilename prodorganization

    $config_regions = "ap-northeast-1","ap-northeast-2","ap-south-1","ap-southeast-1","ap-southeast-2","ca-central-1","eu-central-1","eu-west-1","eu-west-2","eu-north-1","eu-west-3","sa-east-1","us-east-1","us-east-2","us-west-1","us-west-2"
    $config_operation_preference = '{"RegionOrder":["us-east-2","us-east-1","us-west-1","us-west-2","ap-northeast-1","ap-northeast-2","ap-south-1","ap-southeast-1","ap-southeast-2","ca-central-1","eu-central-1","eu-west-1","eu-west-2","eu-west-3","sa-east-1"]}' | ConvertFrom-Json
    if ($aws_config_stackset.Account -contains $new_account_id) {
        Write-Host "Account $new_account_id is already in the Base Account Config StackSet. Nothing to do here."
    } elseif ($aws_config_stackset.Account -notcontains $new_account_id) {
        Write-Host "Account $new_account_id is not in the Base Account Config StackSet and will be added. Creating Stack Instance."
        New-CFNStackInstance -StackSetName "base-account-setup-aws-config-$environment" -Account $new_account_id -StackInstanceRegion $config_regions -OperationPreference $config_operation_preference -Region "us-east-1" -ProfileName prodorganization
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
        [string] $alias,
        [Parameter(Mandatory = $true, Position = 3)]
        [string] $release_train,
        [Parameter(Mandatory = $true, Position = 4)]
        [string] $stream,
        [Parameter(Mandatory = $true, Position = 5)]
        [string] $action
    )

        $body = ConvertTo-Json -Compress @{
            acountId      = $new_account_id
            environment   = $environment
            alias         = $alias
            release_train = $release_train
            stream        = $stream
            action        = $action
        }

        $topic_arn = "arn:aws:sns:us-east-1:984209812669:prod-200947-hal-new-account-queue"

        Publish-SNSMessage -TopicArn $topic_arn -Subject "New Account - $new_account_id" -Message $body -Region "us-east-1" -profilename prodorganization


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

    $email_address = (Get-SSMParameterValue -Name "/kraken/prod-aws/$app_id/email_for_notifications" –WithDecryption $true).Parameters.Value
    New-ASACase -Subject "New Account - Add to Enterprise Support" -IssueType "customer-service" -ServiceCode "account-management" -CategoryCode "billing" -SeverityCode "low" -CommunicationBody "Can you please add $new_account_id to our Enterprise Support agreement?" -CcEmailAddress $email_address -Region "us-east-1"

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
        [string] $org_role_name,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $new_account_id,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $email_address
    )


    $AccountDetails = @{
        AccountId = $new_account_id
        Email     = $email_address
    }





    $guard_duty_regions = @(
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
        },
        @{
            "guarddutyaccount" = "503012327073"
        }
    )

    $account_to_invite_role = "arn:aws:iam::" + $new_account_id + ":role/" + $org_role_name
    $guard_duty_role = "arn:aws:iam::" + $guard_duty_regions.guarddutyaccount + ":role/" + $org_role_name

    #creates a set of crendentials in the account to be invited to guard duty
    $invite_account_Response = (Use-STSRole -RoleArn $account_to_invite_role -RoleSessionName "assumedrole" -ProfileName prodorganization).Credentials
    $invite_account_Credentials = New-AWSCredentials -AccessKey $invite_account_Response.AccessKeyId -SecretKey $invite_account_Response.SecretAccessKey -SessionToken $invite_account_Response.SessionToken

    #creates a set of crendentials in master guard duty account
    $guard_duty_Response = (Use-STSRole -RoleArn $guard_duty_role -RoleSessionName "assumedrole" -ProfileName prodorganization).Credentials
    $guard_duty_Credentials = New-AWSCredentials -AccessKey $guard_duty_Response.AccessKeyId -SecretKey $guard_duty_Response.SecretAccessKey -SessionToken $guard_duty_Response.SessionToken

    $guard_duty_regions | ForEach-Object -Process {
        $current_region = $_.Region
        $current_region_detectorid = $_.$DetectorId
        # this creates a detector in the child/member account.  there needs to be a detector before you can accept an invitiation
        $new_member_detector = New-GDDetector -Enable $true -Credential $invite_account_Credentials -Region $current_region
        Write-Host "Member Account Detector:" $member_detector
        Write-Host "Member Account Region:" $current_region

        New-GDMember -AccountDetail $AccountDetails -Region $current_region -DetectorId $current_region_detectorid -Credential $guard_duty_Credentials
        Send-GDMemberInvitation -AccountId $new_account_id -Region $current_region -DetectorId $current_region_detectorid -DisableEmailNotification $true -Credential $guard_duty_Credentials
        Start-Sleep -Seconds 2

        # this will retrieve the inivitiation from the master account
        $invite = Get-GDInvitationList -Credential $invite_account_Credentials -Region $current_region
        $invite_id = $invite.InvitationId
        $invite_acct_id = $invite.AccountId
        Write-Host "Member Account Invitation:" $invite_id

        # will confirm the invite in the member account from the master guard duty account
        Confirm-GDInvitation -DetectorId $new_member_detector -InvitationId $invite_id -MasterId $invite_acct_id -Credential $invite_account_Credentials -Region $current_region
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
        [string] $org_role_name,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $new_account_id
    )

    Write-Host "Checking the current VPC's...."

    $role = "arn:aws:iam::" + $new_account_id + ":role/" + $org_role_name

    $Response = (Use-STSRole -RoleArn $role -RoleSessionName "assumedrole" -ProfileName prodorganization).Credentials
    $Credentials = New-AWSCredentials -AccessKey $Response.AccessKeyId -SecretKey $Response.SecretAccessKey -SessionToken $Response.SessionToken

    $vpc_regions = "ap-northeast-1","ap-northeast-2","ap-south-1","ap-southeast-1","ap-southeast-2","ca-central-1","eu-central-1","eu-west-1","eu-west-2","eu-west-3","eu-north-1","sa-east-1","us-east-1","us-east-2","us-west-1","us-west-2"
    $regions_count = $vpc_regions.count

        $vpc_regions | ForEach-Object -Process {
        $current_region = $_
        $current_account = Get-STSCallerIdentity -Credential $Credentials

        Write-Host "----------------------------------------------"
        Write-Host "Checking for Default VPCs in" $regions_count "regions."
        Write-Host "Current Account:" $current_account.Account
            Write-Host "Current Region:" $current_region
        Write-Host "----------------------------------------------"

            $vpc = Get-EC2Vpc -Region $current_region -Credential $Credentials -Filter @{Name = "isDefault"; Value = "true" }
        # Write-Host "There are" ($vpc).count "Default VPCs in the Account"

        if ($vpc.count -eq 0) {
            Write-Host " --- There are no Default VPCs in" $current_region -ForegroundColor Yellow
        } elseif ($vpc.count -gt 0) {
                $igw = Get-EC2InternetGateway -Region $current_region -Credential $Credentials -Filter @{Name = "attachment.vpc-id"; Value = $vpc.VpcId }
            if ($igw) {
                Write-Host " --- Attempting to dismount" $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Yellow
                Start-Sleep -Seconds 10
                Dismount-EC2InternetGateway -Region $current_region -Credential $Credentials -VpcId $vpc.VpcId -InternetGatewayId $igw.InternetGatewayId
                    if ($? -eq $true) {
                        Write-Host " --- Succesfully dismounted" $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Green
                    } elseif ($? -eq $false) {
                        Write-Host " --- Failed to dismount" $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Red
                    }
                Write-Host " --- Attempting to remove " $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Yellow
                Remove-EC2InternetGateway -Region $current_region -Credential $Credentials -InternetGatewayId $igw.InternetGatewayId -Force
                    if ($? -eq $true) {
                        Write-Host " --- Succesfully removed" $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Green
                    } elseif ($? -eq $false) {
                        Write-Host " --- Failed to remove" $igw.InternetGatewayId "from VPC" $vpc.VpcId -ForegroundColor Red
                    }
            } elseif ($igw -eq $null) {
                Write-Host " --- There are no Internet Gateways attached to VPC" $vpc.VpcId -ForegroundColor Yellow
            }

                $subnets = Get-EC2Subnet -Region $current_region -Credential $Credentials -Filter @{Name = "vpc-id"; Value = $vpc.VpcId }
            if ($subnets) {
                Write-Host ""
                Write-Host " --- Attempting to remove subnets from Default VPC" $vpc.VpcId -ForegroundColor Yellow
                $subnets | ForEach-Object -Process {
                    # Write-Host $current_region
                    Write-Host " --- Removing Subnet:" $_.SubnetId -ForegroundColor Red
                    Start-Sleep -Seconds 10
                    Remove-EC2Subnet -SubnetId $_.SubnetId -Region $current_region -Credential $Credentials -Force
                    if ($? -eq $true) {
                        Write-Host " --- Succesfully removed" $_.SubnetId "from VPC" $vpc.VpcId -ForegroundColor Green
                    }
                    elseif ($? -eq $false) {
                        Write-Host " --- Failed to remove" $_.SubnetId "from VPC" $vpc.VpcId -ForegroundColor Red
                    }
                }
            } elseif ($subnets -eq $null) {
                Write-Host " --- There are no subnets in the VPC" $vpc.VpcId -ForegroundColor Yellow
            }
            Write-Host " --- Attempting to remove Default VPC" $vpc.VpcId -ForegroundColor Yellow
            Remove-EC2Vpc -VpcId $vpc.VpcId -Region $current_region -Credential $Credentials -Force
                if ($? -eq $true) {
                    Write-Host " --- Succesfully removed Default VPC" $vpc.VpcId -ForegroundColor Green
                } elseif ($? -eq $false) {
                    Write-Host " --- Failed to remove Default VPC" $vpc.VpcId -ForegroundColor Red
                }

        }

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
    } elseif ($current_account_alias -eq $account_alias) {
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

    $saml_64 = (Get-SSMParameterValue -Name "/kraken/prod-aws/$app_id/saml_64" –WithDecryption $true).Parameters.Value
    $saml = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($saml_64))

    Write-Host "Checking the current IAM SAML Provider...."

    # AWSControlTowerExecution
    $role = "arn:aws:iam::" + $new_account_id + ":role/" + $org_role_name

    $Response = (Use-STSRole -Region us-east-2 -RoleArn $role -RoleSessionName "assumedrole" -ProfileName prodorganization).Credentials #dont forget to comment out the organiazation profile here
    $Credentials = New-AWSCredentials -AccessKey $Response.AccessKeyId -SecretKey $Response.SecretAccessKey -SessionToken $Response.SessionToken

    Try {

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

    $grafana_url = (Get-SSMParameterValue -Name "/kraken/prod-aws/$app_id/grafana_url" –WithDecryption $true -ProfileName prodorganization).Parameters.Value
    $grafana_token = (Get-SSMParameterValue -Name "/kraken/prod-aws/$app_id/grafana_token" –WithDecryption $true -ProfileName prodorganization).Parameters.Value

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

# $LambdaInput = '{"AccountName":"[QL] Data Operations Prod","Email":"AWS-QLDataOperations-Prod-Root@quickenloans.com","IamUserAccessToBilling":"ALLOW","Environment":"nonprod"}'

##################################################################################


# Start of the acccount creation process
Write-Host (ConvertTo-Json -InputObject $LambdaInput -Compress -Depth 5)
$account_to_create_name = $LambdaInput.AccountName
$account_to_create_email = $LambdaInput.Email
$account_to_create_billing = $LambdaInput.IamUserAccessToBilling
$account_environment = ($LambdaInput.Environment).tolower()


$organization_role = (Get-SSMParameterValue -Name "/kraken/prod-aws/$app_id/organization_role" –WithDecryption $true).Parameters.Value

Write-Host "Creating a new AWS Account...."
Write-Host "------------------------------"
Write-Host "App ID:" $app_id
Write-Host "Account Name:" $account_to_create_name
Write-Host "Account Email:" $account_to_create_email
Write-Host ""

Try {
    # $create_account = New-ORGAccount -AccountName $account_to_create_name -Email $account_to_create_email -IamUserAccessToBilling $account_to_create_billing -RoleName $organization_role -Region "us-east-2"

    # $check_status = Get-ORGAccountCreationStatus -Region "us-east-2" -CreateAccountRequestId $create_account.Id

    Do {
        Write-Host "$(Get-TimeStamp) - Waiting for account to finish creating...."
        Start-Sleep -Seconds 1
        $check_status = Get-ORGAccountCreationStatus -Region us-east-2 -CreateAccountRequestId $create_account.Id
        if ($check_status.State.Value -eq "SUCCEEDED") {

            $new_account = Get-ORGAccount -region "us-east-2" -AccountId $check_status.AccountId
            $account_tags = @( @{key = "app-id"; value = "203880" }, @{key = "product-id"; value = "000000" }, @{key = "iac"; value = "serverless" } )
            Add-ORGResourceTag -ResourceId $new_account.Id -Tag $account_tags

            Write-Host "$(Get-TimeStamp) ---- Account Creation Successful ----"
            Write-Host "Account ID:    " $new_account.Id
            Write-Host "Account Name:  " $new_account.Name
            Write-Host "Account Email: " $new_account.Email

            $new_account_id = "Account Number: " + $new_account.Id  # this is just needed for the teams message, need to change the variable name

            # post message to teams channel on success
            post_to_teams -process "Account Creation" -status "Success" -details $new_account_id
            # add_account_ent_support -new_account_id $new_account.Id

            $grafana_account_format = $account_to_create_name + " (" + $new_account.Id + ")"
            # add_account_to_grafana -new_account_id $new_account.Id -account_name $grafana_account_format

            $new_account_name_alias = ($new_account.Name).tolower() -replace "((?![a-z0-9\-]).)", ""
            # update_account_alias -account_alias $new_account_name_alias -new_account_id $new_account.Id -org_role_name $organization_role
            # update_saml_identity_provider -new_account_id $new_account.Id -org_role_name $organization_role

            # create_stackset_exec_role -org_role_name $organization_role -new_account_id $new_account.Id
            # add_account_stackset -new_account_id $new_account.Id -environment $account_environment

            # setup_guard_duty -org_role_name $organization_role -new_account_id $new_account.Id -email_address $account_to_create_email
            # delete_default_vpc -org_role_name $organization_role -new_account_id $new_accout.Id

            # add_account_to_hal -new_account_id $new_account.Id -environment $account_environment -alias $new_account_name_alias -release_train $release_train -stream $stream -action $action

        } elseIf ($check_status.State.Value -eq "FAILED" -and $check_status.FailureReason.Value -eq "EMAIL_ALREADY_EXISTS") {
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
