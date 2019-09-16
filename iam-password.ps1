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

# Uncomment to send the input event to CloudWatch Logs
Write-Host (ConvertTo-Json -InputObject $LambdaInput -Compress -Depth 5)

$nl = [Environment]::NewLine

Try {
    $account_policy = Get-IAMAccountPasswordPolicy
    Update-IAMAccountPasswordPolicy -MaxPasswordAge 90 -PasswordReusePrevention 6 -RequireLowercaseCharacter $true -RequireNumber $true -RequireSymbol $true -RequireUppercaseCharacter $true -ErrorAction Stop
    $new_account_policy = Get-IAMAccountPasswordPolicy

    $result = "---- IAM Acccount Properties ---- " + $nl 
    $result += "Max Password Age: " + $new_account_policy.MaxPasswordAge + $nl
    $result += "Min Password Length: " + $new_account_policy.MinimumPasswordLength + $nl
    $result += "Password Reuse: " + $new_account_policy.PasswordReusePrevention + $nl
    $result += "Require Lowercase: " + $new_account_policy.RequireLowercaseCharacters + $nl
    $result += "Require Uppsercase: " + $new_account_policy.RequireUppercaseCharacters + $nl
    $result += "Require Numbers: " + $new_account_policy.RequireNumbers + $nl
    $result += "Require Symbols: " + $new_account_policy.RequireSymbols + $nl
    $result += "---- Successfully Updated ----" + $nl

    Write-Host $result
}
Catch {
    Write-Host "An error occurred:"
    Write-Host $_
    Break
}


