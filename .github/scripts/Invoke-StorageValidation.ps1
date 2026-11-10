[CmdletBinding()]
param([Parameter(Mandatory)][string]$RunnerEnvironment)

function Invoke-StorageValidationCaller {
    param(
        [string]$RunnerEnvironment,
        [string]$Mode,
        [string]$LiveApproval,
        [string]$Ack,
        [string]$ReviewedSha
    )
    $ErrorActionPreference = 'Stop'
    $PSNativeCommandUseErrorActionPreference = $false
    $safeEvidence = $null
    try {
        if ($RunnerEnvironment -cne 'github-hosted' -or
            [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'Arm64' -or
            $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
            $env:RUNNER_ARCH -cne 'ARM64') { throw 'HOLD: hosted Windows ARM64 required.' }
        if ($env:GITHUB_RUN_ID -notmatch '^\d+$' -or $env:GITHUB_RUN_ATTEMPT -cne '1' -or
            $env:RUNNER_TEMP -notmatch '^C:\\' -or $env:RUNNER_TEMP -match '(^|\\)\.\.?($|\\)' -or
            $env:RUNNER_TEMP.Substring(2) -match '[/:*?"<>|]') { throw 'HOLD: private evidence root invalid.' }
        $cursor = $env:RUNNER_TEMP
        while ($cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'HOLD: physical evidence ancestry required.'
            }
            $cursor = Split-Path -Path $cursor -Parent
        }
        $safeEvidence = Join-Path $env:RUNNER_TEMP "storage-candidate-$env:GITHUB_RUN_ID-1"
        if ($Mode -cnotin @('plan', 'provision') -or $LiveApproval -cnotin @('true', 'false')) {
            throw 'HOLD: invalid mode or approval input.'
        }
        if ($Mode -ceq 'provision' -and ($LiveApproval -cne 'true' -or
            $Ack -cne 'APPROVE_EMPTY_EPHEMERAL_NVME_ORDINARY_REFS')) {
            throw 'HOLD: provision requires separate approval and exact acknowledgement.'
        }
        if ($ReviewedSha -cnotmatch '^[0-9a-f]{40}$' -or $ReviewedSha -cne $env:GITHUB_SHA) {
            throw 'HOLD: reviewed source differs.'
        }
        foreach ($path in @($env:GITHUB_WORKSPACE, $env:JAVA_HOME)) {
            if ([string]::IsNullOrWhiteSpace($path) -or $path -notmatch '^C:\\' -or
                $path -match '(^|\\)\.\.?($|\\)' -or $path.Substring(2).Contains(':')) {
                throw 'HOLD: existing ordinary C workspace and SDK required.'
            }
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'HOLD: existing ordinary C workspace and SDK required.'
            }
        }
        $env:RUNNER_ENVIRONMENT = $RunnerEnvironment
        . (Join-Path $PSScriptRoot 'StorageCandidate.ps1')
        $roots = @{
            Workspace = $env:GITHUB_WORKSPACE; Sdk = $env:JAVA_HOME
            Stage = 'D:\java-storage-stage'; Source = 'D:\java-storage-stage\project'
            Cache = 'D:\java-storage-stage\m2'; Output = 'D:\java-storage-stage\output'
            Temp = 'D:\java-storage-stage\tmp'; Evidence = $safeEvidence
        }
        $arguments = @{ ReviewedSha = $ReviewedSha; Roots = $roots }
        if ($Mode -ceq 'provision') {
            $arguments.Execute = $true
            $arguments.LiveApproval = $true
            $arguments.Ack = $Ack
        }
        $result = Invoke-StorageCandidate @arguments
        if ($Mode -ceq 'plan') {
            if (-not (Test-Path -LiteralPath $safeEvidence)) {
                New-Item -ItemType Directory -Path $safeEvidence -ErrorAction Stop | Out-Null
            }
            $item = Get-Item -LiteralPath $safeEvidence -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'HOLD: physical evidence directory required.'
            }
        }
        $result | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath (Join-Path $safeEvidence 'validation.json') -Encoding utf8 -ErrorAction Stop
    }
    catch {
        if ($null -ne $safeEvidence) {
            try {
                if (-not (Test-Path -LiteralPath $safeEvidence)) {
                    New-Item -ItemType Directory -Path $safeEvidence -ErrorAction Stop | Out-Null
                }
                $item = Get-Item -LiteralPath $safeEvidence -Force -ErrorAction Stop
                if (-not $item.PSIsContainer -or
                    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Unsafe evidence directory.'
                }
                [ordered]@{
                    disposition = 'HOLD'; buildAllowed = $false
                    category = [string]$_.CategoryInfo.Category
                    type = $_.Exception.GetType().FullName.Substring(0,
                        [Math]::Min(128, $_.Exception.GetType().FullName.Length))
                    message = 'HOLD: storage validation failed; inspect sanitized provision receipt if present.'
                } | ConvertTo-Json |
                    Set-Content -LiteralPath (Join-Path $safeEvidence 'validation-error.json') -Encoding utf8 -ErrorAction Stop
            }
            catch {
                Write-Warning 'HOLD: sanitized validation error receipt could not be persisted.' -WarningAction Continue
            }
        }
        throw 'HOLD: storage validation failed; no build permission or retry approval.'
    }
}

Invoke-StorageValidationCaller -RunnerEnvironment $RunnerEnvironment `
    -Mode $env:STORAGE_MODE -LiveApproval $env:STORAGE_LIVE_APPROVAL `
    -Ack $env:STORAGE_ACK -ReviewedSha $env:STORAGE_REVIEWED_SHA
