# Dot-source only. No queries or mutations occur while loading this source.
Set-StrictMode -Version Latest

function Get-StorageCandidate {
    $partitions = @(Get-Partition -ErrorAction Stop)
    $volumes = @(Get-Volume -ErrorAction Stop)
    $drives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction Stop)
    $disks = @(Get-Disk -ErrorAction Stop)
    if (@($partitions | Where-Object DriveLetter -eq 'D').Count -or
        @($volumes | Where-Object DriveLetter -eq 'D').Count -or
        @($drives | Where-Object Name -eq 'D').Count) { throw 'HOLD: D is assigned.' }
    $eligible = @($disks | Where-Object {
        $d = $_
        $flags = @('IsBoot', 'IsSystem', 'IsOffline', 'IsReadOnly')
        $affirmative = $true
        foreach ($flag in $flags) {
            if ($d.$flag -isnot [bool] -or $d.$flag -ne $false) { $affirmative = $false }
        }
        $null -ne $d.Number -and $d.BusType -eq 'NVMe' -and
        $d.PartitionStyle -eq 'RAW' -and $affirmative -and
        $null -ne $d.NumberOfPartitions -and $d.NumberOfPartitions -eq 0 -and
        $null -ne $d.Size -and $d.Size -ge 50GB -and
        $d.Number -notin @($partitions | ForEach-Object DiskNumber)
    })
    if ($eligible.Count -ne 1) { throw 'HOLD: require exactly one empty eligible NVMe.' }
    return $eligible[0]
}

function Assert-StoragePhysicalPath {
    param([string]$Path, [switch]$MustExist)
    if ($Path -notmatch '^[CD]:\\' -or $Path -match '(^|\\)\.\.?($|\\)') {
        throw 'HOLD: require an absolute canonical C/D physical path.'
    }
    $cursor = $Path
    $found = $false
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ($cursor -eq $Path) { $found = $true }
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'HOLD: reparse point in physical path ancestry.'
            }
        }
        $cursor = Split-Path -Path $cursor -Parent
    }
    if ($MustExist -and -not $found) { throw 'HOLD: required physical path absent.' }
}

function Get-StorageNativeEvidence {
    param([ValidateSet('C', 'D')][string]$Letter)
    $lines = @(& fltmc.exe instances 2>&1 | ForEach-Object { "$_" })
    $record = [ordered]@{
        command = 'fltmc.exe instances'; volume = "${Letter}:"; exitCode = $LASTEXITCODE
        instances = @($lines | Select-Object -First 32 | ForEach-Object { $_.Substring(0, [Math]::Min(256, $_.Length)) })
    }
    if ($record.exitCode -ne 0 -or -not ($lines -match "^\s*WdFilter\s+${Letter}:\s+")) {
        $record.reason = if ($record.exitCode -ne 0) { 'FilterQueryFailed' } else { 'AttachmentNotObserved' }
        $hold = [InvalidOperationException]::new("HOLD: global filter-instance check $($record.reason) for ${Letter}:; native query evidence retained.")
        $hold.Data['StorageNativeEvidence'] = $record
        throw $hold
    }
    $query = @(& fsutil.exe devdrv query "${Letter}:" 2>&1 | ForEach-Object { "$_" })
    $record.devDriveQuery = [ordered]@{
        command = "fsutil.exe devdrv query ${Letter}:"; exitCode = $LASTEXITCODE
        output = @($query | Select-Object -First 8 | ForEach-Object { $_.Substring(0, [Math]::Min(256, $_.Length)) })
    }
    if ($record.devDriveQuery.exitCode -ne 0 -or
        (($query -join "`n").Trim() -cne 'This is not a developer volume.')) {
        $record.reason = 'VolumeNotProvenOrdinary'
        $hold = [InvalidOperationException]::new("HOLD: ${Letter}: not proven ordinary; never attempt trust repair.")
        $hold.Data['StorageNativeEvidence'] = $record
        throw $hold
    }
    $record
}

function Get-StorageProtection {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $preferences = Get-MpPreference -ErrorAction Stop
    $selected = [ordered]@{}
    foreach ($name in @('AMServiceEnabled', 'AntivirusEnabled', 'RealTimeProtectionEnabled',
        'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'OnAccessProtectionEnabled', 'IsTamperProtected')) {
        if ($status.$name -isnot [bool] -or $status.$name -ne $true) {
            throw "HOLD: missing/disabled protection $name."
        }
        $selected[$name] = $status.$name
    }
    foreach ($name in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring',
        'DisableIOAVProtection', 'DisableScriptScanning')) {
        if ($preferences.$name -isnot [bool] -or $preferences.$name -ne $false) {
            throw "HOLD: missing/enabled disable preference $name."
        }
        $selected[$name] = $preferences.$name
    }
    return ($selected | ConvertTo-Json -Compress)
}

function Invoke-StorageCandidate {
    [CmdletBinding()]
    param(
        [switch]$Execute,
        [switch]$LiveApproval,
        [string]$Ack,
        [string]$ReviewedSha,
        [Parameter(Mandatory)][hashtable]$Roots
    )
    $ErrorActionPreference = 'Stop'
    # Environment values must come from the future reviewed hosted caller, not old inventory.
    if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        $env:RUNNER_OS -cne 'Windows' -or $env:RUNNER_ARCH -cne 'ARM64' -or
        $env:GITHUB_REPOSITORY -cne 'yeelam-gordon/spring-petclinic' -or
        $env:GITHUB_REPOSITORY_OWNER -cne 'yeelam-gordon' -or
        $env:GITHUB_ACTOR -cne 'yeelam-gordon' -or
        $env:GITHUB_REF -cne 'refs/heads/perf/windows-arm-storage' -or
        $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or
        $env:GITHUB_RUN_ATTEMPT -cne '1' -or $env:GITHUB_RUN_ID -notmatch '^\d+$' -or
        $ReviewedSha -cnotmatch '^[0-9a-f]{40}$' -or $ReviewedSha -cne $env:GITHUB_SHA) {
        throw 'HOLD: hosted source/repository/actor/attempt gates failed.'
    }
    if ($Execute -and (-not $LiveApproval -or
        $Ack -cne 'APPROVE_EMPTY_EPHEMERAL_NVME_ORDINARY_REFS')) {
        throw 'HOLD: separate live approval and exact ACK required; no current approval.'
    }
    $event = Get-Content -LiteralPath $env:GITHUB_EVENT_PATH -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($event.repository.fork -isnot [bool] -or $event.repository.fork -ne $true -or
        $event.repository.full_name -cne 'yeelam-gordon/spring-petclinic' -or
        $event.sender.login -cne 'yeelam-gordon') { throw 'HOLD: hosted event fork/actor evidence differs.' }
    foreach ($key in @('Workspace', 'Source', 'Sdk', 'Cache', 'Output', 'Temp', 'Stage', 'Evidence')) {
        if (-not $Roots.ContainsKey($key)) { throw "HOLD: root $key undeclared." }
    }
    if ($Roots.Workspace -cne $env:GITHUB_WORKSPACE -or
        $Roots.Stage -cne 'D:\java-storage-stage' -or
        $Roots.Evidence -cne (Join-Path $env:RUNNER_TEMP "storage-candidate-$env:GITHUB_RUN_ID-1")) {
        throw 'HOLD: workspace/stage/private evidence roots differ.'
    }
    foreach ($key in @('Source', 'Cache', 'Output', 'Temp')) {
        if (-not $Roots[$key].StartsWith('D:\java-storage-stage\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "HOLD: $key must be a declared stage child."
        }
    }
    if (@($Roots.Values | Select-Object -Unique).Count -ne $Roots.Count -or
        $Roots.Workspace -notmatch '^C:\\' -or $Roots.Sdk -notmatch '^C:\\' -or
        $env:RUNNER_TEMP -notmatch '^C:\\') { throw 'HOLD: independent physical roots required.' }
    foreach ($key in $Roots.Keys) {
        Assert-StoragePhysicalPath $Roots[$key] -MustExist:($key -in @('Workspace', 'Sdk'))
    }
    $disk = (Get-StorageCandidate).PSObject.Copy()
    $before = Get-StorageProtection
    $cEvidence = Get-StorageNativeEvidence C
    $formatMetadata = (Get-Command Format-Volume -ErrorAction Stop).Parameters.ContainsKey('DevDrive')
    $plan = [ordered]@{
        disposition = 'HOLD'; formatPending = $true; plainRefsSupportUnknown = $true
        complete = $false; buildAllowed = $false; sourceSha = $ReviewedSha
        diskNumber = $disk.Number; diskSize = $disk.Size; bus = "$($disk.BusType)"
        roots = $Roots; protection = $before; cEvidence = $cEvidence
        devDriveParameterPresent = $formatMetadata
        limitation = 'Selected flags/filter observations only; not all AV policy/provider semantics.'
    }
    if (-not $Execute) { return [pscustomobject]$plan }

    # Persist private intent BEFORE any storage write. No serial/unique identifiers exported.
    New-Item -ItemType Directory -Path $Roots.Evidence -ErrorAction Stop | Out-Null
    $record = Join-Path $Roots.Evidence 'provision.json'
    $plan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $record -Encoding utf8 -ErrorAction Stop
    $operation = 'RefreshCandidate'
    $fresh = $null
    try {
        $fresh = Get-StorageCandidate
        $operation = 'ValidateFreshIdentity'
        foreach ($field in @('Number', 'Size', 'BusType', 'PartitionStyle', 'NumberOfPartitions',
            'IsBoot', 'IsSystem', 'IsOffline', 'IsReadOnly', 'UniqueId')) {
            if ($null -eq $disk.$field -or $disk.$field -cne $fresh.$field) {
                throw 'HOLD: target identity/state changed between fresh inventories.'
            }
        }
        if ([string]::IsNullOrWhiteSpace([string]$fresh.UniqueId)) { throw 'HOLD: private identity unavailable.' }
        $operation = 'CheckPrewriteProtection'
        if ((Get-StorageProtection) -cne $before) { throw 'HOLD: protection changed before initialization.' }
        $operation = 'InitializeDisk'
        $initialized = Initialize-Disk -InputObject $fresh -PartitionStyle GPT -PassThru -ErrorAction Stop
        $operation = 'CreatePartition'
        $partition = New-Partition -InputObject $initialized -UseMaximumSize -DriveLetter D -ErrorAction Stop
        $operation = 'CheckNewPartition'
        if ($partition.DiskNumber -ne $fresh.Number -or $partition.DriveLetter -ne 'D' -or
            $partition.Size -lt 50GB -or $partition.Size -gt $fresh.Size) { throw 'HOLD: unexpected new partition.' }
        $operation = 'FormatOrdinaryReFS'
        $formatted = Format-Volume -Partition $partition -FileSystem ReFS -Confirm:$false -ErrorAction Stop
        $operation = 'CheckFormatResult'
        if ($formatted.FileSystem -ne 'ReFS' -or $formatted.DriveLetter -ne 'D') {
            throw 'HOLD: ordinary ReFS format not established.'
        }
        $operation = 'QueryPostformatVolume'
        $volumes = @(Get-Volume -DriveLetter D -ErrorAction Stop)
        $operation = 'QueryPostformatPartition'
        $parts = @(Get-Partition -DriveLetter D -ErrorAction Stop)
        $operation = 'CheckPostformatFootprint'
        if ($volumes.Count -ne 1 -or $parts.Count -ne 1 -or
            $parts[0].DiskNumber -ne $fresh.Number -or $volumes[0].FileSystem -ne 'ReFS' -or
            $parts[0].PartitionNumber -ne $partition.PartitionNumber -or
            $parts[0].DriveLetter -ne 'D' -or
            $volumes[0].HealthStatus -ne 'Healthy' -or $volumes[0].SizeRemaining -lt 50GB) {
            throw 'HOLD: postformat identity/health/50GiB footprint failed.'
        }
        $operation = 'CheckPostformatProtection'
        $after = Get-StorageProtection
        if ($before -cne $after) { throw 'HOLD: selected protection changed.' }
        $operation = 'CheckPostformatCFilterAndDevDrive'
        $plan.postC = Get-StorageNativeEvidence C
        $operation = 'CheckPostformatDFilterAndDevDrive'
        $plan.postD = Get-StorageNativeEvidence D
        $operation = 'CheckStagePhysicalPath'
        Assert-StoragePhysicalPath 'D:\java-storage-stage'
        $operation = 'CreateStageDirectory'
        New-Item -ItemType Directory -Path 'D:\java-storage-stage' -ErrorAction Stop | Out-Null
        $plan.formatPending = $false
        $plan.plainRefsSupportUnknown = $false
        $plan.disposition = 'PROVISIONED_ONLY_COMPARISON_INTEGRATION_HOLD'
        # No controller/build invocation exists; fidelity/root integration needs separate review.
        $plan.protectionAfter = $after
    }
    catch {
        $plan.disposition = 'FAILED_NO_RETRY_NO_ROLLBACK'
        $diagnostic = [string]$_.Exception.Message
        foreach ($identitySource in @($disk, $fresh)) {
            if ($null -ne $identitySource) {
                $identityProperty = $identitySource.PSObject.Properties['UniqueId']
                if ($null -ne $identityProperty -and
                    -not [string]::IsNullOrWhiteSpace([string]$identityProperty.Value)) {
                    $diagnostic = [regex]::Replace($diagnostic,
                        [regex]::Escape([string]$identityProperty.Value), '[redacted-identity]',
                        [Text.RegularExpressions.RegexOptions]::IgnoreCase)
                }
            }
        }
        $diagnostic = $diagnostic -replace '(?i)https?://\S+', '[redacted-uri]'
        $diagnostic = $diagnostic -replace '(?i)\bBearer\s+\S+', 'Bearer [redacted]'
        $diagnostic = $diagnostic -replace '(?i)\b(password|token|secret|credential|authorization)\s*[:=]\s*("[^"]*"|''[^'']*''|\S+)', '$1=[redacted]'
        $diagnostic = $diagnostic -replace '[\x00-\x1f\x7f]', ' '
        $failureType = $_.Exception.GetType().FullName
        $plan.failure = [ordered]@{
            operation = $operation
            category = [string]$_.CategoryInfo.Category
            type = $failureType.Substring(0, [Math]::Min(128, $failureType.Length))
            diagnostic = $diagnostic.Substring(0, [Math]::Min(512, $diagnostic.Length))
        }
        throw
    }
    finally {
        $plan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $record -Encoding utf8 -ErrorAction Stop
    }
    return [pscustomobject]$plan
}
