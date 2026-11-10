[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunnerEnvironment,
    [Parameter(Mandatory)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$inventory = [ordered]@{
    scope = 'Read-only inventory; no storage or protection changes and no build/timing.'
    complete = $false
    plainReFsCapability = 'UNKNOWN'
    perVolumeDefenderPolicy = 'UNKNOWN'
    disposition = 'Raw-disk candidates do not establish format permission, SKU support, trust, or timing approval.'
}
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop | Out-Null
try {
    if ($RunnerEnvironment -ne 'github-hosted' -or
        $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ARCH -ne 'ARM64' -or
        [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'Arm64') {
        throw 'Inventory requires a GitHub-hosted Windows ARM64 job; no local or self-hosted execution.'
    }
    $inventory.provenance = [ordered]@{
        sourceSha = $env:GITHUB_SHA
        scriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        commands = @('Get-Partition', 'Get-Disk', 'Get-Volume', 'Get-PSDrive',
            'Get-CimInstance Win32_OperatingSystem', 'Get-MpComputerStatus', 'Get-MpPreference',
            'Get-Command Format-Volume (metadata only)', 'fltmc.exe filters',
            'fltmc.exe instances', 'fsutil.exe devdrv query C: / D: (existing volumes only)')
    }

    $partitions = @(Get-Partition)
    $volumes = @(Get-Volume)
    $drives = @(Get-PSDrive -PSProvider FileSystem)
    $disks = @(Get-Disk)
    $inventory.disks = @($disks | Select-Object Number, BusType, PartitionStyle, Size,
        NumberOfPartitions, IsBoot, IsSystem, IsOffline, IsReadOnly)
    $inventory.partitions = @($partitions | Select-Object DiskNumber, PartitionNumber,
        DriveLetter, Size, Type)
    $inventory.volumes = @($volumes | Select-Object DriveLetter, FileSystem, DriveType,
        HealthStatus, Size, SizeRemaining)
    $inventory.fileSystemDrives = @($drives | Select-Object Name)
    $inventory.driveDAlreadyAssigned = [bool](($partitions | Where-Object DriveLetter -eq 'D') -or
        ($volumes | Where-Object DriveLetter -eq 'D') -or
        ($drives | Where-Object Name -eq 'D'))
    $eligible = @($disks | Where-Object {
        $null -ne $_.Number -and $_.BusType -eq 'NVMe' -and $_.PartitionStyle -eq 'RAW' -and
        $_.IsBoot -eq $false -and $_.IsSystem -eq $false -and
        $_.IsOffline -eq $false -and $_.IsReadOnly -eq $false -and
        $null -ne $_.NumberOfPartitions -and $_.NumberOfPartitions -eq 0 -and
        $null -ne $_.Size -and $_.Size -ge 50GB -and
        $_.Number -notin $partitions.DiskNumber
    })
    $inventory.candidateRawNvmeDiskNumbers = @($eligible | Select-Object -ExpandProperty Number)
    $inventory.uniqueRawDiskCandidate = $eligible.Count -eq 1
    $inventory.candidateWithUnassignedD = $eligible.Count -eq 1 -and -not $inventory.driveDAlreadyAssigned

    $os = Get-CimInstance Win32_OperatingSystem
    $inventory.runner = [ordered]@{
        os = $env:RUNNER_OS
        architecture = $env:RUNNER_ARCH
        environment = $RunnerEnvironment
        image = $env:ImageOS
        imageVersion = $env:ImageVersion
        operatingSystem = $os.Caption
        version = $os.Version
        build = $os.BuildNumber
        sku = $os.OperatingSystemSKU
    }
    $inventory.defenderStatus = Get-MpComputerStatus | Select-Object AMServiceEnabled,
        AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
        IoavProtectionEnabled, OnAccessProtectionEnabled, IsTamperProtected
    $inventory.defenderPreferences = Get-MpPreference | Select-Object DisableRealtimeMonitoring,
        DisableBehaviorMonitoring, DisableIOAVProtection, DisableScriptScanning, PerformanceModeStatus
    $formatCommand = Get-Command -Name Format-Volume -ErrorAction SilentlyContinue
    $inventory.devDriveParameterMetadata = if ($null -eq $formatCommand) { 'UNKNOWN' }
        elseif ($formatCommand.Parameters.ContainsKey('DevDrive')) { 'Available; metadata only, not plain ReFS SKU proof' }
        else { 'Not exposed by this cmdlet; SKU capability remains UNKNOWN' }

    foreach ($query in @('filters', 'instances')) {
        $lines = @(& fltmc.exe $query 2>&1 | ForEach-Object { "$_" })
        $exitCode = $LASTEXITCODE
        $key = if ($query -eq 'filters') { 'loadedFilters' } else { 'filterInstances' }
        $inventory[$key] = [ordered]@{ exitCode = $exitCode; output = $lines }
        if ($exitCode -ne 0) { throw "Read-only filter $query inventory failed with exit $exitCode." }
    }
    $inventory.devDriveQueries = @(
        foreach ($letter in @('C', 'D')) {
            if ($letter -in $volumes.DriveLetter) {
                $lines = @(& fsutil.exe devdrv query "${letter}:" 2>&1 | ForEach-Object { "$_" })
                [ordered]@{
                    volume = "${letter}:"
                    exitCode = $LASTEXITCODE
                    output = $lines
                    interpretation = 'Query only. Nonzero may mean a non-Dev-Drive volume or query failure; support remains UNKNOWN.'
                }
            }
        }
    )
    $inventory.complete = $true
}
catch {
    [ordered]@{ complete = $false; error = $_.Exception.Message } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'error.json') -Encoding utf8
    throw
}
finally {
    $inventory | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath (Join-Path $OutputDirectory 'inventory.json') -Encoding utf8
}
