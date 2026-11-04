function Assert-SP($Ok,[string]$Message){if(-not$Ok){throw "HOLD: $Message"}}
function Get-SPBinding([string]$Path){
    & ${function:Assert-SP} ([IO.Path]::IsPathFullyQualified($Path)) 'Absolute parent handoff evidence required'
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop;$probe=$item
    & ${function:Assert-SP} ($item-is[IO.FileInfo]-and$item.Length-le262144) 'Bounded ordinary parent handoff file required'
    while($probe){& ${function:Assert-SP} (-not$probe.LinkType-and-not($probe.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked handoff evidence';$probe=if($probe-is[IO.FileInfo]){$probe.Directory}else{$probe.Parent}}
    @{path=$item.FullName;bytes=$item.Length;sha256=(Microsoft.PowerShell.Utility\Get-FileHash $item.FullName).Hash}
}
function New-SPAllocation {
    param([Diagnostics.Process]$Observer,[string]$ObserverScript,[string]$SourceRoot,[string]$OutputRoot,[hashtable]$Scope,[string]$NotBefore,[switch]$FixtureOnly)
    $sources=@()
    foreach($name in 'OwnedJavaBackstop.psm1','ObserverTelemetry.psm1','Supervise-StagedQualifier.ps1','H3911.ScreenParent.psm1'){$sources+=,(& ${function:Get-SPBinding} (Join-Path $SourceRoot $name))}
    & ${function:Assert-SP} ($sources[0].sha256-ceq'406C71D922394EAA666FE8759390C9114B1457461BA9E4F4C69859CE28A5C647') 'Fixed shared validator required'
    $script=& ${function:Get-SPBinding} $ObserverScript
    if(-not$FixtureOnly){& ${function:Assert-SP} ($script.sha256-ceq'A451B495298D977F0331543F359A606B62ED5B0CEDEE8E93358F0D120DF4A032') 'Fixed native observer required'}
    $exe=$Observer.MainModule.FileName;$created=$Observer.StartTime.ToUniversalTime()
    & ${function:Assert-SP} ($Observer.Id-gt0-and$exe-and$created-ge[DateTimeOffset]::Parse($NotBefore).UtcDateTime) 'Actual observer allocation birth/executable required'
    @{allocationLabel='parent-owner-telemetry';pid=$Observer.Id;created=$created.ToString('o');nativeCreatedTicks=$created.Ticks.ToString();executable=$exe;executableSha256=(Get-FileHash $exe).Hash;prefix=$OutputRoot;capabilities=@('owner','telemetry');sources=$sources;observerScript=$script;scope=$Scope.Clone();notBefore=$NotBefore;fixtureOnly=[bool]$FixtureOnly}
}
function Publish-SPCompletion {
    param([Diagnostics.Process]$Observer,[Diagnostics.Process]$Child,[hashtable]$Allocation,[string]$SourceRoot,[string]$OutputRoot)
    & ${function:Assert-SP} ($Allocation.sources-is[array]-and$Allocation.sources.Count-eq4-and$Allocation.nativeCreatedTicks-is[string]-and$Allocation.created-is[string]-and$Allocation.observerScript-is[hashtable]) 'Complete allocation birth/source bindings required'
    & ${function:Assert-SP} ($Allocation.fixtureOnly-is[bool]) 'Explicit Boolean parent fixture provenance required'
    if(-not$Allocation.fixtureOnly){& ${function:Assert-SP} ($Allocation.observerScript.sha256-ceq'A451B495298D977F0331543F359A606B62ED5B0CEDEE8E93358F0D120DF4A032') 'Fixed native observer provenance required'}
    foreach($b in @($Allocation.sources)+@($Allocation.observerScript)){& ${function:Assert-SP} ($b.sha256-is[string]-and$b.sha256-cmatch'^[A-F0-9]{64}$') 'Missing allocation source hash'}
    & ${function:Assert-SP} ($Observer.Id-eq$Allocation.pid-and$Observer.WaitForExit(0)-and$Observer.ExitCode-is[int]-and$Observer.ExitCode-eq0-and$Observer.StartTime.ToUniversalTime().Ticks-eq[long]$Allocation.nativeCreatedTicks-and-not$Child.HasExited) 'Actual observer exit0 and still-running child required'
    foreach($binding in @($Allocation.sources)+@($Allocation.observerScript)){$actual=& ${function:Get-SPBinding} $binding.path;& ${function:Assert-SP} ($actual.sha256-ceq$binding.sha256-and$actual.bytes-eq$binding.bytes) 'Parent source changed after allocation'}
    & ${function:Assert-SP} ((Get-FileHash $Allocation.executable).Hash-ceq$Allocation.executableSha256-and$Allocation.prefix-ceq$OutputRoot) 'Observer executable/prefix changed'
    $witnessBinding=& ${function:Get-SPBinding} (Join-Path $OutputRoot 'independent-owned-daemon.json')
    $telemetryBinding=& ${function:Get-SPBinding} (Join-Path $OutputRoot 'observer-telemetry.json')
    foreach($b in $witnessBinding,$telemetryBinding){& ${function:Assert-SP} ((Get-Item $b.path).LastWriteTimeUtc-ge[DateTimeOffset]::Parse($Allocation.notBefore).UtcDateTime) 'Stale independent evidence'}
    $witness=Get-Content $witnessBinding.path -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    $telemetry=Get-Content $telemetryBinding.path -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    & ${function:Assert-SP} ($telemetry.complete-is[bool]-and$telemetry.complete-and$telemetry.captureErrors-eq0-and$telemetry.candidateBoundaries-is[array]-and$telemetry.candidateBoundaries.Count-le4-and$telemetry.reasonCounts.Count-eq13-and$telemetry.totalPolls-ge1) 'Complete bounded observer telemetry required'
    $m=Import-Module (Join-Path $SourceRoot 'OwnedJavaBackstop.psm1') -Scope Local -PassThru -Force
    $validator=$m.ExportedCommands['Assert-QualifierOwnerWitness']
    & ${function:Assert-SP} ($validator-is[Management.Automation.FunctionInfo]-and$validator.Module.Path-ceq(Join-Path $SourceRoot 'OwnedJavaBackstop.psm1')) 'Private full witness function binding required'
    $null=& $validator $Allocation.scope $witness @{exitConfirmed=$true;exit=$Observer.ExitCode;jsonPresent=$true} $Allocation.notBefore
    & ${function:Assert-SP} ($witness.pid-ne$Observer.Id-and-not$Child.HasExited) 'Observer PID is not daemon PID; child must still run'
    $path=Join-Path $OutputRoot 'screen-parent-observer.json'
    & ${function:Assert-SP} (-not(Test-Path $path)) 'Fresh parent completion receipt required'
    $record=$Allocation.Clone();$record.schema='h3911-screen-parent-observer-v1';$record.status='OBSERVATION_PROCESS_EXIT_CONFIRMED';$record.gone=$true;$record.exitConfirmed=$true;$record.exit=[int]$Observer.ExitCode;$record.witnessBinding=$witnessBinding;$record.telemetryBinding=$telemetryBinding;$record.publishedUtc=[DateTime]::UtcNow.ToString('o');$record.producerParentPid=$PID;$record.childPid=$Child.Id;$record.childStillRunning=$true;$record.runQualified=$false
    $record|ConvertTo-Json -Depth 12|Set-Content $path
    & ${function:Get-SPBinding} $path
}
function Read-SPCompletion([string]$Path,[string]$ExpectedSha256,[hashtable]$Scope,[string]$NotBefore,[switch]$FixtureOnly){
    $binding=& ${function:Get-SPBinding} $Path
    & ${function:Assert-SP} ($binding.sha256-ceq$ExpectedSha256) 'Parent handoff SHA differs'
    $r=Get-Content $Path -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    & ${function:Assert-SP} ($r.fixtureOnly-is[bool]) 'Explicit Boolean parent fixture provenance required'
    if($FixtureOnly){& ${function:Assert-SP} $r.fixtureOnly 'Explicit fixture reader requires fixture provenance'}
    else{& ${function:Assert-SP} (-not$r.fixtureOnly-and$r.observerScript.sha256-ceq'A451B495298D977F0331543F359A606B62ED5B0CEDEE8E93358F0D120DF4A032') 'Native parent provenance and fixed observer script required'}
    & ${function:Assert-SP} ($r.sources-is[array]-and$r.sources.Count-eq4-and$r.nativeCreatedTicks-is[string]-and$r.observerScript-is[hashtable]) 'Complete bound parent allocation required'
    & ${function:Assert-SP} ($r.schema-ceq'h3911-screen-parent-observer-v1'-and$r.status-ceq'OBSERVATION_PROCESS_EXIT_CONFIRMED'-and$r.gone-is[bool]-and$r.gone-and$r.exitConfirmed-is[bool]-and$r.exitConfirmed-and$r.exit-eq0-and($r.capabilities-join',')-ceq'owner,telemetry'-and[DateTimeOffset]::Parse($r.publishedUtc)-ge[DateTimeOffset]::Parse($NotBefore)) 'Parent handoff shape/freshness differs'
    foreach($key in 'Jdk','Home','Registry','Temp'){& ${function:Assert-SP} ([string]::Equals($r.scope[$key],$Scope[$key],[StringComparison]::OrdinalIgnoreCase)) 'Parent handoff scope differs'}
    foreach($b in @($r.sources)+@($r.observerScript,$r.witnessBinding,$r.telemetryBinding)){$a=& ${function:Get-SPBinding} $b.path;& ${function:Assert-SP} ($a.sha256-ceq$b.sha256-and$a.bytes-eq$b.bytes) 'Parent source/witness/telemetry seal differs'}
    $r
}
function Wait-SPObserverCompletion {
    param([Diagnostics.Process]$Observer,[Diagnostics.Process]$Child,[hashtable]$Allocation,[string]$SourceRoot,[string]$OutputRoot,[Diagnostics.Stopwatch]$Clock,[int]$LimitMilliseconds)
    $remaining=$LimitMilliseconds-[int]$Clock.ElapsedMilliseconds
    & ${function:Assert-SP} ($remaining-gt0) 'Whole parent deadline expired'
    $observerTask=$Observer.WaitForExitAsync();$childTask=$Child.WaitForExitAsync()
    $first=[Threading.Tasks.Task]::WhenAny([Threading.Tasks.Task[]]@($observerTask,$childTask))
    & ${function:Assert-SP} ($first.Wait($remaining)-and$observerTask.IsCompleted-and-not$Child.HasExited) 'Observer must complete before child within whole deadline'
    $binding=& ${function:Publish-SPCompletion} $Observer $Child $Allocation $SourceRoot $OutputRoot
    & ${function:Assert-SP} ($Clock.ElapsedMilliseconds-lt$LimitMilliseconds) 'Early parent handoff exceeded whole deadline'
    $binding
}
Export-ModuleMember -Function New-SPAllocation,Publish-SPCompletion,Read-SPCompletion,Wait-SPObserverCompletion
