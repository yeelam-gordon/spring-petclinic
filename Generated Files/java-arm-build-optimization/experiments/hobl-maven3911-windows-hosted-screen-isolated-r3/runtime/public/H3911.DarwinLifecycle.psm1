function Assert-DarwinLife($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function Assert-LifePath($Value){
    Assert-DarwinLife ($Value-is[string]-and$Value.StartsWith('/',[StringComparison]::Ordinal)-and$Value-notmatch'[\x00-\x1f\\]|//|(^|/)\.\.?(/|$)'-and$Value-notmatch'/$') 'Canonical Darwin path required'
}
function Assert-LifeIdentity($Value){
    Assert-DarwinLife ($Value-is[hashtable]-and($Value.pid-is[int]-or$Value.pid-is[long])-and$Value.pid-gt0-and$Value.pid-le[int]::MaxValue) 'Explicit positive PID identity required'
    $stamp=[DateTimeOffset]::MinValue
    Assert-DarwinLife ($Value.created-is[string]-and$Value.created-cmatch'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$'-and[DateTimeOffset]::TryParse($Value.created,[ref]$stamp)) 'Explicit ISO creation required'
    Assert-LifePath $Value.executable
}
function Assert-LifeContext($Context,$Expected){
    foreach($p in $Context.Jdk,$Context.Home,$Context.Registry,$Context.Temp){Assert-LifePath $p}
    Assert-LifeIdentity $Expected
    Assert-DarwinLife ($Expected.daemonId-is[string]-and$Expected.daemonId-cmatch'^[a-f0-9]{8}$') 'Explicit daemon id required'
    foreach($p in @(@($Expected.executable,($Context.Jdk+'/bin/java')),@($Expected.home,$Context.Home),@($Expected.registryFile,($Context.Registry+'/registry.bin')))){
        Assert-DarwinLife ([string]::Equals($p[0],$p[1],[StringComparison]::Ordinal)) 'Expected effective owner scope differs'
    }
    Assert-LifePath $Expected.jniPath
    Assert-DarwinLife ($Expected.jniPath.StartsWith($Context.Temp+'/',[StringComparison]::Ordinal)) 'Expected effective-owner temp boundary differs'
    Assert-DarwinLife ($Context.ContainsKey('KnownOwnedIdentities')-and$Context.KnownOwnedIdentities-is[array]) 'Explicit known-owned identity array required'
    $seen=[Collections.Generic.HashSet[int]]::new()
    foreach($identity in @($Expected)+@($Context.KnownOwnedIdentities)){Assert-LifeIdentity $identity;Assert-DarwinLife ($seen.Add([int]$identity.pid)) 'Duplicate tracked PID'}
}
function Assert-LifeRegistry($Registry,[int]$Count){
    Assert-DarwinLife ($Registry-is[hashtable]-and$Registry.ContainsKey('schema')-and$Registry.schema-is[string]-and$Registry.schema-ceq'mvnd103-registry'-and$Registry.ContainsKey('count')-and$Registry.count-is[int]-and$Registry.count-eq$Count-and$Registry.records-is[array]-and$Registry.records.Count-eq$Count) 'Complete parsed103 registry witness required'
}
function Test-LifeCreationInstant([string]$A,[string]$B){
    [DateTimeOffset]::Parse($A,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime.Ticks-eq[DateTimeOffset]::Parse($B,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime.Ticks
}
function Test-LifeSame($A,$B){
    ($A.pid-eq$B.pid)-and(Test-LifeCreationInstant $A.created $B.created)-and[string]::Equals($A.executable,$B.executable,[StringComparison]::Ordinal)
}
function New-H3911DarwinStopPlanFacts {
    param([hashtable]$Context,[hashtable]$Expected,[hashtable]$Registry,[hashtable]$Current,[switch]$Emergency)
    Assert-LifeContext $Context $Expected;Assert-LifeRegistry $Registry 1;Assert-LifeIdentity $Current
    Assert-DarwinLife (Test-LifeSame $Expected $Current) 'PID reuse/foreign identity: no stop'
    $row=$Registry.records[0];Assert-LifeIdentity @{pid=$row.pid;created=$Current.created;executable=$Current.executable}
    foreach($p in @(@($row.id,$Expected.daemonId),@($row.javaHome,$Context.Jdk),@($row.home,$Context.Home))){Assert-DarwinLife ([string]::Equals($p[0],$p[1],[StringComparison]::Ordinal)) 'Registry owner differs'}
    Assert-DarwinLife ($row.pid-eq$Expected.pid) 'Foreign registry PID'
    @{exe=($Context.Home+'/bin/mvnd');tokens=@("-Dmvnd.daemonStorage=$($Context.Registry)","-Dmvnd.registry=$($Expected.registryFile)","-Djava.home=$($Context.Jdk)",'--stop');workingDirectory=$Context.Temp;expectedPid=$Expected.pid;expectedCreated=$Expected.created;emergency=[bool]$Emergency;sourceIndependent=$true;runtimeAuthorized=$false;evidenceKind='validated-stop-plan-model';cliSemantics='1.0.3 destroyForcibly then registry removal; not graceful shutdown; later absence proof mandatory'}
}
function ConvertTo-H3911DarwinScopedCensus {
    param([hashtable]$Context,[hashtable]$Expected,[hashtable]$Observation)
    Assert-LifeContext $Context $Expected
    Assert-DarwinLife ($Observation-is[hashtable]-and$Observation.complete-is[bool]-and$Observation.complete-and$Observation.ContainsKey('errors')-and$Observation.errors-is[array]-and$Observation.errors.Count-eq0-and$Observation.ContainsKey('processes')-and$Observation.processes-is[array]) 'Explicit complete enumeration/error/process arrays required'
    $java=$Context.Jdk+'/bin/java';$sameJdk=@();$knownLive=@();$tracked=@($Expected)+@($Context.KnownOwnedIdentities);$seen=[Collections.Generic.HashSet[int]]::new()
    foreach($identity in $Observation.processes){
        Assert-LifeIdentity $identity;Assert-DarwinLife ($seen.Add([int]$identity.pid)) 'Duplicate enumerated PID'
        if([string]::Equals($identity.executable,$java,[StringComparison]::Ordinal)){$sameJdk+=,$identity}
        foreach($known in $tracked){if($known.pid-eq$identity.pid-and(Test-LifeCreationInstant $known.created $identity.created)){$knownLive+=,$identity}}
    }
    $expectedLive=@($knownLive|Where-Object pid -eq $Expected.pid)
    @{schema='darwin-scoped-java-census-v1';complete=$true;errors=@();jdkExecutable=$java;sameJdkJava=$sameJdk;knownLive=$knownLive;expectedIdentityGone=($expectedLive.Count-eq0);tracked=$tracked;evidenceKind='validated-census-model';scope='all admitted-JDK Java plus explicitly tracked PID/create identities; not universal historical descendants'}
}
function Confirm-H3911DarwinAbsenceFacts {
    param([hashtable]$Context,[hashtable]$Expected,[hashtable]$Registry,[hashtable]$Census,[object]$StopExit,[switch]$Forced,[switch]$Emergency)
    Assert-LifeContext $Context $Expected;Assert-LifeRegistry $Registry 0
    Assert-DarwinLife ($PSBoundParameters.ContainsKey('StopExit')-and($StopExit-is[int]-or$StopExit-is[long])-and$StopExit-ge[int]::MinValue-and$StopExit-le[int]::MaxValue) 'Explicit observed integer CLI StopExit required'
    Assert-DarwinLife ($Census-is[hashtable]-and$Census.schema-is[string]-and$Census.schema-ceq'darwin-scoped-java-census-v1'-and$Census.complete-is[bool]-and$Census.complete-and$Census.errors-is[array]-and$Census.errors.Count-eq0-and$Census.sameJdkJava-is[array]-and$Census.knownLive-is[array]-and$Census.tracked-is[array]-and$Census.expectedIdentityGone-is[bool]) 'Complete typed scoped census required'
    Assert-DarwinLife ([string]::Equals($Census.jdkExecutable,($Context.Jdk+'/bin/java'),[StringComparison]::Ordinal)-and$Census.tracked.Count-eq1+$Context.KnownOwnedIdentities.Count) 'Census scope/tracked witnesses differ'
    $wanted=@($Expected)+@($Context.KnownOwnedIdentities)
    for($i=0;$i-lt$wanted.Count;$i++){Assert-LifeIdentity $Census.tracked[$i];Assert-DarwinLife (Test-LifeSame $wanted[$i] $Census.tracked[$i]) 'Census tracked identity differs'}
    Assert-DarwinLife ($Census.expectedIdentityGone-and$Census.sameJdkJava.Count-eq0-and$Census.knownLive.Count-eq0) 'Possible Java/known descendant survivor; empty registry/root exit is insufficient'
    @{status=$(if($StopExit-eq0-and-not$Forced-and-not$Emergency){'NORMAL_CLI_ROUTE_SCOPED_ABSENCE_CONFIRMED'}else{'FAIL_NONZERO_FORCED_OR_EMERGENCY'});runtimeAuthorized=$false;evidenceKind='validated-absence-model';scope=$Census.scope;universalHistoricalDescendantsAbsent=$false}
}
function Get-LifeOsProcesses {
    $rows=@()
    try{$all=[Diagnostics.Process]::GetProcesses()}catch{throw 'HOLD: full native process enumeration failed'}
    foreach($p in $all){
        try{$rows+=,@{pid=$p.Id;created=$p.StartTime.ToUniversalTime().ToString('o');executable=$p.MainModule.FileName};Assert-LifeIdentity $rows[-1]}
        catch{throw 'HOLD: unreadable/exited/ambiguous native process identity during full census'}
        finally{$p.Dispose()}
    }
    @{complete=$true;errors=@();processes=$rows}
}
function Get-LifeCurrent([int]$ProcessId){
    try{$p=[Diagnostics.Process]::GetProcessById($ProcessId)}catch{throw 'HOLD: native identity missing/unavailable before stop admission'}
    try{$r=@{pid=$p.Id;created=$p.StartTime.ToUniversalTime().ToString('o');executable=$p.MainModule.FileName};Assert-LifeIdentity $r;$r}finally{$p.Dispose()}
}
function Assert-LifeNativePaths($Context){
    foreach($path in $Context.Jdk,$Context.Home,$Context.Registry,$Context.Temp){
        $resolved=Resolve-Path -LiteralPath $path -ErrorAction Stop;$item=Get-Item -LiteralPath $resolved.ProviderPath -Force
        Assert-DarwinLife ($resolved.Provider.Name-ceq'FileSystem'-and$item-is[IO.DirectoryInfo]-and[string]::Equals($resolved.ProviderPath,$path,[StringComparison]::Ordinal)) 'Canonical physical private directory required'
        $parent=$item;while($parent){Assert-DarwinLife (-not((Get-Item -LiteralPath $parent.FullName -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked private lifecycle ancestry';$parent=$parent.Parent}
    }
}
function Get-LifeRegistryCommand {
    $path=Join-Path $PSScriptRoot 'H3911.DarwinOwner.psm1'
    Assert-DarwinLife ((Get-FileHash $path).Hash-ceq'E9A8FD932AC839119FDD0B810533E8FB69BA314CB038E7345C484A7988A36E1E') 'Pinned Registry103 dependency differs'
    $m=Import-Module $path -Scope Local -PassThru;$command=$m.ExportedCommands['Read-H3911Registry103']
    Assert-DarwinLife ($command-is[Management.Automation.FunctionInfo]-and[string]::Equals($command.Module.Path,$path,[StringComparison]::Ordinal)) 'Private registry command origin differs';$command
}
function Read-LifeRegistry($Context){
    $path=$Context.Registry+'/registry.bin';$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    Assert-DarwinLife ($item-is[IO.FileInfo]-and-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not$item.LinkType) 'Regular private registry file required'
    $parent=$item.Directory;while($parent){Assert-DarwinLife (-not((Get-Item -LiteralPath $parent.FullName -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked private registry ancestry';$parent=$parent.Parent}
    [byte[]]$bytes=[IO.File]::ReadAllBytes($path);$command=Get-LifeRegistryCommand
    @{registry=(& $command $bytes);digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))}
}
function Read-H3911DarwinScopedCensus {
    param([hashtable]$Context,[hashtable]$Expected,[switch]$RuntimeApproved)
    if(-not$IsMacOS-or-not$RuntimeApproved){throw 'HOLD: Native Mac plus RuntimeApproved required'}
    Assert-LifeContext $Context $Expected
    Assert-LifeNativePaths $Context
    Assert-DarwinLife ($Expected.evidenceKind-is[string]-and$Expected.evidenceKind-ceq'native-mac-effective-owner') 'Prior native effective-owner evidence required'
    $osReader=$ExecutionContext.SessionState.InvokeCommand.GetCommand('Get-LifeOsProcesses',[Management.Automation.CommandTypes]::Function)
    Assert-DarwinLife ([string]::Equals($osReader.Module.Path,$ExecutionContext.SessionState.Module.Path,[StringComparison]::Ordinal)) 'Native OS census command origin differs'
    $result=& ($ExecutionContext.SessionState.Module.ExportedCommands['ConvertTo-H3911DarwinScopedCensus']) $Context $Expected (& $osReader)
    $result.evidenceKind='native-mac-scoped-census';$result
}
function New-H3911DarwinPrivateStopPlan {
    param([hashtable]$Context,[hashtable]$Expected,[switch]$RuntimeApproved,[switch]$Emergency)
    if(-not$IsMacOS-or-not$RuntimeApproved){throw 'HOLD: Native Mac plus RuntimeApproved required'}
    Assert-LifeContext $Context $Expected
    Assert-LifeNativePaths $Context
    Assert-DarwinLife ($Expected.evidenceKind-is[string]-and$Expected.evidenceKind-ceq'native-mac-effective-owner') 'Prior native effective-owner evidence required'
    $registryReader=$ExecutionContext.SessionState.InvokeCommand.GetCommand('Read-LifeRegistry',[Management.Automation.CommandTypes]::Function)
    $osReader=$ExecutionContext.SessionState.InvokeCommand.GetCommand('Get-LifeCurrent',[Management.Automation.CommandTypes]::Function)
    foreach($command in $registryReader,$osReader){Assert-DarwinLife ([string]::Equals($command.Module.Path,$ExecutionContext.SessionState.Module.Path,[StringComparison]::Ordinal)) 'Native lifecycle command origin differs'}
    $snapshot=& $registryReader $Context;$current=& $osReader ([int]$Expected.pid)
    $plan=& ($ExecutionContext.SessionState.Module.ExportedCommands['New-H3911DarwinStopPlanFacts']) $Context $Expected $snapshot.registry $current -Emergency:$Emergency
    Assert-DarwinLife ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($Context.Registry+'/registry.bin')))-ceq$snapshot.digest) 'Registry changed during stop admission'
    $plan.evidenceKind='native-private-cli-stop-plan';$plan.requiresImmediateRevalidationBeforeInvocation=$true;$plan
}
function Confirm-H3911DarwinCliStop {
    param([hashtable]$Context,[hashtable]$Expected,[object]$StopExit,[switch]$RuntimeApproved,[switch]$Forced,[switch]$Emergency)
    Assert-DarwinLife ($PSBoundParameters.ContainsKey('StopExit')-and($StopExit-is[int]-or$StopExit-is[long])) 'Explicit observed CLI StopExit required'
    if(-not$IsMacOS-or-not$RuntimeApproved){throw 'HOLD: Native Mac plus RuntimeApproved required'}
    Assert-LifeContext $Context $Expected;Assert-LifeNativePaths $Context
    $registryReader=$ExecutionContext.SessionState.InvokeCommand.GetCommand('Read-LifeRegistry',[Management.Automation.CommandTypes]::Function)
    Assert-DarwinLife ([string]::Equals($registryReader.Module.Path,$ExecutionContext.SessionState.Module.Path,[StringComparison]::Ordinal)) 'Native registry command origin differs'
    $snapshot=& $registryReader $Context
    $census=& ($ExecutionContext.SessionState.Module.ExportedCommands['Read-H3911DarwinScopedCensus']) $Context $Expected -RuntimeApproved
    $result=& ($ExecutionContext.SessionState.Module.ExportedCommands['Confirm-H3911DarwinAbsenceFacts']) $Context $Expected $snapshot.registry $census $StopExit -Forced:$Forced -Emergency:$Emergency
    Assert-DarwinLife ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($Context.Registry+'/registry.bin')))-ceq$snapshot.digest) 'Registry changed during absence census'
    $result.evidenceKind='native-scoped-absence-result';$result
}
Export-ModuleMember -Function New-H3911DarwinStopPlanFacts,ConvertTo-H3911DarwinScopedCensus,Confirm-H3911DarwinAbsenceFacts,Read-H3911DarwinScopedCensus,New-H3911DarwinPrivateStopPlan,Confirm-H3911DarwinCliStop
