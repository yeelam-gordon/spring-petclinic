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
function ConvertTo-LifeStartTimeTicks([long]$Seconds,[long]$Microseconds){
    Assert-DarwinLife ([Environment]::Version-eq[version]'10.0.15') 'Unreviewed Darwin StartTime projection runtime'
    # .NET v10.0.15 Process.OSX.cs StartTimeCore uses this double-valued projection.
    [DateTime]::UnixEpoch.Add([TimeSpan]::FromSeconds([double]$Seconds+([double]$Microseconds/1000000.0))).Ticks
}
function Assert-LifeCredentialRecordIdentity($Facts,$Identity){
    Assert-DarwinLife ($Identity-is[hashtable]-and($Identity.pid-is[int]-or$Identity.pid-is[long])-and$Identity.pid-gt0-and$Identity.pid-le[int]::MaxValue-and$Identity.created-is[string]-and$Identity.created-cmatch'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$') 'Typed credential PID/birth identity required'
    Assert-DarwinLife ($Facts-is[hashtable]) 'Kernel credential facts required'
    $null=& ${function:ConvertFrom-LifeBsdRecord} @([int]136,[int]0,$Facts.pid,$Facts.parentPid,$Facts.realUid,$Facts.effectiveUid,$Facts.savedUid,$Facts.birthSeconds,$Facts.birthMicroseconds) $Identity.pid
    $projected=& ${function:ConvertTo-LifeStartTimeTicks} $Facts.birthSeconds $Facts.birthMicroseconds
    $nativeMicroseconds=[long]$Facts.birthSeconds*1000000L+[long]$Facts.birthMicroseconds
    $previousMicroseconds=0L;$previousSeconds=[Math]::DivRem(($nativeMicroseconds-1L),1000000L,[ref]$previousMicroseconds)
    $nextMicroseconds=0L;$nextSeconds=[Math]::DivRem(($nativeMicroseconds+1L),1000000L,[ref]$nextMicroseconds)
    Assert-DarwinLife (($projected-gt(& ${function:ConvertTo-LifeStartTimeTicks} $previousSeconds $previousMicroseconds))-and($projected-lt(& ${function:ConvertTo-LifeStartTimeTicks} $nextSeconds $nextMicroseconds))) 'Kernel birth projection cannot uniquely bind microseconds'
    Assert-DarwinLife ([DateTimeOffset]::Parse($Identity.created,[Globalization.CultureInfo]::InvariantCulture).UtcTicks-eq$projected) 'Kernel PID/UID/birth binding mismatch'
}
function Assert-LifeCredentialIdentity($Facts,$Identity,$Uid){
    Assert-LifeCredentialRecordIdentity $Facts $Identity
    $null=& ${function:ConvertFrom-LifeBsdFacts} @([int]136,[int]0,$Facts.pid,$Facts.parentPid,$Facts.realUid,$Facts.effectiveUid,$Facts.savedUid,$Facts.birthSeconds,$Facts.birthMicroseconds) $Identity.pid $Uid
}
function New-LifePidSet($Values){
    Assert-DarwinLife ($Values-is[array]-and$Values.Count-le4096) 'Bounded explicit PID witness array required'
    $set=[Collections.Generic.HashSet[int]]::new()
    foreach($value in $Values){Assert-DarwinLife (($value-is[int]-or$value-is[long])-and$value-gt0-and$value-le[int]::MaxValue-and$set.Add([int]$value)) 'Typed unique positive PID witnesses required'}
    ,$set
}
function Test-LifeProtectedPathPid($Context,$Expected,$Self,$Identity){
    Assert-DarwinLife ($Context.KnownOwnedIdentities-is[array]-and$Self-is[hashtable]-and$Expected-is[hashtable]-and$Identity-is[hashtable]) 'Explicit path/PID scope context required'
    $pids=@($Self.pid,$Expected.pid)+@($Context.KnownOwnedIdentities|ForEach-Object pid)
    $set=New-LifePidSet $pids
    Assert-DarwinLife (($Identity.pid-is[int]-or$Identity.pid-is[long])-and$Identity.pid-gt0-and$Identity.pid-le[int]::MaxValue) 'Typed scope PID required'
    if($set.Contains([int]$Identity.pid)){return $true}
    Assert-LifePath $Identity.executable;Assert-LifePath $Context.Jdk
    [string]::Equals($Identity.executable,($Context.Jdk+'/bin/java'),[StringComparison]::Ordinal)
}
function Assert-LifePathPidRow($Context,$Expected,$Self,$Row,$Uid){
    $protected=Test-LifeProtectedPathPid $Context $Expected $Self $Row
    Assert-DarwinLife ($Row.protectedPathPid-is[bool]-and$Row.protectedPathPid-eq$protected) 'Recomputed path/PID classification differs'
    Assert-LifeIdentity $Row
    Assert-LifeCredentialRecordIdentity $Row.credential $Row
    Assert-DarwinLife (($Uid-is[int]-or$Uid-is[long])-and$Uid-gt0-and$Uid-le[uint32]::MaxValue-and$Row.credential.effectiveUid-eq$Uid) 'Current effective UID differs from launch actor'
    if($protected){
        $null=& ${function:ConvertFrom-LifeBsdFacts} @([int]136,[int]0,$Row.credential.pid,$Row.credential.parentPid,$Row.credential.realUid,$Row.credential.effectiveUid,$Row.credential.savedUid,$Row.credential.birthSeconds,$Row.credential.birthMicroseconds) $Row.pid $Uid @{observed=$Row;self=$Self;expected=$Expected;known=$Context.KnownOwnedIdentities;jdkExecutable=($Context.Jdk+'/bin/java')}
        foreach($snapshot in @($Self,$Expected)+@($Context.KnownOwnedIdentities)){if($snapshot.pid-eq$Row.pid){Assert-DarwinLife (Test-LifeSame $snapshot $Row) 'Protected PID lifetime/executable changed'}}
    }
    $protected
}
function Get-LifeUidCommands {
    $map=@{}
    foreach($name in 'Read-LifeSelfCredential','Read-LifeOwnerCredential','Read-LifeCensusCredential','Read-LifeOwnUidPids','Get-LifeCurrent','Read-LifePresence','Read-LifeRegistry'){
        $command=$ExecutionContext.SessionState.InvokeCommand.GetCommand($name,[Management.Automation.CommandTypes]::Function)
        Assert-DarwinLife ($command-is[Management.Automation.FunctionInfo]-and$command.Module.Path-ceq$ExecutionContext.SessionState.Module.Path) 'Private UID command origin differs';$map[$name]=$command
    };$map
}
function Read-LifeUidSelf($Commands){
    $credential=& $Commands['Read-LifeSelfCredential'] -RuntimeApproved
    $identity=& $Commands['Get-LifeCurrent'] ([int]$credential.pid)
    & ${function:Assert-LifeCredentialIdentity} $credential $identity $credential.effectiveUid
    @{credential=$credential;identity=$identity;uid=$credential.effectiveUid}
}
function Assert-LifeUidCensus($Context,$Expected,$Census){
    Assert-DarwinLife ($Context.KnownOwnedIdentities-is[array]) 'Explicit tracked set required for UID proof'
    Assert-DarwinLife ($Census-is[hashtable]-and$Census.schema-ceq'darwin-launch-uid-java-census-v2'-and$Census.scope-ceq'launch-effective-UID admitted-JDK Java plus explicitly tracked identities'-and$Census.complete-is[bool]-and$Census.complete-and$Census.errors-is[array]-and$Census.errors.Count-eq0-and$Census.expectedIdentityGone-is[bool]) 'Versioned UID scoped census required; no v1 authority'
    $proof=$Census.uidProof
    Assert-DarwinLife ($proof.universalHistory-is[bool]-and-not$proof.universalHistory) 'No universal-history authority'
    Assert-DarwinLife ($proof-is[hashtable]-and$proof.schema-ceq'darwin-launch-uid-proof-v2'-and($proof.filter-is[int]-or$proof.filter-is[long])-and$proof.filter-eq5-and$proof.observationBasis-ceq'EUID_SELECTION_TRACKED_UNION_PATH_PID_SCOPE_V1'-and$proof.atomicEndpoint-is[bool]-and-not$proof.atomicEndpoint-and$proof.newbornCoverage-is[bool]-and-not$proof.newbornCoverage) 'Typed path/PID UID observation basis required'
    & ${function:Assert-LifeCredentialIdentity} $proof.selfCredential $proof.selfIdentity $proof.admittedUid
    Assert-LifeIdentity $proof.selfIdentity
    foreach($field in 'selectedPidCount','knownPidCount','unionPidCount','validatedPidCount','outsideProtectedPathPidCount','missingAtRecheckCount','presenceRecheckAttempts'){Assert-DarwinLife (($proof[$field]-is[int]-or$proof[$field]-is[long])-and$proof[$field]-ge0-and$proof[$field]-le4096) 'Bounded UID accounting required'}
    Assert-DarwinLife ($proof.knownPidCount-eq(1+$Context.KnownOwnedIdentities.Count)-and$proof.unionPidCount-ge$proof.selectedPidCount-and$proof.unionPidCount-ge$proof.knownPidCount-and$proof.unionPidCount-le($proof.selectedPidCount+$proof.knownPidCount)-and$proof.validatedPidCount+$proof.missingAtRecheckCount-eq$proof.unionPidCount-and$proof.presenceRecheckAttempts-ge$proof.missingAtRecheckCount-and$proof.presenceRecheckAttempts-le$proof.unionPidCount) 'UID union/validation/ESRCH accounting differs'
    $selected=New-LifePidSet $proof.selectedPids;$missing=New-LifePidSet $proof.missingAtRecheckPids;$outside=New-LifePidSet $proof.outsideProtectedPathPidPids
    $known=New-LifePidSet @(@($Expected.pid)+@($Context.KnownOwnedIdentities|ForEach-Object pid))
    $reserved=New-LifePidSet @(@($proof.selfIdentity.pid)+@($known))
    $union=[Collections.Generic.HashSet[int]]::new($selected);foreach($id in $known){$null=$union.Add($id)}
    Assert-DarwinLife ($selected.Count-eq$proof.selectedPidCount-and$known.Count-eq$proof.knownPidCount-and$union.Count-eq$proof.unionPidCount-and$missing.Count-eq$proof.missingAtRecheckCount-and$outside.Count-eq$proof.outsideProtectedPathPidCount-and$selected.Contains([int]$proof.selfIdentity.pid)-and-not$missing.Contains([int]$proof.selfIdentity.pid)) 'UID PID witness accounting differs'
    foreach($id in $missing){Assert-DarwinLife ($union.Contains($id)) 'Missing PID outside observed union'}
    foreach($id in $outside){Assert-DarwinLife ($union.Contains($id)-and-not$missing.Contains($id)-and-not$reserved.Contains($id)) 'Outside path/PID witness overlaps protected or missing PID'}
    Assert-DarwinLife ($Census.sameJdkJava-is[array]-and$Census.knownLive-is[array]-and$Census.tracked-is[array]-and$Census.tracked.Count-eq$known.Count-and[string]::Equals($Census.jdkExecutable,$Expected.executable,[StringComparison]::Ordinal)) 'Typed path/PID census subsets required'
    $protected=@{};$jdkIds=[Collections.Generic.HashSet[int]]::new();$knownIds=[Collections.Generic.HashSet[int]]::new()
    $selfRow=@{pid=$proof.selfIdentity.pid;created=$proof.selfIdentity.created;executable=$proof.selfIdentity.executable;credential=$proof.selfCredential;protectedPathPid=$true}
    foreach($row in @($selfRow)+@($Census.sameJdkJava)+@($Census.knownLive)){
        Assert-DarwinLife ($row-is[hashtable]-and$row.protectedPathPid-is[bool]-and$row.protectedPathPid-and(Test-LifeProtectedPathPid $Context $Expected $proof.selfIdentity $row)) 'Protected path/PID summary classification differs'
        Assert-LifeCredentialIdentity $row.credential $row $proof.admittedUid
        foreach($snapshot in @($proof.selfIdentity,$Expected)+@($Context.KnownOwnedIdentities)){if($snapshot.pid-eq$row.pid){Assert-DarwinLife (Test-LifeSame $snapshot $row) 'Protected PID lifetime/executable changed'}}
        Assert-DarwinLife ($union.Contains([int]$row.pid)-and-not$missing.Contains([int]$row.pid)-and-not$outside.Contains([int]$row.pid)) 'Protected PID outside live union partition'
        if($protected.ContainsKey([int]$row.pid)){
            Assert-DarwinLife (Test-LifeSame $protected[[int]$row.pid] $row) 'Protected summary identity differs'
            foreach($field in 'pid','parentPid','realUid','effectiveUid','savedUid','birthSeconds','birthMicroseconds'){Assert-DarwinLife ($protected[[int]$row.pid].credential[$field]-eq$row.credential[$field]) 'Protected summary credential differs'}
        }else{$protected[[int]$row.pid]=$row}
    }
    foreach($row in $Census.sameJdkJava){Assert-DarwinLife ([string]::Equals($row.executable,$Census.jdkExecutable,[StringComparison]::Ordinal)-and$jdkIds.Add([int]$row.pid)) 'Exact unique admitted-JDK path subset required'}
    foreach($row in $Census.knownLive){Assert-DarwinLife ($known.Contains([int]$row.pid)-and$knownIds.Add([int]$row.pid)) 'Exact unique tracked PID subset required'}
    foreach($row in $protected.Values){Assert-DarwinLife ((-not$known.Contains([int]$row.pid)-or$knownIds.Contains([int]$row.pid))-and(-not[string]::Equals($row.executable,$Census.jdkExecutable,[StringComparison]::Ordinal)-or$jdkIds.Contains([int]$row.pid))) 'Protected subset row omitted'}
    foreach($id in $known){Assert-DarwinLife ($protected.ContainsKey($id)-or$missing.Contains($id)) 'Tracked PID missing without ESRCH witness'}
    Assert-DarwinLife ($protected.Count+$outside.Count-eq$proof.validatedPidCount-and$protected.Count+$outside.Count+$missing.Count-eq$union.Count-and$Census.expectedIdentityGone-eq(-not$protected.ContainsKey([int]$Expected.pid))) 'Complete protected/outside/missing partition required'
    if(-not$Census.expectedIdentityGone){
        & ${function:Assert-LifeCredentialIdentity} $proof.ownerCredential $Expected $proof.admittedUid
        foreach($field in 'pid','parentPid','realUid','effectiveUid','savedUid','birthSeconds','birthMicroseconds'){Assert-DarwinLife ($proof.ownerCredential[$field]-eq$protected[[int]$Expected.pid].credential[$field]) 'Owner credential witness differs'}
    }else{Assert-DarwinLife ($null-eq$proof.ownerCredential-and$missing.Contains([int]$Expected.pid)) 'Gone owner requires explicit failed-row ESRCH accounting, not invented credentials'}
}
function Assert-LifeReturnedUidProof($Context,$Expected,$Proof,[bool]$ExpectedGone){
    Assert-DarwinLife ($Proof-is[hashtable]) 'Returned UID proof required'
    $live=@()
    if(-not$ExpectedGone){$row=$Expected.Clone();$row.credential=$Proof.ownerCredential;$row.protectedPathPid=$true;$live=@($row)}
    $census=@{schema='darwin-launch-uid-java-census-v2';scope='launch-effective-UID admitted-JDK Java plus explicitly tracked identities';complete=$true;errors=@();expectedIdentityGone=$ExpectedGone;uidProof=$Proof;jdkExecutable=$Expected.executable;tracked=@($Expected)+@($Context.KnownOwnedIdentities);sameJdkJava=$live;knownLive=$live}
    Assert-LifeUidCensus $Context $Expected $census
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
    $uid=$Observation.schema-ceq'darwin-launch-uid-observation-v2';$outside=[Collections.Generic.HashSet[int]]::new()
    if($Observation.ContainsKey('schema')){Assert-DarwinLife $uid 'Unknown census observation contract'}
    if($uid){Assert-DarwinLife ($Observation.uidProof-is[hashtable]-and$Observation.uidProof.observationBasis-ceq'EUID_SELECTION_TRACKED_UNION_PATH_PID_SCOPE_V1'-and$Observation.processes.Count-le4096) 'Path/PID observation contract required'}
    $java=$Context.Jdk+'/bin/java';$sameJdk=@();$knownLive=@();$tracked=@($Expected)+@($Context.KnownOwnedIdentities);$seen=[Collections.Generic.HashSet[int]]::new()
    foreach($identity in $Observation.processes){
        if($uid){$protected=Assert-LifePathPidRow $Context $Expected $Observation.uidProof.selfIdentity $identity $Observation.uidProof.admittedUid;if(-not$protected){$null=$outside.Add([int]$identity.pid)}}else{Assert-LifeIdentity $identity}
        Assert-DarwinLife ($seen.Add([int]$identity.pid)) 'Duplicate enumerated PID'
        if([string]::Equals($identity.executable,$java,[StringComparison]::Ordinal)){$sameJdk+=,$identity}
        foreach($known in $tracked){if($known.pid-eq$identity.pid-and(Test-LifeCreationInstant $known.created $identity.created)){$knownLive+=,$identity}}
    }
    $expectedLive=@($knownLive|Where-Object pid -eq $Expected.pid)
    $result=@{schema='darwin-scoped-java-census-v1';complete=$true;errors=@();jdkExecutable=$java;sameJdkJava=$sameJdk;knownLive=$knownLive;expectedIdentityGone=($expectedLive.Count-eq0);tracked=$tracked;evidenceKind='validated-census-model';scope='all admitted-JDK Java plus explicitly tracked PID/create identities; not universal historical descendants'}
    if($uid){
        Assert-DarwinLife ($Observation.processes.Count-eq$Observation.uidProof.validatedPidCount) 'Validated row accounting differs'
        $outsideWitness=New-LifePidSet $Observation.uidProof.outsideProtectedPathPidPids
        Assert-DarwinLife ($outside.Count-eq$Observation.uidProof.outsideProtectedPathPidCount-and$outside.SetEquals($outsideWitness)) 'Recomputed outside path/PID accounting differs'
        $result.schema='darwin-launch-uid-java-census-v2';$result.scope='launch-effective-UID admitted-JDK Java plus explicitly tracked identities';$result.uidProof=$Observation.uidProof;$result.evidenceKind='validated-uid-census-model'
        & ${function:Assert-LifeUidCensus} $Context $Expected $result
    };$result
}
function Confirm-H3911DarwinAbsenceFacts {
    param([hashtable]$Context,[hashtable]$Expected,[hashtable]$Registry,[hashtable]$Census,[object]$StopExit,[switch]$Forced,[switch]$Emergency)
    Assert-LifeContext $Context $Expected;Assert-LifeRegistry $Registry 0
    Assert-DarwinLife ($PSBoundParameters.ContainsKey('StopExit')-and($StopExit-is[int]-or$StopExit-is[long])-and$StopExit-ge[int]::MinValue-and$StopExit-le[int]::MaxValue) 'Explicit observed integer CLI StopExit required'
    Assert-DarwinLife ($Census-is[hashtable]-and$Census.schema-is[string]-and$Census.schema-cin@('darwin-scoped-java-census-v1','darwin-launch-uid-java-census-v2')-and$Census.complete-is[bool]-and$Census.complete-and$Census.errors-is[array]-and$Census.errors.Count-eq0-and$Census.sameJdkJava-is[array]-and$Census.knownLive-is[array]-and$Census.tracked-is[array]-and$Census.expectedIdentityGone-is[bool]) 'Complete typed scoped census required'
    if($Census.schema-ceq'darwin-launch-uid-java-census-v2'){& ${function:Assert-LifeUidCensus} $Context $Expected $Census}
    Assert-DarwinLife ([string]::Equals($Census.jdkExecutable,($Context.Jdk+'/bin/java'),[StringComparison]::Ordinal)-and$Census.tracked.Count-eq1+$Context.KnownOwnedIdentities.Count) 'Census scope/tracked witnesses differ'
    $wanted=@($Expected)+@($Context.KnownOwnedIdentities)
    for($i=0;$i-lt$wanted.Count;$i++){Assert-LifeIdentity $Census.tracked[$i];Assert-DarwinLife (Test-LifeSame $wanted[$i] $Census.tracked[$i]) 'Census tracked identity differs'}
    Assert-DarwinLife ($Census.expectedIdentityGone-and$Census.sameJdkJava.Count-eq0-and$Census.knownLive.Count-eq0) 'Possible Java/known descendant survivor; empty registry/root exit is insufficient'
    @{status=$(if($StopExit-eq0-and-not$Forced-and-not$Emergency){'NORMAL_CLI_ROUTE_SCOPED_ABSENCE_CONFIRMED'}else{'FAIL_NONZERO_FORCED_OR_EMERGENCY'});runtimeAuthorized=$false;evidenceKind='validated-absence-model';scope=$Census.scope;universalHistoricalDescendantsAbsent=$false}
}
function ConvertTo-LifePresenceReason($Status,$Errno){
    if($Status-isnot[int]-or$Errno-isnot[int]){return 'UNKNOWN'}
    if($Status-eq0){return 'PRESENT'}
    if($Status-eq-1-and$Errno-eq3){return 'MISSING_ESRCH'}
    if($Status-eq-1-and$Errno-eq1){return 'PRESENT_EPERM'}
    'UNKNOWN'
}
function Get-LifeNativeType([switch]$RuntimeApproved){
    if(-not$IsMacOS-or-not$RuntimeApproved){throw 'HOLD: native Mac approved signal0 presence only'}
    $cached=Get-Variable -Name LifePresenceType -Scope Script -ErrorAction SilentlyContinue
    if($cached-and($cached.Value-isnot[type]-or-not[object]::ReferenceEquals($cached.Value,('H3911.MacNativeUidV3'-as[type])))){throw 'HOLD: native presence cache identity mismatch'}
    if(-not$cached){
        if('H3911.MacNativeUidV3'-as[type]){throw 'HOLD: native presence type collision'}
        $built=@(Add-Type -PassThru -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace H3911 {
    public static class MacNativeUidV3 {
        private const int BsdSize = 136, KinfoSize = 648, MaxBytes = 1048576, Headroom = 3240;
        [StructLayout(LayoutKind.Explicit, Size=BsdSize)]
        private struct BsdInfo {
            [FieldOffset(12)] public uint Pid; [FieldOffset(16)] public uint Parent;
            [FieldOffset(20)] public uint Effective; [FieldOffset(28)] public uint Real; [FieldOffset(36)] public uint Saved;
            [FieldOffset(120)] public ulong Seconds; [FieldOffset(128)] public ulong Microseconds;
        }
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint="kill", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
        private static extern int Kill(int pid, int signal);
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint="getpid", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl)]
        private static extern int SelfPid();
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint="getuid", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl)]
        private static extern uint RealUid();
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint="geteuid", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl)]
        private static extern uint EffectiveUid();
        [DllImport("/usr/lib/libproc.dylib", EntryPoint="proc_pidinfo", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
        private static extern int PidInfo(int pid, int flavor, ulong arg, IntPtr buffer, int bytes);
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint="sysctl", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
        private static extern int Sysctl([In] int[] name, uint count, IntPtr buffer, ref UIntPtr bytes, IntPtr newValue, UIntPtr newBytes);
        private static void MacAbi() {
            if (!OperatingSystem.IsMacOS() || IntPtr.Size != 8 || RuntimeInformation.ProcessArchitecture != Architecture.Arm64 || Marshal.SizeOf<BsdInfo>() != BsdSize) throw new PlatformNotSupportedException("HOLD: unsupported Mac ABI");
        }
        public static int[] Read(int pid) {
            if (pid <= 0) throw new ArgumentOutOfRangeException(nameof(pid));
            if (!OperatingSystem.IsMacOS()) throw new PlatformNotSupportedException();
            int status = Kill(pid, 0);
            int error = Marshal.GetLastPInvokeError();
            return new int[] { status, error };
        }
        public static long[] ReadBsd(int pid) {
            if (pid <= 0) throw new ArgumentOutOfRangeException(nameof(pid)); MacAbi();
            IntPtr b = IntPtr.Zero;
            try {
                b = Marshal.AllocHGlobal(BsdSize);
                for (int i=0; i<BsdSize; i+=4) Marshal.WriteInt32(b,i,0);
                int n = PidInfo(pid,3,0,b,BsdSize);
                int error = Marshal.GetLastPInvokeError();
                if (n != BsdSize) throw new InvalidOperationException("HOLD: BSD record error/size");
                BsdInfo v = Marshal.PtrToStructure<BsdInfo>(b);
                if (v.Pid != pid || v.Parent > Int32.MaxValue || v.Seconds == 0 || v.Seconds > 253402300799UL || v.Microseconds > 999999) throw new InvalidOperationException("HOLD: BSD identity/clock");
                return new long[] { n,error,v.Pid,v.Parent,v.Real,v.Effective,v.Saved,(long)v.Seconds,(long)v.Microseconds };
            } finally { if (b != IntPtr.Zero) Marshal.FreeHGlobal(b); }
        }
        public static long[] ReadSelf() {
            MacAbi(); int pid = SelfPid(); uint real = RealUid(), effective = EffectiveUid();
            long[] b = ReadBsd(pid), result = new long[11]; Array.Copy(b,result,9); result[9]=real; result[10]=effective; return result;
        }
        public static long[] ListOwnUid(uint uid) {
            if (uid == 0) throw new ArgumentOutOfRangeException(nameof(uid)); MacAbi();
            int self = SelfPid(); if (self <= 0 || EffectiveUid() != uid) throw new InvalidOperationException("HOLD: caller UID/PID");
            int[] mib = new int[4]; mib[0]=1; mib[1]=14; mib[2]=5; mib[3]=unchecked((int)uid); UIntPtr length = UIntPtr.Zero;
            int status = Sysctl(mib,4,IntPtr.Zero,ref length,IntPtr.Zero,UIntPtr.Zero);
            int sizingError = Marshal.GetLastPInvokeError();
            ulong needed = length.ToUInt64();
            if (status != 0 || needed == 0 || needed % KinfoSize != 0 || needed > MaxBytes-Headroom) throw new InvalidOperationException("HOLD: UID sizing/error");
            int sizing = checked((int)needed), capacity = checked(sizing+Headroom); IntPtr b = IntPtr.Zero;
            try {
                b = Marshal.AllocHGlobal(capacity); length = (UIntPtr)(uint)capacity;
                status = Sysctl(mib,4,b,ref length,IntPtr.Zero,UIntPtr.Zero);
                int error = Marshal.GetLastPInvokeError();
                ulong filled = length.ToUInt64();
                if (status != 0 || filled == 0 || filled % KinfoSize != 0 || filled >= (ulong)capacity) throw new InvalidOperationException("HOLD: UID sysctl error/length/saturation");
                return ParseUidRecords(b,uid,self,sizing,capacity,checked((int)filled));
            } finally { if (b != IntPtr.Zero) Marshal.FreeHGlobal(b); }
        }
        private static long[] ParseUidRecords(IntPtr b, uint uid, int self, int sizing, int capacity, int n) {
            if (uid == 0 || self <= 0 || b == IntPtr.Zero || sizing <= 0 || sizing % KinfoSize != 0 || sizing > MaxBytes-Headroom || capacity != checked(sizing+Headroom) || n <= 0 || n % KinfoSize != 0 || n >= capacity) throw new InvalidOperationException("HOLD: UID record bounds");
            int count = n/KinfoSize; long[] result = new long[8+count]; var seen = new HashSet<int>(); bool own = false;
            result[0]=KinfoSize; result[1]=uid; result[2]=self; result[3]=sizing; result[4]=capacity; result[5]=n; result[6]=count; result[7]=0;
            for (int i=0;i<count;i++) { int offset=checked(i*KinfoSize), pid=Marshal.ReadInt32(b,offset+40); uint actual=unchecked((uint)Marshal.ReadInt32(b,offset+420)); if(pid<=0 || actual!=uid || !seen.Add(pid)) throw new InvalidOperationException("HOLD: invalid/duplicate PID or UID mutation"); result[8+i]=pid; own |= pid==self; }
            if (!own) throw new InvalidOperationException("HOLD: caller PID absent from UID set");
            return result;
        }
    }
}
'@)
        $root=@($built|Where-Object {$_.FullName-ceq'H3911.MacNativeUidV3'})
        if($root.Count-ne1-or$built.Count-ne2-or@($built|Where-Object {$_.FullName-cnotin@('H3911.MacNativeUidV3','H3911.MacNativeUidV3+BsdInfo')-or-not[object]::ReferenceEquals($_.Assembly,$root[0].Assembly)}).Count){throw 'HOLD: native presence type origin unavailable'}
        $script:LifePresenceType=$root[0]
    }
    $script:LifePresenceType
}
function Read-LifePresence([ValidateRange(1,2147483647)][int]$ProcessId,[switch]$RuntimeApproved){
    $type=& ${function:Get-LifeNativeType} -RuntimeApproved:$RuntimeApproved
    $facts=$type::Read($ProcessId)
    & ${function:ConvertTo-LifePresenceReason} $facts[0] $facts[1]
}
function Get-LifeRejectedCredentialScope($Wire,$ExpectedPid,[hashtable]$Context){
    # PID-set membership only; OTHER is not an unrelated/system-process determination.
    $tags=@{pidScope='UNKNOWN';exeScope='UNKNOWN';birthBinding='UNAVAILABLE'};$snapshot=$null;$observed=if($Context-is[hashtable]){$Context['observed']}else{$null}
    try{
        Assert-DarwinLife ($observed-is[hashtable]-and($observed.pid-is[int]-or$observed.pid-is[long])-and$observed.pid-eq$ExpectedPid-and$Context.known-is[array]) 'Diagnostic PID context unavailable'
        $members=@($Context.self,$Context.expected)+@($Context.known);$ids=[Collections.Generic.HashSet[int]]::new()
        foreach($member in $members){Assert-DarwinLife ($member-is[hashtable]-and($member.pid-is[int]-or$member.pid-is[long])-and$member.pid-gt0-and$member.pid-le[int]::MaxValue-and$ids.Add([int]$member.pid)) 'Diagnostic PID sets unavailable'}
        $tags.pidScope=if($ExpectedPid-eq$Context.self.pid){$snapshot=$Context.self;'SELF'}elseif($ExpectedPid-eq$Context.expected.pid){$snapshot=$Context.expected;'EXPECTED_OWNER'}elseif($ids.Contains([int]$ExpectedPid)){$snapshot=@($Context.known|Where-Object pid -eq $ExpectedPid)[0];'KNOWN_TRACKED'}else{'OTHER'}
    }catch{}
    try{
        Assert-DarwinLife ($observed-is[hashtable]-and($observed.pid-is[int]-or$observed.pid-is[long])-and$observed.pid-eq$ExpectedPid) 'Diagnostic executable context unavailable'
        Assert-LifePath $observed.executable;Assert-LifePath $Context.jdkExecutable
        Assert-DarwinLife ($Context.jdkExecutable.EndsWith('/bin/java',[StringComparison]::Ordinal)) 'Diagnostic admitted Java path unavailable'
        $tags.exeScope=if([string]::Equals($observed.executable,$Context.jdkExecutable,[StringComparison]::Ordinal)){'ADMITTED_JDK_JAVA'}else{'OTHER_CANONICAL'}
    }catch{}
    try{
        Assert-DarwinLife ($tags.pidScope-cne'UNKNOWN') 'Diagnostic birth context unavailable'
        Assert-LifeIdentity $observed
        Assert-DarwinLife ($Wire-is[array]-and$Wire.Count-in@(9,11)) 'Diagnostic wire unavailable'
        foreach($n in $Wire){Assert-DarwinLife ($n-is[int]-or$n-is[long]) 'Diagnostic wire types unavailable'}
        Assert-DarwinLife ($Wire[0]-eq136-and$Wire[2]-eq$ExpectedPid-and$Wire[3]-ge0-and$Wire[3]-le[int]::MaxValue-and$Wire[7]-gt0-and$Wire[7]-le253402300799-and$Wire[8]-ge0-and$Wire[8]-le999999) 'Diagnostic native identity unavailable'
        foreach($index in 4,5,6){Assert-DarwinLife ($Wire[$index]-ge0-and$Wire[$index]-le[uint32]::MaxValue) 'Diagnostic credential representation unavailable'}
        $projected=& ${function:ConvertTo-LifeStartTimeTicks} $Wire[7] $Wire[8]
        $nativeMicroseconds=[long]$Wire[7]*1000000L+[long]$Wire[8]
        $previousMicroseconds=0L;$previousSeconds=[Math]::DivRem(($nativeMicroseconds-1L),1000000L,[ref]$previousMicroseconds)
        $nextMicroseconds=0L;$nextSeconds=[Math]::DivRem(($nativeMicroseconds+1L),1000000L,[ref]$nextMicroseconds)
        Assert-DarwinLife (($projected-gt(& ${function:ConvertTo-LifeStartTimeTicks} $previousSeconds $previousMicroseconds))-and($projected-lt(& ${function:ConvertTo-LifeStartTimeTicks} $nextSeconds $nextMicroseconds))) 'Diagnostic birth projection unavailable'
        $matches=[DateTimeOffset]::Parse($observed.created,[Globalization.CultureInfo]::InvariantCulture).UtcTicks-eq$projected
        if($snapshot){Assert-LifeIdentity $snapshot;$matches=$matches-and(Test-LifeCreationInstant $snapshot.created $observed.created)}
        $tags.birthBinding=if($matches){'MATCH'}else{'MISMATCH'}
    }catch{}
    $tags
}
function ConvertFrom-LifeBsdRecord($Wire,$ExpectedPid){
    Assert-DarwinLife ($Wire-is[array]-and$Wire.Count-in@(9,11)) 'Exact BSD fact wire required'
    foreach($n in $Wire){Assert-DarwinLife (($n-is[int]-or$n-is[long])) 'Integer BSD facts required'}
    Assert-DarwinLife (($ExpectedPid-is[int]-or$ExpectedPid-is[long])-and$ExpectedPid-gt0-and$ExpectedPid-le[int]::MaxValue-and$Wire[0]-eq136-and$Wire[2]-eq$ExpectedPid-and$Wire[3]-ge0-and$Wire[3]-le[int]::MaxValue) 'BSD size/PID/parent/expected UID mismatch'
    foreach($index in 4,5,6){Assert-DarwinLife ($Wire[$index]-ge0-and$Wire[$index]-le[uint32]::MaxValue) 'Kernel credential UID representation invalid'}
    Assert-DarwinLife ($Wire[7]-gt0-and$Wire[7]-le253402300799-and$Wire[8]-ge0-and$Wire[8]-le999999) 'BSD birth outside supported range'
    if($Wire.Count-eq11){foreach($index in 9,10){Assert-DarwinLife ($Wire[$index]-ge0-and$Wire[$index]-le[uint32]::MaxValue) 'Kernel credential UID representation invalid'}}
    @{pid=[int]$Wire[2];parentPid=[int]$Wire[3];realUid=$Wire[4];effectiveUid=$Wire[5];savedUid=$Wire[6];birthSeconds=$Wire[7];birthMicroseconds=$Wire[8]}
}
function ConvertFrom-LifeBsdFacts($Wire,$ExpectedPid,$ExpectedUid,[hashtable]$FailureContext){
    $facts=ConvertFrom-LifeBsdRecord $Wire $ExpectedPid
    Assert-DarwinLife (($ExpectedUid-is[int]-or$ExpectedUid-is[long])-and$ExpectedUid-gt0-and$ExpectedUid-le[uint32]::MaxValue) 'BSD size/PID/parent/expected UID mismatch'
    try{foreach($index in 4,5,6){Assert-DarwinLife ($Wire[$index]-eq$ExpectedUid) 'Nonroot real/effective/saved UID invariant required'}}
    catch{
        # Real/effective/saved: match, zero, other uint32, invalid; never emit raw credential values.
        $uidComparison=-join@(foreach($index in 4,5,6){if($Wire[$index]-lt0-or$Wire[$index]-gt[uint32]::MaxValue){'I'}elseif($Wire[$index]-eq$ExpectedUid){'M'}elseif($Wire[$index]-eq0){'Z'}else{'O'}})
        $scope=@{pidScope='UNKNOWN';exeScope='UNKNOWN';birthBinding='UNAVAILABLE'}
        try{$scope=& ${function:Get-LifeRejectedCredentialScope} $Wire $ExpectedPid $FailureContext}catch{}
        throw ('HOLD: Nonroot real/effective/saved UID invariant required [uidComparison='+$uidComparison+'] [pidScope='+$scope.pidScope+'] [exeScope='+$scope.exeScope+'] [birthBinding='+$scope.birthBinding+']')
    }
    if($Wire.Count-eq11){Assert-DarwinLife ($Wire[9]-eq$ExpectedUid-and$Wire[10]-eq$ExpectedUid) 'getuid/geteuid/kernel disagreement'}
    $facts
}
function Assert-LifeCredentialBinding($Facts,$ExpectedPid,$ExpectedUid,$Seconds,$Microseconds){
    Assert-DarwinLife (($ExpectedPid-is[int]-or$ExpectedPid-is[long])-and($ExpectedUid-is[int]-or$ExpectedUid-is[long])-and($Seconds-is[int]-or$Seconds-is[long])-and($Microseconds-is[int]-or$Microseconds-is[long])-and$Facts.pid-eq$ExpectedPid-and$Facts.effectiveUid-eq$ExpectedUid-and$Facts.birthSeconds-eq$Seconds-and$Facts.birthMicroseconds-eq$Microseconds) 'Kernel PID/UID/birth binding mismatch'
}
function ConvertFrom-LifeUidPidFacts($Wire,$ExpectedUid,$CallerPid){
    Assert-DarwinLife ($Wire-is[array]-and$Wire.Count-ge9) 'Nonempty sysctl UID PID wire required'
    foreach($n in $Wire){Assert-DarwinLife (($n-is[int]-or$n-is[long])) 'Integer UID PID facts required'}
    Assert-DarwinLife (($ExpectedUid-is[int]-or$ExpectedUid-is[long])-and$ExpectedUid-gt0-and$ExpectedUid-le[uint32]::MaxValue-and($CallerPid-is[int]-or$CallerPid-is[long])-and$CallerPid-gt0-and$CallerPid-le[int]::MaxValue-and$Wire[0]-eq648-and$Wire[1]-eq$ExpectedUid-and$Wire[2]-eq$CallerPid-and$Wire[3]-gt0-and$Wire[3]%648-eq0-and$Wire[3]-le1045336-and$Wire[4]-eq($Wire[3]+3240)-and$Wire[4]-le1048576-and$Wire[5]-gt0-and$Wire[5]%648-eq0-and$Wire[5]-lt$Wire[4]-and$Wire[6]-eq($Wire[5]/648)-and$Wire[7]-eq0-and$Wire.Count-eq(8+$Wire[6])) 'Sysctl UID byte/status/capacity mismatch'
    $seen=[Collections.Generic.HashSet[int]]::new();$pids=@()
    foreach($n in $Wire[8..($Wire.Count-1)]){Assert-DarwinLife ($n-gt0-and$n-le[int]::MaxValue-and$seen.Add([int]$n)) 'Invalid/duplicate UID PID';$pids+=[int]$n}
    Assert-DarwinLife ($seen.Contains([int]$CallerPid)) 'Caller PID absent; not empty success'
    @{effectiveUid=$ExpectedUid;callerPid=$CallerPid;filter=5;api='sysctl(KERN_PROC_UID)';pids=$pids;sizingBytes=$Wire[3];capacityBytes=$Wire[4];returnedBytes=$Wire[5];initialPidCount=$Wire[6];atomicEndpoint=$false;newbornCoverage=$false}
}
function Read-LifeSelfCredential([switch]$RuntimeApproved){
    $type=& ${function:Get-LifeNativeType} -RuntimeApproved:$RuntimeApproved;$wire=$type::ReadSelf()
    & ${function:ConvertFrom-LifeBsdFacts} $wire $wire[2] $wire[10]
}
function Read-LifeOwnerCredential([ValidateRange(1,2147483647)][int]$ProcessId,[ValidateRange(1,4294967295)][long]$ExpectedUid,[switch]$RuntimeApproved,[hashtable]$FailureContext){
    $type=& ${function:Get-LifeNativeType} -RuntimeApproved:$RuntimeApproved
    try{$wire=$type::ReadBsd($ProcessId)}catch{throw 'HOLD: kernel credential read unavailable [credentialReadUnavailable=true]'}
    & ${function:ConvertFrom-LifeBsdFacts} $wire $ProcessId $ExpectedUid $FailureContext
}
function Read-LifeCensusCredential([ValidateRange(1,2147483647)][int]$ProcessId,[switch]$RuntimeApproved){
    $type=& ${function:Get-LifeNativeType} -RuntimeApproved:$RuntimeApproved
    try{$wire=$type::ReadBsd($ProcessId)}catch{throw 'HOLD: kernel credential read unavailable [credentialReadUnavailable=true]'}
    & ${function:ConvertFrom-LifeBsdRecord} $wire $ProcessId
}
function Read-LifeOwnUidPids([ValidateRange(1,4294967295)][long]$ExpectedUid,[switch]$RuntimeApproved){
    $type=& ${function:Get-LifeNativeType} -RuntimeApproved:$RuntimeApproved;$wire=$type::ListOwnUid([uint32]$ExpectedUid)
    & ${function:ConvertFrom-LifeUidPidFacts} $wire $ExpectedUid $wire[2]
}
function Get-LifeOsProcesses {
    param([hashtable]$Context,[hashtable]$Expected,[switch]$RuntimeApproved)
    if(-not$IsMacOS-or-not$RuntimeApproved){throw 'HOLD: native Mac approved census required'}
    Assert-LifeContext $Context $Expected
    $commands=& ${function:Get-LifeUidCommands};$self=& ${function:Read-LifeUidSelf} $commands
    $selection=& $commands['Read-LifeOwnUidPids'] -ExpectedUid $self.uid -RuntimeApproved
    $tracked=@($Expected)+@($Context.KnownOwnedIdentities);$selected=New-LifePidSet $selection.pids;$all=[Collections.Generic.HashSet[int]]::new($selected)
    foreach($known in $tracked){$null=$all.Add([int]$known.pid)}
    Assert-DarwinLife ($all.Count-le4096) 'UID union exceeds bounded census'
    $rows=@();$rechecks=0;$missing=0;$missingPids=@();$outsidePids=@()
    foreach($id in $all){
        $p=$null;$phase='lookup';$pidText=$id.ToString([Globalization.CultureInfo]::InvariantCulture);$failed=$false;$missingConfirmed=$false;$presence='NOT_ATTEMPTED';$semantic=$false
        try{
            $p=[Diagnostics.Process]::GetProcessById($id)
            $phase='start-time';$created=$p.StartTime.ToUniversalTime().ToString('o')
            $phase='main-module';$module=$p.MainModule;if($null-eq$module){throw 'Unavailable module value'}
            $phase='module-file-name';$executable=$module.FileName;if($null-eq$executable){throw 'Unavailable executable value'}
            $phase='path-pid-scope';$semantic=$true
            $row=@{pid=$id;created=$created;executable=$executable}
            $row.protectedPathPid=Test-LifeProtectedPathPid $Context $Expected $self.identity $row
            $phase='kernel-credential'
            $row.credential=& $commands['Read-LifeCensusCredential'] -ProcessId $id -RuntimeApproved
            $phase='credential-binding'
            $protected=Assert-LifePathPidRow $Context $Expected $self.identity $row $self.uid
            if(-not$protected){$outsidePids+=,[int]$id}
            $rows+=,$row
        }
        catch{
            $failed=$true
            if($semantic-and-not($_.Exception.Message.Contains('[credentialReadUnavailable=true]'))){
                $invariant=switch -CaseSensitive ($_.Exception.Message){
                    'HOLD: Explicit positive PID identity required'{'PID_SHAPE'}
                    'HOLD: Explicit ISO creation required'{'CREATION_FORMAT'}
                    'HOLD: Canonical Darwin path required'{'EXECUTABLE_PATH'}
                    'HOLD: Typed credential PID/birth identity required'{'CREDENTIAL_IDENTITY_SHAPE'}
                    'HOLD: Kernel credential facts required'{'CREDENTIAL_FACTS'}
                    'HOLD: Kernel credential UID representation invalid'{'CREDENTIAL_REPRESENTATION'}
                    'HOLD: Current effective UID differs from launch actor'{'CREDENTIAL_EUID'}
                    'HOLD: Recomputed path/PID classification differs'{'PATH_PID_SCOPE'}
                    'HOLD: Protected PID lifetime/executable changed'{'KNOWN_IDENTITY'}
                    'HOLD: BSD size/PID/parent/expected UID mismatch'{'CREDENTIAL_PID_UID'}
                    'HOLD: Nonroot real/effective/saved UID invariant required'{'CREDENTIAL_UID'}
                    'HOLD: BSD birth outside supported range'{'CREDENTIAL_BIRTH_RANGE'}
                    'HOLD: Kernel microsecond birth cannot bind metadata'{'BIRTH_PRECISION'}
                    'HOLD: Unreviewed Darwin StartTime projection runtime'{'START_TIME_RUNTIME'}
                    'HOLD: Kernel birth projection cannot uniquely bind microseconds'{'BIRTH_PROJECTION_AMBIGUOUS'}
                    'HOLD: Kernel PID/UID/birth binding mismatch'{'BIRTH_BINDING'}
                    'HOLD: Known PID reuse/foreign identity HOLD'{'KNOWN_IDENTITY'}
                    default{'UNCLASSIFIED'}
                }
                $uidDetail=''
                $uidMatch=[regex]::Match($_.Exception.Message,'\AHOLD: Nonroot real/effective/saved UID invariant required \[uidComparison=([MZOI]{3})\]\z')
                if($invariant-ceq'CREDENTIAL_UID'){$uidDetail=' [uidComparison=UNAVAILABLE] [pidScope=UNKNOWN] [exeScope=UNKNOWN] [birthBinding=UNAVAILABLE]'}
                if($uidMatch.Success){$invariant='CREDENTIAL_UID';$uidDetail=' [uidComparison='+$uidMatch.Groups[1].Value+'] [pidScope=UNKNOWN] [exeScope=UNKNOWN] [birthBinding=UNAVAILABLE]'}
                $scopeMatch=[regex]::Match($_.Exception.Message,'\AHOLD: Nonroot real/effective/saved UID invariant required \[uidComparison=([MZOI]{3})\] \[pidScope=(SELF|EXPECTED_OWNER|KNOWN_TRACKED|OTHER|UNKNOWN)\] \[exeScope=(ADMITTED_JDK_JAVA|OTHER_CANONICAL|UNKNOWN)\] \[birthBinding=(MATCH|MISMATCH|UNAVAILABLE)\]\z')
                if($scopeMatch.Success){$invariant='CREDENTIAL_UID';$uidDetail=' [uidComparison='+$scopeMatch.Groups[1].Value+'] [pidScope='+$scopeMatch.Groups[2].Value+'] [exeScope='+$scopeMatch.Groups[3].Value+'] [birthBinding='+$scopeMatch.Groups[4].Value+']'}
                throw ('HOLD: UID/lifetime invariant [reason=CENSUS_ROW_FAILED;phase='+$phase+';pid='+$pidText+';scanComplete=false] [invariant='+$invariant+']'+$uidDetail)
            }
            $rechecks++;try{$presence=& $commands['Read-LifePresence'] -ProcessId ([int]$id) -RuntimeApproved:$RuntimeApproved}catch{$presence='UNKNOWN'}
            $missingConfirmed=$presence-is[string]-and$presence-ceq'MISSING_ESRCH'
            if(-not$missingConfirmed){throw ('HOLD: unreadable/exited/ambiguous native process identity during full census [reason=CENSUS_ROW_FAILED;phase='+$phase+';pid='+$pidText+';scanComplete=false] [presence='+$presence+';missingAtRecheck='+$missing+';presenceAttempts='+$rechecks+']')}
        }
        finally{if($p){try{$p.Dispose()}catch{if($missingConfirmed){throw ('HOLD: census read and disposal failed [reason=CENSUS_ROW_FAILED;phase='+$phase+';pid='+$pidText+';scanComplete=false] [presence=MISSING_ESRCH;dispose=failed;missingAtRecheck='+$missing+';presenceAttempts='+$rechecks+']')};if(-not$failed){throw ('HOLD: native process disposal failed [reason=CENSUS_DISPOSE_FAILED;phase=dispose;pid='+$pidText+';scanComplete=false] [missingAtRecheck='+$missing+';presenceAttempts='+$rechecks+']')}}}}
        if($missingConfirmed){$missing++;$missingPids+=,[int]$id}
    }
    $ownerCredential=@($rows|Where-Object pid -eq $Expected.pid|ForEach-Object credential)
    $proof=@{schema='darwin-launch-uid-proof-v2';admittedUid=$self.uid;filter=5;selfIdentity=$self.identity;selfCredential=$self.credential;ownerCredential=$(if($ownerCredential.Count-eq1){$ownerCredential[0]}else{$null});selectedPids=@($selection.pids);missingAtRecheckPids=$missingPids;outsideProtectedPathPidPids=$outsidePids;selectedPidCount=$selected.Count;knownPidCount=$tracked.Count;unionPidCount=$all.Count;validatedPidCount=$rows.Count;outsideProtectedPathPidCount=$outsidePids.Count;missingAtRecheckCount=$missing;presenceRecheckAttempts=$rechecks;observationBasis='EUID_SELECTION_TRACKED_UNION_PATH_PID_SCOPE_V1';atomicEndpoint=$false;newbornCoverage=$false}
    $proof.universalHistory=$false
    @{schema='darwin-launch-uid-observation-v2';complete=$true;errors=@();processes=$rows;uidProof=$proof}
}
function Get-LifeCurrent([int]$ProcessId){
    $pidText=if($ProcessId-gt0){$ProcessId.ToString([Globalization.CultureInfo]::InvariantCulture)}else{'unavailable'}
    try{$p=[Diagnostics.Process]::GetProcessById($ProcessId)}catch{throw ('HOLD: native identity missing/unavailable before stop admission [reason=CURRENT_LOOKUP_FAILED;phase=lookup;pid='+$pidText+';scanComplete=false]')}
    $phase='pid';$failed=$false
    try{
        $id=$p.Id;if($null-eq$id){throw 'Unavailable PID value'}
        $phase='start-time';$created=$p.StartTime.ToUniversalTime().ToString('o')
        $phase='main-module';$module=$p.MainModule;if($null-eq$module){throw 'Unavailable module value'}
        $phase='module-file-name';$executable=$module.FileName;if($null-eq$executable){throw 'Unavailable executable value'}
        $phase='identity';$r=@{pid=$id;created=$created;executable=$executable};Assert-LifeIdentity $r;$r
    }catch{$failed=$true;throw ('HOLD: native identity read failed before stop admission [reason=CURRENT_IDENTITY_FAILED;phase='+$phase+';pid='+$pidText+';scanComplete=false]')}
    finally{try{$p.Dispose()}catch{if(-not$failed){throw ('HOLD: native process disposal failed [reason=CURRENT_DISPOSE_FAILED;phase=dispose;pid='+$pidText+';scanComplete=false]')}}}
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
    $observation=& $osReader -Context $Context -Expected $Expected -RuntimeApproved
    $result=& ($ExecutionContext.SessionState.Module.ExportedCommands['ConvertTo-H3911DarwinScopedCensus']) $Context $Expected $observation
    & ${function:Assert-LifeUidCensus} $Context $Expected $result
    if(-not$result.expectedIdentityGone){$commands=& ${function:Get-LifeUidCommands};$snapshot=& $commands['Read-LifeRegistry'] $Context;$current=@($result.knownLive|Where-Object pid -eq $Expected.pid)[0];$null=& ($ExecutionContext.SessionState.Module.ExportedCommands['New-H3911DarwinStopPlanFacts']) $Context $Expected $snapshot.registry $current;$Expected.launchUidAdmission=$result.uidProof}
    $result.evidenceKind='native-mac-launch-uid-census-v2';$result
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
    $commands=& ${function:Get-LifeUidCommands};$self=& ${function:Read-LifeUidSelf} $commands
    $credential=& $commands['Read-LifeOwnerCredential'] -ProcessId ([int]$Expected.pid) -ExpectedUid $self.uid -RuntimeApproved
    & ${function:Assert-LifeCredentialIdentity} $credential $current $self.uid
    $plan=& ($ExecutionContext.SessionState.Module.ExportedCommands['New-H3911DarwinStopPlanFacts']) $Context $Expected $snapshot.registry $current -Emergency:$Emergency
    Assert-DarwinLife ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($Context.Registry+'/registry.bin')))-ceq$snapshot.digest) 'Registry changed during stop admission'
    $Expected.launchUidAdmission=@{schema='darwin-launch-uid-live-admission-v2';admittedUid=$self.uid;ownerCredential=$credential}
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
    & ${function:Assert-LifeUidCensus} $Context $Expected $census
    Assert-DarwinLife ($Expected.launchUidAdmission-is[hashtable]-and$Expected.launchUidAdmission.schema-cin@('darwin-launch-uid-proof-v2','darwin-launch-uid-live-admission-v2')-and$Expected.launchUidAdmission.admittedUid-eq$census.uidProof.admittedUid) 'Prior actual live-owner UID admission required after exit'
    if($Expected.launchUidAdmission.schema-ceq'darwin-launch-uid-proof-v2'){Assert-DarwinLife ($Expected.launchUidAdmission.observationBasis-ceq'EUID_SELECTION_TRACKED_UNION_PATH_PID_SCOPE_V1') 'Prior live census path/PID contract differs'}
    & ${function:Assert-LifeCredentialIdentity} $Expected.launchUidAdmission.ownerCredential $Expected $census.uidProof.admittedUid
    try{$result=& ($ExecutionContext.SessionState.Module.ExportedCommands['Confirm-H3911DarwinAbsenceFacts']) $Context $Expected $snapshot.registry $census $StopExit -Forced:$Forced -Emergency:$Emergency}
    catch{throw ($_.ToString()+' [observationBasis='+$census.uidProof.observationBasis+';missingAtRecheck='+$census.uidProof.missingAtRecheckCount+';presenceAttempts='+$census.uidProof.presenceRecheckAttempts+']')}
    Assert-DarwinLife ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($Context.Registry+'/registry.bin')))-ceq$snapshot.digest) 'Registry changed during absence census'
    $result.schema='darwin-launch-uid-absence-v2';$result.uidProof=$census.uidProof;$result.knownOwnedIdentities=$Context.KnownOwnedIdentities
    $result.evidenceKind='native-scoped-absence-result';$result
}
Export-ModuleMember -Function New-H3911DarwinStopPlanFacts,ConvertTo-H3911DarwinScopedCensus,Confirm-H3911DarwinAbsenceFacts,Read-H3911DarwinScopedCensus,New-H3911DarwinPrivateStopPlan,Confirm-H3911DarwinCliStop
