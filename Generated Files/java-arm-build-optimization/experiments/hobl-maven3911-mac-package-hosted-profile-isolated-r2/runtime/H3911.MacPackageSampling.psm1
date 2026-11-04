function Assert-MPackage($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function Import-MPackage {
    $spec=@{
        'H3911.MacRuntimeInputs.psm1'=@('4B420788E649023771CC59DE0F7C5C67A94E7F19CC57F3EBD4B80E3CFA87BD7F',@('Import-H3911MacRuntimeInputs','Assert-H3911MacSdk','Resolve-H3911MacInputPath','Assert-H3911MacInputDisjoint'))
        'H3911.PackageSampling.psm1'=@('CA1E15176728C26C5ED009F53ADEECBF19E9D16B89913FC388A0631F9D96FC22',@('Get-H3911RetainedProtocol','Get-H3911PackageDecision','Get-PScreenFileBinding','Assert-PScreenSeal','Assert-PScreenFullGate'))
        'H3911.Artifacts.psm1'=@('BD2B01750B3F6954425599F0E70F34F2A04B122E03724B1482704E76FC6B55F6',@('Read-H3911Artifact'))
        'H3911.Offline.psm1'=@('99B6CA8A3025FBF5D55C7DE8E1871C8C0BEF47A69CA541D4C1472A73CC6BEF1D',@('Assert-H3911OfflineDelta'))
        'H3911.Helpers.psm1'=@('1F1C0099CDC1A7DA6FE949BF973269418DCAAC0E1539A4598A6E5CCFE3720BAA',@('TestKeys','CoverageKeys','CoverageSemantics','JacocoExecEvidence'))}
    $bound=@{}
    foreach($row in $spec.GetEnumerator()){
        $path=Join-Path $PSScriptRoot $row.Key;& ${function:Assert-MPackage} ((Get-FileHash $path).Hash-ceq$row.Value[0]) 'Mac sampling dependency differs'
        $m=Import-Module $path -PassThru -Scope Local -DisableNameChecking
        foreach($name in $row.Value[1]){$command=& $m {param($n)Get-Command $n -CommandType Function} $name;& ${function:Assert-MPackage} ($command-is[Management.Automation.FunctionInfo]-and$command.Module.Path-ceq$path) 'Mac sampling command origin differs';$bound[$name]=$command}
    }
    $native=& $bound['Import-H3911MacRuntimeInputs'];foreach($key in $native.Keys){$bound[$key]=$native[$key]};$bound
}
function Get-MPackageSeal($Commands,[string]$Log){@{receipt=(& $Commands['Get-PScreenFileBinding'] ($Log+'.process.json'));stdout=(& $Commands['Get-PScreenFileBinding'] $Log);stderr=(& $Commands['Get-PScreenFileBinding'] ($Log+'.stderr'))}}
function Assert-MPackageProbeLedger($Rows){
    $files=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$processes=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($row in $Rows){
        $birth=[DateTimeOffset]::MinValue
        & ${function:Assert-MPackage} (($row.pid-is[int]-or$row.pid-is[long])-and$row.pid-gt0-and$row.pid-le[int]::MaxValue-and$row.receipt.path-is[string]-and$row.createdUtc-is[string]-and$row.createdUtc-cmatch'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$'-and[DateTimeOffset]::TryParse($row.createdUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$birth)) 'Typed auxiliary PID/birth/path required'
        $key=$row.pid.ToString([Globalization.CultureInfo]::InvariantCulture)+'|'+$birth.UtcTicks.ToString([Globalization.CultureInfo]::InvariantCulture)
        & ${function:Assert-MPackage} ($files.Add($row.receipt.path)-and$processes.Add($key)) 'Duplicate auxiliary receipt/process lifetime; count is not evidence'
    }
}
function Assert-MPackageClock($Commands,[string]$Log,[string]$Exe,[string[]]$Tokens,[string]$Cwd,[DateTimeOffset]$NotBefore){
    $seal=& ${function:Get-MPackageSeal} $Commands $Log
    $r=Get-Content $seal.receipt.path -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    foreach($field in 'exe','workingDirectory','stdoutSha256','stderrSha256','platform','clockBoundary','transport','createdUtc'){& ${function:Assert-MPackage} ($r[$field]-is[string]) 'Scalar receipt identity/hash/transport/birth string required'}
    foreach($field in 'stdoutBytes','stderrBytes'){& ${function:Assert-MPackage} (($r[$field]-is[int]-or$r[$field]-is[long])-and$r[$field]-ge0) 'Scalar receipt stream length required'}
    & ${function:Assert-MPackage} ($r.arguments-is[array]-and$r.arguments.Count-eq$Tokens.Count) 'Exact argument array required'
    for($i=0;$i-lt$Tokens.Count;$i++){& ${function:Assert-MPackage} ($r.arguments[$i]-is[string]-and[string]::Equals($r.arguments[$i],$Tokens[$i],[StringComparison]::Ordinal)) 'Scalar exact argument token required'}
    $birth=[DateTimeOffset]::MinValue
    & ${function:Assert-MPackage} ($r.createdUtc-cmatch'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$'-and[DateTimeOffset]::TryParse($r.createdUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$birth)) 'Invariant explicit-offset birth required'
    & ${function:Assert-MPackage} ($r-is[hashtable]-and$r.platform-ceq'Posix'-and$r.validClock-is[bool]-and$r.validClock-and$r.exitConfirmed-is[bool]-and$r.exitConfirmed-and($r.exit-is[int]-or$r.exit-is[long])-and$r.exit-eq0-and$r.stdoutComplete-is[bool]-and$r.stdoutComplete-and$r.stderrComplete-is[bool]-and$r.stderrComplete-and$r.timeout-is[bool]-and-not$r.timeout-and$r.killRequested-is[bool]-and-not$r.killRequested-and-not$r.failure-and-not$r.terminationError) '6CF normal exit/drain/clock required'
    & ${function:Assert-MPackage} (($r.pid-is[int]-or$r.pid-is[long])-and$r.pid-gt0-and$r.pid-le[int]::MaxValue-and$birth-ge$NotBefore-and$birth-le[DateTimeOffset]::UtcNow-and$r.exe-ceq$Exe-and$r.workingDirectory-ceq$Cwd) '6CF PID/birth/executable/argv/cwd binding differs'
    & ${function:Assert-MPackage} (($r.elapsedSeconds-is[double]-or$r.elapsedSeconds-is[decimal]-or$r.elapsedSeconds-is[int]-or$r.elapsedSeconds-is[long])-and$r.elapsedSeconds-gt0-and-not[double]::IsNaN($r.elapsedSeconds)-and-not[double]::IsInfinity($r.elapsedSeconds)-and$r.clockBoundary-ceq'immediately before Process.Start through normal WaitForExit'-and$r.transport-ceq'direct executable / ArgumentList / no shell') 'Exact finite 6CF inner clock required'
    & ${function:Assert-MPackage} ($r.stdoutSha256-ceq$seal.stdout.sha256-and$r.stderrSha256-ceq$seal.stderr.sha256-and$r.stdoutBytes-eq$seal.stdout.bytes-and$r.stderrBytes-eq$seal.stderr.bytes) '6CF stream bytes/hash differ'
    $seal.pid=$r.pid;$seal.createdUtc=$r.createdUtc;$seal.exe=$r.exe;$seal.arguments=$r.arguments;$seal.workingDirectory=$r.workingDirectory;$seal.seconds=$r.elapsedSeconds;$seal.transportSourceSha256='6CF9CB37879428520B87738FE8A0CDECEA8E0B6AA6577C068FDABB44F038E5A3'
    $seal.nativeImageObservation='Source-selected POSIX executable path; 6CF observes owned PID/birth, not a separate image trace';$seal
}
function Read-MPackageProbes($C,$Commands,$Owner){
    & ${function:Assert-MPackage} ($Owner.receipts-is[string]-and$Owner.evidenceKind-ceq'native-mac-effective-owner') 'Actual native owner/probe receipt directory required'
    & ${function:Assert-MPackage} (& $Commands['Test-LifeSame'] $C.ScreenOwner $Owner) 'Qualification probe owner lifetime differs'
    foreach($key in 'daemonId','home','registryFile','jniPath'){& ${function:Assert-MPackage} ($Owner[$key]-ceq$C.ScreenOwner[$key]) 'Qualification probe private scope differs'}
    $rows=@()
    foreach($probe in 'VM.system_properties','VM.dynlibs'){
        $log=Join-Path $Owner.receipts ($probe+'.log')
        $seal=& ${function:Assert-MPackageClock} $Commands $log (Join-Path $C.Jdk 'bin/jcmd') @([string]$Owner.pid,$probe) $C.Temp ([DateTimeOffset]$C.ScreenNotBefore)
        $seal.probe=$probe;$seal.targetPid=$Owner.pid;$rows+=,$seal
    };$rows
}
function Assert-MPackageAdmission($C,$Commands,[bool]$FixtureOnly,$Hooks,[bool]$Package){
    if($FixtureOnly){& $Hooks.Admit $C $Package;return}
    $null=& $Commands['Assert-H3911Source'] $C;$null=& $Commands['Assert-H3911MacSdk'] $C $C.JdkArchive
    $null=& $Commands['Assert-H3911Darwin103Distribution'] $C.Home -RequireNativeModes
    & ${function:Assert-MPackage} ((Get-FileHash $C.DistributionArchive).Hash-ceq'B5528C92D5B0E14A8A47DDFF138C19D93AC01F6CB8A28514F8FA40F2CEB65194'-and$env:JAVA_HOME-ceq$C.Jdk-and$env:MAVEN_SKIP_RC-ceq'1'-and$env:MVND_HOME-ceq$C.Home-and$env:MVND_DAEMON_STORAGE-ceq$C.Registry) 'Mac archive/environment admission changed'
    $null=& $Commands['Assert-H3911StockMaven3911'] -MavenHome $C.Contexts['baseline-maven-home'].value -PrivateWrapperCache $C.PrivateWrapperCache -Profile MacOriginal -Format $C.ScreenStockFormat
}
function Invoke-H3911MacPackageSamplingOperator {
    param([hashtable]$Context,[switch]$RuntimeApproved,[switch]$FixtureOnly,[hashtable]$FixtureHooks)
    & ${function:Assert-MPackage} ($RuntimeApproved-xor$FixtureOnly) 'Exactly one operator authority required'
    & ${function:Assert-MPackage} ($Context.Platform-ceq'MacOS'-and$Context.SourceProfile-ceq'MacOriginalWrapper') 'Closed original Mac profile required'
    & ${function:Assert-MPackage} (-not$RuntimeApproved-or(-not$FixtureHooks-and-not$Context.FixtureOnly-and$IsMacOS-and[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture-eq'Arm64'-and[Runtime.InteropServices.RuntimeInformation]::OSArchitecture-eq'Arm64')) 'Native ARM64 Mac required; runtime callbacks prohibited'
    if($FixtureOnly){foreach($n in 'Admit','Owner','Census','Process','Capture','Probes'){& ${function:Assert-MPackage} ($FixtureHooks[$n]-is[scriptblock]) 'Closed explicit fixture hooks required'}}
    $C=$Context;$C.FixtureOnly=[bool]$FixtureOnly;$commands=& ${function:Import-MPackage}
    foreach($key in 'ProcessInvoker','OwnerReader','PackageReader','SourceCheck','Timer','FixtureDispatch'){& ${function:Assert-MPackage} (-not$C[$key]) 'Runtime-injected operation prohibited'}
    if($RuntimeApproved){
        & ${function:Assert-MPackage} ($C.ScreenMainAuxLimit-is[int]-and$C.ScreenMainAuxLimit-eq28) 'Explicit reviewed28-main auxiliary budget required; old14 budget insufficient'
        foreach($key in 'Project','Output','Home','Registry','Temp','Cache','Jdk','Settings','JdkArchive','DistributionArchive'){$null=& $commands['Resolve-H3911MacInputPath'] $C[$key];if($key-cne'Project'){$null=& $commands['Assert-H3911MacInputDisjoint'] $C.Project $C[$key]}}
    }
    & ${function:Assert-MPackage} ($C.Contexts-is[hashtable]-and$C.Contexts.Count-eq5-and$C.Calls-is[array]-and$C.Calls.Count-eq7-and(@($C.Calls.plan.label)-join',')-ceq'baseline-project,daemon-arch,daemon-home,daemon-project,baseline-maven-home,baseline-verify,candidate-verify') 'Only after the seven completed online gates, before stop'
    foreach($call in $C.Calls){& ${function:Assert-MPackage} (($call.exit-is[int]-or$call.exit-is[long])-and$call.exit-eq0) 'Qualification child failed'}
    $qualificationSeals=@()
    if($RuntimeApproved){
        foreach($call in $C.Calls){$qualificationSeals+=& ${function:Assert-MPackageClock} $commands $call.log $call.plan.exe $call.plan.arguments $C.Project ([DateTimeOffset]$C.ScreenNotBefore)}
        foreach($name in 'baseline-project','daemon-arch','daemon-home','daemon-project','baseline-maven-home'){
            $call=@($C.Calls|Where-Object {$_.plan.label-ceq$name})[0];$file=& $commands['Get-PScreenFileBinding'] $call.plan.valueFile;$value=[Text.UTF8Encoding]::new($false,$true).GetString([IO.File]::ReadAllBytes($file.path))
            $wanted=switch($name){daemon-arch{'aarch64'}daemon-home{$C.Jdk}baseline-maven-home{$C.Contexts[$name].value}default{$C.Project}}
            & ${function:Assert-MPackage} ($value-ceq$wanted-and$value-ceq$C.Contexts[$name].value-and$file.sha256-ceq$C.Contexts[$name].sha256-and$file.bytes-eq$C.Contexts[$name].bytes) 'Actual qualification scalar receipt/profile differs'
        }
    }
    $gates=@();foreach($pair in @(@('baseline-verify','baseline'),@('candidate-verify','candidate'))){$gates+=& $commands['Assert-PScreenFullGate'] $C $commands $pair[0] $C.ScreenVerification[$pair[1]]}
    & ${function:Assert-MPackage} ($C.ScreenVerification.baseline.fork-ne$C.ScreenVerification.candidate.fork-and$C.ScreenVerification.baseline.session-ne$C.ScreenVerification.candidate.session) 'Distinct online fork/session required'
    $null=& $commands['Compare-H3911Artifacts'] (Join-Path $C.Output 'baseline-verify') (Join-Path $C.Output 'candidate-verify') -SourceProfile MacOriginalWrapper
    $onlineDir=Join-Path $C.Output 'baseline-verify';$online=& $commands['Read-H3911Artifact'] (Join-Path $onlineDir 'application.jar') (Join-Path $onlineDir 'classes') (Join-Path $onlineDir 'test-classes') -SourceProfile MacOriginalWrapper
    & ${function:Assert-MPackage} ($C.ScreenOwnerReads-is[array]-and$C.ScreenOwnerReads.Count-eq6) 'Six retained qualification owner reads required'
    $probes=@();foreach($ownerRead in $C.ScreenOwnerReads){$probes+=if($FixtureOnly){& $FixtureHooks.Probes $C $ownerRead}else{& ${function:Read-MPackageProbes} $C $commands $ownerRead}}
    & ${function:Assert-MPackage} ($probes.Count-eq12) 'Qualification auxiliary ledger incomplete'
    if($RuntimeApproved){$null=& ${function:Assert-MPackageProbeLedger} $probes}
    $boundary=if($FixtureOnly){& $FixtureHooks.Census $C $C.ScreenOwner}else{& $commands['Read-H3911DarwinScopedCensus'] -Context $C -Expected $C.ScreenOwner -RuntimeApproved}
    $null=& $commands['Assert-LifeUidCensus'] $C $C.ScreenOwner $boundary
    & ${function:Assert-MPackage} (-not$boundary.expectedIdentityGone-and$boundary.sameJdkJava.Count-eq1-and$boundary.knownLive.Count-eq1) 'Completed owned-live UID boundary required'
    if($RuntimeApproved){& ${function:Assert-MPackage} ($boundary.evidenceKind-ceq'native-mac-launch-uid-census-v2') 'Actual UID reader required'}
    $out=Join-Path $C.Output 'mac-package-screen';& ${function:Assert-MPackage} (-not(Test-Path $out)) 'Fresh sampling output required';New-Item $out -ItemType Directory|Out-Null
    $before=[Environment]::GetEnvironmentVariables('Process');$cwd=(Get-Location).Path;$native=[Environment]::CurrentDirectory;$samples=@();$captures=@();$seals=@();$reference=$null;$primary=$null
    $result=@{status='FAIL';fixtureOnly=[bool]$FixtureOnly;requiresCallerPrivateCleanup=$true;caller24Integrated=$false;noObserversAllocated=$true;boundary=$boundary;qualificationProcesses=$qualificationSeals;fullGateBindings=$gates;noFreshSkipTestsCoverageClaim=$true;proposedMainAuxMaximum=28;proposedParentAuxMaximum=2;proposedTotalAuxMaximum=30}
    try{
        $plan=& $commands['Get-H3911RetainedProtocol'] -Mode PackageScreen -Platform MacOS
        foreach($step in @($plan.calls|Where-Object {$_.kind-in@('clean','package')})){
            $null=& ${function:Assert-MPackageAdmission} $C $commands ([bool]$FixtureOnly) $FixtureHooks ($step.kind-ceq'package')
            if($step.kind-ceq'package'){
                $owner=if($FixtureOnly){& $FixtureHooks.Owner $C}else{& $commands['Read-H3911DarwinEffectiveOwner'] -Context $C -RuntimeApproved}
                & ${function:Assert-MPackage} (& $commands['Test-LifeSame'] $C.ScreenOwner $owner) 'Native owner lifetime changed'
                foreach($key in 'daemonId','home','registryFile','executable','jniPath'){& ${function:Assert-MPackage} ($owner[$key]-ceq$C.ScreenOwner[$key]) 'Native owner/JNI identity changed'}
                $probes+=if($FixtureOnly){& $FixtureHooks.Probes $C $owner}else{& ${function:Read-MPackageProbes} $C $commands $owner}
                & ${function:Assert-MPackage} ($probes.Count-le28) 'Actual auxiliary budget exceeded'
                if($RuntimeApproved){$null=& ${function:Assert-MPackageProbeLedger} $probes}
                $census=if($FixtureOnly){& $FixtureHooks.Census $C $owner}else{& $commands['Read-H3911DarwinScopedCensus'] -Context $C -Expected $owner -RuntimeApproved}
                $null=& $commands['Assert-LifeUidCensus'] $C $owner $census
                & ${function:Assert-MPackage} (-not$census.expectedIdentityGone-and$census.sameJdkJava.Count-eq1-and$census.knownLive.Count-eq1) 'Prepackage UID owner/visibility HOLD'
            }
            $tokens=@('--batch-mode','--no-transfer-progress','-Dserver.address=127.0.0.1',"-Dmaven.repo.local=$($C.Cache)",'--settings',$C.Settings,'--global-settings',$C.Settings,'--file',(Join-Path $C.Project 'pom.xml'),'-o')
            if($step.route-ceq'B'){$tokens+=@('--serial',"-Djava.home=$($C.Jdk)","-Dmvnd.daemonStorage=$($C.Registry)")};$tokens+=if($step.kind-ceq'clean'){@('clean')}else{@('-DskipTests','package')}
            if($RuntimeApproved){$null=& $commands['Assert-H3911KernelPOM'] $C $tokens $C.Project}
            $exe=if($step.route-ceq'A'){Join-Path $C.Project 'mvnw'}else{Join-Path $C.Home 'bin/mvnd'};$log=Join-Path $out ($step.label+'.log')
            $call=@{label=$step.label;route=$step.route;timed=$step.timed;exit=$null;log=$log};$C.Calls+=,$call;$notBefore=[DateTimeOffset]::UtcNow
            $exit=if($FixtureOnly){& $FixtureHooks.Process $C $step $tokens $log $exe}else{& $commands['Invoke-H3911DirectNative'] -Exe $exe -Tokens $tokens -Log $log -Context $C -WorkingDirectory $C.Project -Platform Posix}
            $call.exit=$exit;& ${function:Assert-MPackage} ($exit-is[int]-and$exit-eq0) 'Mac package/clean nonzero'
            $seal=& ${function:Assert-MPackageClock} $commands $log $exe $tokens $C.Project $notBefore;$call.processEvidence=$seal;$seals+=,$seal
            if($step.kind-ceq'package'){
                & ${function:Assert-MPackage} ((Get-Content $log -Raw)-match'Goal makeAggregateBom requires online mode.*skipping') 'Offline SBOM-only omission not evidenced'
                $project=if($FixtureOnly){& $FixtureHooks.Capture $C $step}else{$C.Project};$jar=@(Get-ChildItem (Join-Path $project 'target') -Filter '*.jar')
                & ${function:Assert-MPackage} ($jar.Count-eq1) 'One offline application JAR required'
                $dir=Join-Path $out $step.label;$offline=& $commands['Read-H3911Artifact'] $jar[0].FullName (Join-Path $project 'target/classes') (Join-Path $project 'target/test-classes') $dir -SourceProfile MacOriginalWrapper -Offline
                $null=& $commands['Assert-H3911OfflineDelta'] $online $onlineDir $offline $dir
                if($reference){$null=& $commands['Compare-H3911Artifacts'] $reference $dir -SourceProfile MacOriginalWrapper -Offline}else{$reference=$dir}
                $captures+=@{label=$step.label;jarSha256=$offline.jarSha256;entries=$offline.entries.Count;regular=@($offline.entries|Where-Object {-not$_.directory}).Count;raw=$offline.raw.Count}
                if($step.timed){$samples+=@{label=$step.label;route=$step.route;timed=$true;seconds=$seal.seconds;processEvidence=$seal}}
            }
        }
        & ${function:Assert-MPackage} ($captures.Count-eq8-and$samples.Count-eq6-and$probes.Count-eq28) 'Exact16/8/6 and actual28 auxiliary ledger required'
        foreach($seal in @($qualificationSeals)+@($seals)+@($probes)){$null=& $commands['Assert-PScreenSeal'] $seal}
        foreach($gate in $gates){foreach($binding in $gate.files){$now=& $commands['Get-PScreenFileBinding'] $binding.path;& ${function:Assert-MPackage} ($now.sha256-ceq$binding.sha256-and$now.bytes-eq$binding.bytes) 'Full online gate evidence changed'}}
        $null=& ${function:Assert-MPackageAdmission} $C $commands ([bool]$FixtureOnly) $FixtureHooks $false
        $final=if($FixtureOnly){& $FixtureHooks.Census $C $C.ScreenOwner}else{& $commands['Read-H3911DarwinScopedCensus'] -Context $C -Expected $C.ScreenOwner -RuntimeApproved}
        $null=& $commands['Assert-LifeUidCensus'] $C $C.ScreenOwner $final
        & ${function:Assert-MPackage} (-not$final.expectedIdentityGone-and$final.sameJdkJava.Count-eq1-and$final.knownLive.Count-eq1) 'Final live UID owner changed'
        if($RuntimeApproved){& ${function:Assert-MPackage} ((Get-FileHash $C.ScreenOwner.jniPath).Hash-ceq'72F98DFA637267E89161F984F6BAB2B9E5653B5F888A41C7733F237070EBE6E9') 'Final JNI bytes changed'};$result.finalCensus=$final
        $raw=& $commands['Get-H3911PackageDecision'] $samples -FixtureOnly:$FixtureOnly
        $result.raw=@{baselineMedian=$raw.baselineMedian;candidateMedian=$raw.candidateMedian;medianLowerPercent=$raw.medianLowerPercent;macRegressionPercent=(-$raw.medianLowerPercent);allPairsFavorable=$raw.allPairsFavorable}
        $result.disposition=if($FixtureOnly){'FIXTURE_ONLY_NOT_PERFORMANCE'}else{'MAC_RAW_ONLY_PENDING_CALLER_STOP_AND_MATCHED_SCREEN'};$result.status='OPERATOR_COMPLETE_CALLER_STOP_STILL_REQUIRED'
    }catch{$primary=$_;$result.failure=$_.ToString()}
    finally{
        $after=[Environment]::GetEnvironmentVariables('Process');$same=$before.Count-eq$after.Count;foreach($k in $before.Keys){if(-not$after.Contains($k)-or$before[$k]-cne$after[$k]){$same=$false}}
        $result.callerStateEqual=$same-and(Get-Location).Path-ceq$cwd-and[Environment]::CurrentDirectory-ceq$native;$result.samples=$samples;$result.offlineCaptures=$captures;$result.auxiliaryLedger=$probes;$result.actualMainAuxCount=$probes.Count
        $result.clientCalls=@($C.Calls|Select-Object -Skip 7)
        if(-not$result.callerStateEqual){$result.status='FAIL';$result.raw=$null;if(-not$primary){$primary=[InvalidOperationException]::new('Sampling caller state changed')}}
        try{$result|ConvertTo-Json -Depth 40 -WarningAction Stop|Set-Content (Join-Path $out 'operator.json')}catch{if(-not$primary){$primary=$_}}
    }
    if($primary){throw $primary};& ${function:Assert-MPackage} ($result.callerStateEqual) 'Sampling caller state changed';$result
}
Export-ModuleMember -Function Invoke-H3911MacPackageSamplingOperator
