function Assert-MQ($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function Get-MQModeContract([ValidateSet('Qualify','PackageScreen',IgnoreCase=$false)][string]$Mode='Qualify'){
    $screen=$Mode-ceq'PackageScreen'
    @{mode=$Mode;normalMaximum=$(if($screen){24}else{8});emergencyMaximum=$(if($screen){25}else{9});mainAuxMaximum=$(if($screen){28}else{12});parentAuxMaximum=2;totalAuxMaximum=$(if($screen){30}else{14});deadlineMilliseconds=$(if($screen){1800000}else{600000});hostedJobProposalMinutes=$(if($screen){40}else{30})}
}
function Get-MQSamplingCommands {
    $path=Join-Path $PSScriptRoot 'H3911.MacPackageSampling.psm1'
    & ${function:Assert-MQ} ((Microsoft.PowerShell.Utility\Get-FileHash $path).Hash-ceq'D214A345F7AD2B0A9FC7B85C9B795927AE4FA2A37FA1CEFD007EE1EB59141F85') 'Pinned Mac operator differs'
    $m=Import-Module $path -Scope Local -PassThru -DisableNameChecking
    $import=& $m {Get-Command Import-MPackage -CommandType Function}
    & ${function:Assert-MQ} ($import-is[Management.Automation.FunctionInfo]-and$import.Module.Path-ceq$path-and$import.Name-ceq'Import-MPackage') 'Operator import origin differs'
    $bound=& $import
    foreach($name in 'Invoke-H3911MacPackageSamplingOperator','Assert-MPackageClock','Assert-MPackageProbeLedger'){$command=& $m {param($n)Get-Command $n -CommandType Function} $name;& ${function:Assert-MQ} ($command-is[Management.Automation.FunctionInfo]-and$command.Name-ceq$name-and$command.Module.Path-ceq$path) 'Operator command origin differs';$bound[$name]=$command}
    $common=$bound['Get-H3911RetainedProtocol'].Module
    foreach($name in 'Assert-PScreenTestFacts','Assert-PScreenCoverageFacts'){$command=& $common {param($n)Get-Command $n -CommandType Function} $name;& ${function:Assert-MQ} ($command-is[Management.Automation.FunctionInfo]-and$command.Name-ceq$name-and$command.Module.Path-ceq(Join-Path $PSScriptRoot 'H3911.PackageSampling.psm1')) 'Semantic gate command origin differs';$bound[$name]=$command}
    $bound
}
function Assert-MQSamplingEvidence($C,$Sampling,[bool]$FixtureOnly){
    & ${function:Assert-MQ} ($Sampling-is[hashtable]-and$Sampling.status-is[string]-and$Sampling.status-ceq'OPERATOR_COMPLETE_CALLER_STOP_STILL_REQUIRED'-and$Sampling.fixtureOnly-is[bool]-and$Sampling.fixtureOnly-eq$FixtureOnly-and$Sampling.clientCalls-is[array]-and$Sampling.clientCalls.Count-eq16-and$Sampling.offlineCaptures-is[array]-and$Sampling.offlineCaptures.Count-eq8-and$Sampling.samples-is[array]-and$Sampling.samples.Count-eq6-and$Sampling.auxiliaryLedger-is[array]-and$Sampling.auxiliaryLedger.Count-eq28-and($Sampling.actualMainAuxCount-is[int]-or$Sampling.actualMainAuxCount-is[long])-and$Sampling.actualMainAuxCount-eq28-and$Sampling.callerStateEqual-is[bool]-and$Sampling.callerStateEqual) 'Typed complete Mac sampling return required'
    $commands=& ${function:Get-MQSamplingCommands};$plan=& $commands['Get-H3911RetainedProtocol'] -Mode PackageScreen -Platform MacOS;$steps=@($plan.calls|Where-Object {$_.kind-in@('clean','package')})
    if(-not$FixtureOnly){
        foreach($pair in @(@('baseline-verify','baseline'),@('candidate-verify','candidate'))){$null=& $commands['Assert-PScreenFullGate'] $C $commands $pair[0] $C.ScreenVerification[$pair[1]]}
        $null=& $commands['Compare-H3911Artifacts'] (Join-Path $C.Output 'baseline-verify') (Join-Path $C.Output 'candidate-verify') -SourceProfile MacOriginalWrapper
    }
    $sampleIndex=0
    for($i=0;$i-lt16;$i++){
        $call=$Sampling.clientCalls[$i];$step=$steps[$i]
        & ${function:Assert-MQ} ($call-is[hashtable]-and$call.label-is[string]-and$call.label-ceq$step.label-and$call.route-is[string]-and$call.route-ceq$step.route-and$call.timed-is[bool]-and$call.timed-eq$step.timed-and($call.exit-is[int]-or$call.exit-is[long])-and$call.exit-eq0) 'Exact sixteen clean/package returns required'
        if(-not$FixtureOnly){
            $tokens=@('--batch-mode','--no-transfer-progress','-Dserver.address=127.0.0.1',"-Dmaven.repo.local=$($C.Cache)",'--settings',$C.Settings,'--global-settings',$C.Settings,'--file',(Join-Path $C.Project 'pom.xml'),'-o')
            if($step.route-ceq'B'){$tokens+=@('--serial',"-Djava.home=$($C.Jdk)","-Dmvnd.daemonStorage=$($C.Registry)")};$tokens+=if($step.kind-ceq'clean'){@('clean')}else{@('-DskipTests','package')}
            $exe=if($step.route-ceq'A'){Join-Path $C.Project 'mvnw'}else{Join-Path $C.Home 'bin/mvnd'};$log=Join-Path $C.Output ('mac-package-screen/'+$step.label+'.log')
            $seal=& $commands['Assert-MPackageClock'] $commands $log $exe $tokens $C.Project ([DateTimeOffset]$C.ScreenNotBefore)
            foreach($part in 'receipt','stdout','stderr'){& ${function:Assert-MQ} ($call.processEvidence[$part].path-is[string]-and$call.processEvidence[$part].path-ceq$seal[$part].path-and$call.processEvidence[$part].sha256-is[string]-and$call.processEvidence[$part].sha256-ceq$seal[$part].sha256-and($call.processEvidence[$part].bytes-is[int]-or$call.processEvidence[$part].bytes-is[long])-and$call.processEvidence[$part].bytes-eq$seal[$part].bytes) 'Native sampling seals changed'}
            & ${function:Assert-MQ} (($call.processEvidence.pid-is[int]-or$call.processEvidence.pid-is[long])-and$call.processEvidence.pid-eq$seal.pid-and($call.processEvidence.seconds-is[double]-or$call.processEvidence.seconds-is[decimal]-or$call.processEvidence.seconds-is[int]-or$call.processEvidence.seconds-is[long])-and$call.processEvidence.seconds-eq$seal.seconds) 'Captured PID/duration differs from actual 6CF receipt'
            foreach($key in 'createdUtc','exe','workingDirectory'){& ${function:Assert-MQ} ($call.processEvidence[$key]-is[string]-and$call.processEvidence[$key]-ceq$seal[$key]) 'Captured process identity differs from sealed receipt'}
        }
        if($step.timed){
            $sample=$Sampling.samples[$sampleIndex];$sampleIndex++
            & ${function:Assert-MQ} ($sample.label-is[string]-and$sample.label-ceq$step.label-and$sample.route-is[string]-and$sample.route-ceq$step.route-and($sample.seconds-is[double]-or$sample.seconds-is[decimal]-or$sample.seconds-is[int]-or$sample.seconds-is[long])-and$sample.seconds-eq$call.processEvidence.seconds-and$sample.processEvidence.receipt.sha256-is[string]-and$sample.processEvidence.receipt.sha256-ceq$call.processEvidence.receipt.sha256) 'Six retained samples must bind the actual timed package receipts'
        }
    }
    $packages=@($steps|Where-Object kind -ceq package)
    for($i=0;$i-lt8;$i++){$capture=$Sampling.offlineCaptures[$i];& ${function:Assert-MQ} ($capture-is[hashtable]-and$capture.label-is[string]-and$capture.label-ceq$packages[$i].label-and($capture.entries-is[int]-or$capture.entries-is[long])-and$capture.entries-eq333-and($capture.regular-is[int]-or$capture.regular-is[long])-and$capture.regular-eq284-and($capture.raw-is[int]-or$capture.raw-is[long])-and$capture.raw-eq5-and$capture.jarSha256-is[string]-and$capture.jarSha256-cmatch'^[A-F0-9]{64}$') 'Strict eight offline captures required'}
    if(-not$FixtureOnly){
        $onlineDir=Join-Path $C.Output 'baseline-verify';$online=& $commands['Read-H3911Artifact'] (Join-Path $onlineDir 'application.jar') (Join-Path $onlineDir 'classes') (Join-Path $onlineDir 'test-classes') -SourceProfile MacOriginalWrapper
        foreach($capture in $Sampling.offlineCaptures){$dir=Join-Path $C.Output ('mac-package-screen/'+$capture.label);$artifact=& $commands['Read-H3911Artifact'] (Join-Path $dir 'application.jar') (Join-Path $dir 'classes') (Join-Path $dir 'test-classes') -SourceProfile MacOriginalWrapper -Offline;& ${function:Assert-MQ} ($artifact.jarSha256-ceq$capture.jarSha256) 'Retained offline JAR changed';$null=& $commands['Assert-H3911OfflineDelta'] $online $onlineDir $artifact $dir}
    }
    $raw=& $commands['Get-H3911PackageDecision'] $Sampling.samples -FixtureOnly:$FixtureOnly
    foreach($key in 'baselineMedian','candidateMedian','medianLowerPercent','macRegressionPercent'){& ${function:Assert-MQ} ($Sampling.raw[$key]-is[double]-or$Sampling.raw[$key]-is[decimal]-or$Sampling.raw[$key]-is[int]-or$Sampling.raw[$key]-is[long]) 'Scalar numeric raw Mac facts required'}
    foreach($key in 'baselineMedian','candidateMedian','medianLowerPercent'){& ${function:Assert-MQ} ($Sampling.raw[$key]-eq$raw[$key]) 'Raw Mac medians differ'}
    & ${function:Assert-MQ} ($Sampling.raw.allPairsFavorable-is[bool]-and$Sampling.raw.allPairsFavorable-eq$raw.allPairsFavorable-and$Sampling.raw.macRegressionPercent-eq(-$raw.medianLowerPercent)) 'Raw Mac direction/regression differs'
    if(-not$FixtureOnly){
        $actualProbes=@()
        foreach($probe in $Sampling.auxiliaryLedger){
            & ${function:Assert-MQ} ($probe.probe-is[string]-and$probe.probe-cin@('VM.system_properties','VM.dynlibs')-and($probe.targetPid-is[int]-or$probe.targetPid-is[long])-and$probe.targetPid-eq$C.ScreenOwner.pid) 'Closed jcmd ledger target differs'
            $actual=& $commands['Assert-MPackageClock'] $commands $probe.stdout.path (Join-Path $C.Jdk 'bin/jcmd') @([string]$C.ScreenOwner.pid,$probe.probe) $C.Temp ([DateTimeOffset]$C.ScreenNotBefore)
            $birth=[DateTimeOffset]::MinValue
            & ${function:Assert-MQ} (($probe.pid-is[int]-or$probe.pid-is[long])-and$probe.pid-eq$actual.pid-and$probe.createdUtc-is[string]-and$probe.createdUtc-cmatch'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$'-and[DateTimeOffset]::TryParse($probe.createdUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$birth)-and$birth.UtcTicks-eq[DateTimeOffset]::Parse($actual.createdUtc,[Globalization.CultureInfo]::InvariantCulture).UtcTicks) 'Claimed probe lifetime differs from reopened receipt'
            foreach($part in 'receipt','stdout','stderr'){& ${function:Assert-MQ} ($probe[$part]-is[hashtable]-and$probe[$part].path-is[string]-and$probe[$part].path-ceq$actual[$part].path-and($probe[$part].bytes-is[int]-or$probe[$part].bytes-is[long])-and$probe[$part].bytes-eq$actual[$part].bytes-and$probe[$part].sha256-is[string]-and$probe[$part].sha256-ceq$actual[$part].sha256) 'Claimed probe file binding differs from reopened receipt'}
            $null=& $commands['Assert-PScreenSeal'] $actual;$actualProbes+=,$actual
        }
        $null=& $commands['Assert-MPackageProbeLedger'] $actualProbes
    }
}
function Get-MQReportRole([string]$Relative){
    if(-not$Relative-or$Relative.Length-gt512-or$Relative-match'[\x00-\x1f\x7f]|(^/|\\|:|//|(^|/)\.\.?(/|$))'-or$Relative-match'(?i)(^|/)(home|registry|sdk|archives|rawenv|auth)(/|$)'){return $null}
    if($Relative-cmatch'^surefire/TEST-[^/]+\.xml$'){return 'surefire-xml'}
    if($Relative-cmatch'^surefire/[^/]+\.txt$'){return 'surefire-text'}
    if($Relative-cmatch'^jacoco/(?:[A-Za-z0-9_$.-]+/)*[A-Za-z0-9_$.-]+\.(xml|html|csv|css|js|gif|png|svg)$'){return 'jacoco-'+[IO.Path]::GetExtension($Relative).Substring(1)}
    return $null
}
function New-MQReportByteWitness([string]$CaptureRoot,[string]$Phase){
    & ${function:Assert-MQ} ($Phase-cin@('baseline-verify','candidate-verify')) 'Exact capture phase required'
    $root=& ${function:Resolve-MQPath} $CaptureRoot;$rows=@()
    foreach($name in 'surefire','jacoco'){
        $directory=& ${function:Resolve-MQPath} (Join-Path $root $name)
        & ${function:Assert-MQ} ((Get-Item -LiteralPath $directory -Force)-is[IO.DirectoryInfo]) 'Ordinary report directory required'
        foreach($file in @(Get-ChildItem -LiteralPath $directory -Recurse -Force|Sort-Object FullName)){
            & ${function:Assert-MQ} (-not$file.LinkType-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked report member forbidden'
            if($file-isnot[IO.FileInfo]){continue}
            $relative=[IO.Path]::GetRelativePath($root,$file.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47)
            $role=& ${function:Get-MQReportRole} $relative
            & ${function:Assert-MQ} ($role-and$file.Length-le16777216-and$rows.Count-lt2000) 'Unknown/oversized report role'
            $null=& ${function:Resolve-MQPath} $file.FullName
            $stream=[IO.File]::OpenRead($file.FullName)
            try{
                [byte[]]$prefix=[byte[]]::new(4);$n=$stream.Read($prefix,0,4)
                & ${function:Assert-MQ} (-not($n-ge2-and(($prefix[0]-eq0x50-and$prefix[1]-eq0x4b)-or($prefix[0]-eq0x1f-and$prefix[1]-eq0x8b)-or($prefix[0]-eq0x4d-and$prefix[1]-eq0x5a)))) 'Archive/executable shaped report forbidden'
            }finally{$stream.Dispose()}
            $rows+=@{name=$relative;role=$role;type='file';bytes=$file.Length;sha256=(Microsoft.PowerShell.Utility\Get-FileHash $file.FullName).Hash}
        }
    }
    & ${function:Assert-MQ} ($rows.Count-gt0) 'Nonempty report witness required'
    @{schema='H3911.report-bytes.v1';phase=$Phase;rows=$rows}
}
function Get-MQRuntimeInputs {
    $path=Join-Path $PSScriptRoot 'H3911.MacRuntimeInputs.psm1'
    & ${function:Assert-MQ} ((Microsoft.PowerShell.Utility\Get-FileHash $path).Hash-ceq'4B420788E649023771CC59DE0F7C5C67A94E7F19CC57F3EBD4B80E3CFA87BD7F') 'Mac runtime-input leaf differs'
    $cached=Get-Variable -Name MQRuntimeInputs -Scope Script -ErrorAction SilentlyContinue
    if(-not$cached){
        $m=Import-Module $path -Scope Local -PassThru -DisableNameChecking;$bound=@{}
        foreach($name in 'Import-H3911MacRuntimeInputs','Assert-H3911MacSdk','Resolve-H3911MacInputPath','Assert-H3911MacInputDisjoint'){
            $command=$m.ExportedCommands[$name];& ${function:Assert-MQ} ($command-is[Management.Automation.FunctionInfo]-and$command.Name-ceq$name-and$command.Module.Path-ceq$path) 'Mac runtime-input command origin differs';$bound[$name]=$command
        };$script:MQRuntimeInputs=$bound
    };$script:MQRuntimeInputs
}
function Import-MQ {$inputs=& ${function:Get-MQRuntimeInputs};& $inputs['Import-H3911MacRuntimeInputs']}
function Resolve-MQPath([string]$Path,[switch]$Missing){$inputs=& ${function:Get-MQRuntimeInputs};& $inputs['Resolve-H3911MacInputPath'] $Path -Missing:$Missing}
function Assert-MQDisjoint([string]$A,[string]$B){$inputs=& ${function:Get-MQRuntimeInputs};& $inputs['Assert-H3911MacInputDisjoint'] $A $B}
function Get-MQWatch([string]$Root){
    @(@(Get-ChildItem (Join-Path $Root 'target') -File -Recurse -Force -ErrorAction SilentlyContinue)+@(foreach($name in 'nohttp-checkstyle.xml','nohttp-checkstyle-suppressions.xml'){$p=Join-Path $Root ('src/checkstyle/'+$name);if(Test-Path -LiteralPath $p){Get-Item -LiteralPath $p}})|Sort-Object FullName|ForEach-Object{@{path=$_.FullName;bytes=$_.Length;sha256=(Microsoft.PowerShell.Utility\Get-FileHash $_.FullName).Hash}})
}
function Assert-MQSdk($C,[string]$Archive){$inputs=& ${function:Get-MQRuntimeInputs};& $inputs['Assert-H3911MacSdk'] $C $Archive}
function Read-MQOwner($C,$Commands,$Hooks){
    if($C.FixtureOnly){$owner=& $Hooks.Owner $C}else{$owner=& ($Commands['Read-H3911DarwinEffectiveOwner']) -Context $C -RuntimeApproved}
    & ${function:Assert-MQ} ($owner-and$owner.pid-gt0-and$owner.created-and$owner.daemonId-cmatch'^[a-f0-9]{8}$'-and$owner.home-ceq$C.Home-and$owner.registryFile-ceq(Join-Path $C.Registry 'registry.bin')-and$owner.executable-ceq(Join-Path $C.Jdk 'bin/java')) 'Mac private PID/id/registry owner differs'
    if($C.ContainsKey('OwnerReads')){$C.OwnerReads+=,$owner};$owner
}
function Assert-MQSame($A,$B){
    foreach($key in 'pid','created','daemonId','home','registryFile','executable','jniPath'){& ${function:Assert-MQ} ($A[$key]-ceq$B[$key]) 'Mac owner identity changed'}
}
function Assert-MQEarlyCensus($C,$Anchor,$Census,$Commands){
    $scope='launch-effective-UID admitted-JDK Java plus explicitly tracked identities'
    & ($Commands['Assert-LifeUidCensus']) $C $Anchor $Census
    & ${function:Assert-MQ} ($Census.jdkExecutable-is[string]-and$Census.jdkExecutable-ceq(Join-Path $C.Jdk 'bin/java')-and-not$Census.expectedIdentityGone) 'Early scoped census incomplete/foreign/owner absent'
    & ${function:Assert-MQ} ($C.KnownOwnedIdentities-is[array]-and$Census.tracked-is[array]-and$Census.tracked.Count-eq(1+$C.KnownOwnedIdentities.Count)-and$Census.sameJdkJava-is[array]-and$Census.sameJdkJava.Count-eq1-and$Census.knownLive-is[array]-and$Census.knownLive.Count-eq1) 'Early scoped census tracked/live set differs'
    $wanted=@($Anchor)+@($C.KnownOwnedIdentities);$seen=[Collections.Generic.HashSet[int]]::new()
    foreach($identity in @($wanted)+@($Census.tracked)+@($Census.sameJdkJava)+@($Census.knownLive)){
        & ${function:Assert-MQ} ($identity-is[hashtable]-and($identity.pid-is[int]-or$identity.pid-is[long])-and$identity.pid-gt0-and$identity.pid-le[int]::MaxValue-and$identity.created-is[string]-and$identity.created-cmatch'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$'-and$identity.executable-is[string]-and$identity.executable.Length-gt0) 'Early census typed identity required'
    }
    for($i=0;$i-lt$wanted.Count;$i++){
        & ${function:Assert-MQ} ($seen.Add([int]$Census.tracked[$i].pid)-and(& ($Commands['Test-LifeSame']) $wanted[$i] $Census.tracked[$i])) 'Early tracked PID/birth/executable differs'
    }
    foreach($key in 'daemonId','home','registryFile','jniPath'){& ${function:Assert-MQ} ($Census.tracked[0][$key]-is[string]-and$Census.tracked[0][$key]-ceq$Anchor[$key]) 'Early tracked owner scope differs'}
    foreach($identity in $Census.sameJdkJava[0],$Census.knownLive[0]){& ${function:Assert-MQ} (& ($Commands['Test-LifeSame']) $Anchor $identity) 'Early live owner reused/foreign'}
    $summary=@{status='COMPLETE_OWNED_RUNNING_SCOPE_CONFIRMED';complete=$true;scope=$scope;ownerPid=$Anchor.pid;trackedCount=$Census.tracked.Count;sameJdkCount=1;knownLiveCount=1;errors=0;ownerLive=$true;absenceAsserted=$false;afterCall='daemon-project';beforeCall='baseline-maven-home';fixtureOnly=$C.FixtureOnly}
    if(-not$C.FixtureOnly){& ${function:Assert-MQ} ($Census.evidenceKind-ceq'native-mac-launch-uid-census-v2') 'Actual native UID census required'}
    $summary.schema=$Census.schema;$summary.uidProof=$Census.uidProof
    $summary
}
function Stop-MQ($C,$Commands,$Anchor,$Hooks,[switch]$Emergency){
    if(-not$Emergency){$null=& ($Commands['Assert-H3911Source']) $C;if(-not$C.FixtureOnly){$null=& ($Commands['Assert-H3911Darwin103Distribution']) $C.Home -RequireNativeModes}}
    if($C.FixtureOnly){$owner=& ${function:Read-MQOwner} $C $Commands $Hooks;& ${function:Assert-MQSame} $owner $Anchor;$plan=& $Hooks.StopPlan $C $Anchor ([bool]$Emergency)}
    else{$plan=& ($Commands['New-H3911DarwinPrivateStopPlan']) -Context $C -Expected $Anchor -RuntimeApproved -Emergency:$Emergency}
    & ${function:Assert-MQ} ($plan.exe-ceq(Join-Path $C.Home 'bin/mvnd')-and$plan.workingDirectory-ceq$C.Temp-and$plan.expectedPid-eq$Anchor.pid-and$plan.expectedCreated-ceq$Anchor.created) 'Admitted private native stop plan differs'
    $call=@{label=$(if($Emergency){'emergency-stop'}else{'normal-stop'});exit=$null;timed=$false};$C.Calls+=,$call
    $call.exit=if($C.FixtureOnly){& $Hooks.Stop $C $plan}else{& ($Commands['Invoke-H3911DirectNative']) -Exe $plan.exe -Tokens $plan.tokens -Log (Join-Path $C.Output ($call.label+'.log')) -Context @{Project=$C.Temp} -WorkingDirectory $C.Temp -Platform Posix}
    $proof=if($C.FixtureOnly){& $Hooks.Confirm $C $Anchor $call.exit ([bool]$Emergency)}else{& ($Commands['Confirm-H3911DarwinCliStop']) -Context $C -Expected $Anchor -StopExit $call.exit -RuntimeApproved -Emergency:$Emergency}
    & ${function:Assert-MQ} ($call.exit-eq0-and($Emergency-or$proof.status-ceq'NORMAL_CLI_ROUTE_SCOPED_ABSENCE_CONFIRMED')) 'Mac native CLI stop/complete scoped absence failed'
    $proof
}
function Invoke-H3911MacQualifier {
    param([string]$Project,[string]$Jdk,[string]$JdkArchive,[string]$DistributionArchive,[string]$Owned,[string]$WatchRoot,[switch]$RuntimeApproved,[switch]$FixtureOnly,[hashtable]$FixtureHooks,[ValidateSet('Qualify','PackageScreen',IgnoreCase=$false)][string]$Mode='Qualify')
    $contract=& ${function:Get-MQModeContract} $Mode
    & ${function:Assert-MQ} ($RuntimeApproved-xor$FixtureOnly) 'Exactly one Mac runtime or fixture mode required'
    & ${function:Assert-MQ} (-not$RuntimeApproved-or(-not$FixtureHooks-and$IsMacOS-and[Runtime.InteropServices.RuntimeInformation]::OSArchitecture-eq'Arm64'-and[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture-eq'Arm64')) 'Native ARM64 Mac required; runtime callbacks prohibited'
    $Project=& ${function:Resolve-MQPath} $Project;$Owned=& ${function:Resolve-MQPath} $Owned -Missing
    $Jdk=& ${function:Resolve-MQPath} $Jdk;$WatchRoot=& ${function:Resolve-MQPath} $WatchRoot
    if($JdkArchive){$JdkArchive=& ${function:Resolve-MQPath} $JdkArchive}
    if($DistributionArchive){$DistributionArchive=& ${function:Resolve-MQPath} $DistributionArchive}
    & ${function:Assert-MQDisjoint} $Project $Owned
    foreach($path in @($Jdk,$JdkArchive,$DistributionArchive)|Where-Object{$_}){$physical=& ${function:Resolve-MQPath} $path;& ${function:Assert-MQDisjoint} $Project $physical;& ${function:Assert-MQDisjoint} $Owned $physical}
    & ${function:Assert-MQ} (-not(Test-Path -LiteralPath $Owned)) 'Fresh Mac owned root required'
    if($FixtureOnly){foreach($key in 'Setup','Dispatch','Owner','Census','Stock','Verify','Compare','StopPlan','Stop','Confirm'){& ${function:Assert-MQ} ($FixtureHooks[$key]-is[scriptblock]) 'Complete explicit Mac fixture hooks required'}}
    if($FixtureOnly-and$Mode-ceq'PackageScreen'){& ${function:Assert-MQ} ($FixtureHooks.Sampling-is[hashtable]) 'Explicit native-boundary sampler fixtures required'}
    $commands=& ${function:Import-MQ}
    $samplingCommands=if($Mode-ceq'PackageScreen'){& ${function:Get-MQSamplingCommands}}else{$null}
    & ${function:Assert-MQ} ((Microsoft.PowerShell.Utility\Get-FileHash (Join-Path $PSScriptRoot 'mac-jdk25-identity.json')).Hash-ceq'B4C08E1980A986419E9B402E9DF2B8DBA2C800E62E20995B1C9420EBE031678E') 'Trusted Mac JDK manifest differs'
    $names=@('JAVA_HOME','PATH','MAVEN_USER_HOME','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MVNW_PREFER_PWSH','MVND_CLIENT','MVND_HOME','MVND_DAEMON_STORAGE','MVND_OPTS','MVND_JVM_ARGS','TMP','TEMP','TMPDIR')
    foreach($name in $names|Where-Object{$_-notin@('JAVA_HOME','PATH','TMP','TEMP','TMPDIR')}){& ${function:Assert-MQ} (-not[Environment]::GetEnvironmentVariable($name)) "Unreviewed Mac environment option $name"}
    foreach($name in 'MAVEN_PROJECTBASEDIR','MAVEN_BASEDIR','MAVEN_CONFIG','MAVEN_CMD_LINE_ARGS','MAVEN_MULTIMODULE_PROJECT_DIRECTORY','MVND_PROJECT_BASE_DIR'){& ${function:Assert-MQ} (-not[Environment]::GetEnvironmentVariable($name)) 'Project override before allocation'}
    $c=@{Project=$Project;Jdk=$Jdk;Home=(Join-Path $Owned 'home');Output=(Join-Path $Owned 'output');Cache=(Join-Path $Owned 'cache');Settings=(Join-Path $Owned 'settings.xml');Registry=(Join-Path $Owned 'registry');Temp=(Join-Path $Owned 'temp');Platform='MacOS';SourceProfile='MacOriginalWrapper';FixtureOnly=[bool]$FixtureOnly;Calls=@();Contexts=@{};KnownOwnedIdentities=@();ExpectedJavaSha256='827ECF403DBFA3CF88E7310B44AD93CB27B75C7E15A7E461DDE0CEE775BB196F';ExpectedJcmdSha256='2D4CB05FEFFBB7F81D6EB5295A84D0DA8B9098AC1A0BD9C314B87585E9498C1A'}
    $c.OwnerReads=@();$c.ScreenNotBefore=[DateTimeOffset]::UtcNow.ToString('o')
    $null=& ($commands['Assert-H3911Source']) $c
    if($RuntimeApproved){$null=& ${function:Assert-MQSdk} $c $JdkArchive}
    $before=& ($commands['PortableEnvironmentSnapshot']);$cwd=(Get-Location).Path;$native=[Environment]::CurrentDirectory;$watch=& ${function:Get-MQWatch} $WatchRoot
    $record=@{owned=$Owned;mode=$Mode;contract=$contract;screenNotBefore=$c.ScreenNotBefore;fixtureOnly=[bool]$FixtureOnly;runtimeQualified=$false;status='ADMISSION';plannedClientCalls=$contract.normalMaximum;allBuildsUntimed=($Mode-ceq'Qualify')};$created=$false;$anchor=$null;$normal=$false;$primary=$null
    try{
        New-Item $Owned -ItemType Directory -ErrorAction Stop|Out-Null;$created=$true
        $record.setup=if($FixtureOnly){& $FixtureHooks.Setup $c}else{& ($commands['Expand-H3911OwnedDistribution']) -Platform Darwin -Archive $DistributionArchive -Destination $c.Home}
        foreach($name in 'output','cache','registry','temp','maven-user-home'){New-Item (Join-Path $Owned $name) -ItemType Directory|Out-Null}
        [IO.File]::WriteAllText($c.Settings,'<settings/>')
        foreach($name in $names|Where-Object{$_-ne'PATH'}){Remove-Item "Env:$name" -ErrorAction SilentlyContinue}
        $env:JAVA_HOME=$Jdk;$env:PATH=(Join-Path $Jdk 'bin')+[IO.Path]::PathSeparator+$env:PATH;$env:MAVEN_USER_HOME=Join-Path $Owned 'maven-user-home';$env:MAVEN_SKIP_RC='1';$env:TMPDIR=$c.Temp;$env:TMP=$c.Temp;$env:TEMP=$c.Temp;$env:MVND_HOME=$c.Home;$env:MVND_DAEMON_STORAGE=$c.Registry
        $env:JAVA_TOOL_OPTIONS="`"-Djava.io.tmpdir=$($c.Temp)`" `"-Dmvndnative.tmpdir=$($c.Temp)`" --enable-native-access=ALL-UNNAMED"
        Push-Location $Project;[Environment]::CurrentDirectory=$Project
        try{
            foreach($label in 'baseline-project','daemon-arch','daemon-home','daemon-project','baseline-maven-home','baseline-verify','candidate-verify'){
                $null=& ($commands['Assert-H3911Source']) $c
                if($RuntimeApproved){$null=& ${function:Assert-MQSdk} $c $JdkArchive;$null=& ($commands['Assert-H3911Darwin103Distribution']) $c.Home -RequireNativeModes}
                if($anchor){$now=& ${function:Read-MQOwner} $c $commands $FixtureHooks;& ${function:Assert-MQSame} $now $anchor}
                $baseline=$label.StartsWith('baseline-',[StringComparison]::Ordinal);$scalar=$label-notlike'*-verify';$valueFile=Join-Path $c.Output ($label+'.value')
                $tokens=@('--batch-mode','--no-transfer-progress',"-Dmaven.repo.local=$($c.Cache)",'--settings',$c.Settings,'--global-settings',$c.Settings,'--file',(Join-Path $Project 'pom.xml'))
                if(-not$baseline){$tokens+=@('--serial',"-Djava.home=$Jdk","-Dmvnd.daemonStorage=$($c.Registry)")}
                if($scalar){& ${function:Assert-MQ} (-not(Test-Path -LiteralPath $valueFile)) 'Fresh scalar namespace required';$expression=switch($label){daemon-arch{'os.arch'}daemon-home{'java.home'}baseline-maven-home{'maven.home'}default{'project.basedir'}};if($label-notin@('baseline-project','daemon-arch')){$tokens+='-o'};$tokens+=@('org.apache.maven.plugins:maven-help-plugin:3.5.1:evaluate',"-Dexpression=$expression",'-q',"-Doutput=$valueFile")}
                else{& ${function:Assert-MQ} ($c.Contexts.Count-eq5) 'All five contexts required before clean';$tokens+=@('clean','verify')}
                $null=& ($commands['Assert-H3911KernelPOM']) $c $tokens $Project
                $plan=@{label=$label;exe=$(if($baseline){Join-Path $Project 'mvnw'}else{Join-Path $c.Home 'bin/mvnd'});arguments=$tokens;workingDirectory=$Project;valueFile=$valueFile;timed=$false}
                $call=@{plan=$plan;log=(Join-Path $c.Output ($label+'.log'));start=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();exit=$null;timed=$false};$c.Calls+=,$call
                $call.exit=if($FixtureOnly){& $FixtureHooks.Dispatch $c $plan}else{& ($commands['Invoke-H3911DirectNative']) -Exe $plan.exe -Tokens $tokens -Log $call.log -Context $c -WorkingDirectory $Project -Platform Posix}
                $call.end=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();& ${function:Assert-MQ} ($call.exit-eq0) 'Mac client nonzero'
                if($scalar){
                    $file=Get-Item -LiteralPath $valueFile -Force;& ${function:Assert-MQ} ($file-is[IO.FileInfo]-and-not$file.LinkType-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Regular scalar file required'
                    $bytes=[IO.File]::ReadAllBytes($valueFile);$value=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
                    & ${function:Assert-MQ} ($value-and$value-notmatch'[\x00-\x1f\x7f]') 'Strict UTF8 scalar required'
                    $wanted=switch($label){daemon-arch{'aarch64'}daemon-home{$Jdk}baseline-maven-home{$value}default{$Project}}
                    & ${function:Assert-MQ} ([string]::Equals($value,$wanted,[StringComparison]::Ordinal)) 'Mac actual scalar context differs'
                    $c.Contexts[$label]=@{value=$value;bytes=$bytes.Length;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))}
                    if($label-ceq'baseline-maven-home'){
                        if($FixtureOnly){$stock=& $FixtureHooks.Stock $c $value}else{
                            $marker=[IO.File]::ReadAllText((Join-Path $value 'mvnw.url'));$inventory=Get-Content (Join-Path $PSScriptRoot 'StockMaven3911.inventory.json') -Raw|ConvertFrom-Json -AsHashtable
                            $format=@('Zip','Tar')|Where-Object{$marker-ceq($inventory.formats[$_].url+"`n")};& ${function:Assert-MQ} (@($format).Count-eq1) 'Exact Mac stock marker format required'
                            $stock=& ($commands['Assert-H3911StockMaven3911']) -MavenHome $value -PrivateWrapperCache (Join-Path $env:MAVEN_USER_HOME 'wrapper/dists') -Profile MacOriginal -Format $format
                        }
                        & ${function:Assert-MQ} ($stock.status-ceq'FULL_TRUSTED_STOCK_MAVEN3911_ADMITTED'-and$stock.archiveFiles-eq96-and$stock.physicalFiles-eq97-and$stock.directories-eq13-and$stock.inventorySha256-ceq'63382624DFFEF090C2B47C476767D9BE9F0620296193B650AE419ABE34FC4D0F') 'Full clean Mac stock admission required'
                        $record.stock=$stock
                    }
                }else{
                    $saved=if($FixtureOnly){& $FixtureHooks.Verify $c $label $call}else{& ($commands['Save-H3911Verify']) $c $label $call}
                    if(-not$FixtureOnly){$saved.reportBytes=& ${function:New-MQReportByteWitness} (Join-Path $c.Output $label) $label}
                    & ${function:Assert-MQ} ($saved.tests.Count-eq56-and$saved.counters.Count-eq726) 'Mac full verify universe differs';$record[$label]=$saved
                    if(-not$baseline){
                        if($Mode-ceq'PackageScreen'){$null=& $samplingCommands['Assert-PScreenTestFacts'] $record['baseline-verify'].tests $saved.tests;$null=& $samplingCommands['Assert-PScreenCoverageFacts'] $record['baseline-verify'].counters $saved.counters;& ${function:Assert-MQ} ($record['baseline-verify'].semantics-ceq$saved.semantics) 'Full coverage semantics differ'}
                        else{foreach($key in 'tests','counters','semantics'){& ${function:Assert-MQ} (($record['baseline-verify'][$key]|ConvertTo-Json -Depth 40 -Compress)-ceq($saved[$key]|ConvertTo-Json -Depth 40 -Compress)) 'Mac full fidelity differs'}}
                        & ${function:Assert-MQ} ($record['baseline-verify'].fork-ne$saved.fork-and$record['baseline-verify'].session-ne$saved.session) 'Mac fresh fork/session required'
                        if($FixtureOnly){& ${function:Assert-MQ} (& $FixtureHooks.Compare $c) 'Mac whole archive comparison failed'}else{$null=& ($commands['Compare-H3911Artifacts']) (Join-Path $c.Output 'baseline-verify') (Join-Path $c.Output 'candidate-verify') -SourceProfile MacOriginalWrapper}
                    }
                }
                if($label-ceq'daemon-arch'){$anchor=& ${function:Read-MQOwner} $c $commands $FixtureHooks}
                if($label-ceq'daemon-project'){
                    $record.earlyCensus=@{status='HOLD';afterCall=$label;beforeCall='baseline-maven-home';absenceAsserted=$false;fixtureOnly=[bool]$FixtureOnly}
                    $visibility=if($FixtureOnly){& $FixtureHooks.Census $c $anchor}else{& ($commands['Read-H3911DarwinScopedCensus']) -Context $c -Expected $anchor -RuntimeApproved}
                    & ($commands['Assert-LifeUidCensus']) $c $anchor $visibility
                    & ${function:Assert-MQ} ($visibility.schema-is[string]-and$visibility.scope-is[string]-and$visibility.uidProof.schema-is[string]-and$visibility.uidProof.observationBasis-is[string]-and$visibility.uidProof.selfIdentity.executable-is[string]-and$visibility.uidProof.selfIdentity.executable.Length-le4096-and$visibility.uidProof.selfIdentity.executable-notmatch'[\x00-\x1f\x7f]') 'Bounded completed UID observation required'
                    $held=@{}
                    foreach($field in 'schema','admittedUid','filter','selectedPidCount','knownPidCount','unionPidCount','validatedPidCount','missingAtRecheckCount','presenceRecheckAttempts','observationBasis','atomicEndpoint','newbornCoverage','universalHistory'){$held[$field]=$visibility.uidProof[$field]}
                    $held.selfIdentity=@{};foreach($field in 'pid','created','executable'){$held.selfIdentity[$field]=$visibility.uidProof.selfIdentity[$field]}
                    foreach($role in 'selfCredential','ownerCredential'){
                        $held[$role]=$null
                        if($null-ne$visibility.uidProof[$role]){$held[$role]=@{};foreach($field in 'pid','parentPid','realUid','effectiveUid','savedUid','birthSeconds','birthMicroseconds'){$held[$role][$field]=$visibility.uidProof[$role][$field]}}
                    }
                    $record.earlyCensus.schema=$visibility.schema;$record.earlyCensus.scope=$visibility.scope;$record.earlyCensus.uidProof=$held
                    $record.earlyCensus=& ${function:Assert-MQEarlyCensus} $c $anchor $visibility $commands
                }
            }
            if($Mode-ceq'PackageScreen'){
                & ${function:Assert-MQ} ($c.OwnerReads.Count-eq6) 'Six actual qualification owner reads required'
                $c.ScreenOwner=$anchor;$c.ScreenOwnerReads=@($c.OwnerReads);$c.ScreenVerification=@{baseline=$record['baseline-verify'];candidate=$record['candidate-verify']};$c.JdkArchive=$JdkArchive;$c.DistributionArchive=$DistributionArchive;$c.PrivateWrapperCache=Join-Path $env:MAVEN_USER_HOME 'wrapper/dists';$c.ScreenStockFormat=$record.stock.archiveFormat;$c.ScreenMainAuxLimit=$contract.mainAuxMaximum
                $args=@{Context=$c};if($FixtureOnly){$args.FixtureOnly=$true;$args.FixtureHooks=$FixtureHooks.Sampling}else{$args.RuntimeApproved=$true}
                $record.sampling=& $samplingCommands['Invoke-H3911MacPackageSamplingOperator'] @args
                & ${function:Assert-MQSamplingEvidence} $c $record.sampling ([bool]$FixtureOnly)
            }
            $record.stopProof=& ${function:Stop-MQ} $c $commands $anchor $FixtureHooks
            & ${function:Assert-MQ} ($c.Calls.Count-eq$contract.normalMaximum) 'Complete mode-specific client calls required';$normal=$true;$record.status=if($FixtureOnly){if($Mode-ceq'PackageScreen'){'MAC_PACKAGE_SCREEN_FIXTURE_ONLY_COMPLETE'}else{'MAC_FIXTURE_ONLY_COMPLETE'}}elseif($Mode-ceq'PackageScreen'){'MAC_PACKAGE_SCREEN_COMPLETE_PENDING_AUDIT'}else{'MAC_UNTIMED_COMPLETE_PENDING_AUDIT'}
        }finally{Pop-Location}
    }catch{$primary=$_;$record.status='FAIL';$record.failure=$_.ToString()}
    finally{
        if(-not$normal-and$created){try{if(-not$anchor){$anchor=& ${function:Read-MQOwner} $c $commands $FixtureHooks};$record.emergency=& ${function:Stop-MQ} $c $commands $anchor $FixtureHooks -Emergency}catch{$record.cleanupFailure=$_.ToString()}}
        if($created){try{$null=& ($commands['Assert-H3911Source']) $c;$record.sourceEqual=$true}catch{$record.sourceEqual=$false;$record.status='FAIL';$record.finalSourceFailure=$_.ToString()}}
        [Environment]::CurrentDirectory=$native;$record.restoration=& ($commands['RestorePortableEnvironment']) $before $names;$record.restoration.cwdEqual=(Get-Location).Path-ceq$cwd
        $record.restoration.nativeCwdEqual=[Environment]::CurrentDirectory-ceq$native;$record.rootWatchEqual=((& ${function:Get-MQWatch} $WatchRoot)|ConvertTo-Json -Depth 6 -Compress)-ceq($watch|ConvertTo-Json -Depth 6 -Compress)
        if(-not$record.restoration.restored-or-not$record.restoration.cwdEqual-or-not$record.restoration.nativeCwdEqual-or-not$record.rootWatchEqual-or$record.cleanupFailure){$record.status='FAIL'}
        $record.calls=$c.Calls;$record.contexts=$c.Contexts;$record.owner=$anchor;$record.knownOwnedIdentities=$c.KnownOwnedIdentities
        if($created){try{$record|ConvertTo-Json -Depth 45 -WarningAction Stop|Set-Content (Join-Path $Owned 'mac-qualifier.json')}catch{if(-not$primary){$primary=$_};$record.status='FAIL'}}
    }
    if($primary){throw $primary};& ${function:Assert-MQ} ($record.status-ne'FAIL') 'Mac cleanup/restoration HOLD'
    $record
}
Export-ModuleMember -Function Invoke-H3911MacQualifier
