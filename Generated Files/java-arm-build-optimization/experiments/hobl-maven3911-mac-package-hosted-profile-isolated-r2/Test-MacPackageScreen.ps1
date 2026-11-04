param([Parameter(Mandatory)][string]$RepositorySource,[Parameter(Mandatory)][string]$OutputRoot,[string]$MaterializedRoot,[switch]$OnlySuccess)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
. (Join-Path $PSScriptRoot 'Synthetic-MacPackageData.ps1')
if(-not[IO.Path]::IsPathFullyQualified($RepositorySource)-or-not[IO.Path]::IsPathFullyQualified($OutputRoot)){throw 'Absolute repository/output required'}
$runtime=Join-Path $PSScriptRoot 'runtime';$output=$OutputRoot
if(Test-Path $output){throw 'Fresh caller models required'};New-Item $output -ItemType Directory|Out-Null
if(-not$MaterializedRoot){$MaterializedRoot=Join-Path $output 'generated';$null=New-SyntheticMacTargets $RepositorySource $MaterializedRoot}
if(-not(Test-Path (Join-Path $MaterializedRoot 'SYNTHETIC_TEST_DATA_NOT_NATIVE.json'))){throw 'Declared synthetic targets required'}
$q=Import-Module (Join-Path $runtime 'H3911.MacQualifier.psm1') -PassThru
$invoke=$q.ExportedCommands['Invoke-H3911MacQualifier'];$commands=& $q {Get-MQSamplingCommands}
$native=Import-Module (Join-Path $runtime 'H3911.NativeProcess.psm1') -PassThru
$log=Join-Path $output 'harmless.log';$exe=[Environment]::ProcessPath;$args=@('-NoProfile','-Command',"[Console]::WriteLine('MODEL_ONLY')")
$null=& $native.ExportedCommands['Invoke-H3911DirectNative'] -Exe $exe -Tokens $args -Log $log -Context @{Project=$output} -WorkingDirectory $output -Platform Posix
$seed=& $commands['Assert-MPackageClock'] $commands $log $exe $args $output ([DateTimeOffset]::UtcNow.AddMinutes(-1))
$project=Join-Path $output 'project'
& git clone --quiet --no-checkout --no-hardlinks $RepositorySource $project;if($LASTEXITCODE){throw 'Local model clone'}
& git -C $project config core.autocrlf false;& git -C $project remote set-url origin 'https://github.com/spring-projects/spring-petclinic.git'
& git -C $project checkout --quiet --detach 6feeae0f13e0e258eedc99832416b42bb13779b1;if($LASTEXITCODE){throw 'Model checkout'}
$jdk=Join-Path $output 'MODEL-JDK';New-Item $jdk -ItemType Directory|Out-Null
$models=$MaterializedRoot;$online=Join-Path $models 'clean\target'
$proof=@()
$cases=if($OnlySuccess){@('complete24')}else{@('complete24','partial-failure','late-census-failure','missing-probes','fullgate-count-shape')}
foreach($case in $cases){
    $owned=Join-Path $output $(if($OnlySuccess){'qualification'}else{$case});$state=@{alive=$false;stops=0;processes=0;probes=0;case=$case};$owner=$null
    $ownerHook={param($c)if($state.alive){@{pid=100;created='2026-01-01T00:00:00Z';daemonId='01234567';home=$c.Home;registryFile=(Join-Path $c.Registry 'registry.bin');executable=(Join-Path $c.Jdk 'bin/java');jniPath=(Join-Path $c.Temp 'MODEL.jnilib')}}}.GetNewClosure()
    $censusHook={
        param($c,$anchor)
        $credential=@{pid=100;parentPid=1;realUid=501L;effectiveUid=501L;savedUid=501L;birthSeconds=1767225600L;birthMicroseconds=0L}
        $self=@{pid=20;parentPid=1;realUid=501L;effectiveUid=501L;savedUid=501L;birthSeconds=1767225600L;birthMicroseconds=0L}
        @{schema='darwin-launch-uid-java-census-v2';scope='launch-effective-UID admitted-JDK Java plus explicitly tracked identities';complete=$true;errors=@();expectedIdentityGone=$false;jdkExecutable=(Join-Path $c.Jdk 'bin/java');tracked=@($anchor);sameJdkJava=@($anchor);knownLive=@($anchor);uidProof=@{schema='darwin-launch-uid-proof-v2';admittedUid=501L;filter=5;selfIdentity=@{pid=20;created='2026-01-01T00:00:00Z';executable='/fixture/pwsh'};selfCredential=$self;ownerCredential=$credential;selectedPidCount=2;knownPidCount=1;unionPidCount=2;validatedPidCount=2;missingAtRecheckCount=0;presenceRecheckAttempts=0;observationBasis='INITIAL_ELIGIBLE_PID_NUMBERS_THEN_UID_SURVIVORS_PLUS_KNOWN_ESRCH_RECHECK';atomicEndpoint=$false;newbornCoverage=$false;universalHistory=$false}}
    }.GetNewClosure()
    $sampling=@{
        Admit={param($c,$pkg)}
        Owner=$ownerHook;Census=$censusHook
        Probes={
            param($c,$current)
            $state.probes++;$dir=Join-Path $c.Output ('effective-owner-'+$state.probes.ToString('x32'));$rows=@();$i=0
            foreach($expression in 'VM.system_properties','VM.dynlibs'){$i++;$path=Join-Path $dir ($expression+'.log');$arguments=@([string]$current.pid,$expression);Write-SyntheticProcessReceipt $path (Join-Path $c.Jdk 'bin/jcmd') $arguments $c.Temp (30000+2*$state.probes+$i);$seal=& $commands['Assert-MPackageClock'] $commands $path (Join-Path $c.Jdk 'bin/jcmd') $arguments $c.Temp ([DateTimeOffset]::UtcNow.AddMinutes(-1));$seal.probe=$expression;$seal.targetPid=$current.pid;$rows+=,$seal}
            if($state.case-eq'missing-probes'){@($rows[0])}else{$rows}
        }.GetNewClosure()
        Process={
            param($c,$step,$tokens,$path,$logicalExe)
            $state.processes++;if($state.case-eq'partial-failure'-and$step.timed){throw 'ORIGINAL_PARTIAL_PACKAGE_FAILURE'}
            [IO.File]::WriteAllText($path,'Goal makeAggregateBom requires online mode; skipping');[IO.File]::WriteAllText(($path+'.stderr'),'')
            @{platform='Posix';validClock=$true;exitConfirmed=$true;exit=0;stdoutComplete=$true;stderrComplete=$true;timeout=$false;killRequested=$false;failure=$null;terminationError=$null;pid=(1000+$state.processes);createdUtc=[DateTimeOffset]::UtcNow.ToString('o');exe=$logicalExe;arguments=$tokens;workingDirectory=$c.Project;elapsedSeconds=$(if($step.route-eq'A'){10.0}else{9.0});clockBoundary='immediately before Process.Start through normal WaitForExit';transport='direct executable / ArgumentList / no shell';stdoutBytes=(Get-Item $path).Length;stderrBytes=0;stdoutSha256=(Get-FileHash $path).Hash;stderrSha256=(Get-FileHash ($path+'.stderr')).Hash;fixtureOnly=$true}|ConvertTo-Json -Depth 8|Set-Content ($path+'.process.json');0
        }.GetNewClosure()
        Capture={param($c,$step)$dest=Join-Path $c.Output ('SYNTHETIC-offline-projects\'+$step.label);New-Item (Split-Path $dest) -ItemType Directory -Force|Out-Null;Copy-Item (Join-Path $models ('offline-projects\'+$step.label)) $dest -Recurse;$dest}.GetNewClosure()
    }
    $hooks=@{
        Setup={param($c)New-Item $c.Home -ItemType Directory|Out-Null;@{fixtureOnly=$true}}
        Owner=$ownerHook;Census=$censusHook;Sampling=$sampling
        Dispatch={param($c,$plan)if($plan.label-eq'daemon-arch'){$state.alive=$true};if($plan.label-notlike'*-verify'){$value=switch($plan.label){daemon-arch{'aarch64'}daemon-home{$c.Jdk}baseline-maven-home{Join-Path $owned 'MODEL-STOCK'}default{$c.Project}};[IO.File]::WriteAllText($plan.valueFile,$value)};Write-SyntheticProcessReceipt (Join-Path $c.Output ($plan.label+'.log')) $plan.exe $plan.arguments $c.Project (20000+$c.Calls.Count) 1.0 ("Starting SYNTHETIC with PID "+(20000+$c.Calls.Count));0}.GetNewClosure()
        Stock={param($c,$root)@{status='FULL_TRUSTED_STOCK_MAVEN3911_ADMITTED';archiveFiles=96;physicalFiles=97;directories=13;inventorySha256='63382624DFFEF090C2B47C476767D9BE9F0620296193B650AE419ABE34FC4D0F';archiveFormat='Zip'}}
        Verify={
            param($c,$label,$call)
            $saved=Save-SyntheticFullCapture $commands $runtime (Join-Path $models 'clean') $c $label $call
            if($state.case-eq'fullgate-count-shape'){$saved.tests=[pscustomobject]@{Count=56}};$saved
        }.GetNewClosure()
        Compare={param($c)$true}
        StopPlan={param($c,$anchor,$emergency)@{exe=(Join-Path $c.Home 'bin/mvnd');tokens=@('--stop');workingDirectory=$c.Temp;expectedPid=$anchor.pid;expectedCreated=$anchor.created;emergency=$emergency}}
        Stop={param($c,$plan)$state.stops++;$state.alive=$false;Write-SyntheticProcessReceipt (Join-Path $c.Output $(if($plan.emergency){'emergency-stop.log'}else{'normal-stop.log'})) $plan.exe $plan.tokens $c.Temp (25000+$state.stops);0}.GetNewClosure()
        Confirm={param($c,$anchor,$exit,$emergency)if($state.case-eq'late-census-failure'){throw 'ORIGINAL_LATE_UID_CENSUS_FAILURE'};@{status='NORMAL_CLI_ROUTE_SCOPED_ABSENCE_CONFIRMED';fixtureOnly=$true}}.GetNewClosure()
    }
    $failure=$null;$record=$null;try{$record=& $invoke -Project $project -Jdk $jdk -Owned $owned -WatchRoot $RepositorySource -Mode PackageScreen -FixtureOnly -FixtureHooks $hooks}catch{$failure=$_.Exception.Message}
    $disk=Get-Content (Join-Path $owned 'mac-qualifier.json') -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    if($case-eq'complete24'){
        $plan=& $commands['Get-H3911RetainedProtocol'] -Mode PackageScreen -Platform MacOS
        $labels=@($disk.calls|ForEach-Object{if($_.plan){$_.plan.label}else{$_.label}})
        if($failure-or$disk.status-cne'MAC_PACKAGE_SCREEN_FIXTURE_ONLY_COMPLETE'-or$labels.Count-ne24-or($labels-join',')-cne($plan.calls.label-join',')-or$disk.sampling.offlineCaptures.Count-ne8-or$disk.sampling.samples.Count-ne6-or$state.processes-ne16-or$state.stops-ne1){throw "Full real-operator fixture failed $failure"}
        $validateSampling=& $q {Get-Command Assert-MQSamplingEvidence -CommandType Function}
        foreach($mutation in 'duration','count-shape'){
            $bad=$disk.sampling|ConvertTo-Json -Depth 40|ConvertFrom-Json -AsHashtable -DateKind String
            if($mutation-eq'duration'){$bad.samples[0].seconds=99.0}else{$bad.samples=[pscustomobject]@{Count=6}}
            $rejected=$false;try{$null=& $validateSampling @{} $bad $true}catch{$rejected=$true}
            if(-not$rejected){throw "Forged sampling result admitted $mutation"};$proof+=@{case=('sampling-forged-'+$mutation);passed=$true}
        }
        if($OnlySuccess){
            @{marker='SYNTHETIC_TEST_DATA_NOT_NATIVE';fixtureOnly=$true;qualified=$false;mode='PackageScreen';contract=$disk.contract;knownOwnedIdentities=$disk.knownOwnedIdentities;packageSampling=$disk.sampling;nativeAuthority=$false}|ConvertTo-Json -Depth 40|Set-Content (Join-Path $output 'parent-model.json')
            @{verdict='SYNTHETIC_COMPLETE_TREE';fixtureOnly=$true;record='qualification/mac-qualifier.json';parent='parent-model.json';calls=24;captures=8;samples=6;auxiliaryMetadataLifetimes=28}|ConvertTo-Json|Set-Content (Join-Path $output 'fixture-tree.json')
            Write-Output 'SYNTHETIC_COMPLETE_PACKAGE_TREE calls24 captures8 samples6 probes28; NOT_NATIVE';return
        }
    }else{
        if(-not$failure-or$disk.status-cne'FAIL'-or$disk.calls.Count-gt25-or$state.stops-ne1){throw "Failure/cleanup model failed $case : $failure"}
        if($case-eq'partial-failure'-and($failure-cne'ORIGINAL_PARTIAL_PACKAGE_FAILURE'-or$disk.calls.Count-ne14)){throw 'Partial reason/count changed'}
        if($case-eq'late-census-failure'-and($failure-cne'ORIGINAL_LATE_UID_CENSUS_FAILURE'-or$disk.calls.Count-ne24)){throw 'Late UID failure masked'}
    }
    $proof+=@{case=$case;passed=$true;calls=$disk.calls.Count;cleanupCalls=$state.stops;realOperatorProcessHookCalls=$state.processes;fixtureOnly=$true;failure=$failure}
}
$sup=Import-Module (Join-Path $runtime 'H3911.MacSupervisor.psm1') -PassThru;$validate=& $sup {Get-Command Assert-SupModeRecord};$get=& $q {Get-Command Get-MQModeContract}
$positive=@{mode='PackageScreen';contract=(& $get PackageScreen)};$checked=& $validate $positive PackageScreen
if($checked.normalMaximum-ne24-or$checked.emergencyMaximum-ne25-or$checked.mainAuxMaximum-ne28-or$checked.totalAuxMaximum-ne30-or$checked.deadlineMilliseconds-ne1800000){throw 'Reviewed package mode bounds differ'}
$proof+=@{case='positive-closed-package-RPC-contract';passed=$true}
foreach($case in 'missing-mode','wrong-case','mismatch','forged-budget'){
    $r=@{mode='PackageScreen';contract=(& $get PackageScreen)}
    switch($case){missing-mode{$r.Remove('mode')}wrong-case{$r.mode='packagescreen'}mismatch{$r.mode='Qualify'}forged-budget{$r.contract.mainAuxMaximum=14}}
    $failed=$false;try{$null=& $validate $r PackageScreen}catch{$failed=$true};if(-not$failed){throw "Bad RPC mode admitted $case"};$proof+=@{case=$case;passed=$true}
}
foreach($badMode in 'packagescreen','Unknown'){$failed=$false;$root=Join-Path $output $badMode;try{$null=& $invoke -Owned $root -Mode $badMode -FixtureOnly}catch{$failed=$true};if(-not$failed-or(Test-Path $root)){throw 'Bad mode allocated'};$proof+=@{case=('early-mode-'+$badMode);passed=$true}}
$badRoot=Join-Path $output 'BAD_BUDGET_NOT_CREATED';$failure=$null
try{$null=& $sup.ExportedCommands['Invoke-H3911MacSupervisor'] -Owned $badRoot -Nonce ([guid]::NewGuid().ToString('N')) -Mode PackageScreen -DeadlineMilliseconds 600000 -RootRuntimeApproved}catch{$failure=$_.Exception.Message}
if(-not$failure-or$failure-notlike'*Unreviewed mode deadline*'-or(Test-Path $badRoot)){throw 'Unreviewed package budget allocated or was silently defaulted'}
$proof+=@{case='wrong-package-deadline-before-allocation';passed=$true}
@{verdict='PASS';cases=$proof;actualMacCalls=0;actualJavaCalls=0;wholeOperatorStub=$false;modelDurationsNotGain=$true}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputRoot 'caller-model-proof.json')
Write-Output "MAC_CALLER_PACKAGE_PROOF_PASS cases=$($proof.Count); real operator fixture16 -> full24; original failure/cleanup/RPC preserved; no Mac/Java"
