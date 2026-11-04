param([switch]$ExecutionApproved,[switch]$ProofOnly,[ValidateSet('Timeout','AfterChildStartFailure','AfterObserverStartFailure','Normal0','Normal1')][string]$ProofScenario='Timeout')
$ErrorActionPreference='Stop';$here=$PSScriptRoot
if($ExecutionApproved-and$ProofOnly){throw 'Proof cannot authorize qualification'}
if(-not$ExecutionApproved-and-not$ProofOnly){throw 'STAGED_ONLY: no root execution allocation'}
$stage=Get-Content (Join-Path $here 'stage.json') -Raw|ConvertFrom-Json
if($ExecutionApproved){
    if(-not$stage.launcherReview.approved-or-not$stage.runtimeAllocation.approved-or$stage.runtimeAllocation.status-cne'ROOT_ALLOCATED_EXACT_RUN'){throw 'UNALLOCATED: separate accepted launcher review and root runtime allocation required'}
    & (Join-Path $here 'Invoke-ScreenCandidate.ps1') -ValidateOnly|Out-Null
}
$output=Join-Path $here $(if($ProofOnly){"proof-$ProofScenario-"+[guid]::NewGuid().ToString('N')}else{'actual-supervision'});New-Item $output -ItemType Directory -ErrorAction Stop|Out-Null
$scope=@{Jdk=$stage.jdk;Home=(Join-Path $stage.owned 'home');Registry=(Join-Path $stage.owned 'registry');Temp=(Join-Path $stage.owned 'temp')}
$parentBackstopPath=Join-Path $here 'OwnedJavaBackstop.psm1'
if((Microsoft.PowerShell.Utility\Get-FileHash $parentBackstopPath).Hash-cne'406C71D922394EAA666FE8759390C9114B1457461BA9E4F4C69859CE28A5C647'){throw 'HOLD: reviewed parent backstop source differs'}
$parentBackstopModule=Import-Module $parentBackstopPath -Force -PassThru
$parentCommands=@{}
foreach($name in 'Assert-QualifierOwnerWitness','Read-QualifierPrivateJava','Stop-RevalidatedQualifierJava'){
    $command=$parentBackstopModule.ExportedCommands[$name]
    if($command-isnot[Management.Automation.FunctionInfo]-or$command.Name-cne$name-or$command.Module.Path-cne$parentBackstopPath-or-not$command.ScriptBlock){throw 'HOLD: closed parent command binding missing or foreign'}
    $parentCommands[$name]=$command
}
Import-Module (Join-Path $here 'ObserverTelemetry.psm1') -Force
$handoffModule=Import-Module (Join-Path $here 'H3911.ScreenParent.psm1') -Force -PassThru
$handoffCommands=$handoffModule.ExportedCommands
$limit=if($ProofOnly){if($ProofScenario-eq'Timeout'){700}else{5000}}else{1800000}
$exe=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$script=if($ProofOnly){
    $safe=Join-Path $output 'owned harmless child.ps1'
    $ending=if($ProofScenario-eq'Normal0'){'exit 0'}elseif($ProofScenario-eq'Normal1'){'exit 1'}else{'Start-Sleep -Seconds 30'}
    [IO.File]::WriteAllText($safe,('[Console]::Out.WriteLine("OWNED_STDOUT");[Console]::Out.Flush();[Console]::Error.WriteLine("OWNED_STDERR");[Console]::Error.Flush();'+$ending));$safe
}else{
    if(-not$stage.approvedQualifierDriver-or-not[IO.Path]::IsPathFullyQualified($stage.approvedQualifierDriver)){throw 'HOLD: separately reviewed child driver missing'}
    if((Get-FileHash $stage.approvedQualifierDriver).Hash-cne$stage.approvedQualifierDriverSha256){throw 'HOLD: reviewed child driver pin missing/changed'}
    $stage.approvedQualifierDriver
}
$info=[Diagnostics.ProcessStartInfo]::new($exe);$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
foreach($arg in @('-NoProfile','-NonInteractive','-File',$script)){$info.ArgumentList.Add($arg)}
if(-not$ProofOnly){$info.ArgumentList.Add('-ExecutionApproved')}
$child=$null;$childExit=$null;$observer=$null;$stdout=$null;$stderr=$null;$a=$null;$b=$null;$normal=$false;$childConfirmed=$false;$observerConfirmed=$false;$primary=$null;$cleanup=@();$killed=$false;$finalCensus=$null;$witness=$null;$witnessValid=$false;$witnessError=$null;$outcome=$null;$outDone=$false;$errDone=$false;$watch=[Diagnostics.Stopwatch]::StartNew();$startUtc=[DateTime]::UtcNow.ToString('o')
try{
    $stdout=[IO.File]::Open((Join-Path $output 'stdout.log'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $stderr=[IO.File]::Open((Join-Path $output 'stderr.log'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $child=[Diagnostics.Process]::Start($info);$created=$child.StartTime.ToUniversalTime().ToString('o')
    $a=$child.StandardOutput.BaseStream.CopyToAsync($stdout);$b=$child.StandardError.BaseStream.CopyToAsync($stderr)
    if(-not$ProofOnly){
        $oi=[Diagnostics.ProcessStartInfo]::new($exe);$oi.UseShellExecute=$false
        foreach($arg in @('-NoProfile','-NonInteractive','-File',(Join-Path $here 'Observe-QualifierOwner.ps1'))){$oi.ArgumentList.Add($arg)}
        $observer=[Diagnostics.Process]::Start($oi)
        $observerAllocation=& ($handoffCommands['New-SPAllocation']) $observer (Join-Path $here 'Observe-QualifierOwner.ps1') $here $output $scope $startUtc
    }elseif($ProofScenario-in@('AfterChildStartFailure','AfterObserverStartFailure')){
        $prefixWait=[Diagnostics.Stopwatch]::StartNew()
        while(($stdout.Position-eq0-or$stderr.Position-eq0)-and$prefixWait.ElapsedMilliseconds-lt2000){Start-Sleep -Milliseconds 25}
        $oi=[Diagnostics.ProcessStartInfo]::new($(if($ProofScenario-eq'AfterChildStartFailure'){Join-Path $output 'missing-observer.exe'}else{$exe}));$oi.UseShellExecute=$false
        if($ProofScenario-eq'AfterObserverStartFailure'){foreach($arg in @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30')){$oi.ArgumentList.Add($arg)}}
        $observer=[Diagnostics.Process]::Start($oi)
        throw 'INJECTED_BENIGN_AFTER_OBSERVER_ALLOCATION'
    }
    if(-not$ProofOnly){
        $earlyHandoff=& ($handoffCommands['Wait-SPObserverCompletion']) $observer $child $observerAllocation $here $output $watch $limit
    }
    $normal=$child.WaitForExit([Math]::Max(1,$limit-[int]$watch.ElapsedMilliseconds));$childConfirmed=$normal
    if(-not$normal){throw 'Owned qualifier hard deadline reached'}
    $childExit=[int]$child.ExitCode
    if($childExit-ne0){throw "Owned qualifier child nonzero exit: $childExit"}
}catch{$primary=$_.ToString()}
finally{
    if($child){
        try{if(-not$child.HasExited){$killed=$true;try{$child.Kill($true)}catch{$cleanup+=,'child kill: '+$_.ToString()}};$childConfirmed=$child.WaitForExit(10000);if(-not$childConfirmed){$cleanup+=,'child exit unconfirmed'}}catch{$cleanup+=,'child finalize: '+$_.ToString()}
        if($childConfirmed){try{$childExit=[int]$child.ExitCode}catch{$cleanup+=,'observed child exit unavailable: '+$_.ToString();$childExit=$null}}
    }
    if($observer){
        try{
            if(-not$ProofOnly){[IO.File]::WriteAllText((Join-Path $output 'observation-done'),'done');$observerConfirmed=$observer.WaitForExit(10000)}
            if(-not$observer.HasExited){try{$observer.Kill($true)}catch{$cleanup+=,'observer kill: '+$_.ToString()}}
            $observerConfirmed=$observer.WaitForExit(5000);if(-not$observerConfirmed){$cleanup+=,'observer exit unconfirmed'}
        }catch{$cleanup+=,'observer finalize: '+$_.ToString()}
    }
    if(-not$ProofOnly){
        try{
            $json=Join-Path $output 'independent-owned-daemon.json'
            $outcome=@{exitConfirmed=$observerConfirmed;exit=$(if($observer-and$observerConfirmed){$observer.ExitCode}else{$null});jsonPresent=(Test-Path $json)}
            $witnessPhase='WITNESS_PARSE'
            if($outcome.jsonPresent){$witness=Get-Content $json -Raw|ConvertFrom-Json -AsHashtable -DateKind String}
            $witnessPhase='WITNESS_VALIDATION'
            $null=& ($parentCommands['Assert-QualifierOwnerWitness']) $scope $witness $outcome $startUtc;$witnessValid=$true
        }catch{
            $witnessError="HOLD: $witnessPhase";$cleanup+=,'independent witness: '+$witnessError
            try{$wireTelemetry=New-QualifierObserverTelemetry;Add-QualifierObserverTelemetry $wireTelemetry @{reasonCode=$witnessPhase};$wireTelemetry|ConvertTo-Json -Depth 10|Set-Content (Join-Path $output 'witness-boundary-telemetry.json')}catch{$cleanup+=,'bounded witness telemetry unavailable'}
        }
    }
    try{
        if($ProofOnly){$finalCensus=@{attempted=$true;nativeQueryExecuted=$false;status='SKIPPED_PROOF_ONLY_NO_JAVA';notActualAbsenceEvidence=$true}}
        else{
            $finalCensus=& ($parentCommands['Read-QualifierPrivateJava']) $scope $witness
            if($finalCensus.status-ceq'owned'){
                if($witnessValid){$backstop=& ($parentCommands['Stop-RevalidatedQualifierJava']) $scope $witness;$cleanup+=,'exact owned PID backstop means qualification FAIL'}
                else{$cleanup+=,'HOLD owned survivor without independently validated witness'}
            }elseif($finalCensus.status-cne'absent'){$cleanup+=,'HOLD final Java census unknown'}
        }
    }catch{$cleanup+=,'final census/backstop: '+$_.ToString();$finalCensus=@{attempted=$true;status='HOLD';error=$_.ToString()}}
    if($a){try{$outDone=$a.Wait(10000)}catch{$cleanup+=,'stdout drain: '+$_.ToString()}}
    if($b){try{$errDone=$b.Wait(10000)}catch{$cleanup+=,'stderr drain: '+$_.ToString()}}
    foreach($sink in $stdout,$stderr){if($sink){try{$sink.Flush()}catch{$cleanup+=,'stream flush: '+$_.ToString()};try{$sink.Dispose()}catch{$cleanup+=,'stream dispose: '+$_.ToString()}}}
    $watch.Stop()
    if($earlyHandoff-and($primary-or$cleanup.Count-or$childExit-ne0-or-not$witnessValid)){
        try{[IO.File]::Move($earlyHandoff.path,(Join-Path $output 'screen-parent-observer.invalidated.json'))}catch{$cleanup+=,'parent completion receipt invalidation failed'}
    }
    $result=@{proofOnly=[bool]$ProofOnly;scenario=$ProofScenario;primaryError=$primary;cleanupErrors=$cleanup;childAllocated=($null-ne$child);observerAllocated=($null-ne$observer);childPid=$(if($child){$child.Id}else{$null});childCreated=$created;childExitConfirmed=$childConfirmed;childExitCode=$childExit;observerExitConfirmed=$observerConfirmed;observerOutcome=$outcome;childTreeKill=$killed;normalExit=$normal;stdoutComplete=$outDone;stderrComplete=$errDone;finalCensus=$finalCensus;independentWitnessRequired=$true;independentWitnessValid=$witnessValid;independentWitnessError=$witnessError;parentCliCalls=0;hardMilliseconds=$limit;futureHardMilliseconds=1800000;elapsedSeconds=$watch.Elapsed.TotalSeconds;qualificationSuccess=($ExecutionApproved-and-not$ProofOnly-and-not$primary-and$cleanup.Count-eq0-and$normal-and$childConfirmed-and$childExit-is[int]-and$childExit-eq0-and$outDone-and$errDone-and$witnessValid-and$finalCensus.status-ceq'absent')}
    $result.parentObserverAllocation=$observerAllocation;$result.earlyParentCompletion=$earlyHandoff
    $result|ConvertTo-Json -Depth 14|Set-Content (Join-Path $output 'result.json')
}
if(-not$ProofOnly){if(-not$result.qualificationSuccess){exit 1}}
else{
    $normalProof=$ProofScenario-in@('Normal0','Normal1')
    if(-not$childConfirmed-or-not$outDone-or-not$errDone-or$result.qualificationSuccess-or-not$result.finalCensus.attempted-or[IO.File]::ReadAllText((Join-Path $output 'stdout.log'))-notmatch'OWNED_STDOUT'-or[IO.File]::ReadAllText((Join-Path $output 'stderr.log'))-notmatch'OWNED_STDERR'){throw 'Benign finalization proof failed'}
    if($normalProof){$expected=if($ProofScenario-eq'Normal0'){0}else{1};if(-not$normal-or$killed-or$childExit-ne$expected-or($expected-eq0-and$primary)-or($expected-eq1-and$primary-notmatch'child nonzero exit: 1')){throw 'Observed normal child exit proof failed'}}
    elseif(-not$primary-or-not$killed){throw 'Benign failure/timeout did not retain owned termination'}
    if($ProofScenario-eq'AfterObserverStartFailure'-and-not$observerConfirmed){throw 'Allocated observer was not confirmed gone'}
    Write-Output "BENIGN_EXCEPTION_SAFE_FINALIZATION_STREAMS_RECEIPT_PASS $output"
}
