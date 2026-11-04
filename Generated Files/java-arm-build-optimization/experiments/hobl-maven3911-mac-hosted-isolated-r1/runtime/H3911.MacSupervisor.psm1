function Assert-Sup($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function Read-SupJson([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    & ${function:Assert-Sup} ($item-is[IO.FileInfo]-and-not$item.LinkType-and-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Regular bound JSON required'
    $value=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    & ${function:Assert-Sup} ($value-is[hashtable]) 'Explicit JSON object required'
    $value
}
function Assert-SupBase {
    $manifest=Join-Path $PSScriptRoot 'mac-qualifier-sha256.json'
    & ${function:Assert-Sup} ((Microsoft.PowerShell.Utility\Get-FileHash $manifest).Hash-ceq'CAC8CC6BC424C00A36A024ABE30C08E4F956757232BB64A742577B5EE2A2CC49') 'Frozen Mac source manifest differs'
    $rows=Get-Content $manifest -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    & ${function:Assert-Sup} ($rows-is[array]-and$rows.Count-eq18) 'Exact frozen source closure required'
    foreach($row in $rows){& ${function:Assert-Sup} ($row.file-is[string]-and$row.file-notmatch'[/\\:]|^\.'-and(Microsoft.PowerShell.Utility\Get-FileHash (Join-Path $PSScriptRoot $row.file)).Hash-ceq$row.sha256) 'Frozen Mac payload differs'}
}
function Read-SupScope($Request){
    & ${function:Assert-Sup} ($Request.nonce-cmatch'^[a-f0-9]{32}$'-and[IO.Path]::IsPathFullyQualified($Request.owned)-and$Request.qualifierOwned-ceq(Join-Path $Request.owned 'qualification')-and$Request.result-ceq(Join-Path $Request.owned ($Request.role+'.result.json'))) 'Bound nonce/root/result layout differs'
    $scope=& ${function:Read-SupJson} (Join-Path $Request.owned 'scope.json')
    & ${function:Assert-Sup} ($scope.schema-ceq'mac-supervisor-scope-v1'-and$scope.nonce-ceq$Request.nonce-and$scope.owned-ceq$Request.owned-and$scope.inputsDigest-ceq$Request.inputsDigest) 'Scope receipt differs; no existing adoption'
}
function Assert-SupQualification($R){
    & ${function:Assert-Sup} ($R-is[hashtable]-and$R.fixtureOnly-is[bool]-and-not$R.fixtureOnly-and$R.status-is[string]-and$R.status-ceq'MAC_UNTIMED_COMPLETE_PENDING_AUDIT') 'Actual returned scalar Mac qualification required'
    & ${function:Assert-Sup} ($R.ContainsKey('knownOwnedIdentities')-and$R.knownOwnedIdentities-is[array]-and$R.stopProof.schema-ceq'darwin-launch-uid-absence-v2'-and$R.earlyCensus.schema-ceq'darwin-launch-uid-java-census-v2') 'Versioned UID return/tracked set required; no old-scope authority'
    foreach($v in @($R.sourceEqual,$R.rootWatchEqual,$R.restoration.restored,$R.restoration.cwdEqual,$R.restoration.nativeCwdEqual)){& ${function:Assert-Sup} ($v-is[bool]-and$v) 'Explicit source/environment/cwd truth required'}
    & ${function:Assert-Sup} ($R.calls-is[array]-and$R.calls.Count-eq8-and$R.contexts-is[hashtable]-and$R.contexts.Count-eq5-and$R.stopProof-is[hashtable]-and$R.stopProof.status-is[string]-and$R.stopProof.status-ceq'NORMAL_CLI_ROUTE_SCOPED_ABSENCE_CONFIRMED'-and$R.stopProof.evidenceKind-is[string]-and$R.stopProof.evidenceKind-ceq'native-scoped-absence-result'-and$R.stopProof.runtimeAuthorized-is[bool]-and-not$R.stopProof.runtimeAuthorized) 'Full eight calls/five contexts/typed native absence required'
    $required=@('baseline-project','daemon-arch','daemon-home','daemon-project','baseline-maven-home')
    foreach($key in $R.contexts.Keys){& ${function:Assert-Sup} ($key-is[string]-and$key-cin$required) 'Exact canonical context keys required'}
    foreach($key in $required){
        $context=$R.contexts[$key]
        & ${function:Assert-Sup} ($context-is[hashtable]-and$context.value-is[string]-and$context.value.Length-gt0-and$context.value-notmatch'[\x00-\x1f\x7f]'-and($context.bytes-is[int]-or$context.bytes-is[long])-and$context.bytes-gt0-and$context.sha256-is[string]-and$context.sha256-cmatch'^[A-F0-9]{64}$') 'Typed nonnull scalar context receipt required'
        $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($context.value)
        & ${function:Assert-Sup} ($context.bytes-eq$bytes.Length-and$context.sha256-ceq[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))) 'Context UTF8 byte/hash binding differs'
        if($key-cne'daemon-arch'){& ${function:Assert-Sup} ($context.value.StartsWith('/',[StringComparison]::Ordinal)) 'Absolute native Darwin context required'}
    }
    & ${function:Assert-Sup} ($R.contexts['daemon-arch'].value-ceq'aarch64'-and$R.contexts['baseline-project'].value-ceq$R.contexts['daemon-project'].value-and$R.owner.executable-is[string]-and$R.owner.executable-ceq($R.contexts['daemon-home'].value+'/bin/java')) 'Actual project/native Java contexts disagree'
    $labels=@()
    foreach($call in $R.calls){& ${function:Assert-Sup} ($call-is[hashtable]-and($call.exit-is[int]-or$call.exit-is[long])-and$call.exit-eq0) 'Explicit integer client exit0 required';$label=if($call.plan){$call.plan.label}else{$call.label};& ${function:Assert-Sup} ($label-is[string]) 'Scalar client label required';$labels+=$label}
    & ${function:Assert-Sup} (($labels-join',')-ceq'baseline-project,daemon-arch,daemon-home,daemon-project,baseline-maven-home,baseline-verify,candidate-verify,normal-stop') 'Exact full client order required'
    foreach($label in 'baseline-verify','candidate-verify'){
        $v=$R[$label];& ${function:Assert-Sup} ($v.tests-is[array]-and$v.tests.Count-eq56-and$v.counters-is[array]-and$v.counters.Count-eq726-and$v.artifact.raw-is[array]-and$v.artifact.raw.Count-eq6) 'Full online verification return required'
    }
    & ${function:Assert-Sup} ($R.stock-is[hashtable]-and$R.stock.status-is[string]-and$R.stock.status-ceq'FULL_TRUSTED_STOCK_MAVEN3911_ADMITTED') 'Typed full Mac stock status required'
    foreach($pair in @(@('archiveFiles',96),@('physicalFiles',97),@('directories',13))){$count=$R.stock[$pair[0]];& ${function:Assert-Sup} (($count-is[int]-or$count-is[long])-and$count-eq$pair[1]) 'Exact Int32/Int64 Mac stock counts required'}
    & ${function:Assert-Sup} (($R.owner.pid-is[int]-or$R.owner.pid-is[long])-and$R.owner.pid-gt0-and$R.owner.pid-le[int]::MaxValue-and$R.owner.created-is[string]-and$R.owner.evidenceKind-is[string]-and$R.owner.evidenceKind-ceq'native-mac-effective-owner') 'String creation/numeric native PID boundary required'
    $stamp=[DateTimeOffset]::MinValue;& ${function:Assert-Sup} ([DateTimeOffset]::TryParse($R.owner.created,[ref]$stamp)) 'ISO creation string required'
}
function Get-SupCommand([string]$File,[string]$Name,[string]$Hash){
    $path=Join-Path $PSScriptRoot $File;& ${function:Assert-Sup} ((Microsoft.PowerShell.Utility\Get-FileHash $path).Hash-ceq$Hash) 'Native cleanup dependency differs'
    $m=Import-Module $path -Scope Local -PassThru -DisableNameChecking;$c=$m.ExportedCommands[$Name]
    & ${function:Assert-Sup} ($c-is[Management.Automation.FunctionInfo]-and$c.Module.Path-ceq$path-and$c.Name-ceq$Name) 'Native cleanup command object origin differs'
    $c
}
function Invoke-SupNativeCleanup($R){
    & ${function:Assert-Sup} ($IsMacOS-and$R.proofOnly-is[bool]-and-not$R.proofOnly) 'Native cleanup cannot be modeled by proof mode'
    $null=& ${function:Assert-SupBase}
    & ${function:Assert-Sup} ($R.ContainsKey('knownOwnedIdentities')-and$R.knownOwnedIdentities-is[array]) 'Explicit request tracked set required; unavailable is HOLD'
    $c=@{Jdk=$R.inputs.Jdk;Home=(Join-Path $R.qualifierOwned 'home');Registry=(Join-Path $R.qualifierOwned 'registry');Temp=(Join-Path $R.qualifierOwned 'temp');Output=(Join-Path $R.owned 'native-cleanup');KnownOwnedIdentities=$R.knownOwnedIdentities;ExpectedJavaSha256='827ECF403DBFA3CF88E7310B44AD93CB27B75C7E15A7E461DDE0CEE775BB196F';ExpectedJcmdSha256='2D4CB05FEFFBB7F81D6EB5295A84D0DA8B9098AC1A0BD9C314B87585E9498C1A'}
    New-Item $c.Output -ItemType Directory -ErrorAction Stop|Out-Null
    $regCmd=& ${function:Get-SupCommand} 'H3911.DarwinOwner.psm1' 'Read-H3911Registry103' 'E9A8FD932AC839119FDD0B810533E8FB69BA314CB038E7345C484A7988A36E1E'
    $censusCmd=& ${function:Get-SupCommand} 'H3911.DarwinLifecycle.psm1' 'Read-H3911DarwinScopedCensus' '8DFD433F1ED138464CAE9FE19B28DDE0B7A91DD37451733D331C813847B8A9FF'
    $out=@{status='HOLD';parentAuxiliaryJcmdMaximum=2;parentEffectiveOwnerReads=0;registryEdited=$false;extraMavenCalls=0;historicalDescendantsAbsent=$false}
    try{
        $reg=& $regCmd ([IO.File]::ReadAllBytes((Join-Path $c.Registry 'registry.bin')))
        & ${function:Assert-Sup} ($reg.schema-ceq'mvnd103-registry'-and$reg.count-is[int]-and$reg.records-is[array]-and$reg.count-eq$reg.records.Count) 'Complete private registry required'
        if($R.mainReturned){
            $record=& ${function:Read-SupJson} (Join-Path $R.qualifierOwned 'mac-qualifier.json');$null=& ${function:Assert-SupQualification} $record
            & ${function:Assert-Sup} ($record.ContainsKey('knownOwnedIdentities')-and$record.knownOwnedIdentities-is[array]-and$record.knownOwnedIdentities.Count-eq$c.KnownOwnedIdentities.Count) 'Returned tracked set unavailable/different'
            $same=& $censusCmd.Module {Get-Command Test-LifeSame -CommandType Function}
            & ${function:Assert-Sup} ($same-is[Management.Automation.FunctionInfo]-and$same.Module.Path-ceq$censusCmd.Module.Path) 'Tracked lifetime comparator origin differs'
            for($i=0;$i-lt$c.KnownOwnedIdentities.Count;$i++){& ${function:Assert-Sup} (& $same $record.knownOwnedIdentities[$i] $c.KnownOwnedIdentities[$i]) 'Returned tracked identity differs'}
            & ${function:Assert-Sup} ($reg.count-eq0) 'Normal registry zero required'
            $confirm=& ${function:Get-SupCommand} 'H3911.DarwinLifecycle.psm1' 'Confirm-H3911DarwinCliStop' '8DFD433F1ED138464CAE9FE19B28DDE0B7A91DD37451733D331C813847B8A9FF'
            $facts=& $confirm -Context $c -Expected $record.owner -StopExit 0 -RuntimeApproved
            & ${function:Assert-Sup} ($facts.status-ceq'NORMAL_CLI_ROUTE_SCOPED_ABSENCE_CONFIRMED') 'Independent normal scoped absence required'
            $out.status='NORMAL_RETURNED_AND_SCOPED_ABSENCE';return $out
        }
        & ${function:Assert-Sup} ($reg.count-eq1) 'Failure cleanup requires one complete registry owner; absent anchor remains HOLD'
        $reader=& ${function:Get-SupCommand} 'H3911.EffectiveOwner.psm1' 'Read-H3911DarwinEffectiveOwner' '4979E2E0160A6DCF9C7B13E279DA712F047634AABB7F3CB021C2A25578CF7B95'
        $out.parentEffectiveOwnerReads=1
        $owner=& $reader -Context $c -RuntimeApproved
        $census=& $censusCmd -Context $c -Expected $owner -RuntimeApproved
        & ${function:Assert-Sup} ($census.complete-and$census.sameJdkJava.Count-eq1-and$census.knownLive.Count-eq1-and-not$census.expectedIdentityGone) 'Ambiguous/unreadable native census; no force'
        $p=[Diagnostics.Process]::GetProcessById([int]$owner.pid)
        try{
            & ${function:Assert-Sup} ($p.Id-eq$owner.pid-and$p.StartTime.ToUniversalTime().Ticks-eq[DateTimeOffset]::Parse($owner.created).UtcDateTime.Ticks-and[string]::Equals($p.MainModule.FileName,$owner.executable,[StringComparison]::Ordinal)) 'Reused/foreign process object; no force'
            $planCmd=& ${function:Get-SupCommand} 'H3911.DarwinLifecycle.psm1' 'New-H3911DarwinPrivateStopPlan' '8DFD433F1ED138464CAE9FE19B28DDE0B7A91DD37451733D331C813847B8A9FF'
            $null=& $planCmd -Context $c -Expected $owner -RuntimeApproved -Emergency
            $p.Kill();& ${function:Assert-Sup} ($p.WaitForExit(5000)) 'Exact owned native exit unconfirmed'
        }finally{$p.Dispose()}
        $after=& $censusCmd -Context $c -Expected $owner -RuntimeApproved
        & ${function:Assert-Sup} ($after.expectedIdentityGone-and$after.sameJdkJava.Count-eq0-and$after.knownLive.Count-eq0) 'Native survivor/visibility HOLD'
        $out.status='FAIL_EXACT_OWNED_PROCESS_TERMINATED_SCOPED_ABSENCE';$out.forced=$true
    }catch{$out.status='HOLD';$out.errorKind=$_.FullyQualifiedErrorId}
    $out
}
function Invoke-SupDriver($R,[int]$WaitMilliseconds,[switch]$InjectPostAllocationFailure){
    $driver=Join-Path $PSScriptRoot 'Invoke-MacSupervisedChild.ps1'
    & ${function:Assert-Sup} ((Microsoft.PowerShell.Utility\Get-FileHash $driver).Hash-ceq'E90C35656859302224A070CA00A49223FDF8EDE90D4B26BBADDD9108B837D2AD') 'Fixed supervisor driver differs'
    $request=Join-Path $R.owned ($R.role+'.request.json')
    $R.supervisorSha256=(Microsoft.PowerShell.Utility\Get-FileHash $PSCommandPath).Hash
    [IO.File]::WriteAllText($request,($R|ConvertTo-Json -Depth 10))
    $info=[Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath);$info.UseShellExecute=$false;$info.WorkingDirectory=$R.owned;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    foreach($arg in @('-NoProfile','-NonInteractive','-File',$driver,'-Request',$request,'-RequestSha256',(Microsoft.PowerShell.Utility\Get-FileHash $request).Hash,'-Nonce',$R.nonce,'-Role',$R.role,$(if($R.proofOnly){'-ProofOnly'}else{'-RootRuntimeApproved'}))){$info.ArgumentList.Add($arg)}
    $files=@{};$p=$null;$a=$null;$b=$null;$primary=$null;$cleanup=@();$exit=$null;$timedOut=$false;$gone=$true;$killed=$false;$processId=$null
    try{
        foreach($suffix in '.stdout','.stderr'){$files[$suffix]=[IO.File]::Open((Join-Path $R.owned ($R.role+$suffix)),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)}
        $p=[Diagnostics.Process]::Start($info);$processId=$p.Id;$gone=$false
        $a=$p.StandardOutput.BaseStream.CopyToAsync($files['.stdout']);$b=$p.StandardError.BaseStream.CopyToAsync($files['.stderr'])
        if($InjectPostAllocationFailure){throw 'Owned harmless postallocation failure'}
        $normal=$p.WaitForExit($WaitMilliseconds);$timedOut=-not$normal
        if(-not$normal){throw 'Owned supervisor child deadline'}
        $observed=$p.ExitCode;& ${function:Assert-Sup} ($observed-is[int]-or$observed-is[long]) 'Missing/null actual child ExitCode'
        $exit=[int]$observed
    }catch{$primary=$_.ToString()}
    finally{
        if($p){try{if(-not$p.HasExited){$p.Kill();$killed=$true};$gone=$p.WaitForExit(3000);if(-not$gone){$cleanup+='Owned child exit unconfirmed'}}catch{$cleanup+='Owned process-object cleanup failed'}}
        foreach($task in $a,$b){if($task){try{if(-not$task.Wait(2000)){$cleanup+='Drain unconfirmed'}}catch{$cleanup+='Drain failed'}}}
        foreach($file in $files.Values){try{$file.Flush()}catch{$cleanup+='Sink flush failed'}finally{try{$file.Dispose()}catch{$cleanup+='Sink disposal failed'}}}
        if($p){try{$p.Dispose()}catch{$cleanup+='Owned process-object disposal failed'}}
    }
    @{exit=$exit;primaryError=$primary;cleanupErrors=$cleanup;pid=$processId;childGone=$gone;killRequested=$killed;timeout=$timedOut;stdoutComplete=($null-ne$a-and$a.IsCompletedSuccessfully);stderrComplete=($null-ne$b-and$b.IsCompletedSuccessfully);observerAllocated=$false}
}
function Invoke-H3911MacSupervisor {
    param([Parameter(Mandatory)][string]$Owned,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce,[string]$Project,[string]$Jdk,[string]$JdkArchive,[string]$DistributionArchive,[string]$WatchRoot,[switch]$RootRuntimeApproved,[switch]$ProofOnly,[ValidateSet('Normal0','Nonzero1','Timeout','PostAllocationFailure','MissingResult','NullResult','IncompleteResult',IgnoreCase=$false)][string]$ProofCase='Normal0',[ValidateRange(1,600000)][int]$DeadlineMilliseconds=600000)
    & ${function:Assert-Sup} ($RootRuntimeApproved-xor$ProofOnly) 'Exactly one supervisor authority mode required'
    & ${function:Assert-Sup} (-not$RootRuntimeApproved-or($IsMacOS-and[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture-eq'Arm64'-and[Runtime.InteropServices.RuntimeInformation]::OSArchitecture-eq'Arm64'-and$DeadlineMilliseconds-eq600000)) 'Native ARM64 Mac and explicit600s budget required'
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $null=& ${function:Assert-SupBase}
    $q=Import-Module (Join-Path $PSScriptRoot 'H3911.MacQualifier.psm1') -Scope Local -PassThru -DisableNameChecking
    $resolve=& $q {Get-Command Resolve-MQPath -CommandType Function};$disjoint=& $q {Get-Command Assert-MQDisjoint -CommandType Function}
    $Owned=& $resolve $Owned -Missing;& ${function:Assert-Sup} (-not(Test-Path -LiteralPath $Owned)) 'Fresh supervisor root required; no adoption'
    $null=& $disjoint $Owned (& $resolve $PSScriptRoot)
    $inputs=@{}
    if($RootRuntimeApproved){
        foreach($name in 'Project','Jdk','JdkArchive','DistributionArchive','WatchRoot'){$inputs[$name]=& $resolve (Get-Variable -Name $name -ValueOnly)}
        foreach($name in 'Project','Jdk','JdkArchive','DistributionArchive'){$null=& $disjoint $Owned $inputs[$name];$null=& $disjoint (& $resolve $PSScriptRoot) $inputs[$name]}
        foreach($name in 'Jdk','JdkArchive','DistributionArchive'){$null=& $disjoint $inputs.Project $inputs[$name]}
        foreach($name in 'JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'){& ${function:Assert-Sup} (-not[Environment]::GetEnvironmentVariable($name)) 'Injected parent Java options prohibited'}
        & ${function:Assert-Sup} ((Microsoft.PowerShell.Utility\Get-FileHash $inputs.JdkArchive).Hash-ceq'C9CF199844411C8BAFD05722D2547538300523A63FF6207A440C71B175FF7873') 'Fixed native SDK archive required'
    }
    $envBefore=[Environment]::GetEnvironmentVariables('Process');$cwd=(Get-Location).Path;$native=[Environment]::CurrentDirectory
    $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($inputs|ConvertTo-Json -Compress))))
    $r=@{schema='mac-supervisor-request-v1';owned=$Owned;nonce=$Nonce;inputsDigest=$digest;inputs=$inputs;knownOwnedIdentities=@();qualifierOwned=(Join-Path $Owned 'qualification');proofOnly=[bool]$ProofOnly;proofCase=$ProofCase;role=$(if($ProofOnly){'Proof'}else{'Main'})}
    $r.result=Join-Path $Owned ($r.role+'.result.json')
    $out=@{status='FAIL';proofOnly=[bool]$ProofOnly;qualified=$false;nativeCensus=$(if($ProofOnly){'SKIPPED_PROOF_ONLY'}else{'PENDING'});overallBudgetMilliseconds=$DeadlineMilliseconds;runtimeMainMaximumMilliseconds=480000;childClientBudget=8;childClientMaximum=9;childAuxJcmdMaximum=12;parentAuxJcmdMaximum=2;auxJcmdMaximum=14;extraParentMavenCalls=0}
    $receipt=$null;$created=$false;$terminal=$null;$out.receiptPersisted=$false;$out.receiptErrors=@()
    try{
        New-Item $Owned -ItemType Directory -ErrorAction Stop|Out-Null;$created=$true
        $receipt=[IO.File]::Open((Join-Path $Owned 'supervisor.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        $scope=$null;$scopeError=$null
        try{$scope=[IO.File]::Open((Join-Path $Owned 'scope.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);$bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{schema='mac-supervisor-scope-v1';nonce=$Nonce;owned=$Owned;inputsDigest=$digest}|ConvertTo-Json));$scope.Write($bytes,0,$bytes.Length);$scope.Flush()}
        catch{$scopeError=$_}
        finally{if($scope){try{$scope.Dispose()}catch{if($scopeError){$out.scopeCleanupError=$_.ToString()}else{$scopeError=$_}}}}
        if($scopeError){throw $scopeError}
        $wait=if($ProofOnly){[Math]::Max(1,$DeadlineMilliseconds-[int]$clock.ElapsedMilliseconds)}else{[Math]::Min(480000,600000-[int]$clock.ElapsedMilliseconds-120000)}
        & ${function:Assert-Sup} ($wait-gt0) 'No child deadline reserve; HOLD before launch'
        $out.child=& ${function:Invoke-SupDriver} $r $wait -InjectPostAllocationFailure:($ProofOnly-and$ProofCase-ceq'PostAllocationFailure')
        if($out.child.primaryError){$out.primaryError=$out.child.primaryError}
        $good=$out.child.exit-is[int]-and$out.child.exit-eq0-and-not$out.child.primaryError-and$out.child.cleanupErrors.Count-eq0-and$out.child.childGone-and$out.child.stdoutComplete-and$out.child.stderrComplete
        $returned=$false
        if($good){
            try{
                $result=& ${function:Read-SupJson} $r.result
                & ${function:Assert-Sup} ($result.schema-is[string]-and$result.schema-ceq'mac-supervisor-result-v1'-and$result.status-is[string]-and$result.proofOnly-is[bool]-and$result.proofOnly-eq[bool]$ProofOnly-and$result.complete-is[bool]-and$result.complete) 'Typed complete scalar child result required'
                if($ProofOnly){& ${function:Assert-Sup} ($result.status-ceq'PROOF_ONLY_COMPLETE'-and$result.qualified-is[bool]-and-not$result.qualified) 'Proof-only result required';$out.status='PROOF_ONLY_COMPLETE_NOT_QUALIFICATION'}
                else{& ${function:Assert-Sup} ($result.qualified-is[bool]-and$result.qualified-and$result.status-ceq'QUALIFICATION_RETURNED_PENDING_AUDIT') 'Returned native qualification required';$record=& ${function:Read-SupJson} (Join-Path $r.qualifierOwned 'mac-qualifier.json');$null=& ${function:Assert-SupQualification} $record;$returned=$true}
            }catch{$out.resultFailure=$_.FullyQualifiedErrorId}
        }
        if(-not$ProofOnly-and$out.child.pid){
            $remaining=600000-[int]$clock.ElapsedMilliseconds-10000
            & ${function:Assert-Sup} ($remaining-gt0) 'No native cleanup deadline reserve; HOLD'
            $r.role='Cleanup';$r.result=Join-Path $Owned 'Cleanup.result.json';$r.mainReturned=$returned
            $out.cleanupWorker=& ${function:Invoke-SupDriver} $r ([Math]::Min(100000,$remaining))
            if($out.cleanupWorker.exit-is[int]-and$out.cleanupWorker.exit-eq0-and-not$out.cleanupWorker.primaryError-and$out.cleanupWorker.cleanupErrors.Count-eq0){
                $clean=& ${function:Read-SupJson} $r.result
                & ${function:Assert-Sup} ($clean.role-ceq'Cleanup'-and$clean.complete-is[bool]-and$clean.complete-and$clean.proofOnly-is[bool]-and-not$clean.proofOnly) 'Typed native cleanup result required'
                $out.nativeCleanup=$clean.cleanup;$out.nativeCensus=$clean.cleanup.status
                & ${function:Assert-Sup} ($clean.cleanup.status-is[string]) 'Scalar native cleanup status required'
                if($returned-and$clean.cleanup.status-ceq'NORMAL_RETURNED_AND_SCOPED_ABSENCE'){$out.status='MAC_RETURNED_PENDING_AUDIT';$out.qualified=$true}
                elseif($clean.cleanup.status-ceq'HOLD'){$out.status='HOLD';$out.qualified=$false}
            }else{$out.nativeCensus='HOLD_CLEANUP_WORKER_INCOMPLETE';$out.status='HOLD';$out.qualified=$false}
        }
    }catch{if($out.primaryError){$out.cleanupBoundaryError=$_.ToString()}else{$out.primaryError=$_.ToString()};$out.status='HOLD';$out.qualified=$false}
    finally{
        try{
            $clock.Stop();$out.elapsedMilliseconds=$clock.ElapsedMilliseconds
            $after=[Environment]::GetEnvironmentVariables('Process');$same=$envBefore.Count-eq$after.Count
            foreach($key in $envBefore.Keys){if(-not$after.Contains($key)-or$envBefore[$key]-cne$after[$key]){$same=$false}}
            $out.parentStateEqual=$same-and(Get-Location).Path-ceq$cwd-and[Environment]::CurrentDirectory-ceq$native
            if(-not$out.parentStateEqual-or$clock.ElapsedMilliseconds-gt$DeadlineMilliseconds){$out.status='HOLD';$out.qualified=$false}
            & ${function:Assert-Sup} ($created-and$null-ne$receipt) 'Authoritative receipt reservation failed'
            $out.receiptPersisted=$true
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($out|ConvertTo-Json -Depth 12));$receipt.Write($bytes,0,$bytes.Length);$receipt.Flush()
        }catch{$out.receiptPersisted=$false;$out.receiptErrors+=,$_.ToString();$out.status='HOLD';$out.qualified=$false}
        finally{if($receipt){try{$receipt.Dispose()}catch{$out.receiptPersisted=$false;$out.receiptErrors+=,$_.ToString();$out.status='HOLD';$out.qualified=$false}}}
        if(-not$out.receiptPersisted){
            $message=if($out.primaryError){$out.primaryError}else{'Supervisor allocation/receipt finalization failed'}
            $terminal=[InvalidOperationException]::new($message)
            $terminal.Data['PrimaryError']=$out.primaryError;$terminal.Data['ReceiptErrors']=@($out.receiptErrors)
            try{$terminal.Data['SupervisorOutcomeJson']=($out|ConvertTo-Json -Depth 12)}catch{$terminal.Data['OutcomeSerializationError']=$_.ToString()}
            try{[Console]::Error.WriteLine(('SUPERVISOR_RECEIPT_FAILURE primary='+$message))}catch{$terminal.Data['FallbackStderrError']=$_.ToString()}
        }
    }
    if($terminal){throw $terminal}
    $out
}
Export-ModuleMember -Function Invoke-H3911MacSupervisor
