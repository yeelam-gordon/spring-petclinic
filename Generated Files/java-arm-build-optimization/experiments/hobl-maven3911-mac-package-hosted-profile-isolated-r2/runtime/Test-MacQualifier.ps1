param([Parameter(Mandatory)][string]$RepositorySource,[Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
if(-not[IO.Path]::IsPathFullyQualified($OutputDirectory)-or(Test-Path $OutputDirectory)){throw 'Fresh absolute model output required'}
New-Item $OutputDirectory -ItemType Directory|Out-Null
$guardRoot=Join-Path $OutputDirectory 'physical guard with spaces';New-Item $guardRoot -ItemType Directory|Out-Null
$guardFile=Join-Path $guardRoot 'ordinary file.txt';[IO.File]::WriteAllText($guardFile,'HARMLESS_PHYSICAL_GUARD_ONLY')
$tokens=$null;$errors=$null;$ownerAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'H3911.EffectiveOwner.psm1'),[ref]$tokens,[ref]$errors)
$guard=$ownerAst.Find({param($n)$n-is[Management.Automation.Language.CommandAst]-and$n.GetCommandName()-ceq'Assert-EffectiveOwner'-and$n.Extent.Text.Contains('$resolved.Provider.Name')},$true)
$physicalCondition=[scriptblock]::Create('param($Path,$Directory,$resolved,$item) '+$guard.CommandElements[1].Extent.Text)
$physicalProof=@()
foreach($sample in @(@($guardRoot,$true,$true),@($guardFile,$false,$true),@($guardRoot,$false,$false),@($guardFile,$true,$false))){
    $item=Get-Item -LiteralPath $sample[0] -Force;$resolved=Resolve-Path -LiteralPath $sample[0]
    $accepted=& $physicalCondition $sample[0] ([Management.Automation.SwitchParameter]::new([bool]$sample[1])) $resolved $item
    if([bool]$accepted-ne[bool]$sample[2]){throw 'Actual source physical directory/file guard regression'}
    $physicalProof+=@{case='actual-kind';expectedDirectory=$sample[1];accepted=[bool]$accepted;passed=$true}
}
$item=Get-Item $guardFile;$resolved=Resolve-Path $guardFile
foreach($kind in 'provider','ordinal','false-valuetype'){
    $r=$resolved;$obj=$item
    switch($kind){provider{$r=[pscustomobject]@{ProviderPath=$guardFile;Provider=[pscustomobject]@{Name='Registry'}}}ordinal{$r=[pscustomobject]@{ProviderPath=($guardFile+'DIFFERENT');Provider=$resolved.Provider}}false-valuetype{$obj=$false}}
    if(& $physicalCondition $guardFile ([Management.Automation.SwitchParameter]::new($false)) $r $obj){throw 'Actual physical guard policy was relaxed'}
    $physicalProof+=@{case=$kind;passed=$true}
}
$fileLink=Join-Path $OutputDirectory 'physical-file-link';New-Item -ItemType SymbolicLink -Path $fileLink -Target $guardFile|Out-Null
if(& $physicalCondition $fileLink ([Management.Automation.SwitchParameter]::new($false)) (Resolve-Path $fileLink) (Get-Item $fileLink -Force)){throw 'Actual physical link guard was relaxed'}
$physicalProof+=@{case='actual-link-reparse';passed=$true}
$dirLink=Join-Path $OutputDirectory 'physical-directory-link';New-Item -ItemType SymbolicLink -Path $dirLink -Target $guardRoot|Out-Null
$ancestryGuard=$ownerAst.Find({param($n)$n-is[Management.Automation.Language.CommandAst]-and$n.GetCommandName()-ceq'Assert-EffectiveOwner'-and$n.Extent.Text.Contains("'Linked owner ancestry'")},$true)
$ancestryCondition=[scriptblock]::Create('param($parent) '+$ancestryGuard.CommandElements[1].Extent.Text)
if(& $ancestryCondition (Get-Item $dirLink -Force)){throw 'Actual physical ancestry guard was relaxed'}
$physicalProof+=@{case='actual-linked-ancestry';passed=$true}
$physicalProof|ConvertTo-Json -Depth 4|Set-Content (Join-Path $OutputDirectory 'physical-guard-proof.json')
$git=(Get-Command git -CommandType Application|Select-Object -First 1).Source;$project=Join-Path $OutputDirectory 'project'
& $git clone --quiet --no-checkout --no-hardlinks $RepositorySource $project;if($LASTEXITCODE){throw 'Model clone failed'}
foreach($a in @(@('config','core.autocrlf','false'),@('remote','set-url','origin','https://github.com/spring-projects/spring-petclinic.git'),@('checkout','--quiet','--detach','6feeae0f13e0e258eedc99832416b42bb13779b1'))){& $git -C $project @a;if($LASTEXITCODE){throw 'Model source admission setup failed'}}
$jdk=Join-Path $OutputDirectory 'SYNTHETIC-JDK';New-Item $jdk -ItemType Directory|Out-Null
$module=Import-Module (Join-Path $PSScriptRoot 'H3911.MacQualifier.psm1') -Scope Local -PassThru -Force -DisableNameChecking
$invoke=$module.ExportedCommands['Invoke-H3911MacQualifier'];$proof=@()
$proof+=@{case='actual-source-physical-guard';passed=$true;controls=$physicalProof.Count;scope='Actual guard AST/real ordinary filesystem objects; no Owner hook or MacOS spoof'}
function CheckModel([string]$Case,[string]$HomeState='absent',[switch]$Aliases){
    $owned=Join-Path $OutputDirectory $Case;$state=@{alive=$false;stops=0;reads=0;case=$Case}
    $hooks=@{
        Setup={param($c)New-Item $c.Home -ItemType Directory|Out-Null;@{fixtureOnly=$true}}
        Dispatch={param($c,$p)
            if($p.label-eq'daemon-arch'){$state.alive=$true}
            $value=switch($p.label){daemon-arch{'aarch64'}daemon-home{if($state.case-eq'context-fail'){'WRONG'}else{$c.Jdk}}baseline-maven-home{Join-Path $owned 'MODEL-MAVEN3911'}default{$c.Project}}
            if($p.label-notlike'*-verify'){[IO.File]::WriteAllText($p.valueFile,$value,[Text.UTF8Encoding]::new($false))}
            0
        }.GetNewClosure()
        Owner={param($c)$state.reads++;if($state.alive){@{pid=$(if($state.case-eq'pid-change'-and$state.reads-gt1){23456}else{12345});created='2026-01-01T00:00:00Z';daemonId=$(if($state.case-eq'id-fail'){'invalid'}else{'01234567'});home=$c.Home;registryFile=$(if($state.case-eq'registry-fail'){'FOREIGN'}else{Join-Path $c.Registry 'registry.bin'});executable=(Join-Path $c.Jdk 'bin/java');jniPath=(Join-Path $c.Temp 'MODEL.jnilib');evidenceKind='MODEL_NOT_NATIVE_MAC'}}}.GetNewClosure()
        Census={param($c,$anchor)
            if($state.case-in@('early-hold','early-hold-cleanup-fail')){throw 'HOLD: unreadable/exited/ambiguous native process identity during full census [reason=CENSUS_ROW_FAILED;phase=main-module;pid=42;scanComplete=false]'}
            if($state.case-eq'early-missing'){return $null}
            $tracked=@{};foreach($p in $anchor.GetEnumerator()){$tracked[$p.Key]=$p.Value}
            $live=@{pid=$anchor.pid;created=$anchor.created;executable=$anchor.executable}
            $credential=@{pid=$anchor.pid;parentPid=1;realUid=501L;effectiveUid=501L;savedUid=501L;birthSeconds=1767225600L;birthMicroseconds=0L}
            $selfCredential=@{pid=22222;parentPid=1;realUid=501L;effectiveUid=501L;savedUid=501L;birthSeconds=1767225600L;birthMicroseconds=0L}
            $live.credential=$credential;$live.protectedPathPid=$true
            $census=@{schema='darwin-launch-uid-java-census-v2';complete=$true;errors=@();scope='launch-effective-UID admitted-JDK Java plus explicitly tracked identities';jdkExecutable=(Join-Path $c.Jdk 'bin/java');expectedIdentityGone=$false;tracked=@($tracked);sameJdkJava=@($live);knownLive=@($live);evidenceKind='validated-uid-census-model';uidProof=@{schema='darwin-launch-uid-proof-v2';admittedUid=501L;filter=5;selfIdentity=@{pid=22222;created='2026-01-01T00:00:00Z';executable='/fixture/pwsh'};selfCredential=$selfCredential;ownerCredential=$credential;selectedPids=@(22222,$anchor.pid,333);outsideProtectedPathPidPids=@(333);missingAtRecheckPids=@();selectedPidCount=3;knownPidCount=1;unionPidCount=3;validatedPidCount=3;outsideProtectedPathPidCount=1;missingAtRecheckCount=0;presenceRecheckAttempts=0;observationBasis='EUID_SELECTION_TRACKED_UNION_PATH_PID_SCOPE_V1';atomicEndpoint=$false;newbornCoverage=$false}}
            $census.uidProof.universalHistory=$false
            switch($state.case){
                early-schema{$census.schema='WRONG'}
                early-types{$census.complete='true'}
                early-tracked{$tracked.registryFile='FOREIGN'}
                early-time{$live.created='not-a-time'}
                early-reused{$live.created='2026-01-01T00:00:01Z'}
                early-foreign{$live.executable='FOREIGN'}
                early-owner-missing{$census.expectedIdentityGone=$true;$census.sameJdkJava=@();$census.knownLive=@();$census.uidProof.ownerCredential=$null;$census.uidProof.validatedPidCount=2;$census.uidProof.missingAtRecheckPids=@($anchor.pid);$census.uidProof.missingAtRecheckCount=1;$census.uidProof.presenceRecheckAttempts=1;$census.uidProof.unvalidatedExtra=@{notEvidence='DROP_ME'};$census.uidProof.selfCredential.unvalidatedExtra='DROP_ME'}
                positive-offset{$live.created='2026-01-01T08:00:00.0000000+08:00';$tracked.created='2026-01-01T00:00:00.0000000Z'}
            }
            $census
        }.GetNewClosure()
        Stock={param($c,$root)@{status='FULL_TRUSTED_STOCK_MAVEN3911_ADMITTED';archiveFiles=$(if($state.case-eq'stock-fail'){1}else{96});physicalFiles=97;directories=13;inventorySha256='63382624DFFEF090C2B47C476767D9BE9F0620296193B650AE419ABE34FC4D0F';archiveFormat=$(if($state.case-eq'positive-tar'){'Tar'}else{'Zip'});fixtureOnly=$true}}.GetNewClosure()
        Verify={param($c,$label,$call)@{tests=@(1..$(if($state.case-eq'fidelity-fail'){55}else{56}));counters=@(1..726);semantics='MODEL_ONLY';fork=$label;session=$label;artifact='NO_COMPILED_ARTIFACT'}}.GetNewClosure()
        Compare={param($c)$true}
        StopPlan={param($c,$anchor,$emergency)@{exe=(Join-Path $c.Home 'bin/mvnd');tokens=@("-Dmvnd.daemonStorage=$($c.Registry)","-Dmvnd.registry=$($anchor.registryFile)","-Djava.home=$($c.Jdk)",'--stop');workingDirectory=$c.Temp;expectedPid=$anchor.pid;expectedCreated=$anchor.created;fixtureOnly=$true}}
        Stop={param($c,$p)$state.stops++;if(($state.case-eq'stop-fail'-and$state.stops-eq1)-or$state.case-eq'early-hold-cleanup-fail'){1}else{$state.alive=$false;0}}.GetNewClosure()
        Confirm={param($c,$anchor,$exit,$emergency)if($state.alive){throw 'MODEL census survivor'};if($state.case-eq'post-census-fail'){throw 'MODEL_POST_STOP_COMPLETE_CENSUS_HOLD'};@{status=$(if($emergency){'FAIL_NONZERO_FORCED_OR_EMERGENCY'}else{'NORMAL_CLI_ROUTE_SCOPED_ABSENCE_CONFIRMED'});fixtureOnly=$true}}.GetNewClosure()
    }
    $helper=Import-Module (Join-Path $PSScriptRoot 'H3911.Helpers.psm1') -PassThru -Scope Local -DisableNameChecking
    $snapshot=$helper.ExportedCommands['PortableEnvironmentSnapshot'];$restore=$helper.ExportedCommands['RestorePortableEnvironment'];$saved=& $snapshot
    switch($HomeState){absent{Remove-Item Env:JAVA_HOME -ErrorAction SilentlyContinue}empty{[Environment]::SetEnvironmentVariable('JAVA_HOME','','Process')}value{$env:JAVA_HOME='MODEL_CALLER'}}
    $before=& $snapshot;$cwd=(Get-Location).Path;$native=[Environment]::CurrentDirectory;$errorText=$null
    $names=@('Assert-MQ','Import-MQ','Resolve-MQPath','Assert-MQDisjoint','Get-MQWatch','Read-MQOwner','Assert-MQSame','Assert-MQEarlyCensus','Stop-MQ')
    if($Aliases){foreach($n in $names){Set-Alias -Name $n -Value Out-Null -Scope Global}}
    try{$result=& $invoke -Project $project -Jdk $jdk -Owned $owned -WatchRoot $RepositorySource -FixtureOnly -FixtureHooks $hooks}catch{$errorText=$_.Exception.Message}
    finally{
        if($Aliases){foreach($n in $names){if((Get-Alias -Name $n -Scope Global).Definition-cne'Out-Null'){throw 'Mac caller alias changed'};Remove-Alias -Name $n -Scope Global}}
        $after=& $snapshot;if($before.Count-ne$after.Count){throw 'Mac model environment universe changed'};foreach($k in $before.Keys){if(-not$after.Contains($k)-or$before[$k]-cne$after[$k]){throw 'Mac model caller environment changed'}}
        if((Get-Location).Path-cne$cwd-or[Environment]::CurrentDirectory-cne$native){throw 'Mac model cwd changed'}
        $null=& $restore $saved @('JAVA_HOME')
    }
    $receipt=Get-Content (Join-Path $owned 'mac-qualifier.json') -Raw|ConvertFrom-Json
    if($Case-like'positive*'){
        $labels=@($receipt.calls|ForEach-Object{if($_.plan){$_.plan.label}else{$_.label}})
        if($errorText-or$receipt.status-cne'MAC_FIXTURE_ONLY_COMPLETE'-or$state.alive-or$state.stops-ne1-or($labels-join',')-cne'baseline-project,daemon-arch,daemon-home,daemon-project,baseline-maven-home,baseline-verify,candidate-verify,normal-stop'){throw "Mac complete eight-call model failed: $errorText"}
        if($receipt.earlyCensus.status-cne'COMPLETE_OWNED_RUNNING_SCOPE_CONFIRMED'-or$receipt.earlyCensus.absenceAsserted-or-not$receipt.earlyCensus.ownerLive){throw 'Early live-scope gate was absent or asserted absence'}
    }else{
        if(-not$errorText-or$receipt.status-cne'FAIL'){throw "Mac negative model accepted $Case"}
        if($Case-in@('pid-change','id-fail','registry-fail')){if(-not$receipt.cleanupFailure-or$state.stops){throw 'Ambiguous owner cleanup was not held'}}
        elseif($Case-eq'early-hold-cleanup-fail'){if(-not$receipt.cleanupFailure-or$errorText-notmatch'CENSUS_ROW_FAILED;phase=main-module;pid=42;scanComplete=false'){throw 'Cleanup failure masked original fixed diagnostic'}}
        elseif($state.alive){throw 'Mac admitted cleanup missed modeled owner'}
        if($Case-like'early-*'){
            if($receipt.calls.Count-ne5-or@($receipt.calls|Where-Object {$_.plan.label-like'*-verify'}).Count-or$state.stops-ne1){throw 'Early visibility hold crossed build boundary or missed one safe stop'}
        }
        if($Case-eq'post-census-fail'-and($receipt.calls.Count-ne8-or$errorText-notmatch'MODEL_POST_STOP_COMPLETE_CENSUS_HOLD')){throw 'Early preflight replaced mandatory post-stop census'}
        if($Case-eq'stop-fail'-and$receipt.calls.Count-ne9){throw 'Mac failed normal stop did not retain nine attempts'}
        if($Case-eq'stock-fail'-and@($receipt.calls|Where-Object{$_.plan.label-like'*-verify'}).Count){throw 'Mac full build preceded stock admission'}
    }
    if(-not$receipt.sourceEqual-or-not$receipt.rootWatchEqual-or-not$receipt.restoration.restored){throw 'Mac source/root/state checks missing'}
    @{case=$Case;passed=$true;calls=$receipt.calls.Count;error=$errorText;mode='WINDOWS_MODEL_NOT_MAC_RUNTIME';ownerAlive=$state.alive}
}
foreach($s in 'absent','empty','value'){$proof+=CheckModel "positive-$s" $s}
$proof+=CheckModel 'positive-tar'
$proof+=CheckModel 'positive-alias' -Aliases
$proof+=CheckModel 'positive-offset'
foreach($s in 'stock-fail','fidelity-fail','context-fail','stop-fail','pid-change','id-fail','registry-fail'){$proof+=CheckModel $s}
foreach($s in 'early-hold','early-missing','early-schema','early-types','early-tracked','early-time','early-reused','early-foreign','early-owner-missing','early-hold-cleanup-fail','post-census-fail'){$proof+=CheckModel $s}
$common=@{Project=$project;Jdk=$jdk;Owned=(Join-Path $OutputDirectory 'NOT_CREATED');WatchRoot=$RepositorySource}
$gateAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'H3911.MacQualifier.psm1'),[ref]$tokens,[ref]$errors)
$platformGate=$gateAst.Find({param($n)$n-is[Management.Automation.Language.CommandAst]-and$n.Extent.Text.Contains("'Native ARM64 Mac required; runtime callbacks prohibited'")},$true)
$platformPredicate=[scriptblock]::Create('param($RuntimeApproved,$FixtureHooks) '+$platformGate.CommandElements[1].Extent.Text)
foreach($case in 'no-authority','real-callback','native-gate','owned-target','identity-pin'){
    $args=@{};foreach($p in $common.GetEnumerator()){$args[$p.Key]=$p.Value};$failure=$null
    $identity=Join-Path $PSScriptRoot 'mac-jdk25-identity.json';$bytes=[IO.File]::ReadAllBytes($identity)
    try{
        switch($case){
            no-authority{$null=& $invoke @args}
            real-callback{if(& $platformPredicate ([Management.Automation.SwitchParameter]::new($true)) @{bad={}}){throw 'Source callback predicate unexpectedly admitted a callback'};throw 'HOLD: source callback predicate rejected'}
            native-gate{if(& $platformPredicate ([Management.Automation.SwitchParameter]::new($true)) $null){$inputs=Import-Module (Join-Path $PSScriptRoot 'H3911.MacRuntimeInputs.psm1') -PassThru;& $inputs.ExportedCommands['Assert-H3911MacSdk'] @{Jdk=$jdk;Project=$project} (Join-Path $OutputDirectory 'ABSENT-SDK-ARCHIVE.tar.gz')}else{throw 'HOLD: source platform predicate rejected'}}
            owned-target{$args.Owned=Join-Path $project 'target\private';$null=& $invoke @args -FixtureOnly -FixtureHooks @{notCalled=$true}}
            identity-pin{[IO.File]::AppendAllText($identity,' ');$null=& $invoke @args -FixtureOnly -FixtureHooks @{Setup={};Dispatch={};Owner={};Census={};Stock={};Verify={};Compare={};StopPlan={};Stop={};Confirm={}}}
        }
    }catch{$failure=$_.Exception.Message}
    finally{if($case-eq'identity-pin'){[IO.File]::WriteAllBytes($identity,$bytes)}}
    if($case-eq'real-callback'-and$failure-cne'HOLD: source callback predicate rejected'){throw 'Actual source callback rejection predicate regressed'}
    if(-not$failure-or(Test-Path -LiteralPath $args.Owned)){throw "Mac early gate failed $case"}
    $proof+=@{case=$case;passed=$true;error=$failure;zeroNativeCalls=$true}
}
@{verdict='PASS';cases=$proof;scope='Synthetic pure Windows models, not native Mac execution/coverage/performance'}|ConvertTo-Json -Depth 7|Set-Content (Join-Path $OutputDirectory 'proof.json')
Write-Output "MAC_QUALIFIER_MODEL_PASS cases=$($proof.Count); no Java/native Mac/runtime"
$gone=Get-Content (Join-Path $OutputDirectory 'early-owner-missing\mac-qualifier.json') -Raw|ConvertFrom-Json -AsHashtable -DateKind String
$held=$gone.earlyCensus
if($held.status-cne'HOLD'-or$held.absenceAsserted-isnot[bool]-or$held.absenceAsserted-or$held.schema-cne'darwin-launch-uid-java-census-v2'-or$held.scope-cne'launch-effective-UID admitted-JDK Java plus explicitly tracked identities'-or$held.uidProof.schema-cne'darwin-launch-uid-proof-v2'-or$held.uidProof.admittedUid-ne501-or$held.uidProof.missingAtRecheckCount-ne1-or$held.uidProof.presenceRecheckAttempts-ne1-or$null-ne$held.uidProof.ownerCredential-or$held.uidProof.ContainsKey('unvalidatedExtra')-or$held.uidProof.selfCredential.ContainsKey('unvalidatedExtra')-or$gone.calls.Count-ne5-or@($gone.calls|Where-Object {$_.plan.label-like'*-verify'}).Count-ne0-or$gone.failure-notlike'*owner absent*'){throw 'Completed owner-gone UID HOLD observation was lost or promoted'}
@{verdict='PASS';cases=1;fixtureOnly=$true;nativeCalls=0;held=$held;clientCalls=$gone.calls.Count;fullVerifies=0;primary=$gone.failure}|ConvertTo-Json -Depth 9|Set-Content (Join-Path $OutputDirectory 'early-receipt-proof.json')
Write-Output 'UID_EARLY_HOLD_RECEIPT_PASS cases=1; completed owner-gone v2 preserved; native0'
$life=Import-Module (Join-Path $PSScriptRoot 'H3911.DarwinLifecycle.psm1') -Force -PassThru
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'H3911.DarwinLifecycle.psm1'),[ref]$tokens,[ref]$errors)
$collector=$ast.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'Get-LifeOsProcesses'},$true).Body.Extent.Text
$collector=$collector.Substring(1,$collector.Length-2).Replace("if(-not`$IsMacOS-or-not`$RuntimeApproved){throw 'HOLD: native Mac approved census required'}",'')
$collector=$collector.Replace('$commands=& ${function:Get-LifeUidCommands}','$commands=$script:UidFixtureCommands').Replace('[Diagnostics.Process]::GetProcessById($id)','(& $script:UidFixtureLookup $id)')
$branch=& $life {param($text)[scriptblock]::Create($text)} $collector
$uidProof=@()
foreach($case in 'valid','equivalent-utc','outside-zmz','sameuid-unreadable','eperm','unknown-presence','enum-error','self-uid','self-birth','owner-birth','birth-precision','invalid-executable','unclassified-credential','selected-mixed-real','selected-mixed-saved','selected-effective-drift','known-credential-drift','uid-matching-image','uid-tampered-birth','uid-unknown-context','uid-noncanonical-image','uid-ambiguous-birth','uid-owner-drift','uid-self-drift','known-uid-birth-mismatch','known-image-change','known-image-and-uid-change','known-outside-uid','known-reuse','unknown-jdk-replacement','owner-gone','post-known-survivor','post-java-survivor','dispose-missing'){
    $ctx=@{Jdk='/fixture/jdk25';Home='/fixture/mvnd';Registry='/fixture/registry';Temp='/fixture/temp';KnownOwnedIdentities=@()}
    $owner=@{pid=100;created='2026-01-01T00:00:00Z';executable='/fixture/jdk25/bin/java';daemonId='01234567';home=$ctx.Home;registryFile='/fixture/registry/registry.bin';jniPath='/fixture/temp/native.jnilib';evidenceKind='SYNTHETIC_UID_MODEL'}
    if($case-in@('known-outside-uid','known-reuse','known-credential-drift','known-uid-birth-mismatch','known-image-change','known-image-and-uid-change','post-known-survivor')){$ctx.KnownOwnedIdentities=@(@{pid=150;created='2026-01-01T00:00:00Z';executable='/fixture/known'})}
    & $life {
        param($case,$owner)
        $script:UidFixtureCase=$case;$script:UidFixtureLookups=@();$script:UidFixtureOwner=$owner;$script:UidFixturePresenceCalls=0
        $script:UidFixtureSelf=@{pid=10;created='2026-01-01T00:00:00Z';executable='/fixture/pwsh'}
        $script:UidFixtureCommands=@{
            'Read-LifeSelfCredential'={@{pid=10;parentPid=1;realUid=$(if($script:UidFixtureCase-eq'self-uid'){502L}else{501L});effectiveUid=501L;savedUid=501L;birthSeconds=$(if($script:UidFixtureCase-eq'self-birth'){1767225601L}else{1767225600L});birthMicroseconds=0L}}
            'Get-LifeCurrent'={param($processId)$script:UidFixtureSelf}
            'Read-LifeOwnUidPids'={if($script:UidFixtureCase-eq'enum-error'){throw 'MODEL_ENUM_TRUNCATED_OR_ERROR'};@{pids=@(10,100)+$(if($script:UidFixtureCase-like'uid-*'-or$script:UidFixtureCase-in@('outside-zmz','unknown-jdk-replacement','post-java-survivor','selected-mixed-real','selected-mixed-saved','selected-effective-drift')){@(200)}else{@()})}}
            'Read-LifeCensusCredential'={
                param($ProcessId)
                if($script:UidFixtureCase-eq'unclassified-credential'){throw "HOLD: Nonroot real/effective/saved UID invariant required [uidComparison=MZMSENSITIVE_FIXTURE_ONLY]`n/untrusted/path"}
                $seconds=if($ProcessId-eq200-and$script:UidFixtureCase-eq'uid-ambiguous-birth'){17179869184L}elseif(($ProcessId-eq100-and$script:UidFixtureCase-eq'owner-birth')-or($ProcessId-eq150-and$script:UidFixtureCase-in@('known-reuse','known-uid-birth-mismatch'))-or$ProcessId-eq200){1767225601L}else{1767225600L}
                $uid=if($ProcessId-eq150-and$script:UidFixtureCase-eq'known-outside-uid'){502L}else{501L}
                $real=$uid;$effective=$uid;$saved=$uid
                if($ProcessId-eq200-and$script:UidFixtureCase-eq'selected-mixed-real'){$real=0L}
                if($ProcessId-eq200-and$script:UidFixtureCase-eq'outside-zmz'){$real=0L;$saved=0L}
                if(($ProcessId-eq200-and$script:UidFixtureCase-eq'uid-matching-image')-or($ProcessId-eq150-and$script:UidFixtureCase-eq'known-credential-drift')-or($ProcessId-eq100-and$script:UidFixtureCase-eq'uid-owner-drift')-or($ProcessId-eq10-and$script:UidFixtureCase-eq'uid-self-drift')){$real=0L}
                if(($ProcessId-eq200-and($script:UidFixtureCase-eq'selected-mixed-saved'-or$script:UidFixtureCase-like'uid-*'))-or($ProcessId-eq150-and$script:UidFixtureCase-in@('known-credential-drift','known-uid-birth-mismatch','known-image-and-uid-change'))-or($ProcessId-eq100-and$script:UidFixtureCase-eq'uid-owner-drift')-or($ProcessId-eq10-and$script:UidFixtureCase-eq'uid-self-drift')){$saved=0L}
                if($ProcessId-eq200-and$script:UidFixtureCase-eq'selected-effective-drift'){$effective=502L}
                & ${function:ConvertFrom-LifeBsdRecord} @([int]136,[int]0,$ProcessId,[int]1,$real,$effective,$saved,$seconds,0L) $ProcessId
            }
            'Read-LifePresence'={param($ProcessId)$script:UidFixturePresenceCalls++;if($script:UidFixtureCase-eq'eperm'){'PRESENT_EPERM'}elseif($script:UidFixtureCase-eq'unknown-presence'){'UNKNOWN'}elseif($script:UidFixtureCase-in@('owner-gone','post-known-survivor','post-java-survivor','dispose-missing','known-reuse')){'MISSING_ESRCH'}else{'PRESENT'}}
        }
        $script:UidFixtureLookup={
            param($processId)
            $script:UidFixtureLookups+=,$processId
            if($processId-eq100-and$script:UidFixtureCase-in@('owner-gone','post-known-survivor','post-java-survivor')){throw 'MODEL_LOOKUP_UNAVAILABLE'}
            $created=if($processId-eq200-and$script:UidFixtureCase-eq'uid-ambiguous-birth'){[DateTime]::UnixEpoch.AddSeconds(17179869184L).ToString('o')}elseif($processId-eq200-and$script:UidFixtureCase-eq'uid-tampered-birth'){'2026-01-01T00:00:02Z'}elseif($processId-eq200-or($processId-eq150-and$script:UidFixtureCase-in@('known-reuse','known-uid-birth-mismatch'))){'2026-01-01T00:00:01Z'}elseif($script:UidFixtureCase-eq'equivalent-utc'){'2026-01-01T08:00:00+08:00'}elseif($script:UidFixtureCase-eq'birth-precision'){'2026-01-01T00:00:00.0000001Z'}else{'2026-01-01T00:00:00Z'}
            $exe=if($script:UidFixtureCase-eq'invalid-executable'-or($processId-eq200-and$script:UidFixtureCase-eq'uid-noncanonical-image')){'relative/SENSITIVE_FIXTURE_ONLY'}elseif($processId-eq150-and$script:UidFixtureCase-in@('known-image-change','known-image-and-uid-change')){'/fixture/changed'}elseif($processId-eq200-and$script:UidFixtureCase-in@('outside-zmz','selected-mixed-real','selected-mixed-saved','selected-effective-drift','uid-tampered-birth','uid-unknown-context','uid-ambiguous-birth')){'/fixture/outside-path-pid'}else{switch($processId){10{'/fixture/pwsh'}150{'/fixture/known'}default{'/fixture/jdk25/bin/java'}}}
            $obj=[pscustomobject]@{StartTime=[DateTimeOffset]::Parse($created).UtcDateTime;MainModule=[pscustomobject]@{FileName=$exe}}
            if($processId-eq100-and$script:UidFixtureCase-in@('sameuid-unreadable','eperm','unknown-presence','dispose-missing')){$obj|Add-Member StartTime -MemberType ScriptProperty -Value {throw 'MODEL_STARTTIME_UNREADABLE'} -Force}
            $obj|Add-Member Dispose -MemberType ScriptMethod -Value {if($script:UidFixtureCase-eq'dispose-missing'){throw 'MODEL_DISPOSAL_FAILED'}}
            $obj
        }
    } $case $owner
    if($case-eq'uid-unknown-context'){$ctx.KnownOwnedIdentities=$null}
    $failure=$null;$census=$null
    try{$observation=& $life {param($text,$context,$expected)& ([scriptblock]::Create($text)) -Context $context -Expected $expected -RuntimeApproved} $collector $ctx $owner;$census=& $life.ExportedCommands['ConvertTo-H3911DarwinScopedCensus'] $ctx $owner $observation}catch{$failure=$_.Exception.Message}
    $mustHold=$case-in@('sameuid-unreadable','eperm','unknown-presence','enum-error','self-uid','self-birth','owner-birth','birth-precision','invalid-executable','unclassified-credential','selected-effective-drift','known-credential-drift','uid-matching-image','uid-tampered-birth','uid-unknown-context','uid-noncanonical-image','uid-ambiguous-birth','uid-owner-drift','uid-self-drift','known-uid-birth-mismatch','known-image-change','known-image-and-uid-change','known-outside-uid','known-reuse','dispose-missing')
    if([bool]$failure-ne$mustHold){throw "Actual UID collector branch unexpected $case : $failure"}
    $diagnostic=@{
        'owner-birth'=@('credential-binding','BIRTH_BINDING')
        'birth-precision'=@('credential-binding','BIRTH_BINDING')
        'invalid-executable'=@('credential-binding','EXECUTABLE_PATH')
        'known-reuse'=@('credential-binding','KNOWN_IDENTITY')
        'unclassified-credential'=@('kernel-credential','UNCLASSIFIED')
        'selected-effective-drift'=@('credential-binding','CREDENTIAL_EUID')
        'known-credential-drift'=@('credential-binding','CREDENTIAL_UID')
        'uid-matching-image'=@('credential-binding','CREDENTIAL_UID')
        'uid-tampered-birth'=@('credential-binding','BIRTH_BINDING')
        'uid-noncanonical-image'=@('path-pid-scope','EXECUTABLE_PATH')
        'uid-ambiguous-birth'=@('credential-binding','BIRTH_PROJECTION_AMBIGUOUS')
        'uid-owner-drift'=@('credential-binding','CREDENTIAL_UID')
        'uid-self-drift'=@('credential-binding','CREDENTIAL_UID')
        'known-uid-birth-mismatch'=@('credential-binding','CREDENTIAL_UID')
        'known-image-change'=@('credential-binding','KNOWN_IDENTITY')
        'known-image-and-uid-change'=@('credential-binding','CREDENTIAL_UID')
    }
    if($diagnostic.ContainsKey($case)){
        $expected=$diagnostic[$case];$presenceCalls=& $life {$script:UidFixturePresenceCalls}
        if($failure-notlike('*phase='+$expected[0]+';*')-or-not$failure.Contains('[invariant='+$expected[1]+']')-or-not$failure.Contains('scanComplete=false')-or$failure.Contains('SENSITIVE_FIXTURE_ONLY')-or$failure-match'[\r\n]'-or$presenceCalls-ne0){throw "Fail-closed bounded census diagnostic differs $case : $failure"}
    }
    $uidCodes=@{'known-credential-drift'='ZMZ';'uid-matching-image'='ZMZ';'uid-owner-drift'='ZMZ';'uid-self-drift'='ZMZ';'known-uid-birth-mismatch'='MMZ';'known-image-and-uid-change'='MMZ'}
    if($uidCodes.ContainsKey($case)-and(-not$failure.Contains('[uidComparison='+$uidCodes[$case]+']')-or$null-ne$census)){throw "Failed UID row lost its bounded comparison or acquired census authority $case"}
    $scopeTags=@{
        'known-credential-drift'=@('KNOWN_TRACKED','OTHER_CANONICAL','MATCH')
        'uid-matching-image'=@('OTHER','ADMITTED_JDK_JAVA','MATCH')
        'uid-owner-drift'=@('EXPECTED_OWNER','ADMITTED_JDK_JAVA','MATCH')
        'uid-self-drift'=@('SELF','OTHER_CANONICAL','MATCH')
        'known-uid-birth-mismatch'=@('KNOWN_TRACKED','OTHER_CANONICAL','MISMATCH')
        'known-image-and-uid-change'=@('KNOWN_TRACKED','OTHER_CANONICAL','MATCH')
    }
    if($scopeTags.ContainsKey($case)){
        $wanted=$scopeTags[$case]
        if(-not$failure.Contains('[pidScope='+$wanted[0]+']')-or-not$failure.Contains('[exeScope='+$wanted[1]+']')-or-not$failure.Contains('[birthBinding='+$wanted[2]+']')){throw "Rejected credential context lost $case : $failure"}
    }
    if($case-eq'known-outside-uid'){$lookups=& $life {$script:UidFixtureLookups};if(150-notin$lookups){throw 'Explicit known outside filter was dropped'}}
    if($case-in@('outside-zmz','selected-mixed-real','selected-mixed-saved')){
        if($census.uidProof.outsideProtectedPathPidCount-ne1-or$census.uidProof.validatedPidCount-ne3-or$census.sameJdkJava.Count-ne1-or$census.knownLive.Count-ne1){throw 'Validated outside path/PID row was dropped or adopted'}
        if($case-eq'outside-zmz'){$acceptedObservation=$observation;$acceptedContext=$ctx;$acceptedOwner=$owner}
    }
    if($case-eq'unknown-jdk-replacement'-and$census.sameJdkJava.Count-ne2){throw 'Current unknown JDK replacement was discarded'}
    if($case-in@('owner-gone','post-known-survivor','post-java-survivor')){
        $absenceFailure=$null
        try{$absence=& $life.ExportedCommands['Confirm-H3911DarwinAbsenceFacts'] $ctx $owner @{schema='mvnd103-registry';count=0;records=@()} $census 0}catch{$absenceFailure=$_.Exception.Message}
        if([bool]$absenceFailure-ne($case-ne'owner-gone')){throw "UID post-stop survivor/ESRCH policy failed $case"}
    }
    $uidProof+=@{case=$case;passed=$true;expectedHold=$mustHold;error=$failure;fixtureOnly=$true;actualCollectorAst=$true}
}
$legacy=@{schema='darwin-scoped-java-census-v1'}
$reject=$false;try{$predicate=& $life {Get-Command Assert-LifeUidCensus};& $predicate $ctx $owner $legacy}catch{$reject=$true}
if(-not$reject){throw 'Legacy v1 acquired UID authority'}
$uidProof+=@{case='legacy-v1-not-UID-authority';passed=$true}
@{verdict='PASS';cases=$uidProof;nativeCalls=0;scope='Actual collector AST, native query/origin discovery replaced only by explicit typed private fixtures; no MacOS spoof'}|ConvertTo-Json -Depth 7|Set-Content (Join-Path $OutputDirectory 'uid-collector-proof.json')
Write-Output "UID_COLLECTOR_ACTUAL_AST_PASS cases=$($uidProof.Count); native0"
$scopeProof=@()
$roundTrip=$acceptedObservation|ConvertTo-Json -Depth 30|ConvertFrom-Json -AsHashtable -DateKind String
$null=& $life.ExportedCommands['ConvertTo-H3911DarwinScopedCensus'] $acceptedContext $acceptedOwner $roundTrip
$scopeProof+=@{case='valid-observation-JSON-roundtrip';passed=$true}
foreach($case in 'outside-count','outside-count-type','filter-string','filter-double','forged-outside','forged-protected','duplicate-row','dropped-row','dropped-adjusted-row','unknown-classification','unknown-path','changed-euid','nonunique-birth','wrong-native-pid','outside-known-witness','duplicate-outside-witness','outside-missing-overlap','legacy-basis','selected-omission','owner-proof-drift'){
    $bad=$acceptedObservation|ConvertTo-Json -Depth 30|ConvertFrom-Json -AsHashtable -DateKind String
    $outside=@($bad.processes|Where-Object pid -eq 200)[0];$ownerRow=@($bad.processes|Where-Object pid -eq 100)[0]
    switch($case){
        outside-count{$bad.uidProof.outsideProtectedPathPidCount=0}
        outside-count-type{$bad.uidProof.outsideProtectedPathPidCount='1'}
        filter-string{$bad.uidProof.filter='5'}
        filter-double{$bad.uidProof.filter=5.0}
        forged-outside{$ownerRow.protectedPathPid=$false}
        forged-protected{$outside.protectedPathPid=$true}
        duplicate-row{$bad.processes+=,$outside;$bad.uidProof.validatedPidCount++}
        dropped-row{$bad.processes=@($bad.processes|Where-Object pid -NE 200)}
        dropped-adjusted-row{$bad.processes=@($bad.processes|Where-Object pid -NE 200);$bad.uidProof.validatedPidCount--}
        unknown-classification{$outside.protectedPathPid='false'}
        unknown-path{$outside.executable='relative/path'}
        changed-euid{$outside.credential.effectiveUid=502L}
        nonunique-birth{$outside.credential.birthSeconds=17179869184L;$outside.credential.birthMicroseconds=0L;$outside.created=[DateTime]::UnixEpoch.AddSeconds(17179869184L).ToString('o')}
        wrong-native-pid{$outside.credential.pid=201}
        outside-known-witness{$bad.uidProof.outsideProtectedPathPidPids=@(100)}
        duplicate-outside-witness{$bad.uidProof.outsideProtectedPathPidPids=@(200,200)}
        outside-missing-overlap{$bad.uidProof.missingAtRecheckPids=@(200);$bad.uidProof.missingAtRecheckCount=1;$bad.uidProof.presenceRecheckAttempts=1}
        legacy-basis{$bad.uidProof.observationBasis='INITIAL_ELIGIBLE_PID_NUMBERS_THEN_UID_SURVIVORS_PLUS_KNOWN_ESRCH_RECHECK'}
        selected-omission{$bad.uidProof.selectedPids=@(10,100);$bad.uidProof.selectedPidCount=2;$bad.uidProof.unionPidCount=2}
        owner-proof-drift{$bad.uidProof.ownerCredential.savedUid=0L}
    }
    $failure=$null
    try{$null=& $life.ExportedCommands['ConvertTo-H3911DarwinScopedCensus'] $acceptedContext $acceptedOwner $bad}catch{$failure=$_.Exception.Message}
    if(-not$failure){throw "Scoped converter accepted forged/malformed witness $case"}
    $scopeProof+=@{case=$case;passed=$true;error=$failure}
}
foreach($role in 'SELF','EXPECTED_PID','KNOWN_PID','ADMITTED_PATH','OUTSIDE_PATH_PID'){
    $context=@{Jdk='/fixture/jdk25';Home='/fixture/mvnd';Registry='/fixture/registry';Temp='/fixture/temp';KnownOwnedIdentities=@(@{pid=150;created='2026-01-01T00:00:00Z';executable='/fixture/known'})}
    $self=@{pid=10;created='2026-01-01T00:00:00Z';executable='/fixture/pwsh'}
    $expected=@{pid=100;created='2026-01-01T00:00:00Z';executable='/fixture/jdk25/bin/java';daemonId='01234567';home=$context.Home;registryFile='/fixture/registry/registry.bin';jniPath='/fixture/temp/native.jnilib'}
    $id=switch($role){SELF{10}EXPECTED_PID{100}KNOWN_PID{150}default{200}}
    $exe=switch($role){SELF{'/fixture/pwsh'}KNOWN_PID{'/fixture/known'}OUTSIDE_PATH_PID{'/fixture/outside-path-pid'}default{'/fixture/jdk25/bin/java'}}
    $row=@{pid=$id;created='2026-01-01T00:00:00Z';executable=$exe;credential=@{pid=$id;parentPid=1;realUid=0L;effectiveUid=501L;savedUid=0L;birthSeconds=1767225600L;birthMicroseconds=0L}}
    $row.protectedPathPid=& $life {param($c,$e,$s,$r)Test-LifeProtectedPathPid $c $e $s $r} $context $expected $self $row
    $failure=$null
    try{$null=& $life {param($c,$e,$s,$r)Assert-LifePathPidRow $c $e $s $r 501L} $context $expected $self $row}catch{$failure=$_.Exception.Message}
    if([bool]$failure-ne($role-cne'OUTSIDE_PATH_PID')){throw "ZMZ protection predicate differs $role"}
    $scopeProof+=@{case="ZMZ-$role";passed=$true;held=[bool]$failure}
    $row.credential.realUid=501L;$row.credential.savedUid=501L;$row.credential.effectiveUid=502L;$failure=$null
    try{$null=& $life {param($c,$e,$s,$r)Assert-LifePathPidRow $c $e $s $r 501L} $context $expected $self $row}catch{$failure=$_.Exception.Message}
    if($failure-cne'HOLD: Current effective UID differs from launch actor'){throw "Effective UID drift escaped $role : $failure"}
    $scopeProof+=@{case="EUID-$role";passed=$true}
}
$strictFailure=$null
try{$null=& $life {ConvertFrom-LifeBsdFacts @(136,0,200,1,0L,501L,0L,1767225601L,0L) 200 501L}}catch{$strictFailure=$_.Exception.Message}
if(-not$strictFailure){throw 'Strict direct reader codec admitted mixed credentials'}
$scopeProof+=@{case='strict-default-codec-still-rejects-ZMZ';passed=$true}
@{verdict='PASS';cases=$scopeProof;nativeCalls=0;outsidePositiveProof=$acceptedObservation.uidProof;scope='Validated exact ordinal path/PID scope; no image-alias/unrelatedness claim'}|ConvertTo-Json -Depth 12|Set-Content (Join-Path $OutputDirectory 'path-pid-scope-proof.json')
Write-Output "PATH_PID_SCOPE_PASS cases=$($scopeProof.Count); native0; full PID partition"
$projectionProof=@()
# Golden Unix ticks from the v10.0.15 Process.OSX.cs/TimeSpan(double) producer, not exact-microsecond normalization.
foreach($sample in @(
    @{name='projected-eight';microseconds=8L;unixTicks=17955032910000082L}
    @{name='projected-thirteen';microseconds=13L;unixTicks=17955032910000132L}
    @{name='projected-eighteen';microseconds=18L;unixTicks=17955032910000178L}
    @{name='second-start';microseconds=0L;unixTicks=17955032910000000L}
    @{name='second-end';microseconds=999999L;unixTicks=17955032919999990L}
    @{name='equivalent-offset';microseconds=8L;unixTicks=17955032910000082L;offset=$true}
    @{name='wrong-normalized-time';microseconds=8L;unixTicks=17955032910000080L;hold=$true}
    @{name='one-tick-mismatch';microseconds=8L;unixTicks=17955032910000083L;hold=$true}
    @{name='native-microsecond-mismatch';microseconds=9L;unixTicks=17955032910000082L;hold=$true}
    @{name='native-second-mismatch';microseconds=8L;unixTicks=17955032910000082L;seconds=1795503292L;hold=$true}
    @{name='foreign-pid';microseconds=8L;unixTicks=17955032910000082L;pid=101;hold=$true}
    @{name='foreign-uid';microseconds=8L;unixTicks=17955032910000082L;uid=502L;hold=$true}
    @{name='microseconds-out-of-range';microseconds=1000000L;unixTicks=17955032910000082L;hold=$true}
    @{name='ambiguous-native-birth';microseconds=0L;unixTicks=171798691840000000L;seconds=17179869184L;hold=$true}
)){
    $seconds=if($sample.ContainsKey('seconds')){$sample.seconds}else{1795503291L}
    $facts=@{pid=100;parentPid=1;realUid=501L;effectiveUid=501L;savedUid=501L;birthSeconds=$seconds;birthMicroseconds=$sample.microseconds}
    $created=[DateTimeOffset]::new([DateTime]::UnixEpoch.AddTicks($sample.unixTicks))
    if($sample.offset){$created=$created.ToOffset([TimeSpan]::FromHours(8))}
    $identity=@{pid=$(if($sample.pid){$sample.pid}else{100});created=$created.ToString('o');executable='/fixture/jdk25/bin/java'}
    $failure=$null
    try{& $life {param($facts,$identity,$uid)Assert-LifeCredentialIdentity $facts $identity $uid} $facts $identity $(if($sample.uid){$sample.uid}else{501L})}catch{$failure=$_.Exception.Message}
    if([bool]$failure-ne[bool]$sample.hold-or$facts.birthMicroseconds-ne$sample.microseconds-or$facts.birthSeconds-ne$seconds-or$identity.created-cne$created.ToString('o')){throw "Exact native-birth projection differs $($sample.name) : $failure"}
    if($sample.name-ceq'ambiguous-native-birth'-and$failure-cne'HOLD: Kernel birth projection cannot uniquely bind microseconds'){throw 'Ambiguous native microsecond identity was not rejected'}
    $projectionProof+=@{case=$sample.name;passed=$true;expectedHold=[bool]$sample.hold;error=$failure;nativeMicroseconds=$facts.birthMicroseconds;created=$identity.created}
}
@{verdict='PASS';cases=$projectionProof;nativeCalls=0;scope='Exact .NET 10.0.15 Darwin projection; full native tuple retained; no interop or process calls'}|ConvertTo-Json -Depth 7|Set-Content (Join-Path $OutputDirectory 'birth-projection-proof.json')
Write-Output "DARWIN_BIRTH_PROJECTION_PASS cases=$($projectionProof.Count); native0; no precision normalization"
$returnRecord=Get-Content (Join-Path $OutputDirectory 'positive-absent\mac-qualifier.json') -Raw|ConvertFrom-Json -AsHashtable -DateKind String
$returnRecord.fixtureOnly=$false;$returnRecord.status='MAC_UNTIMED_COMPLETE_PENDING_AUDIT'
$returnValues=@{'baseline-project'='/fixture/project';'daemon-project'='/fixture/project';'daemon-arch'='aarch64';'daemon-home'=$acceptedContext.Jdk;'baseline-maven-home'='/fixture/maven'}
foreach($key in $returnValues.Keys){$bytes=[Text.Encoding]::UTF8.GetBytes($returnValues[$key]);$returnRecord.contexts[$key]=@{value=$returnValues[$key];bytes=$bytes.Length;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))}}
$returnRecord.owner=$acceptedOwner.Clone();$returnRecord.owner.evidenceKind='native-mac-effective-owner';$returnRecord.knownOwnedIdentities=@()
$returnRecord.earlyCensus=@{schema='darwin-launch-uid-java-census-v2';uidProof=$acceptedObservation.uidProof}
$returnedGone=$acceptedObservation|ConvertTo-Json -Depth 30|ConvertFrom-Json -AsHashtable -DateKind String
$returnedGone.processes=@($returnedGone.processes|Where-Object pid -NE 100);$returnedGone.uidProof.ownerCredential=$null;$returnedGone.uidProof.missingAtRecheckPids=@(100);$returnedGone.uidProof.missingAtRecheckCount=1;$returnedGone.uidProof.presenceRecheckAttempts=1;$returnedGone.uidProof.validatedPidCount=2
$returnedGoneCensus=& $life.ExportedCommands['ConvertTo-H3911DarwinScopedCensus'] $acceptedContext $acceptedOwner $returnedGone
$returnedStop=& $life.ExportedCommands['Confirm-H3911DarwinAbsenceFacts'] $acceptedContext $acceptedOwner @{schema='mvnd103-registry';count=0;records=@()} $returnedGoneCensus 0
$returnedStop.schema='darwin-launch-uid-absence-v2';$returnedStop.uidProof=$returnedGone.uidProof;$returnedStop.evidenceKind='native-scoped-absence-result'
$returnRecord.stopProof=$returnedStop
foreach($label in 'baseline-verify','candidate-verify'){$returnRecord[$label].artifact=@{raw=@(1..6)}}
$supervisor=Import-Module (Join-Path $PSScriptRoot 'H3911.MacSupervisor.psm1') -PassThru -DisableNameChecking
$returnedValidator=& $supervisor {Get-Command Assert-SupQualification -CommandType Function}
$returnProof=@()
# Native-return flags here are explicit synthetic claims for the pure validator, not runtime authority.
foreach($case in 'valid-roundtrip','valid-known-roundtrip','missing-early','missing-stop','legacy-early','legacy-stop','bad-early-witness','bad-stop-witness','missing-known-set','known-proof-mismatch'){
    $candidate=$returnRecord|ConvertTo-Json -Depth 50|ConvertFrom-Json -AsHashtable -DateKind String
    switch($case){
        valid-known-roundtrip{
            $candidate.knownOwnedIdentities=@(@{pid=150;created='2026-01-01T00:00:00Z';executable='/fixture/known'})
            foreach($proof in @($candidate.earlyCensus.uidProof,$candidate.stopProof.uidProof)){$proof.knownPidCount++;$proof.unionPidCount++;$proof.missingAtRecheckPids+=150;$proof.missingAtRecheckCount++;$proof.presenceRecheckAttempts++}
        }
        missing-early{$candidate.earlyCensus.Remove('uidProof')}
        missing-stop{$candidate.stopProof.Remove('uidProof')}
        legacy-early{$candidate.earlyCensus.uidProof.observationBasis='LEGACY'}
        legacy-stop{$candidate.stopProof.uidProof.observationBasis='LEGACY'}
        bad-early-witness{$candidate.earlyCensus.uidProof.outsideProtectedPathPidPids=@(100)}
        bad-stop-witness{$candidate.stopProof.uidProof.missingAtRecheckPids=@()}
        missing-known-set{$candidate.Remove('knownOwnedIdentities')}
        known-proof-mismatch{$candidate.knownOwnedIdentities=@(@{pid=150;created='2026-01-01T00:00:00Z';executable='/fixture/known'})}
    }
    $failure=$null
    try{$null=& $returnedValidator $candidate Qualify $candidate.owned}catch{$failure=$_.Exception.Message}
    if([bool]$failure-ne($case-notin@('valid-roundtrip','valid-known-roundtrip'))){throw "Actual supervisor UID return contract differs $case : $failure"}
    $returnProof+=@{case=$case;passed=$true;error=$failure;nativeCalls=0}
}
@{verdict='PASS';cases=$returnProof;scope='Actual pure supervisor Qualify return validator; synthetic candidate UID/absence facts only';runtimeQualified=$false;nativeCalls=0}|ConvertTo-Json -Depth 7|Set-Content (Join-Path $OutputDirectory 'returned-uid-proof.json')
Write-Output "SUPERVISOR_RETURN_UID_CONTRACT_PASS cases=$($returnProof.Count); actual validator; native0"
