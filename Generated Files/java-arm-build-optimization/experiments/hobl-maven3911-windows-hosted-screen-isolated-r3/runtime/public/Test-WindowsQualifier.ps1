param([string]$RepositorySource,[string]$OutputDirectory)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
if(Test-Path $OutputDirectory){throw 'Fresh Windows qualifier fixture required'}
New-Item $OutputDirectory -ItemType Directory|Out-Null
$git=(Get-Command git -CommandType Application|Select-Object -First 1).Source
$project=Join-Path $OutputDirectory 'project'
& $git clone --quiet --no-hardlinks --no-checkout $RepositorySource $project;if($LASTEXITCODE){throw 'Fixture clone failed'}
foreach($a in @(@('config','core.autocrlf','false'),@('remote','set-url','origin','https://github.com/spring-projects/spring-petclinic.git'),@('checkout','--quiet','--detach','6feeae0f13e0e258eedc99832416b42bb13779b1'))){& $git -C $project @a;if($LASTEXITCODE){throw 'Fixture source setup failed'}}
Copy-Item (Join-Path $PSScriptRoot 'fixtures/Reviewed-AAA-mvnw.cmd') (Join-Path $project 'mvnw.cmd')
$readmeRel=@(& $git -C $project ls-files -- 'readme.md' 'README.md')[0]
$jdk=Join-Path $OutputDirectory 'SYNTHETIC-JDK';New-Item $jdk -ItemType Directory|Out-Null
$module=Import-Module (Join-Path $PSScriptRoot 'H3911.WindowsQualifier.psm1') -Scope Local -PassThru -Force -DisableNameChecking
$invoke=$module.ExportedCommands['Invoke-H3911WindowsQualifier'];$proof=@()
function CheckRun([string]$Case,[string]$HomeState='absent',[bool]$Hosted=$false,[bool]$Aliases=$false,[string]$OwnedOverride,[bool]$ExpectIsolation=$false){
    $owned=if($OwnedOverride){$OwnedOverride}else{Join-Path $OutputDirectory $Case}
    $state=@{alive=$false;stops=0;labels=@();case=$Case}
    $evidence=Join-Path $OutputDirectory ("evidence-"+$Case);New-Item $evidence -ItemType Directory|Out-Null
    $birth=[DateTime]::UtcNow.AddSeconds(-1);[long]$cimTicks=$birth.Ticks-($birth.Ticks%[long]10)
    $cim=[DateTime]::new($cimTicks,[DateTimeKind]::Utc)
    $hooks=@{
        GateDeadlineMilliseconds=$(if($Case-in@('witness-late-file','witness-late-native','witness-exact-expiry')){30}else{1000})
        GateWait={param($c,$json)if($state.case-ceq'witness-late-file'){Start-Sleep -Milliseconds 120;$state.native|ConvertTo-Json|Set-Content $json}}.GetNewClosure()
        Setup={param($home)New-Item $home -ItemType Directory|Out-Null;@{fixtureOnly=$true}}.GetNewClosure()
        Dispatch={
            param($c,$p)
            $state.labels+=,$p.label
            if($state.case-eq'nonzero'-and$p.label-eq'baseline-project'){return 1}
            if($p.label-eq'daemon-arch'){$state.alive=$true}
            if($p.label-in@('baseline-project','daemon-project')){$value=$c.Project}
            elseif($p.label-eq'daemon-arch'){$value='aarch64'}
            elseif($p.label-eq'daemon-home'){$value=$c.Jdk}
            elseif($p.label-eq'baseline-maven-home'){$value=Join-Path $owned 'SYNTHETIC-MAVEN3911'}
            else{$value=$null}
            if($value){[IO.File]::WriteAllText($p.valueFile,$value,[Text.UTF8Encoding]::new($false))}
            if($p.label-ceq'daemon-project'){
                $w=@{status='owned';complete=$true;pid=12345;id='01234567';created=$birth.ToString('o');nativeCreatedTicks=$birth.Ticks.ToString();cimCreated=$cim.ToString('o');cimCreatedTicks=$cimTicks.ToString();observedUtc=[DateTime]::UtcNow.ToString('o');executable=(Join-Path $c.Jdk 'bin\java.exe');home=$c.Home;registry=$c.Registry;temp=$c.Temp;jniPath=(Join-Path $c.Temp 'fixture.dll');jniSha256='728F9A0F7A8A74D15C6DE37DBE32A73CF8013605D2E881098692E1C88A0F4C2D';javaSha256='094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0';jniMachine=0xAA64}
                $state.native=$w.Clone()
                if($state.case-ceq'witness-stale'){$w.observedUtc=[DateTime]::UtcNow.AddDays(-1).ToString('o')}
                if($state.case-ceq'witness-wrong-owner'){$w.pid++}
                if($state.case-ceq'witness-companion'){$state.native=@{status='HOLD';complete=$true;reasonCode='CENSUS_UNKNOWN'}}
                if($state.case-ceq'witness-error'){@{status='HOLD_OBSERVER_ERROR';observed=$false}|ConvertTo-Json|Set-Content (Join-Path $evidence 'observer-outcome.json')}
                elseif($state.case-ceq'witness-malformed'){[IO.File]::WriteAllText((Join-Path $evidence 'independent-owned-daemon.json'),'{bad')}
                elseif($state.case-notin@('witness-missing','witness-late-file')){$w|ConvertTo-Json|Set-Content (Join-Path $evidence 'independent-owned-daemon.json')}
            }
            if($state.case-eq'source-fail'-and$p.label-eq'baseline-verify'){[IO.File]::AppendAllText((Join-Path $project $readmeRel),"`nSYNTHETIC_SOURCE_FAILURE")}
            return 0
        }.GetNewClosure()
        Owner={param($c)if($state.alive){@{pid=12345;id='01234567';created=$cim.ToString('o');executable=(Join-Path $c.Jdk 'bin\java.exe');jni='728F9A0F7A8A74D15C6DE37DBE32A73CF8013605D2E881098692E1C88A0F4C2D'}}}.GetNewClosure()
        GateNativeFacts={param($c)if($state.case-ceq'witness-late-native'){Start-Sleep -Milliseconds 120};if($state.case-ceq'witness-exact-expiry'){while($c.WitnessGateClock.ElapsedMilliseconds-lt$c.WitnessGateLimit){Start-Sleep -Milliseconds 1}};$state.native}.GetNewClosure()
        Verify={param($c,$label,$call)@{tests=@(1..$(if($state.case-in@('verify-fail','alias-emergency')){55}else{56}));counters=@(1..726);semantics='SYNTHETIC_FULL_SEMANTICS';fork=$label;session=$label;artifact='SYNTHETIC_ONLY'}}.GetNewClosure()
        Compare={param($c)$true}
        BaselineInventory={param($root,$cache)@{status='FULL_TRUSTED_STOCK_MAVEN3911_ADMITTED';archiveFiles=$(if($state.case-eq'baseline-inventory-fail'){1}else{96});physicalFiles=96;directories=13;inventorySha256='63382624DFFEF090C2B47C476767D9BE9F0620296193B650AE419ABE34FC4D0F';coreSha256='93D3C0523DDA6C86C6620D9E692E7DF39D0E2E4E4CD860061A8C0D274C2AD185';fixtureOnly=$true;home=$root;privateWrapperCache=$cache}}.GetNewClosure()
        Stop={param($c,$tokens)$state.stops++;if($state.case-eq'stop-fail'-and$state.stops-eq1){return 1};$state.alive=$false;return 0}.GetNewClosure()
        Absence={param($c)-not$state.alive}.GetNewClosure()
    }
    $initial=[Environment]::GetEnvironmentVariables('Process');$oldHome=[Environment]::GetEnvironmentVariable('JAVA_HOME');$homePresent=Test-Path Env:JAVA_HOME
    switch($HomeState){absent{Remove-Item Env:JAVA_HOME -ErrorAction SilentlyContinue}empty{[Environment]::SetEnvironmentVariable('JAVA_HOME','','Process')}value{$env:JAVA_HOME='SYNTHETIC_CALLER_HOME'}}
    $before=[Environment]::GetEnvironmentVariables('Process');$failure=$null
    $aliasNames=@('Invoke-WQStop','Read-WQOwner','Same-WQOwner','Assert-WQ','Import-WQ','Get-WQWatch','Resolve-WQNamespace','Assert-WQDisjoint','Invoke-WQWitnessFirstGate','Read-WQGateJson','Get-WQGateRemaining')
    $oldAliases=@{}
    if($Aliases){foreach($name in $aliasNames){$oldAliases[$name]=Get-Alias -Name $name -Scope Global -ErrorAction SilentlyContinue;Set-Alias -Name $name -Value Out-Null -Scope Global}}
    try{$result=& $invoke -Project $project -Jdk $jdk -Owned $owned -CoreExe (Get-Process -Id $PID).Path -WatchRoot $RepositorySource -IndependentWitnessRoot $evidence -FixtureOnly -FixtureHooks $hooks -ReviewedHostedDefaults:$Hosted}
    catch{$failure=$_.Exception.Message}
    finally{
        if($Aliases){foreach($name in $aliasNames){if((Get-Alias -Name $name -Scope Global).Definition-cne'Out-Null'){throw "Caller alias changed $name"};if($oldAliases[$name]){Set-Alias -Name $name -Value $oldAliases[$name].Definition -Options $oldAliases[$name].Options -Scope Global}else{Remove-Alias -Name $name -Scope Global}}}
        $after=[Environment]::GetEnvironmentVariables('Process')
        foreach($key in $before.Keys){if(-not$after.Contains($key)-or$before[$key]-cne$after[$key]){throw "Caller environment changed $key"}}
        if($before.Count-ne$after.Count){throw 'Caller environment universe changed'}
        if($homePresent){[Environment]::SetEnvironmentVariable('JAVA_HOME',$oldHome,'Process')}else{Remove-Item Env:JAVA_HOME -ErrorAction SilentlyContinue}
        if($Case-eq'source-fail'){& $git -C $project restore -- $readmeRel;if($LASTEXITCODE){throw 'Fixture source restore failed'}}
    }
    if($ExpectIsolation){
        if($failure-notlike'*trees must be disjoint*'-or(Test-Path -LiteralPath $owned)-or$state.labels.Count-or$state.stops-or$state.alive){throw 'Complete public API model bypassed pre-allocation isolation'}
        return @{case=$Case;passed=$true;failure=$failure;completeHooks=$true;noAllocation=$true;zeroNativeCalls=$true}
    }
    $receipt=Get-Content (Join-Path $owned 'qualifier.json') -Raw|ConvertFrom-Json
    if($Case-like'positive*'){
        if($failure-or$receipt.status-cne'FIXTURE_ONLY_COMPLETE_NOT_RUNTIME'-or$receipt.calls.Count-ne8-or$state.alive-or$state.stops-ne1-or-not$receipt.stopProof.ownerGone){throw "Positive qualifier failed: $failure"}
        $expected=@('baseline-project','daemon-arch','daemon-home','daemon-project','baseline-maven-home','baseline-verify','candidate-verify','normal-stop')
        if(($receipt.calls|ForEach-Object{if($_.plan){$_.plan.label}else{$_.label}})-join',' -cne($expected-join',')){throw 'Eight-call order differs'}
    }else{
        if(-not$failure-or$receipt.status-cne'FAIL'-or$state.alive){throw "Failure/cleanup not retained $Case : $failure"}
        if($Case-eq'nonzero'-and$receipt.calls.Count-ne1){throw 'Nonzero did not stop first'}
        if($Case-eq'stop-fail'-and$receipt.calls.Count-ne9){throw 'Stop failure did not retain one emergency cleanup call'}
        if($Case-eq'baseline-inventory-fail'-and($receipt.calls.Count-ne6-or@($state.labels|Where-Object{$_-like'*-verify'}).Count-or$state.stops-ne1)){throw 'Incomplete baseline inventory reached a full build or missed owned cleanup'}
        if($Case-eq'alias-emergency'-and($state.stops-ne1-or-not$receipt.emergencyStopProof.ownerGone-or-not$receipt.emergency)){throw 'Alias bypassed actual emergency stop/absence procedure'}
        if($Case-like'witness-*'-and($receipt.calls.Count-ne5-or@($state.labels|Where-Object{$_-like'*-verify'}).Count-or$state.stops-ne1-or$receipt.witnessFirstGate.status-cne'HOLD')){throw 'Witness failure reached builds or wrong cleanup/call budget'}
    }
    if(-not$receipt.restoration.restored-or-not$receipt.restoration.cwdEqual-or-not$receipt.restoration.nativeCwdEqual-or-not$receipt.rootWatchEqual-or($Case-ne'source-fail'-and-not$receipt.inputsUnchanged)){throw 'Source/caller/root restoration proof missing'}
    @{case=$Case;state=$HomeState;passed=$true;failure=$failure;calls=$receipt.calls.Count;fixtureOnly=$true;ownerGone=(-not$state.alive);restored=$receipt.restoration.restored;aliasesPreserved=$Aliases}
}
foreach($s in 'absent','empty','value'){$proof+=CheckRun "positive-$s" $s}
foreach($case in 'nonzero','source-fail','verify-fail','stop-fail','baseline-inventory-fail'){$proof+=CheckRun $case}
foreach($case in 'witness-missing','witness-error','witness-malformed','witness-stale','witness-wrong-owner','witness-companion'){$proof+=CheckRun $case}
foreach($case in 'witness-late-file','witness-late-native','witness-exact-expiry'){$proof+=CheckRun $case}
$priorOpts=[Environment]::GetEnvironmentVariable('MAVEN_OPTS');$optsPresent=Test-Path Env:MAVEN_OPTS
try{$env:MAVEN_OPTS='-Xms256m';$proof+=CheckRun 'positive-reviewed-hosted' absent $true}
finally{if($optsPresent){[Environment]::SetEnvironmentVariable('MAVEN_OPTS',$priorOpts,'Process')}else{Remove-Item Env:MAVEN_OPTS -ErrorAction SilentlyContinue}}
$common=@{Project=$project;Jdk=$jdk;Owned=(Join-Path $OutputDirectory 'NOT_CREATED');CoreExe=(Get-Process -Id $PID).Path;WatchRoot=$RepositorySource}
foreach($case in 'no-authority','runtime-callback','fake-native-jdk','caller-baseline-override','unsupported-mac'){
    $errorText=$null
    try{
        if($case-eq'no-authority'){$null=& $invoke @common}
        elseif($case-eq'runtime-callback'){$null=& $invoke @common -RuntimeApproved -FixtureHooks @{bad={}}}
        elseif($case-eq'caller-baseline-override'){$null=& $invoke @common -FixtureOnly -FixtureHooks @{notCalled=$true} -BaselineInventoryBinding @{notAllowed=$true}}
        elseif($case-eq'unsupported-mac'){$null=& $invoke @common -Platform MacOS -FixtureOnly -FixtureHooks @{notCalled=$true}}
        else{$null=& $invoke @common -RuntimeApproved}
    }catch{$errorText=$_.Exception.Message}
    if(-not$errorText-or(Test-Path $common.Owned)){throw "Early authority/binding gate failed $case"}
    $proof+=@{case=$case;passed=$true;failure=$errorText;zeroNativeCalls=$true}
}
foreach($name in 'MAVEN_OPTS','MAVEN_USER_HOME'){
    $prior=[Environment]::GetEnvironmentVariable($name);$present=Test-Path "Env:$name"
    try{
        [Environment]::SetEnvironmentVariable($name,'SYNTHETIC_UNREVIEWED_INPUT','Process')
        $errorText=$null;try{$null=& $invoke @common -FixtureOnly -FixtureHooks @{notCalled=$true}}catch{$errorText=$_.Exception.Message}
        if($errorText-notlike"*Unreviewed injected $name*" -or(Test-Path $common.Owned)-or[Environment]::GetEnvironmentVariable($name)-cne'SYNTHETIC_UNREVIEWED_INPUT'){throw 'Unknown input was normalized/allocated'}
        $proof+=@{case="unknown-$name";passed=$true;zeroNativeCalls=$true}
    }finally{if($present){[Environment]::SetEnvironmentVariable($name,$prior,'Process')}else{Remove-Item "Env:$name" -ErrorAction SilentlyContinue}}
}
$reuse=@{};foreach($p in $common.GetEnumerator()){$reuse[$p.Key]=$p.Value};$reuse.Owned=Join-Path $OutputDirectory 'positive-absent'
$errorText=$null;try{$null=& $invoke @reuse -FixtureOnly -FixtureHooks @{notCalled=$true}}catch{$errorText=$_.Exception.Message}
if($errorText-notlike'*Fresh owned root required*'){throw 'Owned root reused'}
$proof+=@{case='existing-owned-root-reject';passed=$true;zeroNativeCalls=$true}
$sourceBefore=@(& $git -C $project status --porcelain --untracked-files=all)-join"`n"
$isolationCases=@(
    @{case='owned-under-target';owned=(Join-Path $project 'target\private-qualification')},
    @{case='owned-case-target';owned=(Join-Path $project.ToUpperInvariant() 'TARGET\private-qualification')},
    @{case='owned-dotdot-target';owned=(Join-Path $project 'target\..\target\private-qualification')},
    @{case='owned-project-ancestor';owned=$OutputDirectory},
    @{case='owned-sdk-descendant';owned=(Join-Path $jdk 'private-qualification')},
    @{case='source-sdk-overlap';jdk=$project},
    @{case='source-core-overlap';coreexe=(Join-Path $project 'mvnw.cmd')},
    @{case='source-archive-overlap';distributionarchive=(Join-Path $project 'pom.xml')},
    @{case='source-staged-input-overlap';windowsinputs=(Join-Path $project '.mvn')}
)
foreach($case in $isolationCases){
    $callArgs=@{};foreach($p in $common.GetEnumerator()){$callArgs[$p.Key]=$p.Value}
    foreach($p in $case.GetEnumerator()){if($p.Key-ne'case'){$callArgs[$p.Key]=$p.Value}}
    $beforeExists=Test-Path -LiteralPath $callArgs.Owned;$beforeEnv=[Environment]::GetEnvironmentVariables('Process');$errorText=$null
    try{$null=& $invoke @callArgs -FixtureOnly -FixtureHooks @{notCalled=$true}}catch{$errorText=$_.Exception.Message}
    $afterEnv=[Environment]::GetEnvironmentVariables('Process')
    if($errorText-notlike'*trees must be disjoint*'-or((Test-Path -LiteralPath $callArgs.Owned)-ne$beforeExists)-or$beforeEnv.Count-ne$afterEnv.Count){throw "Isolation admission failed $($case.case): $errorText"}
    foreach($key in $beforeEnv.Keys){if(-not$afterEnv.Contains($key)-or$beforeEnv[$key]-cne$afterEnv[$key]){throw 'Isolation rejection changed caller environment'}}
    if((@(& $git -C $project status --porcelain --untracked-files=all)-join"`n")-cne$sourceBefore){throw 'Isolation rejection changed source'}
    $proof+=@{case=$case.case;passed=$true;failure=$errorText;noAllocation=$true;zeroNativeCalls=$true}
}
$proof+=CheckRun 'positive-prefix-sibling' absent $false $false ($project+'-execution')
$proof+=CheckRun 'owned-under-target-full-model' absent $false $false (Join-Path $project 'target\private-qualification') $true
$proof+=CheckRun 'positive-private-aliases' absent $false $true
$proof+=CheckRun 'alias-emergency' absent $false $true
@{verdict='PASS';cases=$proof;scope='Complete8-call fixture orchestration; no Java or real verification/owner; actual runtime branch not executed';realBaselineInventoryBinding='Fixed3D8 module/633 inventory unchanged; root reports independent dependency acceptance'}|ConvertTo-Json -Depth 7|Set-Content (Join-Path $OutputDirectory 'proof.json')
Write-Output "WINDOWS_QUALIFIER_FIXTURE_PASS cases=$($proof.Count) eight-order/fullgate-model/cleanup/state/authority; no Java"
