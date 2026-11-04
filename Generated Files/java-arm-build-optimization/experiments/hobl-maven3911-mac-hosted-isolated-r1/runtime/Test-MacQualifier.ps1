param([Parameter(Mandatory)][string]$RepositorySource,[Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
if(-not[IO.Path]::IsPathFullyQualified($OutputDirectory)-or(Test-Path $OutputDirectory)){throw 'Fresh absolute model output required'}
New-Item $OutputDirectory -ItemType Directory|Out-Null
$git=(Get-Command git -CommandType Application|Select-Object -First 1).Source;$project=Join-Path $OutputDirectory 'project'
& $git clone --quiet --no-checkout --no-hardlinks $RepositorySource $project;if($LASTEXITCODE){throw 'Model clone failed'}
foreach($a in @(@('config','core.autocrlf','false'),@('remote','set-url','origin','https://github.com/spring-projects/spring-petclinic.git'),@('checkout','--quiet','--detach','6feeae0f13e0e258eedc99832416b42bb13779b1'))){& $git -C $project @a;if($LASTEXITCODE){throw 'Model source admission setup failed'}}
$jdk=Join-Path $OutputDirectory 'SYNTHETIC-JDK';New-Item $jdk -ItemType Directory|Out-Null
$module=Import-Module (Join-Path $PSScriptRoot 'H3911.MacQualifier.psm1') -Scope Local -PassThru -Force -DisableNameChecking
$invoke=$module.ExportedCommands['Invoke-H3911MacQualifier'];$proof=@()
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
        Stock={param($c,$root)@{status='FULL_TRUSTED_STOCK_MAVEN3911_ADMITTED';archiveFiles=$(if($state.case-eq'stock-fail'){1}else{96});physicalFiles=97;directories=13;inventorySha256='63382624DFFEF090C2B47C476767D9BE9F0620296193B650AE419ABE34FC4D0F';archiveFormat=$(if($state.case-eq'positive-tar'){'Tar'}else{'Zip'});fixtureOnly=$true}}.GetNewClosure()
        Verify={param($c,$label,$call)@{tests=@(1..$(if($state.case-eq'fidelity-fail'){55}else{56}));counters=@(1..726);semantics='MODEL_ONLY';fork=$label;session=$label;artifact='NO_COMPILED_ARTIFACT'}}.GetNewClosure()
        Compare={param($c)$true}
        StopPlan={param($c,$anchor,$emergency)@{exe=(Join-Path $c.Home 'bin/mvnd');tokens=@("-Dmvnd.daemonStorage=$($c.Registry)","-Dmvnd.registry=$($anchor.registryFile)","-Djava.home=$($c.Jdk)",'--stop');workingDirectory=$c.Temp;expectedPid=$anchor.pid;expectedCreated=$anchor.created;fixtureOnly=$true}}
        Stop={param($c,$p)$state.stops++;if($state.case-eq'stop-fail'-and$state.stops-eq1){1}else{$state.alive=$false;0}}.GetNewClosure()
        Confirm={param($c,$anchor,$exit,$emergency)if($state.alive){throw 'MODEL census survivor'};@{status=$(if($emergency){'FAIL_NONZERO_FORCED_OR_EMERGENCY'}else{'NORMAL_CLI_ROUTE_SCOPED_ABSENCE_CONFIRMED'});fixtureOnly=$true}}.GetNewClosure()
    }
    $helper=Import-Module (Join-Path $PSScriptRoot 'H3911.Helpers.psm1') -PassThru -Scope Local -DisableNameChecking
    $snapshot=$helper.ExportedCommands['PortableEnvironmentSnapshot'];$restore=$helper.ExportedCommands['RestorePortableEnvironment'];$saved=& $snapshot
    switch($HomeState){absent{Remove-Item Env:JAVA_HOME -ErrorAction SilentlyContinue}empty{[Environment]::SetEnvironmentVariable('JAVA_HOME','','Process')}value{$env:JAVA_HOME='MODEL_CALLER'}}
    $before=& $snapshot;$cwd=(Get-Location).Path;$native=[Environment]::CurrentDirectory;$errorText=$null
    $names=@('Assert-MQ','Import-MQ','Resolve-MQPath','Assert-MQDisjoint','Get-MQWatch','Read-MQOwner','Assert-MQSame','Stop-MQ')
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
    }else{
        if(-not$errorText-or$receipt.status-cne'FAIL'){throw "Mac negative model accepted $Case"}
        if($Case-in@('pid-change','id-fail','registry-fail')){if(-not$receipt.cleanupFailure-or$state.stops){throw 'Ambiguous owner cleanup was not held'}}
        elseif($state.alive){throw 'Mac admitted cleanup missed modeled owner'}
        if($Case-eq'stop-fail'-and$receipt.calls.Count-ne9){throw 'Mac failed normal stop did not retain nine attempts'}
        if($Case-eq'stock-fail'-and@($receipt.calls|Where-Object{$_.plan.label-like'*-verify'}).Count){throw 'Mac full build preceded stock admission'}
    }
    if(-not$receipt.sourceEqual-or-not$receipt.rootWatchEqual-or-not$receipt.restoration.restored){throw 'Mac source/root/state checks missing'}
    @{case=$Case;passed=$true;calls=$receipt.calls.Count;error=$errorText;mode='WINDOWS_MODEL_NOT_MAC_RUNTIME';ownerAlive=$state.alive}
}
foreach($s in 'absent','empty','value'){$proof+=CheckModel "positive-$s" $s}
$proof+=CheckModel 'positive-tar'
$proof+=CheckModel 'positive-alias' -Aliases
foreach($s in 'stock-fail','fidelity-fail','context-fail','stop-fail','pid-change','id-fail','registry-fail'){$proof+=CheckModel $s}
$common=@{Project=$project;Jdk=$jdk;Owned=(Join-Path $OutputDirectory 'NOT_CREATED');WatchRoot=$RepositorySource}
foreach($case in 'no-authority','real-callback','native-gate','owned-target','identity-pin'){
    $args=@{};foreach($p in $common.GetEnumerator()){$args[$p.Key]=$p.Value};$failure=$null
    $identity=Join-Path $PSScriptRoot 'mac-jdk25-identity.json';$bytes=[IO.File]::ReadAllBytes($identity)
    try{
        switch($case){
            no-authority{$null=& $invoke @args}
            real-callback{$null=& $invoke @args -RuntimeApproved -FixtureHooks @{bad={}}}
            native-gate{$null=& $invoke @args -RuntimeApproved}
            owned-target{$args.Owned=Join-Path $project 'target\private';$null=& $invoke @args -FixtureOnly -FixtureHooks @{notCalled=$true}}
            identity-pin{[IO.File]::AppendAllText($identity,' ');$null=& $invoke @args -FixtureOnly -FixtureHooks @{Setup={};Dispatch={};Owner={};Stock={};Verify={};Compare={};StopPlan={};Stop={};Confirm={}}}
        }
    }catch{$failure=$_.Exception.Message}
    finally{if($case-eq'identity-pin'){[IO.File]::WriteAllBytes($identity,$bytes)}}
    if(-not$failure-or(Test-Path -LiteralPath $args.Owned)){throw "Mac early gate failed $case"}
    $proof+=@{case=$case;passed=$true;error=$failure;zeroNativeCalls=$true}
}
@{verdict='PASS';cases=$proof;scope='Synthetic pure Windows models, not native Mac execution/coverage/performance'}|ConvertTo-Json -Depth 7|Set-Content (Join-Path $OutputDirectory 'proof.json')
Write-Output "MAC_QUALIFIER_MODEL_PASS cases=$($proof.Count); no Java/native Mac/runtime"
