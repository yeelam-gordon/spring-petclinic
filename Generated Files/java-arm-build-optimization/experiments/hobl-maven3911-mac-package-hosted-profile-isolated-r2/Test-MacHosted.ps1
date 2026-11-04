param([Parameter(Mandatory)][string]$SourceRoot,[Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not[IO.Path]::IsPathFullyQualified($OutputDirectory)-or(Test-Path $OutputDirectory)){throw 'Fresh absolute pure hosted fixture output required'}
New-Item $OutputDirectory -ItemType Directory|Out-Null
$m=Import-Module (Join-Path $SourceRoot 'H3911.MacHosted.psm1') -Scope Local -PassThru -Force -DisableNameChecking
$guard=$m.ExportedCommands['Assert-H3911MacHostedGuard'];$fixture=$m.ExportedCommands['Invoke-H3911MacHostedFixture'];$source=$m.ExportedCommands['Assert-H3911MacHostedSource'];$role=$m.ExportedCommands['Get-H3911MacRetentionRole'];$copy=$m.ExportedCommands['Copy-H3911MacHostedRetention'];$proof=@()
$sha='a'*40
$context=@{event='workflow_dispatch';repository='yeelam-gordon/spring-petclinic';owner='yeelam-gordon';actor='yeelam-gordon';fork=$true;attempt=1;ref='refs/heads/perf/arm64-matched-comparison';sha=$sha;reviewedSha=$sha;reviewed=$true;environment='matched-comparison-approval';ack='I_APPROVE_1_MAC_ARM_QUALIFICATION_JOB_30MIN_600S_9MAX_14AUX_NO_RETRY'}
$r=& $fixture -FixtureOnly -Context $context -ReviewedSha $sha -Workspace $OutputDirectory
if($r.executionAuthorityGranted-or$r.nativeCalls-ne0-or$r.mode-cne'FIXTURE_ONLY_NOT_PROVISIONING'-or(Test-Path $r.contract.root)-or$r.contract.clientsMaximum-ne9-or$r.contract.auxiliaryJcmdMaximum-ne14){throw 'Pure fixture granted execution or wrote layout'}
$proof+=@{case='pure-plan-positive';passed=$true}
foreach($name in 'event','repository','actor','ref','sha','reviewedSha','environment','ack','fork','reviewed','attempt','array-status'){
    $bad=@{};foreach($p in $context.GetEnumerator()){$bad[$p.Key]=$p.Value}
    if($name-in@('fork','reviewed')){$bad[$name]=$false}elseif($name-eq'attempt'){$bad.attempt=2}elseif($name-eq'array-status'){$bad.repository=@($context.repository,'foreign')}else{$bad[$name]='WRONG'}
    $errorText=$null;try{$null=& $guard $bad $sha}catch{$errorText=$_.Exception.Message}
    if(-not$errorText){throw "Hosted guard negative accepted $name"}
    $proof+=@{case="guard-$name";passed=$true}
}
$null=& $source $SourceRoot;$proof+=@{case='actual-closed-runtime-source';passed=$true}
$changed=Join-Path $OutputDirectory 'changed-public-source';New-Item $changed -ItemType Directory|Out-Null;Copy-Item (Join-Path $SourceRoot 'runtime') $changed -Recurse;Copy-Item (Join-Path $SourceRoot 'runtime-pins.json'),(Join-Path $SourceRoot '.gitattributes') $changed
[IO.File]::AppendAllText((Join-Path $changed 'runtime/H3911.NativeProcess.psm1'),'SYNTHETIC_MUTATION')
$errorText=$null;try{$null=& $source $changed}catch{$errorText=$_.Exception.Message};if(-not$errorText){throw 'Changed public source admitted'};$proof+=@{case='source-byte-negative';passed=$true}
foreach($path in 'qualification/output/baseline-verify/01.raw','qualification/output/candidate-verify/06.raw','qualification/output/baseline-verify/application.jar','qualification/output/candidate-verify/classes/META-INF/sbom/application.cdx.json','qualification/output/daemon-home.value','supervisor.json'){
    if(-not(& $role Run $path)){throw "Required raw/full/context role excluded $path"};$proof+=@{case="retention-positive-$path";passed=$true}
}
foreach($path in 'qualification/registry/registry.bin','qualification/home/bin/mvnd','qualification/cache/library.jar','archives/jdk.tar.gz','home/.m2/settings.xml','qualification/output/baseline-verify/classes/.env','.git/config','rawenv.json','qualification/output/credentials.txt'){
    if(& $role Run $path){throw "Unsafe retention role admitted $path"};$proof+=@{case="retention-exclude-$path";passed=$true}
}
$errorText=$null;try{$null=& $role Run '../secret'}catch{$errorText=$_.Exception.Message};if(-not$errorText){throw 'Traversal retention admitted'};$proof+=@{case='retention-traversal';passed=$true}
$run=Join-Path $OutputDirectory 'run';$setup=Join-Path $OutputDirectory 'setup';$project=Join-Path $OutputDirectory 'model-source'
New-Item $run,$setup,$project -ItemType Directory|Out-Null
foreach($relative in 'supervisor.json','qualification/mac-qualifier.json','qualification/output/baseline-verify/application.jar','qualification/output/baseline-verify/01.raw','qualification/output/baseline-verify/04.raw','qualification/output/baseline-verify/classes/META-INF/sbom/application.cdx.json','qualification/output/daemon-home.value','qualification/registry/registry.bin','qualification/home/SDK.zip'){
    $path=Join-Path $run $relative;New-Item (Split-Path $path) -ItemType Directory -Force|Out-Null;[IO.File]::WriteAllText($path,'SYNTHETIC_NOT_COMPILED_NOT_RUNTIME')
}
[IO.File]::WriteAllText((Join-Path $setup 'host.json'),'{"mode":"SYNTHETIC"}');[IO.File]::WriteAllText((Join-Path $setup 'credentials.txt'),'DO_NOT_COPY')
[IO.File]::WriteAllText((Join-Path $project 'pom.xml'),'SYNTHETIC_ONLY')
$before=[Environment]::GetEnvironmentVariables('Process');$cwd=(Get-Location).Path;$native=[Environment]::CurrentDirectory
$retained=Join-Path $OutputDirectory 'retained';$receipt=& $copy -SourceRoot $SourceRoot -RunRoot $run -SetupRoot $setup -Destination $retained -Project $project
if($receipt.runtimeQualified-or$receipt.status-cne'FAILED_EVIDENCE_BINDING'-or(Test-Path (Join-Path $retained 'Run/qualification/output/baseline-verify/04.raw'))-or(Test-Path (Join-Path $retained 'Run/qualification/registry/registry.bin'))-or(Test-Path (Join-Path $retained 'Setup/credentials.txt'))){throw 'Partial synthetic capture was copied or failure metadata lost'}
$attribute=Get-Content (Join-Path $retained 'source/payload-attributes.receipt.json') -Raw|ConvertFrom-Json
if(-not$attribute.copyBound-or$attribute.actualSha256-cne$attribute.retainedSha256){throw 'Visible actual attributes binding failed'}
$after=[Environment]::GetEnvironmentVariables('Process');if($before.Count-ne$after.Count-or(Get-Location).Path-cne$cwd-or[Environment]::CurrentDirectory-cne$native){throw 'Hosted fixture changed caller state'};foreach($k in $before.Keys){if(-not$after.Contains($k)-or$before[$k]-cne$after[$k]){throw 'Hosted fixture changed environment'}}
$proof+=@{case='actual-tiny-retention-visible-attributes-state';passed=$true}
$errorText=$null;try{$null=& $copy -SourceRoot $SourceRoot -RunRoot $run -SetupRoot $setup -Destination (Join-Path $run 'unsafe-nested')}catch{$errorText=$_.Exception.Message};if(-not$errorText-or(Test-Path (Join-Path $run 'unsafe-nested'))){throw 'Unsafe retention-root overlap admitted'};$proof+=@{case='retention-overlap-no-writes';passed=$true}
$workflow=Get-Content (Join-Path $SourceRoot 'mac-qualification.workflow.yml') -Raw
if($workflow-notmatch'runs-on: macos-15'-or$workflow-match'\bmatrix:|continue-on-error|include-hidden-files|macos-14|macos-26'-or$workflow-notmatch'RootRuntimeApproved -DeadlineMilliseconds 600000'){throw 'Fixed Mac/strict untimed template boundary changed'}
@{verdict='PASS';cases=$proof;scope='Pure FixtureOnly host/retention models; no provisioning, Java or runtime'}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $OutputDirectory 'proof.json')
Write-Output "MAC_HOSTED_FIXTURE_PASS cases=$($proof.Count); no provisioning/runtime/network"
