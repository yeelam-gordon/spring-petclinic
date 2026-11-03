param([Parameter(Mandatory)][string]$FixtureRoot,[switch]$IntentionalFailure)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
. "$PSScriptRoot\Invoke-HoblJacocoJob.ps1" -LibraryOnly
RequireJob (-not(Test-Path $FixtureRoot)) 'Fresh integration fixtures';New-Item $FixtureRoot -ItemType Directory|Out-Null
$root=(Resolve-Path $FixtureRoot).ProviderPath;$python=(Get-Process -Id $PID).Path
$workflow=Get-Content "$PSScriptRoot\paired-test.workflow.yml" -Raw
$expression=[regex]::Match($workflow,'(?m)^    if: (.+)$').Groups[1].Value.Replace('toJSON(inputs.candidate_reviewed)','(ConvertTo-Json -Compress -InputObject $Reviewed)').Replace('toJSON(inputs.paired_test_screen)','(ConvertTo-Json -Compress -InputObject $Screen)').Replace('github.repository','$Repo').Replace('inputs.acknowledgement','$Ack').Replace('&&','-and').Replace('==','-ceq')
RequireJob (-not[string]::IsNullOrWhiteSpace($expression)) 'Actual production admission missing'
$admit=[scriptblock]::Create('param($Repo,$Ack,$Reviewed,$Screen) '+$expression)
$admission=@()
foreach($case in @(@('yeelam-gordon/spring-petclinic','I_HAVE_APPROVAL_AND_BUDGET',$true,$true,$true),@('wrong/repo','I_HAVE_APPROVAL_AND_BUDGET',$true,$true,$false),@('yeelam-gordon/spring-petclinic','wrong',$true,$true,$false),@('yeelam-gordon/spring-petclinic','I_HAVE_APPROVAL_AND_BUDGET',$false,$true,$false),@('yeelam-gordon/spring-petclinic','I_HAVE_APPROVAL_AND_BUDGET',$true,$false,$false),@('yeelam-gordon/spring-petclinic','I_HAVE_APPROVAL_AND_BUDGET','true',$true,$false),@('yeelam-gordon/spring-petclinic','I_HAVE_APPROVAL_AND_BUDGET',$true,'true',$false),@('yeelam-gordon/spring-petclinic','I_HAVE_APPROVAL_AND_BUDGET',$true,$null,$false))){$actual=[bool](& $admit $case[0] $case[1] $case[2] $case[3]);RequireJob ($actual-eq$case[4]) 'Typed owner/ack/review/screen admission failed';$admission+=@{expected=$case[4];actual=$actual}}
$runners=@([regex]::Match($workflow,'runner: \[([^\]]+)\]').Groups[1].Value.Split(',')|ForEach-Object {$_.Trim()})
RequireJob (($runners-join',')-ceq'windows-11-arm,macos-15'-and$workflow.Contains('timeout-minutes: 60')-and([regex]::Matches($workflow,'if: always\(\)')).Count-eq2-and$workflow-notmatch'continue-on-error|retry|AppData|Q:\\') 'Exact2OS/bounds/always retention/private-path policy failed'
foreach($file in 'Invoke-HoblJacocoJob.ps1','Test-HoblJacocoIntegration.ps1'){RequireJob ($workflow.Contains((Get-FileHash (Join-Path $PSScriptRoot $file)).Hash)) 'Workflow exact integration hash mismatch'}
$blocks=@();$lines=$workflow-split'\r?\n'
for($i=0;$i-lt$lines.Count;$i++){if($lines[$i]-match'^        run: \|'){$body=@();for($i++;$i-lt$lines.Count-and($lines[$i]-match'^          '-or$lines[$i]-eq'');$i++){$body+=@($lines[$i]-replace'^          ','')};$i--;$blocks+=@($body-join"`n")}}
$forward=$null
foreach($body in $blocks){$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors);RequireJob ($errors.Count-eq0) 'Actual workflow script syntax invalid';$node=$ast.Find({param($n)$n-is[Management.Automation.Language.CommandAst]-and$n.GetCommandName()-like'*Invoke-HoblJacocoJob.ps1'},$true);if($node){$forward=$node}}
$names=@($forward.CommandElements|Where-Object {$_-is[Management.Automation.Language.CommandParameterAst]}|ForEach-Object ParameterName|Sort-Object)
RequireJob (($names-join',')-ceq'CandidateReviewed,ExecuteAuthorized,JavaHome,LocalCache,OutputDirectory,ProjectFullClone,PythonExecutable,SetupDirectory') 'Actual native workflow invocation forwarding differs'
$realDispatch=(Get-Command InvokeHoblJobRunner).ScriptBlock
$nativeStub=Join-Path $root 'native-plan-stub.ps1'
@'
param($ProjectFullClone,$JavaHome,$LocalCache,$OutputDirectory,$PythonExecutable,[switch]$ExecuteAuthorized,[switch]$CandidateReviewed)
New-Item $OutputDirectory -ItemType Directory -Force|Out-Null
$PSBoundParameters|ConvertTo-Json|Set-Content (Join-Path $OutputDirectory 'received.json')
if($ProjectFullClone-eq'FAIL_NATIVE'){exit 41}
'@|Set-Content $nativeStub
$nativePlan=GetHoblJacocoJobPlan 'project' 'jdk' 'cache' (Join-Path $root 'native-output') $python;$nativePlan.runner=NativeJobLeaf $nativeStub
& $realDispatch $nativePlan
$received=Get-Content (Join-Path $root 'native-output/received.json') -Raw|ConvertFrom-Json
RequireJob ($received.ExecuteAuthorized-and$received.CandidateReviewed-and$received.ProjectFullClone-ceq'project'-and$received.JavaHome-ceq'jdk'-and$received.LocalCache-ceq'cache'-and$received.PythonExecutable-ceq(NativeJobLeaf $python)) 'Actual production splat lost named fields'
$nativePlan.parameters.ProjectFullClone='FAIL_NATIVE';$nativeFailed=$false;try{& $realDispatch $nativePlan}catch{$nativeFailed=$true};RequireJob $nativeFailed 'Actual native exit41 accepted'
$saved=GetHoblContractEnvironment;$script:invocations=@();$script:fault=''
function InvokeHoblJobRunner($Plan){
    $script:invocations+=@{parameters=$Plan.parameters;observedMavenOptsPresent=(Test-Path Env:MAVEN_OPTS)}
    RequireJob (-not(Test-Path Env:MAVEN_OPTS)) 'Outer normalization failed'
    if($script:fault-eq'Missing'){return}
    $innerBefore=GetHoblContractEnvironment
    $env:MAVEN_ARGS='fixture-inner-mutation'
    try{if($script:fault-eq'OriginalAndCleanup'){throw 'ORIGINAL_RUNNER_FAILURE'}}finally{$innerRestore=RestoreHoblContractEnvironment $innerBefore}
    New-Item $Plan.parameters.OutputDirectory -ItemType Directory -Force|Out-Null
    @{status='PASS';scope='HOBLDerivedWarmTest_NOT5Loop_NOTBuild';pin='6feeae0f13e0e258eedc99832416b42bb13779b1';trialPomSha256='D7FF6C0FB845850374020A16A65F4B2B1F1BF8E3204C65AB56BDCA2137BDA818';samples=@(1..6);snapshots=@(1..8);sourceRestored=$true;environmentRestoration=$innerRestore;remainingJavaCandidates=0}|ConvertTo-Json -Depth 20|Set-Content (Join-Path $Plan.parameters.OutputDirectory 'result.json')
}
function RestoreHoblJobOuter($Before){$proof=RestoreHoblContractEnvironment $Before;if($script:fault-eq'OriginalAndCleanup'){throw 'OUTER_CLEANUP_FAILURE'};return $proof}
$rows=@()
try{
    foreach($case in @(@{platform='Windows';opts='-Xms256m';fault='';pass=$true},@{platform='MacOS';opts=$null;fault='';pass=$true},@{platform='Windows';opts='unknown';fault='';pass=$false},@{platform='MacOS';opts='-Xms256m';fault='';pass=$false},@{platform='Windows';opts=$null;fault='Missing';pass=$false},@{platform='MacOS';opts=$null;fault='OriginalAndCleanup';pass=$false})){
        $id=[string]$rows.Count;$script:fault=$case.fault;$beforeCalls=$script:invocations.Count
        if($null-eq$case.opts){Remove-Item Env:MAVEN_OPTS -ErrorAction SilentlyContinue}else{$env:MAVEN_OPTS=$case.opts}
        $plan=GetHoblJacocoJobPlan (Join-Path $root "$id-project") (Join-Path $root "$id-jdk") (Join-Path $root "$id-m2") (Join-Path $root "$id-evidence") $python
        RequireJob ($plan.parameters.ExecuteAuthorized-and$plan.parameters.CandidateReviewed-and$plan.parameters.Count-eq7-and$plan.runner-ceq(NativeJobLeaf "$PSScriptRoot\Invoke-HoblJacocoTest.ps1")) 'Actual named native script invocation differs'
        $failed=$false;try{$null=InvokeHoblJacocoJob $case.platform $plan (Join-Path $root "$id-setup")}catch{$failed=$true}
        RequireJob ($failed-ne$case.pass) 'Actual integration failure propagation mismatch'
        $receipt=Get-Content (Join-Path $root "$id-setup\job-environment.json") -Raw|ConvertFrom-Json
        RequireJob ([Environment]::GetEnvironmentVariable('MAVEN_OPTS')-ceq$case.opts-and((Test-Path Env:MAVEN_ARGS)-eq$saved.values.Contains('MAVEN_ARGS'))-and[Environment]::GetEnvironmentVariable('MAVEN_ARGS')-ceq$saved.values['MAVEN_ARGS']) 'Actual outer restore lost presence/value'
        if($case.opts-and-not($case.platform-eq'Windows'-and$case.opts-ceq'-Xms256m')){RequireJob ($script:invocations.Count-eq$beforeCalls) 'Unknown opts invoked runner'}
        if($case.fault-eq'OriginalAndCleanup'){RequireJob ($receipt.originalFailure-match'ORIGINAL_RUNNER_FAILURE'-and($receipt.cleanupErrors|ConvertTo-Json)-match'OUTER_CLEANUP_FAILURE') 'Original error masked by cleanup'}
        $rows+=@{platform=$case.platform;expectedPass=$case.pass;observedFailure=$failed;originalAndCleanupRetained=($case.fault-eq'OriginalAndCleanup');fixtureOnly=$true}
    }
    $leaf=Join-Path $root 'provider.ps1';[IO.File]::WriteAllText($leaf,'fixture');$drive='JobFixture'+[guid]::NewGuid().ToString('N');New-PSDrive $drive FileSystem $root -Scope Local|Out-Null
    try{RequireJob ((NativeJobLeaf ($drive+':\provider.ps1'))-ceq(Resolve-Path $leaf).ProviderPath) 'Native ProviderPath lost'}finally{Remove-PSDrive $drive}
    if($IntentionalFailure){$script:fault='OriginalAndCleanup';$plan=GetHoblJacocoJobPlan $root $root $root (Join-Path $root 'failure-output') $python;$null=InvokeHoblJacocoJob MacOS $plan (Join-Path $root 'failure-setup')}
    @{status='PASS';fixtureOnly=$true;nativeJavaMaven=$false;actualEntrypointComposition=$true;cases=$rows;capturedInvocationParameters=$script:invocations;retainedCorpusRequired=$false;admission=$admission;resolvedRunners=$runners;workflowScriptBlocksParsed=$blocks.Count;actualNativeDispatchSplat=$true;actualNativeExit41Rejected=$true}|ConvertTo-Json -Depth 20|Set-Content (Join-Path $root 'integration-qualification.json')
}finally{$null=RestoreHoblContractEnvironment $saved}
$global:LASTEXITCODE=0
