param([Parameter(Mandatory)][string]$FixtureRoot,[string]$OriginalWrapper)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
$base=Join-Path $PSScriptRoot '..\hobl-contract';$matched=Join-Path $PSScriptRoot '..\hobl-matched-after';$matchedTest=(Resolve-Path "$matched\Test-MatchedAfter.ps1").ProviderPath
if(Test-Path $FixtureRoot){throw 'Fresh diagnostic fixtures required'}
New-Item $FixtureRoot -ItemType Directory|Out-Null
& "$matched\Test-MatchedAfter.ps1" -FixtureRoot (Join-Path $FixtureRoot 'normal') -OriginalWrapper $OriginalWrapper
if($LASTEXITCODE){throw 'Accepted matched readiness failed'}
$normal=Join-Path $FixtureRoot 'normal\core\Invoke-HoblContract.ps1'
if((Get-FileHash $normal).Hash-ne'BFEC3C20F7F89D786AA5A7B37D5DE67DBCB1654AA7BD92430CF7E54A23712811'){throw 'Default-false driver byte identity failed'}
New-Item "$FixtureRoot\core" -ItemType Directory|Out-Null
Get-ChildItem $base -File|Copy-Item -Destination "$FixtureRoot\core"
Copy-Item "$FixtureRoot\normal\hobl-wrapper-diagnostic" "$FixtureRoot\hobl-wrapper-diagnostic" -Recurse
git -C $FixtureRoot init --quiet;$diagnosticPatch=(Resolve-Path "$PSScriptRoot\hosted-elapsed.patch").ProviderPath;git -C $FixtureRoot apply --check --directory=core $diagnosticPatch
if($LASTEXITCODE){throw 'Diagnostic patch check failed'}
git -C $FixtureRoot apply --directory=core $diagnosticPatch;if($LASTEXITCODE){throw 'Diagnostic patch failed'}
$runner=(Resolve-Path "$FixtureRoot\core\Invoke-HoblContract.ps1").ProviderPath
. $runner -LibraryOnly
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors);Require (-not$errors) 'Diagnostic syntax failed'
$old=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $normal).ProviderPath,[ref]$tokens,[ref]$errors)
foreach($name in 'Phase','ContractArguments','Snapshot','SourceGate','RestoreMatchedEnvironment'){
    Same ($ast.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true).Extent.Text) ($old.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true).Extent.Text) "Diagnostic changed $name"
}
Same ($ast.Find({param($n)$n-is[Management.Automation.Language.ForStatementAst]},$true).Extent.Text) ($old.Find({param($n)$n-is[Management.Automation.Language.ForStatementAst]},$true).Extent.Text) 'Five-loop AST changed'
$text=Get-Content $runner -Raw
Require ($text.IndexOf('Review nonempty injected option')-lt$text.IndexOf('$saved=GetMatchedEnvironmentSnapshot')-and$text.IndexOf('$saved=GetMatchedEnvironmentSnapshot')-lt$text.IndexOf('    EnableHoblElapsedDiagnostic $DiagnosticMode')-and$text.IndexOf('    EnableHoblElapsedDiagnostic $DiagnosticMode')-lt$text.IndexOf("Phase 'prep-go-offline'")) 'Logger guard/snapshot/scope ordering failed'
$before=GetMatchedEnvironmentSnapshot
try{
    $env:MAVEN_OPTS='unknown-fixture';$rejected=$false;try{EnableHoblElapsedDiagnostic HostedElapsed}catch{$rejected=$true};Require ($rejected-and$env:MAVEN_OPTS-ceq'unknown-fixture') 'Unknown options silently replaced'
    Remove-Item Env:MAVEN_OPTS;EnableHoblElapsedDiagnostic HostedElapsed;Require ($env:MAVEN_OPTS-ceq'-Dorg.slf4j.simpleLogger.showDateTime=true') 'Exact supported logger flag missing'
    $rejected=$false;try{& $runner -LibraryOnly -DiagnosticMode INVALID}catch{$rejected=$true};Require $rejected 'Unknown driver mode accepted'
}finally{$restore=RestoreMatchedEnvironment $before @('JAVA_HOME','PATH','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME','MVNW_PREFER_PWSH');Require $restore.restored 'Diagnostic flag restoration failed'}
$OutputDirectory=$FixtureRoot;$result=@{samples=@(@{iteration=1});snapshots=@(@{name='fixture'});phases=@(@{timed=$true});summary=@{buildMedian=1}}
. ([scriptblock]::Create($ast.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Save'},$true).Extent.Text));Save
$roundtrip=Get-Content "$FixtureRoot\result.json" -Raw|ConvertFrom-Json
foreach($record in @($roundtrip)+@($roundtrip.samples)+@($roundtrip.snapshots)+@($roundtrip.phases)+@($roundtrip.summary)){Require ($record.instrumented-eq$true-and$record.performanceEligible-eq$false-and$record.eligibility-ceq'DiagnosticNotPerformance') 'Diagnostic eligibility escaped serialization'}
$workflow=Get-Content "$PSScriptRoot\hosted-elapsed.workflow.yml" -Raw
$expression=[regex]::Match($workflow,'(?m)^\s+if: ([^\r\n]+)').Groups[1].Value.Replace('toJSON(inputs.elapsed_diagnostic)','$DiagnosticJson').Replace('github.repository','$Repository').Replace('inputs.acknowledgement','$Acknowledgement').Replace('inputs.windows_benefit_reviewed','$Reviewed').Replace('inputs.platform_selection','$Selection').Replace('==','-eq').Replace('&&','-and').Replace('||','-or')
$admission=[scriptblock]::Create('param($Repository,$Acknowledgement,$Reviewed,$Selection,$DiagnosticJson) '+$expression)
$testAst=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path "$matched\Test-MatchedAfter.ps1").ProviderPath,[ref]$tokens,[ref]$errors)
. ([scriptblock]::Create($testAst.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'ReadMatchedRunners'},$true).Extent.Text))
$cases=@()
foreach($mode in @($true,$false,'true','false','',1,$null)){foreach($selection in @('Both','MacOnly','INVALID','',$null)){
    $json=ConvertTo-Json -InputObject $mode -Compress;$valid=$mode-is[bool]-and$selection-in@('Both','MacOnly');$allowed=[bool](& $admission 'yeelam-gordon/spring-petclinic' 'I_HAVE_APPROVAL_AND_BUDGET' $true $selection $json);Require ($allowed-eq$valid) 'Actual diagnostic admission failed closed'
    $runners=@(ReadMatchedRunners $workflow $selection);Same $runners @($(if($selection-eq'Both'){@('windows-11-arm','macos-15')}elseif($selection-eq'MacOnly'){@('macos-15')}else{@()})) 'Production matrix changed'
    foreach($guards in @(@('other/repo','I_HAVE_APPROVAL_AND_BUDGET',$true),@('yeelam-gordon/spring-petclinic','wrong',$true),@('yeelam-gordon/spring-petclinic','I_HAVE_APPROVAL_AND_BUDGET',$false))){Require (-not(& $admission $guards[0] $guards[1] $guards[2] $selection $json)) 'Diagnostic OR bypassed existing authority'}
    $cases+=@{input=$mode;platform=$selection;admitted=$allowed;runners=$runners}
}}
$selector=[regex]::Match($workflow,'(?m)^\s*\$patch=if[^\r\n]+').Value+';'+[regex]::Match($workflow,'(?m)^\s*\$test=if[^\r\n]+').Value
foreach($value in 'false','true'){. ([scriptblock]::Create($selector.Replace('$env:ELAPSED_DIAGNOSTIC','$value')));Require ($patch.EndsWith($(if($value-eq'true'){'hobl-hosted-elapsed-diagnostic/hosted-elapsed.patch'}else{'hobl-matched-after/matched-after.patch'}))-and$test.EndsWith($(if($value-eq'true'){'hobl-hosted-elapsed-diagnostic/Test-HostedElapsed.ps1'}else{'hobl-matched-after/Test-MatchedAfter.ps1'}))) 'Actual workflow patch/test forwarding failed'}
Require ($workflow.Contains('default: false')-and$workflow.Contains('hobl-instrumented-elapsed-DiagnosticNotPerformance')) 'Default/diagnostic artifact label missing'
& (Get-Process -Id $PID).Path -NoProfile -File $matchedTest -FixtureRoot (Join-Path $FixtureRoot 'diagnostic-environment') -EnvironmentChild -PatchedDriver $runner *> "$FixtureRoot\diagnostic-environment.log"
Require ($LASTEXITCODE-eq0) 'Diagnostic actual eleven-key child restoration failed'
$cases|ConvertTo-Json -Depth 10|Set-Content "$FixtureRoot\admission.json"
@{status='PASS';normalDriverSha256=(Get-FileHash $normal).Hash;diagnosticDriverSha256=(Get-FileHash $runner).Hash;phaseArgvLoopSnapshotSourceAstUnchanged=$true;runtimeExecuted=$false;instrumented=$true;performanceEligible=$false;eligibility='DiagnosticNotPerformance';loggerRestoration=$restore}|ConvertTo-Json -Depth 10|Set-Content "$FixtureRoot\qualification.json"
$global:LASTEXITCODE=0
