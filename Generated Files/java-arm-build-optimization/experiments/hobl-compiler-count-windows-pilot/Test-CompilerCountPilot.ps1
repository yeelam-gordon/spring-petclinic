#requires -Version 7.5
param([Parameter(Mandatory)][string]$FixtureRoot,[switch]$IntentionalFailure,
    [string]$ReferenceReport,[string]$ReferenceBom,[string]$ReferenceOnlineManifest,[string]$ReferenceOfflineManifest)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
if($IntentionalFailure){throw 'Intentional genuine Actions failure'}
if(Test-Path $FixtureRoot){throw 'Fresh fixture root required'}
New-Item $FixtureRoot -ItemType Directory|Out-Null
$original="$PSScriptRoot\..\hobl-pwsh-pilot"
$argsOld=@('-NoProfile','-File',"$original\Test-PwshPackagePilot.ps1",'-FixtureRoot',"$FixtureRoot\original9")
foreach($name in 'ReferenceReport','ReferenceBom','ReferenceOnlineManifest','ReferenceOfflineManifest'){if(Get-Variable $name -ValueOnly){$argsOld+=@("-$name",(Get-Variable $name -ValueOnly))}}
& ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) @argsOld
if($LASTEXITCODE){throw 'Original9 failed'}
. "$PSScriptRoot\Invoke-CompilerCountPilot.ps1" -Project 'owned-project' -Cache 'owned-cache' -JavaHome 'owned-jdk' -Output 'owned-output' -LibraryOnly
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\Invoke-CompilerCountPilot.ps1",[ref]$tokens,[ref]$errors)
Require (-not$errors.Count) 'Runner parse errors'
function Reject([scriptblock]$Body){$failed=$false;try{&$Body}catch{$failed=$true};Require $failed 'Negative accepted'}
$names=@('MAVEN_OPTS','MVNW_PREFER_PWSH');$before=GetBoundaryEnvironmentSnapshot
try{
    Remove-Item Env:MAVEN_OPTS -ErrorAction SilentlyContinue
    SetCompilerCountArm baseline;Require (-not(Test-Path Env:MAVEN_OPTS)-and$env:MVNW_PREFER_PWSH-ceq'true') 'Baseline must remain Core'
    SetCompilerCountArm candidate;Require ($env:MAVEN_OPTS-ceq'-XX:CICompilerCount=2'-and$env:MVNW_PREFER_PWSH-ceq'true') 'Candidate treatment'
    $env:MAVEN_OPTS='-XX:+PrintFlagsFinal';Reject {PilotCall 'pair-1-baseline-package' @('fake') $true}
    $env:MAVEN_OPTS='UNKNOWN';Reject {SetCompilerCountArm baseline};Require ($env:MAVEN_OPTS-ceq'UNKNOWN') 'Unknown option overwritten'
}finally{$restore=RestoreBoundaryEnvironment $before $names;Require $restore.restored 'Test environment restoration'}
$text="Apache Maven 3.9.11`nJava version: 25.0.5.0.2, vendor: Microsoft`narch: `"aarch64`"`n"
$flags=@{CICompilerCount='3';CICompilerCountPerCPU='true';TieredCompilation='true';TieredStopAtLevel='4';UseG1GC='true';ActiveProcessorCount='-1'}
foreach($key in $flags.Keys){$text+="intx $key = $($flags[$key])`n"}
$a=@{flags=(ReadCompilerConfig $text)};$b=@{flags=(ReadCompilerConfig ($text.Replace('CICompilerCount = 3','CICompilerCount = 2')))}
AssertCompilerTreatment $a $b;Reject {AssertCompilerTreatment $b $b}
Reject {ReadCompilerConfig ($text.Replace('TieredStopAtLevel = 4','TieredStopAtLevel = 1'))}
Reject {ReadCompilerConfig ($text+"intx CICompilerCount = 3`n")}
$probeBefore=GetBoundaryEnvironmentSnapshot;$script:probeOptions=@()
function PilotCall($Label,$Arguments,$Timed=$false){
    Require (-not$Timed-and$Arguments[-1]-eq'--version') 'Probe must be untimed version only'
    $script:probeOptions+=,$env:MAVEN_OPTS
    $path=Join-Path $FixtureRoot "$Label.log"
    $(if($Label-eq'config-candidate'){$text.Replace('CICompilerCount = 3','CICompilerCount = 2')}else{$text})|Set-Content $path
    return @{log=$path}
}
try{
    Remove-Item Env:MAVEN_OPTS -ErrorAction SilentlyContinue
    $base=@('fixture-cache');$null=CompilerConfigProbe baseline
    Require (-not(Test-Path Env:MAVEN_OPTS)) 'Baseline probe observer leaked'
    $null=CompilerConfigProbe candidate;Require ($env:MAVEN_OPTS-ceq'-XX:CICompilerCount=2') 'Candidate probe observer leaked'
    Same $script:probeOptions @('-XX:+PrintFlagsFinal','-XX:CICompilerCount=2 -XX:+PrintFlagsFinal') 'Actual probe option sequence'
}finally{$restore=RestoreBoundaryEnvironment $probeBefore $names;Require $restore.restored 'Probe fixture restore'}
Require ($CandidateRevision-eq'UpstreamF62f442HttpsLicense') 'New variant default is not fixed AAA'
AssertPilotCandidateFile (PilotCandidateRevision $CandidateRevision)
$samples=@(foreach($i in 1..3){@{pair=$i;arm='baseline';seconds=10};@{pair=$i;arm='candidate';seconds=9}})
Require (CompilerScreenDecision $samples) 'Positive rule'
$samples[1].seconds=10.1;Require (-not(CompilerScreenDecision $samples)) 'One unfavorable pair must close'
foreach($s in $samples){if($s.arm-eq'candidate'){$s.seconds=9.6}};Require (-not(CompilerScreenDecision $samples)) 'Noisy/small change must close'
$oldAst=[Management.Automation.Language.Parser]::ParseFile("$original\Invoke-PwshPackagePilot.ps1",[ref]$tokens,[ref]$errors)
foreach($name in 'PilotPayload','PilotProperties','PilotBom','ComparePilotBom','PilotManifest','ComparePilotManifest','ComparePilotPayload','PilotArtifact','PilotSource'){
    $one=$ast.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true)
    $two=$oldAst.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true)
    Require ($one.Body.Extent.Text-ceq$two.Body.Extent.Text) "Protected comparator/schema changed: $name"
}
@{status='PURE_PASS';original9=$true;coreBothArms=$true;observerLeakRejected=$true;unknownOptionsPreserved=$true;noTreatmentRejected=$true;decisionRule=$true;protectedComparators=9;newJavaMaven=0}|ConvertTo-Json|Set-Content "$FixtureRoot\qualification.json"
