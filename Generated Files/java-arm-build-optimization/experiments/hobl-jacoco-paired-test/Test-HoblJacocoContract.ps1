param([Parameter(Mandatory)][string]$FixtureRoot,[string]$RetainedRoot,[string]$SourceProject,[string]$AcceptedDriver,[string]$Python='python',[switch]$EnvironmentChild,[switch]$IntentionalFailure)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
Import-Module "$PSScriptRoot\HoblJacocoContract.psm1" -Force -DisableNameChecking
function Check($Value,[string]$Message){if(-not$Value){throw $Message}}
function Reject([scriptblock]$Body){$failed=$false;try{& $Body}catch{$failed=$true};Check $failed 'Negative accepted'}
if(Test-Path $FixtureRoot){throw 'Fresh fixture root required'};New-Item $FixtureRoot -ItemType Directory|Out-Null
if($EnvironmentChild){
    $saved=GetHoblContractEnvironment
    try{[Environment]::SetEnvironmentVariable('MAVEN_ARGS','','Process');Remove-Item Env:MVNW_PREFER_PWSH -ErrorAction SilentlyContinue;$fixture=GetHoblContractEnvironment;$names=@('JAVA_HOME','PATH','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME','MVNW_PREFER_PWSH');foreach($n in $names){[Environment]::SetEnvironmentVariable($n,"test-$n",'Process')};if($IsWindows){[Environment]::SetEnvironmentVariable('pAtH','mixed-case-test','Process')};$proof=RestoreHoblContractEnvironment $fixture;Check ($proof.restored-and$proof.keys.Count-eq11-and(Test-Path Env:MAVEN_ARGS)-and$env:MAVEN_ARGS-ceq''-and-not(Test-Path Env:MVNW_PREFER_PWSH)) 'Actual eleven-key/empty/absent restore failed';$proof|ConvertTo-Json -Depth 10|Set-Content "$FixtureRoot\environment.json"}finally{$null=RestoreHoblContractEnvironment $saved}
    $global:LASTEXITCODE=0;return
}
Check ($RetainedRoot-and$AcceptedDriver-and$SourceProject) 'Explicit actual evidence/unsuppressed full clone/accepted driver required'
Check ((Get-FileHash $AcceptedDriver).Hash-ceq'BFEC3C20F7F89D786AA5A7B37D5DE67DBCB1654AA7BD92430CF7E54A23712811') 'Exact accepted portable HOBL Snapshot donor required'
$r=Get-Content "$RetainedRoot\result.json" -Raw|ConvertFrom-Json
$original=[IO.File]::ReadAllBytes("$RetainedRoot\original-pom.xml");$trial=[IO.File]::ReadAllBytes("$PSScriptRoot\trial-pom.xml")
if($IntentionalFailure){$trial[0]=$trial[0]-bxor1};AssertHoblTrialPom $original $trial
Reject {AssertHoblTrialPom $trial $original}
$java=Join-Path $r.javaHome 'bin\java.exe';$jvm=(Get-FileHash (Join-Path $SourceProject '.mvn/jvm.config')).Hash
$before=@{javaSha256=(Get-FileHash $java).Hash;jvmConfigSha256=$jvm;javaRuntime='25.0.5.0.2+1-LTS';arch='aarch64'}
$context=ReadHoblTrialContext $SourceProject $java $before Windows;AssertHoblTrialSource $context Windows -Original
$context.dirty=@(' M mvnw.cmd',' M pom.xml');$context.pomSha256='D7FF6C0FB845850374020A16A65F4B2B1F1BF8E3204C65AB56BDCA2137BDA818';$context.cmdSha256='AAA4957C5AB29267A0D89C03D33621740A4233BF25AFEB480797023687CABB7D';$context.corePreference='true'
AssertHoblTrialSource $context Windows
$mac=$context.Clone();$mac.dirty=@(' M pom.xml');$mac.cmdSha256='5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A';$mac.absoluteWrapper='/Users/fixture/owned/project/mvnw';AssertHoblTrialSource $mac MacOS
foreach($field in 'head','origin','commonDir','pomSha256','javaSha256','jvmConfigSha256','mavenVersion','corePreference'){$bad=$context.Clone();$bad[$field]='wrong';Reject {AssertHoblTrialSource $bad Windows}}
$bad=$context.Clone();$bad.borrowed=$true;Reject {AssertHoblTrialSource $bad Windows}
$bad=$context.Clone();$bad.dirty+=@(' M other');Reject {AssertHoblTrialSource $bad Windows}
$bad=$context.Clone();$bad.absoluteWrapper='C:\owned\build\project\mvnw.cmd';Reject {AssertHoblTrialSource $bad Windows}
$restoreProject=Join-Path $FixtureRoot 'restore';New-Item $restoreProject -ItemType Directory|Out-Null
Copy-Item "$PSScriptRoot\trial-pom.xml" "$restoreProject\pom.xml";$cmd=[IO.File]::ReadAllBytes((Resolve-Path "$PSScriptRoot\..\hobl-pwsh-pilot\upstream-f62f442-https-license-mvnw.cmd").ProviderPath)
[IO.File]::WriteAllBytes("$restoreProject\mvnw.cmd",$cmd);$originalCmd=[IO.File]::ReadAllBytes((Join-Path $SourceProject 'mvnw.cmd'));RestoreHoblTrialFiles $restoreProject $original $originalCmd
[IO.File]::WriteAllText("$restoreProject\pom.xml",'unexpected');Reject {RestoreHoblTrialFiles $restoreProject $original $originalCmd};Check ([IO.File]::ReadAllText("$restoreProject\pom.xml")-ceq'unexpected') 'Unexpected source overwritten'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $AcceptedDriver).ProviderPath,[ref]$tokens,[ref]$errors);Check (-not$errors) 'Accepted helper syntax'
. $AcceptedDriver -LibraryOnly
foreach($name in 'Snapshot'){$definition=$ast.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true);. ([scriptblock]::Create($definition.Extent.Text))}
function Save {}
$OutputDirectory=$FixtureRoot;$JavaHome=$r.javaHome;$result=@{snapshots=@()};$script:preferActive=$true
foreach($arm in 'default','candidate'){
    $source=Join-Path $RetainedRoot $arm;$ProjectFullClone=Join-Path $FixtureRoot $arm;New-Item "$ProjectFullClone\target\site\jacoco" -ItemType Directory -Force|Out-Null
    Copy-Item "$source\application.jar" "$ProjectFullClone\target\application.jar";Copy-Item "$source\coverage\jacoco.xml" "$ProjectFullClone\target\site\jacoco\jacoco.xml";Copy-Item "$source\jacoco.exec" "$ProjectFullClone\target\jacoco.exec";Copy-Item "$source\surefire" "$ProjectFullClone\target\surefire-reports" -Recurse;Copy-Item (Join-Path $r.project 'target\test-classes') "$ProjectFullClone\target\test-classes" -Recurse
    Snapshot "$arm-snapshot" $true;$snap=$result.snapshots[-1];AssertHoblSnapshot $snap
    $bad=$snap.Clone();$bad.counters=@{};Reject {AssertHoblSnapshot $bad}
    & $Python "$PSScriptRoot\Read-HoblExec.py" "$source\jacoco.exec" $arm "$FixtureRoot\$arm-exec.json";Check ($LASTEXITCODE-eq0) 'Actual retained exec parser failed'
    $execution=Get-Content "$FixtureRoot\$arm-exec.json" -Raw|ConvertFrom-Json;$log=Get-Content "$source\clean-verify.log" -Raw;[xml]$report=Get-Content "$source\coverage\jacoco.xml" -Raw;[xml]$properties=(Get-ChildItem "$source\surefire" -Filter 'TEST-*.xml'|Select-Object -First 1|Get-Content -Raw)
    $invocation=Get-Content "$source\invocation.json" -Raw|ConvertFrom-Json;$oldSnap=Get-Content "$source\snapshot.json" -Raw|ConvertFrom-Json
    $agent=[regex]::Match($log,'argLine set to [^\r\n]*destfile=([^,\r\n]+)').Groups[1].Value.Replace('\\','\')
    $case=@{startMs=$oldSnap.invocationStartMs;endMs=$oldSnap.invocationEndMs;seenSessions=@();seenPids=@();javaHome=$r.javaHome;execPath=$agent}
    $proof=AssertHoblTestExecution $log $report $properties $execution $case $arm
    $actualFork=Get-Content "$source\actual-fork.json" -Raw|ConvertFrom-Json;$expectedScope=if($arm-eq'candidate'){'org.springframework.samples.petclinic.*'}else{'*'};Check ($actualFork.pid-eq$proof.reportedPid-and$actualFork.commandLine.Contains("includes=$expectedScope")-and$actualFork.commandLine.Contains('org.jacoco.agent-0.8.13-runtime.jar=')) 'Retained actual OS argv scope/PID differs'
    Reject {AssertHoblTestExecution ($log.Replace('0.8.13-runtime','0.8.15-runtime')) $report $properties $execution $case $arm}
    Reject {AssertHoblTestExecution ($log.Replace('includes=','includes=wrong')) $report $properties $execution $case $arm}
    $bad=$case.Clone();$bad.startMs=[long]$report.report.sessioninfo.start+1;Reject {AssertHoblTestExecution $log $report $properties $execution $bad $arm}
    $bad=$case.Clone();$bad.seenSessions=@($proof.session.id);Reject {AssertHoblTestExecution $log $report $properties $execution $bad $arm}
    $bad=$case.Clone();$bad.seenPids=@($proof.reportedPid);Reject {AssertHoblTestExecution $log $report $properties $execution $bad $arm}
    if($arm-eq'candidate'){$bad=$execution.PSObject.Copy();$bad.externalRecords=1;Reject {AssertHoblTestExecution $log $report $properties $bad $case $arm}}
    $proof|ConvertTo-Json -Depth 8|Set-Content "$FixtureRoot\$arm-freshness.json"
}
Check ($result.snapshots[0].jarSha256-ceq$result.snapshots[1].jarSha256) 'Whole actual335 JAR differs'
AssertHoblSnapshot $result.snapshots[1] $result.snapshots[0]
foreach($side in 'actual','reference'){foreach($mutation in 'GitReplacement','SbomReplacement','BothReplacement','Duplicate','Unknown','Missing','CaseMutation','SwappedRoles','EmptyHash','ZeroBytes'){
    $bad=$result.snapshots[1].Clone();$bad.rawMetadata=@($bad.rawMetadata|ForEach-Object {$_.Clone()})
    $git=@($bad.rawMetadata|Where-Object entry -eq 'BOOT-INF/classes/git.properties')[0];$bom=@($bad.rawMetadata|Where-Object entry -eq 'META-INF/sbom/application.cdx.json')[0]
    switch($mutation){
        GitReplacement {$git.entry='unexpected-git.raw'} SbomReplacement {$bom.entry='unexpected-bom.raw'}
        BothReplacement {$git.entry='unexpected-git.raw';$bom.entry='unexpected-bom.raw'}
        Duplicate {$git.entry=$bom.entry} Unknown {$bad.rawMetadata[0].entry='unexpected.raw'} Missing {$bad.rawMetadata=@($bad.rawMetadata|Where-Object entry -ne 'BOOT-INF/classes/git.properties')}
        CaseMutation {$git.entry='BOOT-INF/classes/GIT.properties'} SwappedRoles {$name=$git.entry;$git.entry=$bom.entry;$bom.entry=$name}
        EmptyHash {$git.sha256=''} ZeroBytes {$git.bytes=0}
    }
    if($side-eq'actual'){Reject {AssertHoblSnapshot $bad $result.snapshots[0]}}else{Reject {AssertHoblSnapshot $result.snapshots[0] $bad}}
}}
$bad=$result.snapshots[1].Clone();$copy=[ordered]@{};foreach($kv in $bad.counters.GetEnumerator()){$copy[$kv.Key]=$kv.Value};$bad.counters=$copy;$first=@($bad.counters.Keys)[0];$bad.counters[$first]='1/999';Reject {AssertHoblSnapshot $bad $result.snapshots[0]}
& (Get-Process -Id $PID).Path -NoProfile -File $PSCommandPath -FixtureRoot "$FixtureRoot\environment-child" -EnvironmentChild *> "$FixtureRoot\environment-child.log";Check ($LASTEXITCODE-eq0) 'Isolated actual module environment failed'
@{status='PASS';scope='Dedicated contract only; actual retained Windows replay plus Mac source-shape fixtures, not a new runtime/Mac observation';sourceTrial=$true;actualPortableHoblSnapshots=2;jarSha256=$result.snapshots[0].jarSha256;newJavaMavenCINetwork=0}|ConvertTo-Json|Set-Content "$FixtureRoot\qualification.json"
$global:LASTEXITCODE=0
