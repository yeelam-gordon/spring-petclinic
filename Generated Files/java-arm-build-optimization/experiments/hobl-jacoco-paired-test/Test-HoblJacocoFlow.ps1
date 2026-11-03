param([Parameter(Mandatory)][string]$FixtureRoot,[Parameter(Mandatory)][string]$RetainedRoot,[Parameter(Mandatory)][string]$Python,[switch]$IntentionalFailure)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Invoke-HoblJacocoTest.ps1" -LibraryOnly
Require (-not(Test-Path $FixtureRoot)) 'Fresh fixture root';New-Item $FixtureRoot -ItemType Directory|Out-Null
$fixtureBase=(Resolve-Path $FixtureRoot).ProviderPath;$retained=Get-Content "$RetainedRoot\result.json" -Raw|ConvertFrom-Json
$script:originalSnapshot=(Get-Command Snapshot).ScriptBlock
$phaseText=$donor.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Phase'},$true).Extent.Text
$runnerText=Get-Content "$PSScriptRoot\Invoke-HoblJacocoTest.ps1" -Raw
Require ((Get-Command Phase).ScriptBlock.Ast.Extent.Text-ceq$donor.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Phase'},$true).Extent.Text) 'Native Phase body changed'
Require ($phaseText.Contains('/usr/bin/time -p -o $time')-and$phaseText.Contains('Measure-Command')-and$phaseText.Contains('*> $log')) 'Accepted native clock/redirection missing'
$drive='WarmFixture'+[guid]::NewGuid().ToString('N');[IO.File]::WriteAllText("$fixtureBase\provider-proof.txt",'owned');New-PSDrive $drive FileSystem $fixtureBase -Scope Local|Out-Null
try{$native=HoblNativePath ($drive+':\provider-proof.txt');Require ($native-ceq(Resolve-Path "$fixtureBase\provider-proof.txt").ProviderPath) 'Native provider path not resolved'}finally{Remove-PSDrive $drive}
$time=ParseTime "real 1.25`nuser 2.00`nsys 0.25`n";Require ($time.real-eq1.25-and$time.user-eq2) 'Mac native time parse'
$failed=$false;try{ParseTime "real 1`nreal 2`nuser 1`nsys 1`n"}catch{$failed=$true};Require $failed 'Duplicate time accepted'
function HoblIdentity {$result.runtime=@{'java.home'=$JavaHome;'java.version'='25.0.5.0.2';'java.runtime.version'='25.0.5.0.2+1-LTS';'java.vendor'='Microsoft';'os.arch'='aarch64'};$result.fixtureOnly=$true}
function HoblJavaCandidates {return @()}
function HoblSourceCheck([bool]$Original=$false){
    $pom=(Get-FileHash (Join-Path $ProjectFullClone 'pom.xml')).Hash;$cmd=(Get-FileHash (Join-Path $ProjectFullClone 'mvnw.cmd')).Hash
    Require ($pom-ceq$(if($Original){'A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D'}else{'D7FF6C0FB845850374020A16A65F4B2B1F1BF8E3204C65AB56BDCA2137BDA818'})) 'Production install/restore POM failed'
    Require ($cmd-ceq$(if(-not$Original-and$script:platform-eq'Windows'){'AAA4957C5AB29267A0D89C03D33621740A4233BF25AFEB480797023687CABB7D'}else{'5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A'})) 'Production wrapper treatment/restore failed'
}
function HoblNow {$script:clock+=10000;return $script:clock}
function WriteFixtureExec($Path,$Session,[long]$Start,[long]$Dump,$Arm){
    $m=[IO.MemoryStream]::new()
    function Byte([byte]$Value){$m.WriteByte($Value)}
    function Utf([string]$Value){$b=[Text.Encoding]::UTF8.GetBytes($Value);Byte 0;Byte ([byte]$b.Length);$m.Write($b,0,$b.Length)}
    function Long([long]$Value){$b=[BitConverter]::GetBytes($Value);[Array]::Reverse($b);$m.Write($b,0,$b.Length)}
    $header=[byte[]](1,192,192,16,7);$m.Write($header,0,$header.Length);Byte 16;Utf $Session;Long $Start;Long $Dump
    foreach($name in @('org/springframework/samples/petclinic/Fixture')+$(if($Arm-eq'default'){@('outside/Fixture')}else{@()})){Byte 17;Long 1;Utf $name;Byte 1;Byte 1}
    [IO.File]::WriteAllBytes($Path,$m.ToArray());$m.Dispose()
}
function FixturePopulate($Arm){
    $script:serial++;$sid="fixture-$script:serial";if($script:fault-eq'StaleSession'-and$script:serial-gt2){$sid='fixture-1'}
    $target=Join-Path $ProjectFullClone 'target';New-Item "$target\site\jacoco" -ItemType Directory -Force|Out-Null
    if(-not(Test-Path "$target\application.jar")){
        Copy-Item "$RetainedRoot\default\application.jar" "$target\application.jar"
        Copy-Item (Join-Path $retained.project 'target\classes') "$target\classes" -Recurse;Copy-Item (Join-Path $retained.project 'target\test-classes') "$target\test-classes" -Recurse
    }
    if(Test-Path "$target\surefire-reports"){Remove-Item "$target\surefire-reports" -Recurse -Force}
    Copy-Item "$RetainedRoot\$Arm\surefire" "$target\surefire-reports" -Recurse
    foreach($f in Get-ChildItem "$target\surefire-reports" -Filter 'TEST-*.xml'){[xml]$x=Get-Content $f.FullName -Raw;$x.SelectSingleNode('//properties/property[@name="java.home"]').SetAttribute('value',$JavaHome);$x.Save($f.FullName)}
    [xml]$xml=Get-Content "$RetainedRoot\$Arm\coverage\jacoco.xml" -Raw;$s=$xml.report.sessioninfo;$s.SetAttribute('id',$sid);$s.SetAttribute('start',[string]($script:clock+1));$s.SetAttribute('dump',[string]($script:clock+2));$xml.Save("$target\site\jacoco\jacoco.xml")
    WriteFixtureExec "$target\jacoco.exec" $sid ($script:clock+1) ($script:clock+2) $Arm
    if($script:fault-eq'ChangedResource'-and$script:serial-gt2){$file=Get-ChildItem "$target\classes" -Recurse -File|Select-Object -First 1;[IO.File]::WriteAllText($file.FullName,'fixture mutation')}
}
function Phase([string]$Name,[string[]]$Arguments,[bool]$Timed=$false){
    $script:events+=@{name=$Name;arguments=$Arguments;timed=$Timed}
    $goal=$Arguments[-1];$arm=if($Arguments-contains'-Djacoco.instrumentation.includes=org.springframework.samples.petclinic.*'){'candidate'}else{'default'}
    $log=Join-Path $OutputDirectory "$Name.log";$code=if($script:fault-ceq$Name){41}else{0}
    if($goal-eq'--version'){'Apache Maven 3.9.11'|Set-Content $log}else{
        if($goal-in@('verify','test')){if($Timed){Require (-not(Test-Path (Join-Path $ProjectFullClone 'target/jacoco.exec'))) 'Reset did not precede timer';Require ($goal-eq'test'-and$Arguments[0]-eq'-o') 'Only offline test timed'};FixturePopulate $arm}
        $scope=if($arm-eq'candidate'){'org.springframework.samples.petclinic.*'}else{'*'}
        @("argLine set to -javaagent:fixture/org.jacoco.agent-0.8.13-runtime.jar=destfile=$(Join-Path $ProjectFullClone 'target/jacoco.exec'),includes=$scope","Starting Fixture with PID $($script:serial+1000)",'Nothing to compile - all classes are up to date','Nothing to compile - all classes are up to date')|Set-Content $log
        if($script:fault-eq'Recompiled'-and$Timed){'Compiling 1 source files'|Add-Content $log}
    }
    $p=@{name=$Name;arguments=$Arguments;timed=$Timed;seconds=$(if($arm-eq'candidate'){25.0}else{30.0});exitCode=$code;log=$log;nativeTime=$null;nativeTimeRaw=$null};$result.phases+=,$p;Save
    Require ($code-eq0) "Injected native failure=$code";return $p
}
function Snapshot([string]$Name,[bool]$Online){
    & $script:originalSnapshot $Name $Online
    if($script:fault-eq'MissingRole'-and$script:serial-gt2){$result.snapshots[-1].rawMetadata[0].entry='unexpected.raw'}
}
$records=@()
foreach($scenario in @(@{platform='Windows';fault=''},@{platform='MacOS';fault=''},@{platform='Windows';fault='pair-2-candidate-test'},@{platform='Windows';fault='MissingRole'},@{platform='MacOS';fault='StaleSession'},@{platform='Windows';fault='ChangedResource'},@{platform='MacOS';fault='Recompiled'})){
    $name="$($scenario.platform)-$($scenario.fault)";if(-not$scenario.fault){$name+='success'}
    $ProjectFullClone=Join-Path $fixtureBase "$name-project";$JavaHome=Join-Path $fixtureBase "$name-jdk";$LocalCache=Join-Path $fixtureBase "$name-cache";$OutputDirectory=Join-Path $fixtureBase "$name-output";$PythonExecutable=$Python
    New-Item "$ProjectFullClone\.mvn","$JavaHome\bin",$LocalCache -ItemType Directory -Force|Out-Null
    Copy-Item "$RetainedRoot\original-pom.xml" "$ProjectFullClone\pom.xml";Copy-Item (Join-Path $retained.project 'mvnw.cmd') "$ProjectFullClone\mvnw.cmd";[IO.File]::WriteAllText("$ProjectFullClone\mvnw",'fixture');[IO.File]::WriteAllText("$ProjectFullClone\.mvn\jvm.config",'');[IO.File]::WriteAllText("$JavaHome\bin\java.exe",'fixture');[IO.File]::WriteAllText("$JavaHome\bin\java",'fixture')
    $script:clock=1793608400000L;$script:serial=0;$script:events=@();$script:fault=$scenario.fault
    if($IntentionalFailure){$script:fault='pair-2-candidate-test';InvokeHoblWarmRun $scenario.platform;throw 'Failure expected'}
    $rejected=$false;try{InvokeHoblWarmRun $scenario.platform}catch{$rejected=$true}
    Require ($rejected-eq[bool]$scenario.fault) 'Actual production failure propagation mismatch'
    $actual=Get-Content (Join-Path $OutputDirectory 'result.json') -Raw|ConvertFrom-Json -AsHashtable -Depth 100
    Require ($actual.sourceRestored-and$actual.environmentRestoration.restored-and$actual.environmentRestoration.keys.Count-eq11-and$actual.environmentRestoration.cwdEqual) 'Actual production finally restoration missing'
    if(-not$scenario.fault){Require ($actual.samples.Count-eq6-and$actual.snapshots.Count-eq8-and$actual.preparations.Count-eq2) 'Production flow incomplete';Same @($actual.samples|ForEach-Object {"$($_.pair)-$($_.arm)"}) @('1-default','1-candidate','2-candidate','2-default','3-default','3-candidate') 'Actual AB BA AB order';Require (@($script:events|Where-Object timed).Count-eq6) 'Extra timed work';$records+=@{scenario=$name;fixtureOnly=$true;actualProductionFlow=$true;samples=6;snapshots=8;status='PASS'}}
    else{$records+=@{scenario=$name;fixtureOnly=$true;expectedFailure=$true;status='PASS';nativeCalls=$script:events.Count}}
}
$records|ConvertTo-Json -Depth 10|Set-Content (Join-Path $fixtureBase 'fixture-qualification.json')
$w=Get-Content "$fixtureBase\Windows-success-output\result.json" -Raw|ConvertFrom-Json -AsHashtable -Depth 100
$m=Get-Content "$fixtureBase\MacOS-success-output\result.json" -Raw|ConvertFrom-Json -AsHashtable -Depth 100
$rejected=$false;try{CompareHoblWarmResults $w $m}catch{$rejected=$true};Require $rejected 'Fixture results entered actual comparison'
$w.fixtureOnly=$false;$m.fixtureOnly=$false
$policy=CompareHoblWarmResults $w $m;Require ($policy.advance-and$policy.baselineWindowsMacRatio-eq1-and$policy.candidateWindowsMacRatio-eq1-and$policy.relativeRatioChange-eq1) 'Separate absolute/relative ratio policy'
foreach($s in $m.samples){if($s.arm-eq'candidate'){$s.seconds=31.5}};Require (-not(CompareHoblWarmResults $w $m).advance) 'Exact5% Mac regression admitted'
foreach($s in $m.samples){if($s.arm-eq'candidate'){$s.seconds=30}}
foreach($s in $w.samples){if($s.arm-eq'candidate'){$s.seconds=28.5}};Require (CompareHoblWarmResults $w $m).advance 'Exact5% Windows gain rejected'
@($w.samples|Where-Object {$_.pair-eq1-and$_.arm-eq'candidate'})[0].seconds=30.1;Require (-not(CompareHoblWarmResults $w $m).advance) 'Unfavorable Windows pair admitted'
@{fixtureOnly=$true;actualRuntime=$false;positiveAndBoundaryPolicies=$true;fixtureActualComparisonDenied=$true}|ConvertTo-Json|Set-Content "$fixtureBase\policy-fixtures.json"
$global:LASTEXITCODE=0
