param([string]$RepositorySource,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
New-Item $OutputDirectory -ItemType Directory -ErrorAction Stop|Out-Null
$p=Join-Path $PSScriptRoot 'public';$git=(Get-Command git -CommandType Application).Source
python (Join-Path $p 'Make-SyntheticFixtures.py') --git $git --repository $RepositorySource --output (Join-Path $OutputDirectory 'models')
if($LASTEXITCODE){throw 'Synthetic factory failed'}
$project=Join-Path $OutputDirectory 'project'
git clone --quiet --no-hardlinks --no-checkout $RepositorySource $project
git -C $project config core.autocrlf false;git -C $project remote set-url origin 'https://github.com/spring-projects/spring-petclinic.git';git -C $project checkout --quiet --detach 6feeae0f13e0e258eedc99832416b42bb13779b1
Copy-Item (Join-Path $p 'fixtures\Reviewed-AAA-mvnw.cmd') (Join-Path $project 'mvnw.cmd')
$jdk=Join-Path $OutputDirectory 'SYNTHETIC-JDK';New-Item $jdk -ItemType Directory|Out-Null
$m=Import-Module (Join-Path $p 'H3911.WindowsQualifier.psm1') -PassThru -Force
$a=Import-Module (Join-Path $p 'H3911.Artifacts.psm1') -PassThru
$h=Import-Module (Join-Path $p 'H3911.Helpers.psm1') -PassThru
$online=Join-Path $OutputDirectory 'models\reviewed\online\target';$offline=Join-Path $OutputDirectory 'models\reviewed\offline'
$tests=& ($h.ExportedCommands['TestKeys']) @([xml](Get-Content (Join-Path $online 'surefire-reports\TEST-synthetic.xml') -Raw))
$xml=[xml](Get-Content (Join-Path $online 'site\jacoco\jacoco.xml') -Raw)
$counters=& ($h.ExportedCommands['CoverageKeys']) $xml;$semantics=& ($h.ExportedCommands['CoverageSemantics']) $xml
$proof=@()
foreach($case in 'full24','sampling-failure'){
 $owned=Join-Path $OutputDirectory $case;$evidence=Join-Path $OutputDirectory ('evidence-'+$case);New-Item $evidence -ItemType Directory|Out-Null
 $state=@{alive=$false;stops=0;native=$null};$birth=[DateTime]::UtcNow.AddSeconds(-1);[long]$ticks=$birth.Ticks-($birth.Ticks%[long]10);$cim=[DateTime]::new($ticks,[DateTimeKind]::Utc)
 $screenOwner=@{pid=12345;created=$birth.ToString('o');id='01234567';executable='SYNTHETIC';jniSha256='SYNTHETIC'}
 $sampling=@{
  Boundary={param($c)$allocated=@();$i=4201;foreach($label in 'baseline-project','baseline-maven-home','baseline-verify','parent-owner-telemetry'){$allocated+=@{allocationLabel=$label;pid=$i;created='2026-01-01T00:00:00Z';executable='SYNTHETIC_PWSH';prefix=$label;gone=$true};$i++};@{schema='h3911-screen-boundary-v2';status='OBSERVERS_EXIT_CONFIRMED';allocated=$allocated;observers=$allocated}}
  Admit={param($c)$screenOwner}.GetNewClosure()
  Process={param($c,$step,$tokens,$log)[IO.File]::WriteAllText($log,'Goal makeAggregateBom requires online mode; skipping');@{validClock=$true;exit=$(if($case-eq'sampling-failure'-and$step.timed){1}else{0});stdoutComplete=$true;stderrComplete=$true;timeout=$false;elapsedSeconds=$(if($step.route-eq'A'){10.0}else{9.0});clockBoundary='immediately before Process.Start through normal WaitForExit; MODEL';createdUtc=[DateTimeOffset]::UtcNow.ToString('o');observer=$null;observerGone=$true}}.GetNewClosure()
  Capture={param($c,$step)$offline}.GetNewClosure()
 }
 $hooks=@{
  Setup={param($mavenRoot)New-Item $mavenRoot -ItemType Directory|Out-Null;@{fixtureOnly=$true}}
  Dispatch={param($c,$plan)
   if($plan.label-eq'daemon-arch'){$state.alive=$true}
   $value=switch($plan.label){daemon-arch{'aarch64'}daemon-home{$c.Jdk}baseline-maven-home{Join-Path $owned 'SYNTHETIC_MAVEN'}default{$c.Project}}
   if($plan.label-notlike'*-verify'){[IO.File]::WriteAllText($plan.valueFile,$value)}
   if($plan.label-eq'daemon-project'){
    $w=@{status='owned';complete=$true;pid=12345;id='01234567';created=$birth.ToString('o');nativeCreatedTicks=$birth.Ticks.ToString();cimCreated=$cim.ToString('o');cimCreatedTicks=$ticks.ToString();observedUtc=[DateTime]::UtcNow.ToString('o');executable=(Join-Path $c.Jdk 'bin\java.exe');home=$c.Home;registry=$c.Registry;temp=$c.Temp;jniPath=(Join-Path $c.Temp 'fixture.dll');jniSha256='728F9A0F7A8A74D15C6DE37DBE32A73CF8013605D2E881098692E1C88A0F4C2D';javaSha256='094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0';jniMachine=0xAA64}
    $state.native=$w;$w|ConvertTo-Json|Set-Content (Join-Path $evidence 'independent-owned-daemon.json')
   };0
  }.GetNewClosure()
  Owner={param($c)if($state.alive){@{pid=12345;id='01234567';created=$cim.ToString('o');executable=(Join-Path $c.Jdk 'bin\java.exe');jni='728F9A0F7A8A74D15C6DE37DBE32A73CF8013605D2E881098692E1C88A0F4C2D'}}}.GetNewClosure()
  GateNativeFacts={param($c)$state.native}.GetNewClosure()
  GateDeadlineMilliseconds=1000
  Verify={param($c,$label,$call)$artifact=& ($a.ExportedCommands['Read-H3911Artifact']) (Join-Path $online 'application.jar') (Join-Path $online 'classes') (Join-Path $online 'test-classes') (Join-Path $c.Output $label) -SourceProfile ReviewedHttpsCoreWrapper;@{tests=$tests;counters=$counters;semantics=$semantics;fork=$label;session=$label;artifact=$artifact}}.GetNewClosure()
  Compare={param($c)$true}
  BaselineInventory={param($r,$cache)@{status='FULL_TRUSTED_STOCK_MAVEN3911_ADMITTED';archiveFiles=96;physicalFiles=96;directories=13;inventorySha256='63382624DFFEF090C2B47C476767D9BE9F0620296193B650AE419ABE34FC4D0F';coreSha256='93D3C0523DDA6C86C6620D9E692E7DF39D0E2E4E4CD860061A8C0D274C2AD185'}}
  Stop={param($c,$tokens)$state.stops++;$state.alive=$false;0}.GetNewClosure()
  Absence={param($c)-not$state.alive}.GetNewClosure()
  ScreenOwner={param($c)$screenOwner}.GetNewClosure()
  Sampling=$sampling
 }
 $failure=$null
 try{$r=& ($m.ExportedCommands['Invoke-H3911WindowsQualifier']) -Project $project -Jdk $jdk -Owned $owned -CoreExe ([Environment]::ProcessPath) -WatchRoot $RepositorySource -IndependentWitnessRoot $evidence -FixtureOnly -FixtureHooks $hooks -Mode PackageScreen}catch{$failure=$_.ToString()}
 $disk=Get-Content (Join-Path $owned 'qualifier.json') -Raw|ConvertFrom-Json -AsHashtable
 if($state.alive-or$state.stops-ne1){throw 'Caller normal/failure cleanup omitted'}
 if($case-eq'full24'){if($failure-or$disk.calls.Count-ne24-or$disk.packageScreen.samples.Count-ne6-or$disk.packageScreen.offlineCaptures.Count-ne8-or$disk.stopProof.exit-ne0){throw "Full24 caller failed: $failure"}}
 elseif(-not$failure-or$disk.status-cne'FAIL'-or$disk.calls.Count-gt25){throw 'Sampling failure did not fail whole caller'}
 $proof+=@{case=$case;calls=$disk.calls.Count;cleanupCalls=$state.stops;passed=$true;fixtureOnly=$true;noNativeTiming=$true}
}
$proof|ConvertTo-Json -Depth 6|Set-Content (Join-Path $OutputDirectory 'proof.json')
Write-Output 'ENTIRE_WINDOWS_CALLER_FULL24_AND_SAMPLING_FAILURE_CLEANUP_MODEL_PASS'
