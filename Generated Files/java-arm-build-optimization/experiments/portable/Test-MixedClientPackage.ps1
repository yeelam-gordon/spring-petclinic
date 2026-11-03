param([Parameter(Mandatory)][string]$FixtureRoot)
$ErrorActionPreference='Stop'
$e=$FixtureRoot;New-Item $e -ItemType Directory -Force|Out-Null
Copy-Item "$PSScriptRoot\Fixture-MixedProcess.ps1" "$e\Fixture-Child.ps1"
$source=Join-Path $PSScriptRoot 'Invoke-MatchedComparison.ps1'
. $source -LibraryOnly
$fixtureEnvironmentBefore=PortableEnvironmentSnapshot
$tokens=$null;$errors=$null;$tree=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors){throw 'Collector parse failed'}
$definitions=@(foreach($name in 'Run','SourceGate','Save'){$tree.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true).Extent.Text})
$all=@()
foreach($os in 'Windows','MacOS'){
 foreach($case in 'positive','admission-fail','process-fail','source-fail','wrong-context','empty-context','stale-context','stop-fail','ownership-reject'){
  $module=New-Module -ArgumentList $source,$definitions,$e,$os,$case -ScriptBlock {
   param($source,$definitions,$e,$os,$case)
   . $source -LibraryOnly
   foreach($definition in $definitions){. ([scriptblock]::Create($definition))}
   $Comparison='MixedClientPackage';$Workload='current17';$Samples=3;$LoopbackTests=$true
   $fixture=Join-Path $e ("fixture-$os-$case-"+[guid]::NewGuid().ToString('N'));$OutputDirectory=Join-Path $fixture 'output space'
   $ProjectFullClone=Join-Path $fixture 'project space';$JavaHome=Join-Path $fixture 'jdk space';$MvndHome=Join-Path $fixture 'home space'
   $LocalCache=Join-Path $fixture 'cache space';$registry=Join-Path $fixture 'private registry';$tmp=Join-Path $fixture 'tmp space';$settings=Join-Path $fixture 'settings space.xml'
   New-Item $OutputDirectory,$ProjectFullClone,$registry,$tmp,(Join-Path $MvndHome 'mvn/lib') -ItemType Directory -Force|Out-Null
   [IO.File]::WriteAllBytes((Join-Path $MvndHome 'mvn/lib/maven-core-3.9.16.jar'),[byte[]]@(1))
   $java=Join-Path $JavaHome 'bin/java.exe';$jcmd=Join-Path $JavaHome 'bin/jcmd.exe'
   $plan=ComparisonPlan $os current17 $MvndHome;MixedClientPlan $plan current17 3
   $result=@{status='RUNNING';phases=@();snapshots=@();cleanup=@()};$verify=0
   function git {if($args-contains'HEAD'){ '500158f732419217507c7656904b8e6aa1bcc0d6' }elseif($case-eq'source-fail'-and(Test-Path "$fixture\alive")){' M source.java'};$global:LASTEXITCODE=0}
   function Get-FileHash($Path){if($Path-like'*maven-core-3.9.16.jar'){@{Hash='5D45C72E3DBFAB8B68D15AD4F12777B7D9B5FE4D4ADC99C3BD51FB9641FAB009'}}else{Microsoft.PowerShell.Utility\Get-FileHash $Path}}
   function MixedBinaryIdentity($Path){@{machine=0x8664;sha256='386B03C8DF458D8573B9241259EEBFABA894B32DDF8D0767C8CAE6168F81FAD4'}}
   function ReadDaemonIdentity($Id){if(-not(Test-Path "$fixture\alive")){return $null};@{pid=12345;started='synthetic';executable=$(if($case-eq'ownership-reject'){'unowned'}else{Join-Path $JavaHome $(if($os-eq'Windows'){'bin/java.exe'}else{'bin/java'})});command="$registry -Dmvnd.id=abcdef12"}}
   function Get-Process($Id,$ErrorAction){Require ($Id-eq12345) 'Unexpected fixture PID';if(Test-Path "$fixture\alive"){$p=[pscustomobject]@{};$p|Add-Member ScriptMethod WaitForExit {param($milliseconds)return $false};return $p}}
   function Stop-Process($Id,$ErrorAction){Require ($Id-eq12345) 'Unexpected fixture termination';Remove-Item "$fixture\alive" -ErrorAction SilentlyContinue;$result.syntheticForcedCleanup=$true}
   function MixedOwnedProcesses {if(Test-Path "$fixture\alive"){ReadDaemonIdentity 12345}}
   function ObserveMixedRuntime {$null=AssertMixedDaemon;$result.syntheticRuntimeObserved=$true}
   function Snapshot($Name,$WithTests,[switch]$CompleteArtifact){Require $CompleteArtifact 'Missing full artifact gate';$result.snapshots+=,@{name=$Name;synthetic=$true}}
   function CompareCompleteArtifacts($Left,$Right){@{status='PASS';synthetic=$true}}
   function JacocoReportEvidence($Xml){@{synthetic=$true}}
   function Get-Content($Path,[switch]$Raw){if($Path-like'*jacoco.xml'){Microsoft.PowerShell.Management\Get-Content "$ProjectFullClone\site\coverage.xml" -Raw}else{Microsoft.PowerShell.Management\Get-Content $Path -Raw:$Raw}}
   function InvokePortableProcess($Executable,$Arguments,$Log){
    if($Executable-eq$java){
     $runtime=if($case-eq'admission-fail'){'wrong'}else{'17.0.21.0.2+1-LTS'}
     [IO.File]::WriteAllText($Log,"java.home = $JavaHome`njava.version = 17.0.21.0.2`njava.runtime.version = $runtime`njava.vendor = Microsoft`nos.arch = aarch64");return 0
    }
    if($Executable-eq'file'){[IO.File]::WriteAllText($Log,'Mach-O 64-bit executable arm64');return 0}
    if($Arguments-contains'verify'){$script:verify++;$env:MIXED_VERIFY=[string]$script:verify}
    $env:MIXED_CASE=$case;$env:MIXED_FIXTURE=$fixture;$env:MIXED_PROJECT=$ProjectFullClone;$env:MIXED_REGISTRY=$registry;$env:MIXED_TOKENS=ConvertTo-Json -InputObject @($Arguments) -Compress
    $info=[Diagnostics.ProcessStartInfo]::new([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
    $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    foreach($token in @('-NoProfile','-File',"$e\Fixture-Child.ps1")){$info.ArgumentList.Add($token)}
    $child=[Diagnostics.Process]::Start($info)
    $stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
    $child.WaitForExit();[IO.File]::WriteAllText($Log,$stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult())
    return $child.ExitCode
   }
   if($case-eq'stale-context'){[IO.File]::WriteAllText((Join-Path $OutputDirectory 'baseline-os.arch.value'),'stale')}
   $env:JAVA_HOME='SYNTHETIC_PRIOR_VALUE';[Environment]::SetEnvironmentVariable('MVND_OPTS','','Process')
   $before=PortableEnvironmentSnapshot;$cwd=(Get-Location).Path
   InvokeMixedClientPackage
   Require ($result.restoration.restored-and$result.restoration.keys.Count-eq18-and$result.restoration.cwdEqual-and(Get-Location).Path-eq$cwd) '18-state/cwd failure'
   if($case-eq'positive'){
    Require ($result.status-eq'PASS'-and$result.phases.Count-eq19-and$result.snapshots.Count-eq8-and$result.prep.Count-eq2) "Positive flow failed: $($result.failure) $($result.cleanupFailure)"
    Same @($result.phases|Where-Object timed|ForEach-Object clientMode) $(if($os-eq'Windows'){@('jvm','native','native','jvm','jvm','native')}else{@('native','native','native','native','native','native')}) 'Mixed arm routing'
    Require (-not(Test-Path "$fixture\alive")) 'Normal stop left owner'
    $rows=@(Microsoft.PowerShell.Management\Get-Content "$fixture\argv.jsonl"|ForEach-Object{$_|ConvertFrom-Json})
    Require ($rows.Count-eq19) 'Child argv recorder count'
    for($i=0;$i-lt19;$i++){Same @($rows[$i].arguments) @($result.phases[$i].arguments) 'Child argv differs';Require (@($rows[$i].arguments|Where-Object{$_-ceq"-Djava.home=$JavaHome"}).Count-eq1-and$settings-cin$rows[$i].arguments) 'Atomic Java/settings argument lost'}
    foreach($phase in $result.phases|Where-Object timed){Same @($phase.arguments[-2..-1]) @('package','-DskipTests') 'Timed test/reset/report entered package window'}
   }else{Require ($result.status-eq'FAIL') 'Failure became success'}
   if($case-eq'source-fail'){Require ($result.emergencyCleanup-and-not(Test-Path "$fixture\alive")) 'Source failure blocked owned cleanup'}
   if($case-eq'ownership-reject'){Require (-not@($result.phases|Where-Object{$_.name-like'*stop*'}).Count) 'Unowned process targeted'}
   if($case-eq'admission-fail'){Require (-not$result.phases.Count-and-not(Test-Path "$fixture\alive")) 'Admission failure dispatched workload'}
   $intended=switch($case){
    'admission-fail'{@('Mixed native17 identity differs',0,$false)}
    'process-fail'{@('baseline-prep returned native exit 1',4,$true)}
    'source-fail'{@('Measured source is dirty',2,$true)}
    'wrong-context'{@('Wrong Maven os.arch',2,$true)}
    'empty-context'{@('Empty Maven context output',2,$true)}
    'stale-context'{@('Stale Maven context output',0,$false)}
    'stop-fail'{@('mixed-native-stop returned native exit 1',20,$true)}
    'ownership-reject'{@('Private process ownership rejected',1,$true)}
   }
   if($case-ne'positive'){Require ($result.failure-ceq$intended[0]-and$result.phases.Count-eq$intended[1]-and(Test-Path "$fixture\owner-created")-eq$intended[2]) "Wrong intended branch: $case / $($result.failure) / $($result.phases.Count)"}
   $script:fixtureResult=@{os=$os;case=$case;result=$result;fixture=$fixture;syntheticMacProcessFileAndArtifactBoundaries=$true}
  }
  $all+=,(& $module {$fixtureResult})
  Remove-Module $module
 }
}
$all|ConvertTo-Json -Depth 40|Set-Content "$e\mode-fixtures.json"
. $source -LibraryOnly
if($IsWindows){
    $pwsh=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $recorder=Join-Path $e 'direct argv recorder.cmd'
    $batch="@echo off`r`nsetlocal DisableDelayedExpansion`r`nset DIRECT_TOKEN_COUNT=0`r`n:next`r`nif `"%~1`"==`"`" goto done`r`nset /a DIRECT_TOKEN_COUNT+=1 >nul`r`nset `"DIRECT_TOKEN_%DIRECT_TOKEN_COUNT%=%~1`"`r`nshift`r`ngoto next`r`n:done`r`n@`"$pwsh`" -NoProfile -File `"$e\Fixture-Child.ps1`"`r`n@exit /b %errorlevel%`r`n"
    [IO.File]::WriteAllText($recorder,$batch)
    [string[]]$expected=@('-V','--settings',"$e\settings with spaces.xml","-Djava.home=$e\native JDK","-Dmvnd.daemonStorage=$e\private registry",'clean','verify')
    $directBefore=PortableEnvironmentSnapshot;$directProof=@()
    try{
        foreach($code in 0,1){
            $env:MIXED_DIRECT_RECORD=Join-Path $e "direct-argv-$code.json";$env:MIXED_DIRECT_EXIT=[string]$code
            $actual=InvokePortableProcess $recorder $expected (Join-Path $e "direct-argv-$code.log")
            Require ($actual-eq$code) 'Actual production helper changed genuine child exit'
            Same @(Get-Content $env:MIXED_DIRECT_RECORD -Raw|ConvertFrom-Json) @($expected) 'Actual native helper argv differs'
            $directProof+=,@{expected=$code;actual=$actual;arguments=$expected}
        }
        $directProof|ConvertTo-Json -Depth 6|Set-Content (Join-Path $e 'actual-production-helper-proof.json')
    }finally{$null=RestorePortableEnvironment $directBefore @('MIXED_DIRECT_RECORD','MIXED_DIRECT_EXIT')}
}
$fixtureRestore=RestorePortableEnvironment $fixtureEnvironmentBefore @('JAVA_HOME','MVND_OPTS')
Require $fixtureRestore.restored 'Fixture environment seed leaked'
foreach($bad in @(@('normalizedHobl25',3),@('current17',1))){$blocked=$false;try{MixedClientPlan (ComparisonPlan Windows $bad[0] fixture) $bad[0] $bad[1]}catch{$blocked=$true};Require $blocked 'Invalid mode plan accepted'}
$blocked=$false;try{MixedClientPlan (ComparisonPlan Linux current17 fixture) current17 3}catch{$blocked=$true};Require $blocked 'Invalid platform admitted'
$caseKeys=[Collections.Hashtable]::new([StringComparer]::Ordinal);$caseKeys.Add('PATH','a');$caseKeys.Add('Path','b')
$blocked=$false;try{$null=PortableEnvironmentSnapshot $caseKeys $true}catch{$blocked=$true};Require $blocked 'Windows ambiguous environment accepted'
Require ((PortableEnvironmentSnapshot $caseKeys $false).Count-eq2) 'Mac ordinal environment conflated'
$run=$tree.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Run'},$true).Extent.Text
Require ($run.IndexOf('$watch.Stop()')-lt$run.IndexOf('$result.phases+=')-and$run.IndexOf('$result.phases+=')-lt$run.IndexOf('Save;NativeCode')) 'Clock/report boundary changed'
Write-Output 'BOTH_OS_ACTUAL_ADMISSION_AND_MODE_ORCHESTRATION_FIXTURES_PASS'
