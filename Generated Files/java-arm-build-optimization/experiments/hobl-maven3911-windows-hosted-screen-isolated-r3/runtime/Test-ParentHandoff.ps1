param([string]$OutputDirectory)
$ErrorActionPreference='Stop'
New-Item $OutputDirectory -ItemType Directory -ErrorAction Stop|Out-Null
$m=Import-Module (Join-Path $PSScriptRoot 'H3911.ScreenParent.psm1') -PassThru -Force
$proof=@()
foreach($case in 'Normal0','Normal1','ChildFirst','Timeout','PostAllocationFailure','ChildNonzero'){
 $root=Join-Path $OutputDirectory $case;New-Item $root -ItemType Directory|Out-Null
 $scope=@{Jdk='C:\synthetic jdk';Home='C:\synthetic home';Registry='C:\synthetic registry';Temp='C:\synthetic temp'}
 $native=[DateTime]::UtcNow.AddSeconds(-1);[long]$ticks=$native.Ticks-($native.Ticks%[long]10)
 $w=@{status='owned';pid=1;id='deadbeef';created=$native.ToString('o');nativeCreatedTicks=$native.Ticks.ToString();cimCreated=([DateTime]::new($ticks,[DateTimeKind]::Utc)).ToString('o');cimCreatedTicks=$ticks.ToString();observedUtc=[DateTime]::UtcNow.ToString('o');executable='C:\synthetic jdk\bin\java.exe';home=$scope.Home;registry=$scope.Registry;temp=$scope.Temp;jniPath='C:\synthetic temp\native.dll';jniSha256='728F9A0F7A8A74D15C6DE37DBE32A73CF8013605D2E881098692E1C88A0F4C2D';javaSha256='094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0';jniMachine=0xAA64}
 $start=[DateTime]::UtcNow.AddSeconds(-1).ToString('o')
 $w|ConvertTo-Json|Set-Content (Join-Path $root 'independent-owned-daemon.json')
 Import-Module (Join-Path $PSScriptRoot 'ObserverTelemetry.psm1') -Force
 $t=New-QualifierObserverTelemetry;Add-QualifierObserverTelemetry $t @{reasonCode='OBSERVED';status='owned';unknown=@()};$t|ConvertTo-Json -Depth 10|Set-Content (Join-Path $root 'observer-telemetry.json')
 $childScript=Join-Path $root 'harmless-child.ps1';$obsScript=Join-Path $root 'harmless-observer.ps1'
 $childCode=if($case-eq'ChildFirst'){'exit 0'}elseif($case-eq'ChildNonzero'){'Start-Sleep -Seconds 3;exit 1'}else{'Start-Sleep -Seconds 3;exit 0'}
 $obsCode=if($case-in@('ChildFirst','Timeout')){'Start-Sleep -Seconds 10;exit 0'}elseif($case-eq'Normal1'){'exit 1'}else{'exit 0'}
 [IO.File]::WriteAllText($childScript,$childCode);[IO.File]::WriteAllText($obsScript,$obsCode)
 $child=$null;$observer=$null;$binding=$null;$errorText=$null;$clock=[Diagnostics.Stopwatch]::StartNew()
 try{
  $ci=[Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath);$ci.UseShellExecute=$false;foreach($a in '-NoProfile','-NonInteractive','-File',$childScript){$ci.ArgumentList.Add($a)};$child=[Diagnostics.Process]::Start($ci)
  $oi=[Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath);$oi.UseShellExecute=$false;foreach($a in '-NoProfile','-NonInteractive','-File',$obsScript){$oi.ArgumentList.Add($a)};$observer=[Diagnostics.Process]::Start($oi)
  $allocation=& ($m.ExportedCommands['New-SPAllocation']) $observer $obsScript $PSScriptRoot $root $scope $start -FixtureOnly
  if($case-eq'PostAllocationFailure'){throw 'INJECTED_AFTER_ALLOCATION'}
  $limit=if($case-eq'Timeout'){500}else{10000}
  $binding=& ($m.ExportedCommands['Wait-SPObserverCompletion']) $observer $child $allocation $PSScriptRoot $root $clock $limit
  if($child.HasExited){throw 'Receipt was not early'}
  $read=& ($m.ExportedCommands['Read-SPCompletion']) $binding.path $binding.sha256 $scope $start -FixtureOnly
  $rejected=$false;try{$null=& ($m.ExportedCommands['Read-SPCompletion']) $binding.path ('0'*64) $scope $start -FixtureOnly}catch{$rejected=$true};if(-not$rejected){throw 'Wrong SHA accepted'}
  $null=$child.WaitForExit(10000);if($child.ExitCode-ne0){throw 'Child nonzero after publication'}
 }catch{$errorText=$_.ToString()}
 finally{
  foreach($proc in $child,$observer){if($proc){if(-not$proc.HasExited){$proc.Kill($true)};if(-not$proc.WaitForExit(10000)){throw 'Harmless owned exit unconfirmed'}}}
  if($errorText-and$binding-and(Test-Path $binding.path)){[IO.File]::Move($binding.path,(Join-Path $root 'screen-parent-observer.invalidated.json'))}
 }
 if($case-eq'Normal0'){if($errorText-or-not$binding){throw "Early actual completion failed: $errorText"}}
 elseif(-not$errorText-or(Test-Path (Join-Path $root 'screen-parent-observer.json'))){throw 'Failure left accepted handoff'}
 $proof+=@{case=$case;passed=$true;actualObserverPid=$observer.Id;actualChildPid=$child.Id;observerNotDaemon=$observer.Id-ne1;nativeCensus='NOT_QUERIED';publishedBeforeChildExit=($null-ne$binding);finalAcceptedHandoff=($case-eq'Normal0');fixtureJniOnly=$true}
}
$proof|ConvertTo-Json -Depth 6|Set-Content (Join-Path $OutputDirectory 'proof.json')
Write-Output 'REAL_HARMLESS_PARENT_OBSERVER_EARLY_COMPLETION_AND_FAILURE_CLEANUP_PASS6'
