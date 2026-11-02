#requires -Version 7.5
[CmdletBinding()]
param([string]$Project,[string]$JavaHome,[string]$Output,[switch]$ExecuteAuthorized,[switch]$LibraryOnly)
$ErrorActionPreference='Stop'
$probeRequest=@{Project=$Project;JavaHome=$JavaHome;Output=$Output;ExecuteAuthorized=[bool]$ExecuteAuthorized;LibraryOnly=[bool]$LibraryOnly}
. "$PSScriptRoot\..\hobl-wrapper-diagnostic\Invoke-WrapperBoundary.ps1" -LibraryOnly
foreach($p in $probeRequest.GetEnumerator()){Set-Variable -Name $p.Key -Value $p.Value}
function NewBootstrapVariant([byte[]]$Original,[string]$Directory){
    $Directory=[IO.Path]::GetFullPath($Directory)
    Require ($Directory-notmatch'[%!&|<>^"\r\n]') 'Unsafe batch destination'
    $batch=Join-Path $Directory 'batch-markers.raw';$data=Join-Path $Directory 'child-stage-data.json';$end=Join-Path $Directory 'child-diagnostic-end.raw'
    $literalData="'"+$data.Replace("'","''")+"'";$literalEnd="'"+$end.Replace("'","''")+"'"
    $text=[Text.Encoding]::UTF8.GetString((AddBoundaryMarkers $Original $batch))
    $nl=if($text.Contains("`r`n")){"`r`n"}else{"`n"}
    $inlineAnchor='& {$scriptDir='
    $bodyAnchor='$ErrorActionPreference = "Stop"'
    $cacheAnchor='if (Test-Path -Path "$MAVEN_HOME" -PathType Container) {'
    foreach($anchor in @($inlineAnchor,$bodyAnchor,$cacheAnchor)){Require (([regex]::Matches($text,[regex]::Escape($anchor))).Count-eq1) 'Ambiguous stock stage anchor'}
    $entry='$__hobl_entry_utc=[DateTimeOffset]::UtcNow; $__hobl_entry_ticks=[Diagnostics.Stopwatch]::GetTimestamp(); '
    $body='$__hobl_body_utc=[DateTimeOffset]::UtcNow; $__hobl_body_ticks=[Diagnostics.Stopwatch]::GetTimestamp();'+$nl
    $cached=@'
  $__hobl_cached_utc=[DateTimeOffset]::UtcNow; $__hobl_cached_ticks=[Diagnostics.Stopwatch]::GetTimestamp()
  $__hobl_diag_start_utc=[DateTimeOffset]::UtcNow; $__hobl_diag_start_ticks=[Diagnostics.Stopwatch]::GetTimestamp()
  $__hobl_identity=[ordered]@{status='ERROR';pid=$PID;psHome=$PSHOME;psVersionTable=$PSVersionTable;ownExecutable=$null;ownPeMachine=$null}
  try {
    $__hobl_self=[Diagnostics.Process]::GetCurrentProcess()
    try { $__hobl_exe=$__hobl_self.MainModule.FileName } finally { $__hobl_self.Dispose() }
    $__hobl_exe_bytes=[IO.File]::ReadAllBytes($__hobl_exe)
    $__hobl_pe=[BitConverter]::ToInt32($__hobl_exe_bytes,60)
    if([BitConverter]::ToUInt16($__hobl_exe_bytes,0)-ne0x5A4D -or [BitConverter]::ToUInt32($__hobl_exe_bytes,$__hobl_pe)-ne0x4550){throw 'Invalid own PE image'}
    $__hobl_identity.ownExecutable=$__hobl_exe
    $__hobl_identity.ownPeMachine='0x{0:X4}' -f [BitConverter]::ToUInt16($__hobl_exe_bytes,$__hobl_pe+4)
    $__hobl_identity['is64BitProcess']=[Environment]::Is64BitProcess
    $__hobl_identity.status='OK'
  } catch { $__hobl_identity['errorType']=$_.Exception.GetType().FullName; $__hobl_identity['error']=$_.Exception.Message }
  $__hobl_data=[ordered]@{
    variant='source stage markers; version-only diagnostic, not baseline/performance'
    identity=$__hobl_identity;stopwatchFrequency=[Diagnostics.Stopwatch]::Frequency;cachedHome=$MAVEN_HOME
    entryUtc=$__hobl_entry_utc.ToString('o');entryTicks=$__hobl_entry_ticks
    bodyUtc=$__hobl_body_utc.ToString('o');bodyTicks=$__hobl_body_ticks
    cachedUtc=$__hobl_cached_utc.ToString('o');cachedTicks=$__hobl_cached_ticks
    diagnosticStartUtc=$__hobl_diag_start_utc.ToString('o');diagnosticStartTicks=$__hobl_diag_start_ticks
  }
  $__hobl_json=$__hobl_data | ConvertTo-Json -Depth 8
  [IO.File]::WriteAllText(__DATA__,$__hobl_json,[Text.UTF8Encoding]::new($false))
  $__hobl_diag_end_utc=[DateTimeOffset]::UtcNow; $__hobl_diag_end_ticks=[Diagnostics.Stopwatch]::GetTimestamp()
  [IO.File]::WriteAllText(__END__,($__hobl_diag_end_utc.ToString('o')+'|'+$__hobl_diag_end_ticks),[Text.UTF8Encoding]::new($false))
'@
    $cached=$cached.Replace("`r`n","`n").Replace("`n",$nl).Replace('__DATA__',$literalData).Replace('__END__',$literalEnd)+$nl
    $text=$text.Replace($inlineAnchor,'& {'+$entry+'$scriptDir=').Replace($bodyAnchor,$body+$bodyAnchor).Replace($cacheAnchor+$nl,$cacheAnchor+$nl+$cached)
    $reconstructed=$text.Replace('& {'+$entry+'$scriptDir=',$inlineAnchor).Replace($body+$bodyAnchor,$bodyAnchor).Replace($cacheAnchor+$nl+$cached,$cacheAnchor+$nl)
    $reconstructed=(@($reconstructed-split"(?<=`n)"|Where-Object{-not$_.StartsWith('@echo HOBL_BOUNDARY_')})-join'')
    Require ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($reconstructed))-ceq[Convert]::ToBase64String($Original)) 'Non-marker source change'
    return @{bytes=[Text.Encoding]::UTF8.GetBytes($text);entry=$entry;body=$body;cached=$cached;batchFile=$batch;dataFile=$data;endFile=$end;originalReconstructed=$true}
}
function AssertProbeVersion([string]$Log,[string]$ExpectedHome){
    Require ($Log-match'(?m)^Apache Maven 3\.9\.11\b'-and$Log-match'(?m)^Java version: 25\.0\.5\.0\.2, vendor: Microsoft, runtime:'-and$Log-match'(?m)^OS name:.*arch: "aarch64"') 'Actual version/vendor/architecture mismatch'
    if($ExpectedHome){Require ($Log-match('(?m)^Java version: 25\.0\.5\.0\.2, vendor: Microsoft, runtime: '+[regex]::Escape($ExpectedHome)+'\r?$')) 'Actual Java home mismatch'}
}
function BootstrapWindows([string]$Json,[string]$ChildJson,[string]$EndRaw){
    $r=$Json|ConvertFrom-Json -DateKind String;$child=$ChildJson|ConvertFrom-Json -DateKind String
    $v=@{status='UNKNOWN';raw=$r;child=$child;diagnosticEndRaw=$EndRaw}
    try{
        $culture=[Globalization.CultureInfo]::InvariantCulture;$b=[DateTimeOffset]::Parse($r.before,$culture);$e=[DateTimeOffset]::Parse($r.after,$culture)
        Require ($b.Date-eq$e.Date-and$b.Offset-eq$e.Offset-and[Math]::Abs(($e-$b).TotalSeconds-$r.seconds)-lt0.25) 'Clock/rollover inconsistency'
        Require ($r.markers.Count-eq2-and$r.markers[0]-like'HOBL_BOUNDARY_BEFORE_FOR|*'-and$r.markers[1]-like'HOBL_BOUNDARY_AFTER_FOR|*') 'Missing/invalid batch marks'
        $batch=@(foreach($row in $r.markers){$p=$row-split'\|';Require ($p.Count-eq3-and$p[1]-ceq$b.ToString('ddd MM/dd/yyyy',$culture)) 'Ambiguous local date';$m=[regex]::Match($p[2],'^\s*(\d{1,2}):(\d{2}):(\d{2})[.,](\d{2})$');Require $m.Success 'Ambiguous time';$h=[int]$m.Groups[1].Value;$n=[int]$m.Groups[2].Value;$s=[int]$m.Groups[3].Value;Require ($h-lt24-and$n-lt60-and$s-lt60) 'Invalid time';[DateTimeOffset]::new($b.Date.AddMilliseconds(1000*($h*3600+$n*60+$s)+10*[int]$m.Groups[4].Value),$b.Offset)})
        $entry=[DateTimeOffset]::Parse($child.entryUtc,$culture);$body=[DateTimeOffset]::Parse($child.bodyUtc,$culture);$cached=[DateTimeOffset]::Parse($child.cachedUtc,$culture);$diag=[DateTimeOffset]::Parse($child.diagnosticStartUtc,$culture)
        $endParts=$EndRaw.Trim()-split'\|';Require ($endParts.Count-eq2) 'Missing diagnostic end';$diagEnd=[DateTimeOffset]::Parse($endParts[0],$culture);$endTicks=[long]$endParts[1]
        Require ($batch[1]-ge$batch[0]-and$batch[0]-ge$b.AddMilliseconds(-20)-and$entry-ge$batch[0].AddMilliseconds(-20)-and$body-ge$entry-and$cached-ge$body-and$diag-ge$cached-and$diagEnd-ge$diag-and$batch[1]-ge$diagEnd.AddMilliseconds(-20)-and$batch[1]-le$e.AddMilliseconds(20)) 'UTC stages reversed/outside brackets'
        foreach($key in 'entryTicks','bodyTicks','cachedTicks','diagnosticStartTicks'){Require ($null-ne$child.$key-and[string]$child.$key-match'^[0-9]+$') 'Missing same-child ticks'}
        $freq=[double]$child.stopwatchFrequency;Require ($freq-gt0-and$child.bodyTicks-ge$child.entryTicks-and$child.cachedTicks-ge$child.bodyTicks-and$child.diagnosticStartTicks-ge$child.cachedTicks-and$endTicks-ge$child.diagnosticStartTicks) 'Missing/reversed same-child ticks'
        $v.beforeFirstExpressionApproxSeconds=($entry-$batch[0]).TotalSeconds;$v.sourceLoadEnvelopeSeconds=($child.bodyTicks-$child.entryTicks)/$freq;$v.cachedWorkSeconds=($child.cachedTicks-$child.bodyTicks)/$freq
        $v.addedMetadataSeconds=($endTicks-$child.diagnosticStartTicks)/$freq;$v.forDisplaySeconds=($batch[1]-$batch[0]).TotalSeconds
        $v.status=if($child.identity.status-eq'OK'-and$child.identity.pid-gt0-and$child.identity.psHome-and$child.identity.psVersionTable.PSVersion-and$child.identity.ownExecutable-and$child.identity.ownPeMachine-match'^0x[0-9A-Fa-f]{4}$'-and$child.identity.ownPeMachine-ne'0x0000'){'PARSED_DIAGNOSTIC_ONLY'}else{'UNKNOWN_METADATA'}
    }catch{$v.reason=$_.Exception.Message};return $v
}
if($LibraryOnly){return}
Require ($ExecuteAuthorized-and$IsWindows) 'Explicit owner authorization and Windows required'
foreach($p in @($Project,$JavaHome,$Output)){Require (-not[string]::IsNullOrWhiteSpace($p)) 'Explicit owned paths required'}
$Project=[IO.Path]::GetFullPath($Project);$JavaHome=[IO.Path]::GetFullPath($JavaHome);$Output=[IO.Path]::GetFullPath($Output)
AssertBoundaryPaths $Project $Output $Output $JavaHome;Require (-not(Test-Path $Output)) 'Fresh output required'
New-Item $Output -ItemType Directory|Out-Null
$names=@('JAVA_HOME','PATH','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME')
$before=GetBoundaryEnvironmentSnapshot;$cwd=(Get-Location).Path;$original=$null;$variant=$null;$pushed=$false
$record=@{status='STARTED';variant='VERSION ONLY source probe; no HOBL score/app artifacts';phases=@();failures=@();host=@{pwsh=$PSVersionTable.PSVersion.ToString();processArchitecture=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString();os=[Runtime.InteropServices.RuntimeInformation]::OSDescription;cpu=[Environment]::ProcessorCount;imageOS=$env:ImageOS;imageVersion=$env:ImageVersion}}
function ProbeSource([bool]$Dirty){
    Require ((BoundaryGit -Arguments @('-C',$Project,'rev-parse','HEAD'))-eq'6feeae0f13e0e258eedc99832416b42bb13779b1') 'Wrong source pin'
    $s=BoundaryGit -Arguments @('-C',$Project,'status','--porcelain','--untracked-files=all');Require ($(if($Dirty){$s-ceq' M mvnw.cmd'}else{[string]::IsNullOrEmpty($s)})) 'Unexpected source changes'
    Require ((Get-FileHash "$Project\pom.xml").Hash-eq'A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D') 'POM drift'
}
function ProbeCall([string]$Name){
    $arguments=@('--version');$log="$Output\$Name.log";$start=[DateTimeOffset]::Now
    $duration=Measure-Command {& $wrapper @arguments *> $log;$script:code=$LASTEXITCODE}
    $finish=[DateTimeOffset]::Now;$v=@{name=$Name;arguments=$arguments;nativeExit=$script:code;before=$start.ToString('o');after=$finish.ToString('o');beforeUtc=$start.ToUniversalTime().ToString('o');afterUtc=$finish.ToUniversalTime().ToString('o');seconds=$duration.TotalSeconds}
    $record.phases+=$v;$record|ConvertTo-Json -Depth 15|Set-Content "$Output\receipt.json";Require ($script:code-eq0) 'Version call failed; no retry';AssertProbeVersion (Get-Content $log -Raw) $JavaHome;return $v
}
try{
    Require (-not@(Get-Process -Name java,javaw -ErrorAction SilentlyContinue).Count) 'Competing JVM present'
    ProbeSource $false;Require ((Test-Path "$Project\.git" -PathType Container)-and-not(Test-Path "$Project\.git\objects\info\alternates")) 'Full unborrowed clone required'
    Require ((BoundaryGit -Arguments @('-C',$Project,'remote','get-url','origin'))-eq'https://github.com/spring-projects/spring-petclinic.git') 'Canonical origin required'
    foreach($n in 'MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME','MVNW_REPOURL','MVNW_USERNAME','MVNW_PASSWORD','GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR','__MVNW_ARG0_NAME__'){Require (-not[Environment]::GetEnvironmentVariable($n)) "Review nonempty key $n"}
    foreach($n in '.m2\settings.xml','.mavenrc','.mavenrc_pre.cmd','.mavenrc_pre.bat','mavenrc_pre.cmd','mavenrc_pre.bat','mavenrc_post.cmd','mavenrc_post.bat'){Require (-not(Test-Path (Join-Path $HOME $n))) 'Unreviewed user config/rc'}
    foreach($n in 'DATE','TIME'){Require (-not(Test-Path ('Env:'+$n))) 'Shadowed clock variable'}
    $java="$JavaHome\bin\java.exe";$bytes=[IO.File]::ReadAllBytes($java)
    Require ((Get-FileHash $java).Hash-eq'094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0'-and[BitConverter]::ToUInt16($bytes,([BitConverter]::ToInt32($bytes,60)+4))-eq0xAA64) 'Pinned native Microsoft25 JDK required'
    $wrapper="$Project\mvnw.cmd";Require ((Get-FileHash $wrapper).Hash-eq'5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A') 'Original wrapper drift'
    $original=[IO.File]::ReadAllBytes($wrapper);[IO.File]::WriteAllBytes("$Output\original-mvnw.cmd",$original)
    $env:JAVA_HOME=$JavaHome;$env:PATH="$JavaHome\bin"+[IO.Path]::PathSeparator+$env:PATH;Push-Location $Project;$pushed=$true
    $null=ProbeCall 'warm-original';ProbeSource $false
    $homes=[regex]::Matches((Get-Content "$Output\warm-original.log" -Raw),'(?m)^Maven home:\s+([^\r\n]+)\r?$')
    Require ($homes.Count-eq1-and(Test-Path (Join-Path $homes[0].Groups[1].Value.Trim() 'bin\mvn.cmd'))) 'Warm distribution not present'
    $variant=NewBootstrapVariant $original $Output
    [IO.File]::WriteAllBytes($wrapper,$variant.bytes);[IO.File]::WriteAllBytes("$Output\instrumented-mvnw.cmd",$variant.bytes);ProbeSource $true
    git -C $Project diff -- mvnw.cmd > "$Output\source.patch";$gitExit=$LASTEXITCODE;Require ($gitExit-eq0) 'Patch retention failed'
    $case=ProbeCall 'cached-instrumented';$case.markers=@(Get-Content $variant.batchFile)
    $childJson=Get-Content $variant.dataFile -Raw;$endRaw=Get-Content $variant.endFile -Raw
    $child=$childJson|ConvertFrom-Json -DateKind String
    Require ([IO.Path]::GetFullPath($child.cachedHome).TrimEnd('\')-eq[IO.Path]::GetFullPath($homes[0].Groups[1].Value.Trim()).TrimEnd('\')) 'Marked wrapper used different cached home'
    $record.analysis=BootstrapWindows (ConvertTo-Json $case -Depth 6) $childJson $endRaw
    $record.instrumentedSha=(HashBytes $variant.bytes);$record.status='CAPTURED_VERSION_DIAGNOSTIC_ONLY'
    Require ($record.analysis.status-ne'UNKNOWN_METADATA') 'Self metadata error retained; no fabricated identity'
}catch{$record.status='FAIL_STOPPED_NO_RETRY';$record.failures+=@{phase='main';error=$_.ToString()}}
finally{
    try{if($variant){Require ((HashBytes ([IO.File]::ReadAllBytes($wrapper)))-eq(HashBytes $variant.bytes)) 'Unexpected wrapper changes; refuse overwrite';[IO.File]::WriteAllBytes($wrapper,$original);Require ((Get-FileHash $wrapper).Hash-eq'5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A') 'Original wrapper restore mismatch';ProbeSource $false;$record.sourceRestored=$true}}catch{$record.failures+=@{phase='source-restoration';error=$_.ToString()}}
    try{if($pushed){Pop-Location}}catch{$record.failures+=@{phase='cwd';error=$_.ToString()}}
    $restore=RestoreBoundaryEnvironment $before $names;$restore.cwdEqual=(Get-Location).Path-eq$cwd;$restore|ConvertTo-Json -Depth 10|Set-Content "$Output\restoration.json"
    if(-not$restore.restored-or-not$restore.cwdEqual){$record.failures+=@{phase='environment';error='Restoration mismatch'}}
    $record.remainingJavaCandidates=@(Get-Process -Name java,javaw -ErrorAction SilentlyContinue).Count
    if($record.remainingJavaCandidates){$record.failures+=@{phase='cleanup';error='Java remains without proven owned identity; none killed'}}
    if($record.failures.Count){$record.status='FAIL_STOPPED_NO_RETRY'};$record|ConvertTo-Json -Depth 20|Set-Content "$Output\receipt.json"
}
Require ($record.status-eq'CAPTURED_VERSION_DIAGNOSTIC_ONLY') 'Probe failed; no retry'
