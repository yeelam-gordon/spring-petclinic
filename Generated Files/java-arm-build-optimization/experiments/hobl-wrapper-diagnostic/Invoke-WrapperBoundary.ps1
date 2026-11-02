#requires -Version 7.5
[CmdletBinding()]
param([string]$Project,[string]$Cache,[string]$JavaHome,[string]$Output,[switch]$ExecuteAuthorized,[switch]$LibraryOnly)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
$requested=@{Project=$Project;Cache=$Cache;JavaHome=$JavaHome;Output=$Output;ExecuteAuthorized=[bool]$ExecuteAuthorized;LibraryOnly=[bool]$LibraryOnly}
. "$PSScriptRoot\..\hobl-contract\Invoke-HoblContract.ps1" -LibraryOnly
foreach($parameter in $requested.GetEnumerator()){Set-Variable -Name $parameter.Key -Value $parameter.Value}
function BoundaryGit([string[]]$Arguments){
    $text=@(& git @Arguments);$nativeExit=$LASTEXITCODE
    Require ($nativeExit-eq0) "Git query failed: exit $nativeExit"
    return ($text-join"`n")
}
function AssertBoundaryPaths([string]$Source,[string]$Evidence,[string]$LocalCache,[string]$Jdk){
    foreach($path in @($Source,$Evidence,$LocalCache,$Jdk)){
        $current=[IO.Path]::GetFullPath($path)
        while($current){
            if(Test-Path -LiteralPath $current){Require (-not((Get-Item -LiteralPath $current -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked input/output ancestry rejected'}
            $parent=[IO.Directory]::GetParent($current);$current=if($parent){$parent.FullName}else{$null}
        }
    }
    $root=[IO.Path]::GetFullPath($Source).TrimEnd('\')
    foreach($path in @($Evidence,$LocalCache,$Jdk)){
        $full=[IO.Path]::GetFullPath($path).TrimEnd('\')
        Require (-not$full.Equals($root,[StringComparison]::OrdinalIgnoreCase)-and-not$full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) 'Cache/evidence/JDK must be outside source'
    }
}
function BoundaryCoverage([xml]$Xml){
    Require ($Xml.DocumentElement.LocalName-eq'report') 'Missing prep report'
    $counters=CoverageKeys $Xml;$classes=@($Xml.SelectNodes('/report/package/class'));$lines=@($Xml.SelectNodes('/report/package/sourcefile/line'))
    Require ($counters.Count-eq726-and$classes.Count-eq25-and$lines.Count-eq296) 'Wrong HOBL coverage universe'
    $identities=[Collections.Generic.List[string]]::new()
    foreach($counter in $Xml.SelectNodes('//counter')){
        Require ($counter.GetAttribute('missed')-match'^[0-9]+$'-and$counter.GetAttribute('covered')-match'^[0-9]+$') 'Malformed coverage counter'
        $parts=@();$node=$counter.ParentNode
        while($node-and$node.NodeType-eq[Xml.XmlNodeType]::Element){
            [string[]]$attrs=@($node.Attributes|ForEach-Object{"$($_.Name)=$($_.Value)"});[Array]::Sort($attrs,[StringComparer]::Ordinal)
            $parts=@($node.LocalName+'['+($attrs-join'|')+']')+$parts;$node=$node.ParentNode
        }
        $identities.Add('C|'+($parts-join'/')+'|'+$counter.GetAttribute('type'))
    }
    foreach($node in $classes){$identities.Add('K|'+$node.GetAttribute('name'))}
    foreach($node in $lines){$identities.Add('L|'+$node.ParentNode.ParentNode.GetAttribute('name')+'|'+$node.ParentNode.GetAttribute('name')+'|'+$node.GetAttribute('nr'))}
    $identities.Sort([StringComparer]::Ordinal);$digest=HashBytes ([Text.Encoding]::UTF8.GetBytes(($identities-join"`n")))
    Require ($digest-eq'03B5B165FB54E374972903C841E42EB6895FB75CD544AEB97E0969208AE6B371') "Wrong pinned HOBL coverage identities: $digest"
    return @{classes=@($classes|ForEach-Object{$_.GetAttribute('name')});lineRecords=$lines.Count;counters=$counters;universeSha256=$digest;semantics=(CoverageSemantics $Xml)}
}
function AddBoundaryMarkers([byte[]]$Original,[string]$Destination){
    Require ($Destination-notmatch'[%!&|<>^"\r\n]') 'Unsafe batch marker destination'
    $t=[Text.Encoding]::UTF8.GetString($Original);$nl=if($t.Contains("`r`n")){"`r`n"}else{"`n"}
    $anchor=')'+$nl+'@SET PSModulePath=%__MVNW_PSMODULEP_SAVE%'
    Require (([regex]::Matches($t,'@FOR /F ')).Count-eq1-and([regex]::Matches($t,[regex]::Escape($anchor))).Count-eq1) 'Ambiguous wrapper anchors'
    $before='@echo HOBL_BOUNDARY_BEFORE_FOR^|%DATE%^|%TIME%>>"'+$Destination+'"'
    $after='@echo HOBL_BOUNDARY_AFTER_FOR^|%DATE%^|%TIME%>>"'+$Destination+'"'
    $v=$t.Replace('@FOR /F ',$before+$nl+'@FOR /F ').Replace($anchor,')'+$nl+$after+$nl+'@SET PSModulePath=%__MVNW_PSMODULEP_SAVE%')
    Require (($v.Replace($before+$nl,'').Replace($after+$nl,''))-ceq$t) 'Non-marker edit'
    return ,[Text.Encoding]::UTF8.GetBytes($v)
}
function RestoreBoundaryEnvironment($Before,[string[]]$Names){
    $errors=@();foreach($n in $Names){try{if($Before.Contains($n)){[Environment]::SetEnvironmentVariable($n,$Before[$n],'Process')}elseif(Test-Path ('Env:'+$n)){Remove-Item ('Env:'+$n) -ErrorAction Stop}}catch{$errors+=$n}}
    $after=[Environment]::GetEnvironmentVariables('Process')
    $keys=@(foreach($n in $Names){$a=$Before.Contains($n);$b=$after.Contains($n);@{name=$n;equal=($a-eq$b-and[string]::Equals($Before[$n],$after[$n],[StringComparison]::Ordinal));beforePresent=$a;afterPresent=$b;beforeType=$(if($a){$Before[$n].GetType().FullName}else{'null'});afterType=$(if($b){$after[$n].GetType().FullName}else{'null'});beforeLength=$(if($a){$Before[$n].Length}else{$null});afterLength=$(if($b){$after[$n].Length}else{$null});beforeSha=$(if($a){HashBytes ([Text.Encoding]::UTF8.GetBytes($Before[$n]))}else{$null});afterSha=$(if($b){HashBytes ([Text.Encoding]::UTF8.GetBytes($after[$n]))}else{$null})}})
    return @{restored=($errors.Count-eq0-and@($keys|Where-Object{-not$_.equal}).Count-eq0);keys=$keys;errors=$errors;unmanagedAdded=@($after.Keys|Where-Object{-not$Before.Contains($_)-and$_-notin$Names});unmanagedRemoved=@($Before.Keys|Where-Object{-not$after.Contains($_)-and$_-notin$Names})}
}
function BoundaryWindow([string]$Json,[string]$Log){
    $r=$Json|ConvertFrom-Json -DateKind String;$v=@{status='UNKNOWN';raw=$r.markers;outer=$r.seconds}
    try{
        $c=[Globalization.CultureInfo]::InvariantCulture;$b=[DateTimeOffset]::Parse($r.before,$c);$e=[DateTimeOffset]::Parse($r.after,$c)
        Require ($b.Date-eq$e.Date-and$b.Offset-eq$e.Offset-and[Math]::Abs(($e-$b).TotalSeconds-$r.seconds)-lt0.25) 'Clock/rollover inconsistency'
        $times=@(foreach($row in $r.markers){$p=$row-split'\|';Require ($p.Count-eq3-and$p[1]-ceq$b.ToString('ddd MM/dd/yyyy',$c)) 'Unresolved local date';$m=[regex]::Match($p[2],'^\s*(\d{1,2}):(\d{2}):(\d{2})[.,](\d{2})$');Require $m.Success 'Unresolved time';$h=[int]$m.Groups[1].Value;$n=[int]$m.Groups[2].Value;$s=[int]$m.Groups[3].Value;Require ($h-lt24-and$n-lt60-and$s-lt60) 'Invalid time';[DateTimeOffset]::new($b.Date.AddMilliseconds(1000*($h*3600+$n*60+$s)+10*[int]$m.Groups[4].Value),$b.Offset)})
        Require ($times.Count-eq2-and$times[0]-ge$b.AddMilliseconds(-20)-and$times[1]-ge$times[0]-and$times[1]-le$e.AddMilliseconds(20)) 'Marker order'
        $m=[regex]::Matches($Log,'(?m)^\[INFO\] Total time:\s+([0-9.]+) s\r?$');Require ($m.Count-eq1) 'Unknown Maven footer'
        $forSeconds=($times[1]-$times[0]).TotalSeconds;$mavenSeconds=[double]::Parse($m[0].Groups[1].Value,$c)
        Require ($r.seconds-$forSeconds-$mavenSeconds-ge0) 'Inconsistent reported/marker remainder'
        $v.status='PARSED_COARSE_LOCAL_ONLY';$v.forSeconds=$forSeconds;$v.mavenSeconds=$mavenSeconds;$v.coarseRest=$r.seconds-$forSeconds-$mavenSeconds
    }catch{$v.reason=$_.Exception.Message};return $v
}
function BoundaryArtifact([string]$Label,[bool]$Online,[bool]$Dirty){
    $j=@(Get-ChildItem "$Project\target" -Filter '*.jar' -File);Require ($j.Count-eq1) 'One executable JAR required'
    Copy-Item $j[0].FullName "$Output\$Label.jar";$z=[IO.Compression.ZipFile]::OpenRead($j[0].FullName)
    try{
        Require (@($z.Entries.FullName|Group-Object|Where-Object Count -gt 1).Count-eq0) 'Duplicate entry'
        $entries=@();$classes=[ordered]@{};$deps=[ordered]@{}
        foreach($e in $z.Entries){if($e.FullName.EndsWith('/')){continue};$bytes=StreamBytes $e $true;$hash=HashBytes $bytes;$entries+=@{name=$e.FullName;bytes=$bytes.Length;sha=$hash};if($e.FullName-match'^BOOT-INF/classes/.+\.class$'){$classes[$e.FullName]=$hash;Require ((256*[int]$bytes[6]+[int]$bytes[7])-eq61) 'Wrong class target'};if($e.FullName-match'^BOOT-INF/lib/.+\.jar$'){$deps[$e.FullName]=$hash}}
        $required=@('META-INF/MANIFEST.MF','META-INF/build-info.properties','BOOT-INF/classes/git.properties','META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml','META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties')
        $sbom=$z.GetEntry('META-INF/sbom/application.cdx.json');Require ([bool]$sbom-eq$Online) 'Wrong SBOM mode';if($Online){$required+='META-INF/sbom/application.cdx.json'}
        $raw=@();foreach($name in $required){$entry=$z.GetEntry($name);Require $entry 'Missing raw metadata';$bytes=StreamBytes $entry;[IO.File]::WriteAllBytes("$Output\$Label-$($raw.Count).raw",$bytes);$raw+=@{name=$name;bytes=$bytes.Length;sha=(HashBytes $bytes)};if($name-eq'BOOT-INF/classes/git.properties'){$git=[Text.Encoding]::UTF8.GetString($bytes)};if($name-eq'META-INF/sbom/application.cdx.json'){$bom=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json;Require ($bom.components.Count-gt0-and$bom.dependencies.Count-gt0) 'Empty online SBOM/graph'}}
        Require (($raw|Where-Object name -eq 'META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml').sha-eq'A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D') 'Packaged POM differs'
        $dirtyText=$Dirty.ToString().ToLowerInvariant();Require ($git-match"(?m)^git\.commit\.id=6feeae0f13e0e258eedc99832416b42bb13779b1\r?$"-and$git-match"(?m)^git\.dirty=$dirtyText\r?$"-and$git-match'(?m)^git\.remote\.origin\.url=https\\?://github\.com/spring-projects/spring-petclinic\.git\r?$') 'Wrong Git provenance'
    }finally{$z.Dispose()}
    $tests=[ordered]@{};foreach($f in Get-ChildItem "$Project\target\test-classes" -Recurse -Filter '*.class'){$tests[[IO.Path]::GetRelativePath("$Project\target\test-classes",$f.FullName).Replace('\','/')]=(Get-FileHash $f.FullName).Hash}
    Require ($classes.Count-eq30-and$tests.Count-eq25-and$deps.Count-eq98) 'Wrong inventory'
    $v=@{classes=$classes;testClasses=$tests;dependencies=$deps;entries=$entries;raw=$raw;git=$git;jarSha=(Get-FileHash $j[0].FullName).Hash;online=$Online}
    $v|ConvertTo-Json -Depth 15|Set-Content "$Output\$Label-artifact.json";return $v
}
if($LibraryOnly){return}
Require ($ExecuteAuthorized-and$IsWindows) 'Explicit owner authorization and Windows required; not CI allocation'
foreach($p in @($Project,$Cache,$JavaHome,$Output)){Require (-not[string]::IsNullOrWhiteSpace($p)) 'Explicit paths required'}
$Project=[IO.Path]::GetFullPath($Project);$Output=[IO.Path]::GetFullPath($Output);$Cache=[IO.Path]::GetFullPath($Cache);$JavaHome=[IO.Path]::GetFullPath($JavaHome)
AssertBoundaryPaths $Project $Output $Cache $JavaHome
Require ($Output-notmatch'[%!&|<>^"\r\n]') 'Unsafe output for batch redirection'
Require (-not$Output.StartsWith($Project.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)-and-not(Test-Path $Output)) 'Fresh output outside source required'
foreach($p in @($Cache,$JavaHome)){Require (-not$p.StartsWith($Project.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) 'Cache/JDK must be outside source inputs'}
New-Item $Output -ItemType Directory|Out-Null
$names=@('JAVA_HOME','PATH','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME')
$before=[Environment]::GetEnvironmentVariables('Process');$cwd=(Get-Location).Path;$original=$null;$variant=$null;$pushed=$false
$record=@{status='STARTED';variant='source markers, not baseline/performance';failures=@();phases=@();host=@{pwsh=$PSVersionTable.PSVersion.ToString();os=[Runtime.InteropServices.RuntimeInformation]::OSDescription;processArchitecture=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString();osArchitecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();logicalProcessors=[Environment]::ProcessorCount;imageOS=$env:ImageOS;imageVersion=$env:ImageVersion}}
function BoundarySource([bool]$Dirty){
    Require ((BoundaryGit -Arguments @('-C',$Project,'rev-parse','HEAD'))-eq'6feeae0f13e0e258eedc99832416b42bb13779b1') 'Wrong pin'
    $changes=BoundaryGit -Arguments @('-C',$Project,'status','--porcelain','--untracked-files=all')
    Require ($(if($Dirty){$changes-ceq' M mvnw.cmd'}else{[string]::IsNullOrEmpty($changes)})) 'Unexpected source changes'
    Require ((Get-FileHash "$Project\pom.xml").Hash-eq'A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D') 'POM drift'
}
function BoundaryCall([string]$Name,[string[]]$Arguments,[bool]$Timed=$false){
    $log="$Output\$Name.log";$start=[DateTimeOffset]::Now
    $duration=Measure-Command {& $wrapper @Arguments *> $log;$script:code=$LASTEXITCODE}
    $end=[DateTimeOffset]::Now;$v=@{name=$Name;arguments=$Arguments;nativeExit=$script:code;before=$start.ToString('o');after=$end.ToString('o');beforeUtc=$start.ToUniversalTime().ToString('o');afterUtc=$end.ToUniversalTime().ToString('o');seconds=$duration.TotalSeconds;diagnostic=$Timed}
    $record.phases+=$v;$record|ConvertTo-Json -Depth 10|Set-Content "$Output\receipt.json";Require ($script:code-eq0) 'Native failure; no retry';return $v
}
try{
    BoundarySource $false;Require ((Test-Path "$Project\.git" -PathType Container)-and-not(Test-Path "$Project\.git\objects\info\alternates")) 'Unborrowed full clone required'
    Require (-not@(Get-Process -Name java,javaw -ErrorAction SilentlyContinue).Count) 'Competing JVM present'
    Require ((BoundaryGit -Arguments @('-C',$Project,'remote','get-url','origin'))-eq'https://github.com/spring-projects/spring-petclinic.git') 'Canonical origin required'
    foreach($n in 'MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME','MVNW_REPOURL','MVNW_USERNAME','MVNW_PASSWORD','GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR','__MVNW_ARG0_NAME__'){Require (-not[Environment]::GetEnvironmentVariable($n)) "Review nonempty key $n"}
    foreach($n in '.m2\settings.xml','.mavenrc','.mavenrc_pre.cmd','.mavenrc_pre.bat','mavenrc_pre.cmd','mavenrc_pre.bat','mavenrc_post.cmd','mavenrc_post.bat'){Require (-not(Test-Path (Join-Path $HOME $n))) 'Unreviewed user config/rc'}
    foreach($n in 'DATE','TIME'){Require (-not(Test-Path ('Env:'+$n))) 'Clock variable shadowing'}
    $java="$JavaHome\bin\java.exe";$bytes=[IO.File]::ReadAllBytes($java)
    Require ((Get-FileHash $java).Hash-eq'094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0'-and[BitConverter]::ToUInt16($bytes,([BitConverter]::ToInt32($bytes,60)+4))-eq0xAA64) 'Pinned native Microsoft25 JDK required'
    $wrapper="$Project\mvnw.cmd";Require ((Get-FileHash $wrapper).Hash-eq'5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A') 'Original wrapper differs'
    $original=[IO.File]::ReadAllBytes($wrapper);[IO.File]::WriteAllBytes("$Output\original-mvnw.cmd",$original)
    $env:JAVA_HOME=$JavaHome;$env:PATH="$JavaHome\bin"+[IO.Path]::PathSeparator+$env:PATH;Push-Location $Project;$pushed=$true
    $base=@("-Dmaven.repo.local=$Cache",'-Dserver.address=127.0.0.1')
    $null=BoundaryCall 'prep-go-offline' ($base+@('-DskipTests','dependency:go-offline'))
    $null=BoundaryCall 'prep-verify' ($base+@('clean','verify'));BoundarySource $false
    $reference=BoundaryArtifact 'prep' $true $false
    $reports=@(Get-ChildItem "$Project\target\surefire-reports\TEST-*.xml"|ForEach-Object{[xml](Get-Content $_ -Raw)});$ids=@(TestKeys $reports)
    Require ($ids.Count-eq56-and@($ids|Where-Object state -eq skipped).Count-eq2-and@($ids|Where-Object state -eq passed).Count-eq54) 'Prep tests differ'
    foreach($report in $reports){foreach($pair in @(@('java.home',$JavaHome),@('os.arch','aarch64'),@('server.address','127.0.0.1'))){Require ($report.SelectSingleNode("//properties/property[@name='$($pair[0])']").GetAttribute('value')-eq$pair[1]) 'Prep runtime/loopback mismatch'}}
    $xml=[xml](Get-Content "$Project\target\site\jacoco\jacoco.xml" -Raw)
    $coverage=BoundaryCoverage $xml
    @{tests=$ids;coverage=$coverage}|ConvertTo-Json -Depth 35|Set-Content "$Output\prep-proof.json"
    Copy-Item "$Project\target\surefire-reports" "$Output\prep-surefire" -Recurse;Copy-Item "$Project\target\site\jacoco\jacoco.xml" "$Output\prep-jacoco.xml"
    $null=BoundaryCall 'prep-clean' ($base+@('clean'));BoundarySource $false
    $marker="$Output\wrapper-markers.raw";Require (-not(Test-Path $marker)) 'Fresh marker file required';$variant=AddBoundaryMarkers $original $marker
    [IO.File]::WriteAllBytes($wrapper,$variant);[IO.File]::WriteAllBytes("$Output\instrumented-mvnw.cmd",$variant);BoundarySource $true
    git -C $Project diff -- mvnw.cmd > "$Output\wrapper-source.patch";$gitExit=$LASTEXITCODE;Require ($gitExit-eq0) 'Patch retention failed'
    $case=BoundaryCall 'diagnostic-package' (@('-o')+$base+@('-DskipTests','package')) $true
    $case.markers=@(Get-Content $marker);Require ($case.markers.Count-eq2-and$case.markers[0]-like'HOBL_BOUNDARY_BEFORE_FOR|*'-and$case.markers[1]-like'HOBL_BOUNDARY_AFTER_FOR|*') 'Missing/duplicate markers'
    $log=Get-Content "$Output\diagnostic-package.log" -Raw
    $record.rawMavenFooters=@([regex]::Matches($log,'(?m)^\[INFO\] (?:Total time:|Finished at:)[^\r\n]*')|ForEach-Object Value)
    Require ($log-match'BUILD SUCCESS'-and$log-match'0 Checkstyle violations'-and$log-match'Tests are skipped'-and$log-match'Compiling 30 source files'-and$log-match'Compiling 17 source files'-and$log-match'Goal makeAggregateBom requires online mode.*skipping') 'Required package work absent'
    $actual=BoundaryArtifact 'diagnostic' $false $true
    foreach($field in 'classes','testClasses','dependencies'){foreach($key in $reference[$field].Keys){Require ($actual[$field][$key]-eq$reference[$field][$key]) 'Fresh prep/package bytes differ'}}
    BoundarySource $true;Require ((HashBytes ([IO.File]::ReadAllBytes($wrapper)))-eq(HashBytes $variant)) 'Instrumented wrapper drift'
    Require ((Get-FileHash $java).Hash-eq'094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0') 'JDK drift'
    $record.clock=BoundaryWindow (ConvertTo-Json $case -Depth 6) $log;$record.status='PASS_SOURCE_VARIANT_ONLY';$record.instrumentedSha=(HashBytes $variant)
}catch{$record.status='FAIL_STOPPED_NO_RETRY';$record.failures+=@{phase='main';error=$_.ToString()}}
finally{
    try{if($variant){Require ((HashBytes ([IO.File]::ReadAllBytes($wrapper)))-eq(HashBytes $variant)) 'Unexpected wrapper changes; refuse overwrite';[IO.File]::WriteAllBytes($wrapper,$original);BoundarySource $false;$record.sourceRestored=$true}}catch{$record.failures+=@{phase='source-restoration';error=$_.ToString()}}
    try{if($pushed){Pop-Location}}catch{$record.failures+=@{phase='cwd';error=$_.ToString()}}
    $restore=RestoreBoundaryEnvironment $before $names;$restore.cwdEqual=(Get-Location).Path-eq$cwd;$restore|ConvertTo-Json -Depth 8|Set-Content "$Output\restoration.json"
    if(-not$restore.restored-or-not$restore.cwdEqual){$record.failures+=@{phase='environment';error='Restoration mismatch'}}
    $record.remainingJavaCandidates=@(Get-Process -Name java,javaw -ErrorAction SilentlyContinue).Count
    if($record.remainingJavaCandidates){$record.failures+=@{phase='cleanup';error='Java remains without proven owned identity; none killed'}}
    if($record.failures.Count){$record.status='FAIL_STOPPED_NO_RETRY'};$record|ConvertTo-Json -Depth 12|Set-Content "$Output\receipt.json"
}
Require ($record.status-eq'PASS_SOURCE_VARIANT_ONLY') 'Diagnostic failed; no retry'
