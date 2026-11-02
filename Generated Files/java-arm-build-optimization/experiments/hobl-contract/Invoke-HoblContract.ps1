[CmdletBinding()]
param(
    [string]$ProjectFullClone,[string]$JavaHome,[string]$LocalCache,[string]$OutputDirectory,
    [switch]$ExclusiveSlotApproved,[switch]$AcknowledgeContractReconstruction,
    [switch]$LoopbackTests,[switch]$LibraryOnly
)
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
function Require($Condition,[string]$Message){if(-not $Condition){throw $Message}}
function HashBytes([byte[]]$Bytes){[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))}
function Json($Value){ConvertTo-Json -InputObject $Value -Depth 40 -Compress}
function Same($Actual,$Expected,[string]$Message){Require ((Json $Actual)-ceq(Json $Expected)) $Message}
function Median([double[]]$Values){
    Require ($Values.Count-gt0) 'No samples'
    $ordered=@($Values|Sort-Object);$middle=[int][Math]::Floor($ordered.Count/2)
    if($ordered.Count%2){return $ordered[$middle]}
    return ($ordered[$middle-1]+$ordered[$middle])/2
}
function Summarize($Samples){
    $totals=@($Samples|ForEach-Object {$_.buildSeconds+$_.testSeconds})
    return @{buildMedian=(Median @($Samples.buildSeconds));testMedian=(Median @($Samples.testSeconds));scenarioMedian=(Median $totals);scenarioMin=($totals|Measure-Object -Minimum).Minimum;scenarioMax=($totals|Measure-Object -Maximum).Maximum}
}
function ContractArguments([string]$Phase,[string]$Cache,[bool]$Loopback=$true){
    $repo="-Dmaven.repo.local=$Cache";$bind=if($Loopback){@('-Dserver.address=127.0.0.1')}else{@()}
    switch($Phase){
        'go-offline'{return @($repo)+$bind+@('-DskipTests','dependency:go-offline')}
        'verify'{return @($repo)+$bind+@('clean','verify')}
        'clean'{return @($repo)+$bind+@('clean')}
        'package'{return @('-o',$repo)+$bind+@('-DskipTests','package')}
        'test'{return @('-o',$repo)+$bind+@('test')}
        'report'{return @('-o',$repo)+$bind+@('jacoco:report')}
        default{throw 'Unknown contract phase'}
    }
}
function ParseTime([string]$Text){
    $result=@{}
    foreach($key in 'real','user','sys'){
        $matches=[regex]::Matches($Text,"(?m)^$key\s+([0-9]+(?:\.[0-9]+)?)\s*$")
        Require ($matches.Count-eq1) "Missing/ambiguous native time $key"
        $result[$key]=[double]::Parse($matches[0].Groups[1].Value,[Globalization.CultureInfo]::InvariantCulture)
    }
    return $result
}
function CoverageKeys([xml]$Xml){
    $map=[ordered]@{}
    foreach($counter in $Xml.SelectNodes('//counter')){
        $parts=@();$node=$counter.ParentNode
        while($node -and $node.NodeType-eq[Xml.XmlNodeType]::Element){
            $attributes=[ordered]@{};foreach($a in @($node.Attributes|Sort-Object Name)){$attributes[$a.Name]=$a.Value}
            $parts=@(@{element=$node.LocalName;attributes=$attributes})+$parts;$node=$node.ParentNode
        }
        $key=Json @{ancestors=$parts;type=$counter.GetAttribute('type')}
        Require (-not$map.Contains($key)) 'Duplicate complete coverage identity'
        $map[$key]="$($counter.GetAttribute('missed'))/$($counter.GetAttribute('covered'))"
    }
    return $map
}
function CoverageSemantics([xml]$Xml){
    $copy=$Xml.CloneNode($true)
    foreach($session in @($copy.SelectNodes('/report/sessioninfo'))){$null=$session.ParentNode.RemoveChild($session)}
    return $copy.OuterXml
}
function TestKeys([xml[]]$Reports){
    $rows=@(foreach($xml in $Reports){foreach($test in $xml.SelectNodes('//testcase')){
        $state=if($test.SelectSingleNode('failure')){'failure'}elseif($test.SelectSingleNode('error')){'error'}elseif($test.SelectSingleNode('skipped')){'skipped'}else{'passed'}
        @{class=$test.GetAttribute('classname');name=$test.GetAttribute('name');state=$state}
    }})
    $identities=@($rows|ForEach-Object {Json @($_.class,$_.name)})
    Require (@($identities|Group-Object|Where-Object Count -gt 1).Count-eq0) 'Duplicate recursive test identity'
    return @($rows|Sort-Object class,name,state)
}
function NativeRuntime([string]$Text){
    $result=@{}
    foreach($name in 'java.home','java.version','java.runtime.version','java.vendor','os.arch'){
        $matches=[regex]::Matches($Text,'(?m)^\s*'+[regex]::Escape($name)+' = ([^\r\n]+)')
        Require ($matches.Count-eq1) "Missing/ambiguous runtime $name";$result[$name]=$matches[0].Groups[1].Value.Trim()
    }
    Require ($result['java.vendor']-eq'Microsoft' -and $result['java.runtime.version']-eq'25.0.5.0.2+1-LTS' -and $result['os.arch']-eq'aarch64') 'Pinned native Microsoft JDK25 required'
    return $result
}
function StreamBytes($Entry,[bool]$AllowEmpty=$false){
    $stream=$Entry.Open();$memory=[IO.MemoryStream]::new()
    try{$stream.CopyTo($memory);$bytes=$memory.ToArray()}finally{$stream.Dispose();$memory.Dispose()}
    Require (($AllowEmpty -or $bytes.Length-gt0) -and $bytes.Length-eq$Entry.Length) 'Empty/truncated required ZIP entry'
    return ,$bytes
}
if($LibraryOnly){return}
Require ($ExclusiveSlotApproved -and $AcknowledgeContractReconstruction -and $LoopbackTests) 'Explicit runtime approval, reconstruction acknowledgement and loopback safety required'
foreach($path in @($ProjectFullClone,$JavaHome,$LocalCache,$OutputDirectory)){Require (-not[string]::IsNullOrWhiteSpace($path)) 'Explicit clone/JDK/cache/fresh output required'}
$ProjectFullClone=[IO.Path]::GetFullPath($ProjectFullClone);$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory);$LocalCache=[IO.Path]::GetFullPath($LocalCache)
foreach($path in @($ProjectFullClone,$OutputDirectory,$LocalCache,$JavaHome)){
    $current=$path
    while($current){
        if(Test-Path -LiteralPath $current){Require (-not((Get-Item -LiteralPath $current -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked input/output ancestry rejected'}
        $parent=[IO.Directory]::GetParent($current);$current=if($parent){$parent.FullName}else{$null}
    }
}
foreach($path in @($OutputDirectory,$LocalCache)){Require (-not$path.Equals($ProjectFullClone,[StringComparison]::OrdinalIgnoreCase) -and -not$path.StartsWith($ProjectFullClone+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) 'Cache/evidence must be outside source'}
Require (-not(Test-Path $OutputDirectory)) 'Fresh output required'
Require (Test-Path (Join-Path $ProjectFullClone '.git') -PathType Container) 'Ordinary full clone required; worktrees rejected'
foreach($name in 'MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','JAVACMD','MAVEN_USER_HOME','MVNW_REPOURL','MVNW_USERNAME','MVNW_PASSWORD','GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR'){
    Require (-not[Environment]::GetEnvironmentVariable($name)) "Review nonempty injected option $name first"
}
foreach($name in '.m2/settings.xml','.mavenrc','.mavenrc_pre.cmd','.mavenrc_pre.bat'){
    Require (-not(Test-Path (Join-Path $HOME $name))) "Unreviewed user Maven configuration: $name"
}
New-Item $OutputDirectory -ItemType Directory|Out-Null
$result=[ordered]@{
    status='running';lane='MATCHED HOBL-CONTRACT REPRODUCTION';pin='6feeae0f13e0e258eedc99832416b42bb13779b1'
    hoblSource='df120528374c0a5de5cb5a526175973d1ea2b53f';project=$ProjectFullClone;cache=$LocalCache;phases=@();samples=@();snapshots=@()
    deviations=@('JDK25.0.5.0.2+1-LTS instead of original requested25.0.0.36; actual original DUT unknown','Pinned full clone repairs Windows checkout/Mac HEAD ambiguity','Explicit common loopback property','PowerShell7 outer harness, including Mac process launch/redirection; native /usr/bin/time -p boundary retained','Windows timer also includes immediate native-exit assignment; retain raw samples rather than only rounded CSV','Per-case logs/artifact retention; no outer HOBL tracing/system prep','Additional untimed offline JaCoCo report after each test for audit','No official DUT score or online/offline artifact-equivalence claim')
}
function Save {$result|ConvertTo-Json -Depth 45|Set-Content (Join-Path $OutputDirectory 'result.json') -Encoding utf8}
function GitText([string[]]$Arguments){
    $text=@(& (Get-Command git -CommandType Application).Source @Arguments);$code=$LASTEXITCODE;Require ($code-eq0) "Git failed $code";return ($text-join"`n")
}
function SourceGate{
    Require ((GitText @('-C',$ProjectFullClone,'rev-parse','HEAD'))-eq$result.pin) 'Wrong source pin'
    Require (-not(GitText @('-C',$ProjectFullClone,'status','--porcelain=v1','--untracked-files=all'))) 'Source dirty'
}
function Phase([string]$Name,[string[]]$Arguments,[bool]$Timed=$false){
    $log=Join-Path $OutputDirectory "$Name.log";$script:code=$null
    if($Timed -and $IsMacOS){
        $time=Join-Path $OutputDirectory "$Name.time";& /usr/bin/time -p -o $time $script:wrapper @Arguments *> $log;$script:code=$LASTEXITCODE
        $raw=Get-Content $time -Raw;$cpu=ParseTime $raw;$seconds=$cpu.real
    }else{
        $duration=Measure-Command {& $script:wrapper @Arguments *> $log;$script:code=$LASTEXITCODE}
        $seconds=$duration.TotalSeconds;$cpu=$null;$raw=$null
    }
    $record=@{name=$Name;arguments=$Arguments;timed=$Timed;seconds=$seconds;exitCode=$script:code;log=$log;nativeTime=$cpu;nativeTimeRaw=$raw}
    $result.phases+=,$record;Save
    Require ($script:code-eq0) "$Name native exit=$script:code; see $log"
    return $record
}
function Snapshot([string]$Name,[bool]$Online){
    $destination=Join-Path $OutputDirectory $Name;New-Item $destination -ItemType Directory|Out-Null
    $jars=@(Get-ChildItem (Join-Path $ProjectFullClone 'target') -Filter '*.jar' -File);Require ($jars.Count-eq1) 'Expected one executable JAR'
    $jar=$jars[0];$zip=[IO.Compression.ZipFile]::OpenRead($jar.FullName)
    $classes=[ordered]@{};$dependencies=[ordered]@{};$entries=@();$raw=@();$sbom=$null
    try{
        Require (@($zip.Entries.FullName|Group-Object|Where-Object Count -gt 1).Count-eq0) 'Duplicate JAR entry'
        foreach($entry in $zip.Entries){
            if($entry.FullName.EndsWith('/')){continue}
            $bytes=StreamBytes $entry $true;$hash=HashBytes $bytes;$entries+=@{name=$entry.FullName;bytes=$bytes.Length;sha256=$hash}
            if($entry.FullName-match'^BOOT-INF/classes/.+\.class$'){$classes[$entry.FullName]=$hash}
            if($entry.FullName-match'^BOOT-INF/lib/.+\.jar$'){$dependencies[$entry.FullName]=$hash}
        }
        $required=@('META-INF/MANIFEST.MF','META-INF/build-info.properties','BOOT-INF/classes/git.properties','META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml','META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties')
        $sbomEntry=$zip.GetEntry('META-INF/sbom/application.cdx.json')
        if($Online){Require $sbomEntry 'Online full-artifact sidecar requires SBOM';$required+='META-INF/sbom/application.cdx.json'}
        else{Require (-not$sbomEntry) 'Expected intentional offline SBOM omission'}
        foreach($metadataEntryName in $required){
            $entry=$zip.GetEntry($metadataEntryName);Require $entry "Required raw metadata missing: $metadataEntryName"
            $bytes=StreamBytes $entry;$path=Join-Path $destination ("metadata-$($raw.Count).raw");[IO.File]::WriteAllBytes($path,$bytes)
            $raw+=@{entry=$metadataEntryName;path=$path;bytes=$bytes.Length;sha256=(HashBytes $bytes)}
            if($metadataEntryName-eq'BOOT-INF/classes/git.properties'){
                $text=[Text.Encoding]::UTF8.GetString($bytes)
                Require ($text-match'(?m)^git\.commit\.id=6feeae0f13e0e258eedc99832416b42bb13779b1\r?$' -and $text-match'(?m)^git\.dirty=false\r?$') 'Wrong packaged Git provenance'
            }
            if($metadataEntryName-eq'META-INF/sbom/application.cdx.json'){$sbom=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json;Require ($sbom.components.Count-gt0 -and $sbom.dependencies.Count-gt0) 'Empty online SBOM/graph'}
        }
    }catch{
        @{status='FAIL';entries=$raw;error=$_.ToString()}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $destination 'raw-metadata.json')
        throw
    }finally{$zip.Dispose()}
    @{status='PASS';entries=$raw;representation='exact unmodified bytes'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $destination 'raw-metadata.json')
    $testClasses=[ordered]@{}
    foreach($file in @(Get-ChildItem (Join-Path $ProjectFullClone 'target/test-classes') -Filter '*.class' -Recurse -File|Sort-Object FullName)){
        $testClasses[[IO.Path]::GetRelativePath((Join-Path $ProjectFullClone 'target/test-classes'),$file.FullName).Replace('\','/')]=(Get-FileHash $file.FullName).Hash
    }
    $reports=@(Get-ChildItem (Join-Path $ProjectFullClone 'target/surefire-reports') -Filter 'TEST-*.xml' -File|ForEach-Object {[xml](Get-Content $_.FullName -Raw)})
    $tests=TestKeys $reports
    Require ($tests.Count-eq56 -and @($tests|Where-Object state -eq 'passed').Count-eq54 -and @($tests|Where-Object state -eq 'skipped').Count-eq2) 'HOBL expected56 identities/54pass/2skip'
    foreach($xml in $reports){
        $observedRuntimeHome=$xml.SelectSingleNode('//properties/property[@name="java.home"]');$version=$xml.SelectSingleNode('//properties/property[@name="java.runtime.version"]')
        $vendor=$xml.SelectSingleNode('//properties/property[@name="java.vendor"]');$arch=$xml.SelectSingleNode('//properties/property[@name="os.arch"]')
        Require ($observedRuntimeHome -and [IO.Path]::GetFullPath($observedRuntimeHome.value)-eq[IO.Path]::GetFullPath($JavaHome) -and $version.value-eq'25.0.5.0.2+1-LTS' -and $vendor.value-eq'Microsoft' -and $arch.value-eq'aarch64') 'Actual test JDK differs'
    }
    [xml]$coverage=Get-Content (Join-Path $ProjectFullClone 'target/site/jacoco/jacoco.xml') -Raw
    $counters=CoverageKeys $coverage
    Require ($counters.Count-eq726 -and $coverage.SelectNodes('/report/package/sourcefile/line').Count-eq296 -and $coverage.SelectNodes('/report/package/class').Count-eq25) 'HOBL full coverage universe differs'
    Require ($classes.Count-eq30 -and $testClasses.Count-eq25 -and $dependencies.Count-eq98) 'HOBL class/dependency universe differs'
    Copy-Item (Join-Path $ProjectFullClone 'target/surefire-reports') (Join-Path $destination 'surefire') -Recurse
    Copy-Item (Join-Path $ProjectFullClone 'target/site/jacoco/jacoco.xml') (Join-Path $destination 'coverage.xml')
    Copy-Item (Join-Path $ProjectFullClone 'target/jacoco.exec') (Join-Path $destination 'jacoco.exec')
    Copy-Item $jar.FullName (Join-Path $destination 'application.jar')
    $snapshot=@{name=$Name;online=$Online;jarSha256=(Get-FileHash $jar.FullName).Hash;entries=$entries;classes=$classes;testClasses=$testClasses;dependencies=$dependencies;tests=$tests;counters=$counters;coverageSemantics=(CoverageSemantics $coverage);rawMetadata=$raw;sbomMode=$(if($Online){'online full artifact sidecar'}else{'intentional offline requires-online goal skip; NOT full-online-equivalent'});sbomComponents=$(if($sbom){$sbom.components.Count}else{0})}
    if($result.snapshots.Count){
        $reference=$result.snapshots[0]
        foreach($key in 'classes','testClasses','dependencies','tests','counters','coverageSemantics'){Same $snapshot[$key] $reference[$key] "Output fidelity changed: $key"}
    }
    $result.snapshots+=,$snapshot;Save
}
$saved=@{};foreach($name in 'JAVA_HOME','PATH'){$saved[$name]=[Environment]::GetEnvironmentVariable($name)}
$pushed=$false
try{
    SourceGate
    Require ((GitText @('-C',$ProjectFullClone,'rev-parse','--git-common-dir'))-eq'.git') 'Shared common Git directory rejected'
    Require (-not(Test-Path (Join-Path $ProjectFullClone '.git/objects/info/alternates'))) 'Borrowed Git objects rejected'
    $result.source=@{head=(GitText @('-C',$ProjectFullClone,'rev-parse','HEAD'));tree=(GitText @('-C',$ProjectFullClone,'rev-parse','HEAD^{tree}'));origin=(GitText @('-C',$ProjectFullClone,'remote','get-url','origin'));pomSha256=(Get-FileHash (Join-Path $ProjectFullClone 'pom.xml')).Hash;wrapperProperties=(Get-Content (Join-Path $ProjectFullClone '.mvn/wrapper/maven-wrapper.properties') -Raw);shell=$PSVersionTable.PSVersion.ToString();os=[Runtime.InteropServices.RuntimeInformation]::OSDescription}
    Require ($result.source.origin-in@('https://github.com/spring-projects/spring-petclinic','https://github.com/spring-projects/spring-petclinic.git')) 'Explicit normal public upstream origin required for artifact provenance'
    $result.source.inputs=@(foreach($name in 'pom.xml','mvnw','mvnw.cmd','.mvn/jvm.config','.mvn/wrapper/maven-wrapper.properties'){
        @{path=$name;sha256=(Get-FileHash (Join-Path $ProjectFullClone $name)).Hash}
    })
    $result.environment=@{logicalProcessors=[Environment]::ProcessorCount;processArchitecture=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString();osArchitecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();imageOS=$env:ImageOS;imageVersion=$env:ImageVersion;injectedOptions='Required empty, never silently normalized by local runner';gitVariables=@(Get-ChildItem Env:|Where-Object Name -like 'GIT*'|ForEach-Object {@{name=$_.Name;value='[REDACTED]';sha256=(HashBytes ([Text.Encoding]::UTF8.GetBytes($_.Value)))}})}
    if($IsWindows){$competing=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('java.exe','javaw.exe','cl.exe','link.exe','msbuild.exe')}|Select-Object ProcessId,Name)}
    else{$all=@(& /bin/ps -axo 'pid=,command=');Require ($LASTEXITCODE-eq0) 'Process preflight failed';$competing=@($all|Where-Object {$_-match'[/ ]java(?:\s|$)'})}
    $result.environment.competingWorkloads=$competing;Require ($competing.Count-eq0) 'Competing Java/native build workload; none will be stopped'
    Require ($result.source.wrapperProperties-match'/3\.9\.11/apache-maven-3\.9\.11-bin\.zip') 'Original Maven3.9.11 wrapper required'
    $env:JAVA_HOME=$JavaHome;$env:PATH=(Join-Path $JavaHome 'bin')+[IO.Path]::PathSeparator+$env:PATH
    Push-Location $ProjectFullClone;$pushed=$true
    $script:wrapper=Join-Path $ProjectFullClone $(if($IsWindows){'mvnw.cmd'}else{'mvnw'})
    Require ($IsWindows -or $IsMacOS) 'Only Windows/macOS qualified contract supported'
    $java=Join-Path $JavaHome $(if($IsWindows){'bin/java.exe'}else{'bin/java'})
    & $java -XshowSettings:properties -version *> (Join-Path $OutputDirectory 'java.log');Require ($LASTEXITCODE-eq0) 'Java identity command failed'
    $result.runtime=NativeRuntime (Get-Content (Join-Path $OutputDirectory 'java.log') -Raw)
    Require ([IO.Path]::GetFullPath($result.runtime['java.home'])-eq[IO.Path]::GetFullPath($JavaHome)) 'Selected Java home differs'
    $result.javaSha256=(Get-FileHash $java).Hash
    $version=Phase 'wrapper-version' @("-Dmaven.repo.local=$LocalCache",'--version')
    Require ((Get-Content $version.log -Raw)-match'Apache Maven 3\.9\.11') 'Actual wrapper Maven version differs'
    $null=Phase 'prep-go-offline' (ContractArguments 'go-offline' $LocalCache)
    $null=Phase 'prep-clean-verify' (ContractArguments 'verify' $LocalCache)
    Snapshot 'online-sidecar' $true
    for($i=1;$i-le5;$i++){
        $clean=Phase "loop-$i-clean" (ContractArguments 'clean' $LocalCache)
        $build=Phase "loop-$i-package" (ContractArguments 'package' $LocalCache) $true
        $test=Phase "loop-$i-test" (ContractArguments 'test' $LocalCache) $true
        $result.samples+=@{iteration=$i;cleanSeconds=$clean.seconds;buildSeconds=$build.seconds;testSeconds=$test.seconds;scenarioRuntimeSeconds=($build.seconds+$test.seconds);hoblWindowsRoundedScenarioSeconds=$(if($IsWindows){[Math]::Round([Math]::Round($build.seconds,2)+[Math]::Round($test.seconds,2),2)}else{$null})}
        $null=Phase "loop-$i-audit-report" (ContractArguments 'report' $LocalCache)
        Require ((Get-Content $build.log -Raw)-match'Goal makeAggregateBom requires online mode.*skipping') 'Offline SBOM skip not evidenced'
        Snapshot "offline-loop-$i" $false;SourceGate;Save
    }
    $result.summary=Summarize $result.samples
    $result.timer=if($IsWindows){'Measure-Command: unrounded TotalSeconds, redirection inside command'}else{'Original /usr/bin/time -p real/user/sys raw text retained; native hundredth-second precision, no invented higher precision'}
    $result.status='PASS'
}catch{$result.status='FAIL';$result.failure=$_.ToString()}
finally{
    if($pushed){Pop-Location}
    foreach($name in $saved.Keys){if($null-eq$saved[$name]){Remove-Item "Env:$name" -ErrorAction SilentlyContinue}else{[Environment]::SetEnvironmentVariable($name,$saved[$name])}}
    try{SourceGate;$result.sourceCleanAfter=$true}catch{$result.status='FAIL';$result.restorationFailure=$_.ToString()}
    try{
        if($IsWindows){
            $remaining=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-eq'java.exe' -and $_.CommandLine -and ($_.CommandLine.Contains($ProjectFullClone) -or $_.CommandLine.Contains($OutputDirectory))}|Select-Object ProcessId,ExecutablePath,CommandLine)
        }else{
            $psOutput=@(& /bin/ps -axo 'pid=,command=');Require ($LASTEXITCODE-eq0) 'Owned JVM cleanup observation failed'
            $remaining=@($psOutput|Where-Object {$_-match'[/ ]java(?:\s|$)' -and ($_.Contains($ProjectFullClone) -or $_.Contains($OutputDirectory))})
        }
        $result.remainingOwnedJvmCandidates=$remaining;Require ($remaining.Count-eq0) 'Owned JVM remains; retained identity evidence, no blind kill'
    }catch{$result.status='FAIL';$result.cleanupFailure=$_.ToString()}
    $result.cleanup='Post-exit Java command/path candidates checked; no daemon, process-name kill, system prep or persistent service created by harness. Process creation/OS argv for exited forks not captured.'
    Save
}
if($result.status-ne'PASS'){throw ((@($result.failure,$result.restorationFailure,$result.cleanupFailure)|Where-Object {$_})-join'; ')}
