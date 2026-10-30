[CmdletBinding()]
param(
    [string]$ProjectFullClone, [string]$JavaHome=$env:JAVA_HOME, [string]$MvndHome=$env:MVND_HOME,
    [string]$LocalCache, [string]$OutputDirectory,
    [ValidateSet('current17','normalizedHobl25')][string]$Workload='current17',
    [ValidateSet('Auto','Windows','MacOS')][string]$Platform='Auto',
    [ValidateRange(1,3)][int]$Samples=3, [switch]$LoopbackTests,
    [switch]$PlanOnly, [switch]$LibraryOnly, [switch]$ExclusiveSlotApproved,
    [string[]]$CompareResults
)
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
function Require($Condition,[string]$Message) { if(-not $Condition){throw $Message} }
function DriverPath([string]$Root,[string]$Relative,[string]$Os) {
    $sep=if($Os-eq'Windows'){'\'}else{'/'}
    $Root.TrimEnd([char[]]'\/')+$sep+$Relative.Replace('\',$sep).Replace('/',$sep)
}
function ComparisonPlan([string]$Os,[string]$Mode,[string]$DriverHome) {
    $windows=$Os-eq'Windows'
    [ordered]@{
        platform=$Os; workload=$Mode
        sourcePin=$(if($Mode-eq'current17'){'500158f732419217507c7656904b8e6aa1bcc0d6'}else{'6feeae0f13e0e258eedc99832416b42bb13779b1'})
        javaMajor=$(if($Mode-eq'current17'){17}else{25})
        expectedTests=$(if($Mode-eq'current17'){79}else{56}); expectedSkipped=2
        stock=(DriverPath $DriverHome $(if($windows){'mvn/bin/mvn.cmd'}else{'mvn/bin/mvn'}) $Os)
        candidate=(DriverPath $DriverHome $(if($windows){'bin/mvnd.cmd'}else{'bin/mvnd'}) $Os)
        client=$(if($windows){'LOCAL/UNRELEASED JVM fallback with added ARM64 JNI default resource'}else{'official Darwin ARM64 native-image client; native client differs from Windows'})
        mavenCore='3.9.16'; online=$true; pairs=@(@('stock','daemon'),@('daemon','stock'),@('stock','daemon'))
        phases=@('untimed stock clean verify','untimed daemon clean verify','untimed clean','timed online package -DskipTests','separately timed online test','untimed complete coverage/artifact/reuse audit')
        scope=$(if($Mode-eq'current17'){'current revision / Java17'}else{'normalized HOBL-source / Java25; NOT original HOBL Maven3.9.11 or score'})
        authorization='Preparation is not permission. CI approval and budget remain unestablished.'
    }
}
function CompleteCounters([xml]$Xml) {
    $map=[Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach($counter in $Xml.SelectNodes('//counter')){
        $parts=@();$node=$counter.ParentNode
        while($node -and $node.NodeType-eq[Xml.XmlNodeType]::Element){
            $attrs=[ordered]@{};foreach($a in @($node.Attributes|Sort-Object Name)){$attrs[$a.Name]=$a.Value}
            $parts=@([ordered]@{element=$node.LocalName;attributes=$attrs})+$parts;$node=$node.ParentNode
        }
        $key=ConvertTo-Json -InputObject ([ordered]@{ancestors=$parts;type=$counter.GetAttribute('type')}) -Depth 20 -Compress
        Require (-not $map.ContainsKey($key)) 'Duplicate complete counter identity'
        $map.Add($key,"$($counter.GetAttribute('missed'))/$($counter.GetAttribute('covered'))")
    }
    Require ($map.Count-gt0) 'No semantic coverage counters'
    return ,$map
}
function TestIdentities([xml[]]$Reports) {
    $items=@(foreach($xml in $Reports){foreach($t in $xml.SelectNodes('//testcase')){
        $state=if($t.SelectSingleNode('failure')){'failure'}elseif($t.SelectSingleNode('error')){'error'}elseif($t.SelectSingleNode('skipped')){'skipped'}else{'passed'}
        [ordered]@{class=$t.GetAttribute('classname');name=$t.GetAttribute('name');state=$state}
    }})
    return @($items|Sort-Object class,name,state)
}
function Signature($Value) { ConvertTo-Json -InputObject $Value -Depth 25 -Compress }
function Same($Actual,$Expected,[string]$Message) { Require ((Signature $Actual)-ceq(Signature $Expected)) $Message }
function Median([double[]]$Values) { Require ($Values.Count-gt0) 'Empty timing sample';$s=@($Values|Sort-Object);if($s.Count%2){$s[[int][math]::Floor($s.Count/2)]}else{($s[$s.Count/2-1]+$s[$s.Count/2])/2} }
function NativeCode([int]$Code,[string]$Label) { Require ($Code-eq0) "$Label returned native exit $Code" }
function MacNativeLibraryPath([string]$Text) {
    $records=@([regex]::Matches($Text,'(?m)^0x[0-9A-Fa-f]+[ \t]+(/[^\r\n]*mvndnative[^\r\n]*\.(?:jnilib|dylib))[ \t]*\r?$'))
    Require ($records.Count-eq1) 'Expected exactly one mapped JNI library record'
    $records[0].Groups[1].Value
}
function DecodeJavaProperty([string]$Value) {
    $out=[Text.StringBuilder]::new()
    for($i=0;$i-lt$Value.Length;$i++){
        $c=$Value[$i]
        if($c-eq'\' -and $i+1-lt$Value.Length){
            $i++;$c=$Value[$i]
            if($c-eq'u' -and $i+4-lt$Value.Length){$hex=$Value.Substring($i+1,4);Require ($hex-match'^[0-9A-Fa-f]{4}$') 'Invalid Java property Unicode escape';$c=[char][Convert]::ToInt32($hex,16);$i+=4}
            else{$c=switch($c){'t'{"`t"}'n'{"`n"}'r'{"`r"}'f'{[char]12}default{$c}}}
        }
        $null=$out.Append($c)
    }
    return $out.ToString()
}
function RuntimeProfile([string]$Text,[switch]$EscapedProperties) {
    $values=[ordered]@{}
    foreach($pair in @(@('home','java.home'),@('version','java.version'),@('runtime','java.runtime.version'),@('vendor','java.vendor'),@('arch','os.arch'))){
        $value=[regex]::Match($Text,"(?m)^\s*$([regex]::Escape($pair[1]))\s*=\s*(.+)").Groups[1].Value.Trim()
        $values[$pair[0]]=if($EscapedProperties){DecodeJavaProperty $value}else{$value}
    }
    return $values
}
function AssertRuntime($Actual,$Expected,[string]$Role) {
    foreach($key in 'home','version','runtime','vendor','arch'){
        Require (-not[string]::IsNullOrWhiteSpace($Actual[$key])) "$Role lacks actual $key"
        $same=if($key-eq'home'){[IO.Path]::GetFullPath($Actual[$key]).TrimEnd([char[]]'\/')-eq[IO.Path]::GetFullPath($Expected[$key]).TrimEnd([char[]]'\/')}else{$Actual[$key]-ceq$Expected[$key]}
        Require $same "$Role actual $key differs from selected native JDK"
    }
}
function OwnedIdentityMatches($Current,$Expected) {
    return [bool]($Current -and $Current.pid-eq$Expected.pid -and $Current.started-eq$Expected.started -and
        $Current.executable-eq$Expected.executable -and $Current.command-ceq$Expected.command -and
        $Current.command.Contains($Expected.registry) -and $Current.command.Contains("-Dmvnd.id=$($Expected.daemonId)"))
}
function SafeOwnedStop($Expected,[scriptblock]$Read,[scriptblock]$Wait,[scriptblock]$Kill) {
    $current=& $Read $Expected.pid
    if(-not(OwnedIdentityMatches $current $Expected)){return @{pid=$Expected.pid;action='exited-or-reused; untouched';exited=$true}}
    try { & $Wait $Expected.pid }
    catch [TimeoutException] {
        $fresh=& $Read $Expected.pid
        if(-not(OwnedIdentityMatches $fresh $Expected)){return @{pid=$Expected.pid;action='reused-before-force; untouched';exited=$true}}
        & $Kill $Expected.pid
        & $Wait $Expected.pid
        return @{pid=$Expected.pid;action='terminated-revalidated-owned-after-timeout';exited=$true}
    }
    return @{pid=$Expected.pid;action='normal-exit';exited=$true}
}
function CommonMavenArguments([string]$Cache,[string]$Settings,[string]$Pom,[bool]$BindLoopback) {
    $values=@('--batch-mode','--no-transfer-progress','--file',$Pom,'--settings',$Settings,'--global-settings',$Settings,"-Dmaven.repo.local=$Cache")
    if($BindLoopback){$values+=,'-Dserver.address=127.0.0.1'}
    return $values
}
function CompareEvidence($Windows,$Mac) {
    Require ($Windows.status-eq'PASS' -and $Mac.status-eq'PASS') 'Both executions must pass'
    Require ($Windows.plan.samples-eq3 -and $Mac.plan.samples-eq3) 'Smoke samples are not comparison acceptance'
    Require ($Windows.plan.platform-eq'Windows' -and $Mac.plan.platform-eq'MacOS') 'Wrong platform pair'
    foreach($field in 'sourcePin','javaMajor','workload','mavenCore','loopbackTests'){Same $Windows.plan.$field $Mac.plan.$field "Cross-OS $field mismatch"}
    Same $Windows.deviations $Mac.deviations 'Cross-OS declared workload deviations differ'
    Same $Windows.javaIdentity $Mac.javaIdentity 'Native JDK vendor/runtime version mismatch'
    Same $Windows.mavenCoreSha256 $Mac.mavenCoreSha256 'Bundled Maven core bytes mismatch'
    Same $Windows.correctness.tests $Mac.correctness.tests 'Cross-OS test identity/status mismatch'
    Same $Windows.correctness.coverage $Mac.correctness.coverage 'Cross-OS complete coverage mismatch'
    Same $Windows.correctness.classes $Mac.correctness.classes 'Cross-OS application bytecode mismatch'
    Same $Windows.correctness.testClasses $Mac.correctness.testClasses 'Cross-OS test bytecode mismatch'
    Same $Windows.correctness.dependencies $Mac.correctness.dependencies 'Cross-OS dependency bytes mismatch'
    [ordered]@{
        windowsHardware=$Windows.hardware;macHardware=$Mac.hardware
        stockPackageWindowsToMac=(Median $Windows.package.stock)/(Median $Mac.package.stock)
        daemonPackageWindowsToMac=(Median $Windows.package.daemon)/(Median $Mac.package.daemon)
        stockTestWindowsToMac=(Median $Windows.test.stock)/(Median $Mac.test.stock)
        daemonTestWindowsToMac=(Median $Windows.test.daemon)/(Median $Mac.test.daemon)
        wholeJarBytesEqual=($Windows.correctness.jarSha256-eq$Mac.correctness.jarSha256)
        limitation='Retained Git/build/SBOM metadata may differ across hosts; no byte normalization and no full-JAR equivalence claim. Unequal hosted hardware; three-pair screen, not parity proof.'
    }
}
if($LibraryOnly){return}
if($CompareResults){
    Require ($CompareResults.Count-eq2) 'Supply Windows then Mac result.json'
    CompareEvidence (Get-Content $CompareResults[0] -Raw|ConvertFrom-Json) (Get-Content $CompareResults[1] -Raw|ConvertFrom-Json)|ConvertTo-Json -Depth 15
    return
}
if($Platform-eq'Auto'){$Platform=if($IsWindows){'Windows'}elseif($IsMacOS){'MacOS'}else{throw 'Only Windows/macOS ARM64 supported'}}
$plan=ComparisonPlan $Platform $Workload $MvndHome
$plan.samples=$Samples;$plan.loopbackTests=[bool]$LoopbackTests
if($PlanOnly){$plan|ConvertTo-Json -Depth 8;return}
Require $ExclusiveSlotApproved 'Explicit exclusive local slot required; this is not CI authorization'
Require (($IsWindows -and $Platform-eq'Windows') -or ($IsMacOS -and $Platform-eq'MacOS')) 'Requested platform differs from actual OS'
Require ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture-eq'Arm64') 'Native ARM64 OS required'
foreach($p in @($ProjectFullClone,$JavaHome,$MvndHome,$LocalCache,$OutputDirectory)){Require (-not[string]::IsNullOrWhiteSpace($p)) 'Explicit project/JAVA_HOME/MVND_HOME/cache/output required'}
$ProjectFullClone=[IO.Path]::GetFullPath($ProjectFullClone);$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory);$LocalCache=[IO.Path]::GetFullPath($LocalCache)
foreach($p in @($OutputDirectory,$LocalCache)){Require (-not $p.StartsWith($ProjectFullClone+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) 'Cache/evidence must be outside measured source'}
Require (-not(Test-Path $OutputDirectory)) 'Fresh output required'
Require (Test-Path (Join-Path $ProjectFullClone '.git') -PathType Container) 'Full clone with independent .git directory required'
Require (-not(Test-Path (Join-Path $ProjectFullClone '.git/shallow')) -and -not(Test-Path (Join-Path $ProjectFullClone '.git/objects/info/alternates'))) 'Independent, nonshallow clone required'
foreach($n in 'MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MVND_OPTS','MVND_CLIENT','GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR'){Require (-not[Environment]::GetEnvironmentVariable($n)) "Review nonempty injected option $n first"}
Require (-not $env:MVND_PROPERTIES_PATH) 'Supplied mvnd properties require isolation/review'
foreach($config in @((Join-Path $ProjectFullClone '.mvn/mvnd.properties'),(Join-Path $HOME '.m2/mvnd.properties'))){Require (-not(Test-Path $config)) "Overriding mvnd config is not permitted: $config"}
$globalMvndConfig=Join-Path $MvndHome 'conf/mvnd.properties'
if(Test-Path $globalMvndConfig){Require ((Get-Content $globalMvndConfig -Raw)-notmatch'(?m)^\s*java\.home\s*=') 'Vendor-global Java home override requires review'}
New-Item $OutputDirectory -ItemType Directory|Out-Null
$registry=Join-Path $OutputDirectory 'daemon-registry';$tmp=Join-Path $OutputDirectory 'jvm-owned'
New-Item $registry,$tmp,$LocalCache -ItemType Directory -Force|Out-Null
$settings=Join-Path $OutputDirectory 'owned-settings.xml'
'<settings/>'|Set-Content $settings -Encoding utf8
$java=Join-Path $JavaHome $(if($IsWindows){'bin\java.exe'}else{'bin/java'})
$jcmd=Join-Path $JavaHome $(if($IsWindows){'bin\jcmd.exe'}else{'bin/jcmd'})
$result=[ordered]@{status='RUNNING';plan=$plan;scope=$(if($Samples-eq1){'ONE-SAMPLE EXECUTION SMOKE; NOT performance acceptance/parity'}else{'matched three-pair screen'});deviations=@();phases=@();snapshots=@();package=@{stock=@();daemon=@()};test=@{stock=@();daemon=@()};cleanup=@()}
if($LoopbackTests){$result.deviations+=,'Common Spring Boot server.address=127.0.0.1 on BOTH engines, including prep; management uses the same server/port, so no separate management address is set. Not original unbound test environment.'}
$daemonTag=$null;$daemonPid=$null;$daemonStart=$null
$expectedDaemon=$null
$sourcePushed=$false
$vars=@('JAVA_HOME','MVND_HOME','MVND_CLIENT','MVND_DAEMON_STORAGE','MAVEN_SKIP_RC','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','PATH')
$saved=@{};foreach($n in $vars){$saved[$n]=[Environment]::GetEnvironmentVariable($n)}
function Save { $result|ConvertTo-Json -Depth 30|Set-Content (Join-Path $OutputDirectory 'result.json') -Encoding utf8 }
function ReadHostCommand([string]$Executable,[string[]]$Arguments) {
    $text=& $Executable @Arguments;NativeCode $LASTEXITCODE "hardware $Executable"
    return ($text|Out-String).Trim()
}
function ReadDaemonIdentity([int]$ProcessId) {
    $process=Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if(-not $process){return $null}
    if($IsWindows){
        $native=Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId"
        if(-not $native){return $null}
        return @{pid=$ProcessId;started=$native.CreationDate.ToUniversalTime().ToString('o');executable=$native.ExecutablePath;command=$native.CommandLine}
    }
    $command=ReadHostCommand 'ps' @('-p',[string]$ProcessId,'-o','command=')
    return @{pid=$ProcessId;started=$process.StartTime.ToUniversalTime().ToString('o');executable=$process.Path;command=$command}
}
function SourceGate {
    $head=& git -C $ProjectFullClone rev-parse HEAD;NativeCode $LASTEXITCODE 'Git HEAD';Require ($head-eq$plan.sourcePin) 'Wrong source SHA'
    $dirty=@(& git -C $ProjectFullClone status --porcelain --untracked-files=all);NativeCode $LASTEXITCODE 'Git status';Require ($dirty.Count-eq0) 'Measured source is dirty'
}
function Run([string]$Name,[string]$Engine,[string[]]$Goals,[bool]$Timed) {
    SourceGate
    $exe=if($Engine-eq'daemon'){$plan.candidate}else{$plan.stock}
    $args=@(CommonMavenArguments $LocalCache $settings (Join-Path $ProjectFullClone 'pom.xml') ([bool]$LoopbackTests))
    if($Engine-eq'daemon'){$args+=@("-Dmvnd.daemonStorage=$registry",'--serial')}
    $args+=$Goals;$log=Join-Path $OutputDirectory "$Name.log"
    $watch=[Diagnostics.Stopwatch]::StartNew();& $exe @args *> $log;$code=$LASTEXITCODE;$watch.Stop()
    $phase=[ordered]@{name=$Name;engine=$Engine;timed=$Timed;seconds=$watch.Elapsed.TotalSeconds;exitCode=$code;launcher=$exe;arguments=$args;workingDirectory=(Get-Location).Path;log=$log}
    $result.phases+=,$phase;Save;NativeCode $code $Name
    if($Engine-eq'daemon' -and $Goals -notcontains '--version' -and $Goals -notcontains '--status'){
        $tag=[regex]::Match((Get-Content $log -Raw),'Processing build on daemon ([a-f0-9]+)').Groups[1].Value
        Require $tag 'Actual daemon ID missing from invocation log'
        if($script:daemonTag){Require ($tag-eq$script:daemonTag) 'Daemon reuse changed'}else{$script:daemonTag=$tag}
        $phase.daemonId=$tag
    }
    return $phase
}
function Snapshot([string]$Name,[bool]$WithTests) {
    $jar=@(Get-ChildItem (Join-Path $ProjectFullClone 'target') -Filter '*.jar' -File);Require ($jar.Count-eq1) 'Expected executable JAR'
    $zip=[IO.Compression.ZipFile]::OpenRead($jar[0].FullName)
    try{
        $classes=[ordered]@{};$deps=[ordered]@{};$inventory=@()
        foreach($e in @($zip.Entries|Sort-Object FullName)){
            $inventory+=@{name=$e.FullName;bytes=$e.Length}
            if($e.FullName-match'^BOOT-INF/classes/.+\.class$' -or $e.FullName-match'^BOOT-INF/lib/.+\.jar$'){
                $s=$e.Open();try{$hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($s))}finally{$s.Dispose()}
                if($e.FullName-match'\.class$'){$classes[$e.FullName]=$hash}else{$deps[$e.FullName]=$hash}
            }
        }
        Require ($classes.Count-eq30) 'Application class inventory mismatch'
        $metadata=[ordered]@{}
        foreach($path in 'META-INF/MANIFEST.MF','META-INF/build-info.properties','BOOT-INF/classes/git.properties','META-INF/sbom/application.cdx.json'){
            $e=$zip.GetEntry($path);Require ($e -and $e.Length-gt0) "Missing required packaged $path"
            $reader=[IO.StreamReader]::new($e.Open());try{$metadata[$path]=$reader.ReadToEnd()}finally{$reader.Dispose()}
        }
        $git=$metadata['BOOT-INF/classes/git.properties'];Require ($git-match"(?m)^git.commit.id=$($plan.sourcePin)\r?$" -and $git-match'(?m)^git.dirty=false\r?$') 'Packaged Git metadata mismatch'
        $testClasses=[ordered]@{};$testRoot=Join-Path $ProjectFullClone 'target/test-classes'
        foreach($file in @(Get-ChildItem $testRoot -Filter '*.class' -Recurse -File|Sort-Object FullName)){
            $testClasses[$file.FullName.Substring($testRoot.Length).TrimStart([char[]]'\/').Replace('\','/')]=(Get-FileHash $file.FullName).Hash
        }
        Require ($testClasses.Count-gt0) 'Test compilation output missing'
        $snapshot=[ordered]@{name=$Name;jarSha256=(Get-FileHash $jar[0].FullName).Hash;classes=$classes;testClasses=$testClasses;dependencies=$deps;inventory=$inventory;metadata=$metadata;sbomMode='online generated and packaged; never offline reduced workload'}
        if($WithTests){
            $reports=@(Get-ChildItem (Join-Path $ProjectFullClone 'target/surefire-reports') -Filter 'TEST-*.xml'|ForEach-Object{[xml](Get-Content $_.FullName -Raw)})
            $snapshot.tests=TestIdentities $reports
            $snapshot.testRuntimes=@(foreach($report in $reports){
                $profile=[ordered]@{}
                foreach($pair in @(@('home','java.home'),@('version','java.version'),@('runtime','java.runtime.version'),@('vendor','java.vendor'),@('arch','os.arch'))){
                    $profile[$pair[0]]=$report.SelectSingleNode("//properties/property[@name='$($pair[1])']").GetAttribute('value')
                }
                AssertRuntime $profile $result.selectedRuntime "$Name Surefire";$profile
            })
            if($LoopbackTests){
                $bound=@($reports|ForEach-Object{$_.SelectNodes('//properties/property')}|Where-Object {$_.GetAttribute('name')-eq'server.address' -and $_.GetAttribute('value')-eq'127.0.0.1'})
                Require ($bound.Count-gt0) 'Loopback server address absent from actual fork properties'
                $snapshot.loopbackPropertyReports=$bound.Count
            }
            Require ($snapshot.tests.Count-eq$plan.expectedTests) 'Wrong testcase count'
            Require (@($snapshot.tests|Where-Object state -eq 'skipped').Count-eq$plan.expectedSkipped) 'Unexpected Docker skips'
            Require (@($snapshot.tests|Where-Object state -in @('failure','error')).Count-eq0) 'Tests failed'
            $snapshot.coverage=CompleteCounters ([xml](Get-Content (Join-Path $ProjectFullClone 'target/site/jacoco/jacoco.xml') -Raw))
        }
        if($result.snapshots.Count){
            Same $classes $result.snapshots[0].classes 'Application class bytes changed'
            Same $testClasses $result.snapshots[0].testClasses 'Test class bytes changed'
            Same $deps $result.snapshots[0].dependencies 'Dependencies changed'
            Require ($snapshot.jarSha256-eq$result.snapshots[0].jarSha256) 'Whole JAR changed within host; no normalization allowed'
            if($WithTests){Same $snapshot.tests $result.snapshots[0].tests 'Test identities/statuses changed';Same $snapshot.coverage $result.snapshots[0].coverage 'Complete coverage changed'}
        }
        $snapshot|ConvertTo-Json -Depth 30|Set-Content (Join-Path $OutputDirectory "$Name-artifact.json")
        $result.snapshots+=,$snapshot;Save
    }finally{$zip.Dispose()}
}
try{
    SourceGate;Add-Type -AssemblyName System.IO.Compression.FileSystem
    Push-Location $ProjectFullClone;$sourcePushed=$true
    $env:JAVA_HOME=$JavaHome;$env:MVND_HOME=$MvndHome;$env:MVND_CLIENT=$null;$env:MVND_DAEMON_STORAGE=$registry;$env:MAVEN_SKIP_RC='1';$env:MAVEN_OPTS='';$env:MAVEN_ARGS=$null
    $env:PATH=(Join-Path $JavaHome 'bin')+[IO.Path]::PathSeparator+$env:PATH
    $env:JAVA_TOOL_OPTIONS="`"-Djava.io.tmpdir=$tmp`" `"-Dmvndnative.tmpdir=$tmp`" --enable-native-access=ALL-UNNAMED"
    $result.hardware=if($IsWindows){@{os=([Runtime.InteropServices.RuntimeInformation]::OSDescription);cpu=@(Get-CimInstance Win32_Processor|Select-Object Name,NumberOfCores,NumberOfLogicalProcessors);memoryBytes=(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory}}else{@{os=(ReadHostCommand 'sw_vers' @());cpu=(ReadHostCommand 'sysctl' @('-n','machdep.cpu.brand_string'));cores=(ReadHostCommand 'sysctl' @('-n','hw.ncpu'));memoryBytes=(ReadHostCommand 'sysctl' @('-n','hw.memsize'))}}
    $result.image=@{imageOS=$env:ImageOS;imageVersion=$env:ImageVersion;runnerArch=$env:RUNNER_ARCH;cache=$LocalCache;output=$OutputDirectory}
    & $java -XshowSettings:properties -version *> (Join-Path $OutputDirectory 'java.log');NativeCode $LASTEXITCODE 'Java identity'
    $props=Get-Content (Join-Path $OutputDirectory 'java.log') -Raw
    Require ($props-match'os.arch = aarch64') 'Java is not native ARM64'
    $version=[regex]::Match($props,'java.runtime.version = (.+)').Groups[1].Value.Trim();Require ($version-match"^$($plan.javaMajor)\.") 'Wrong JDK major'
    $result.javaIdentity=[ordered]@{runtime=$version;vendor=[regex]::Match($props,'java.vendor = (.+)').Groups[1].Value.Trim()}
    $result.selectedRuntime=RuntimeProfile $props
    $result.mavenCoreSha256=(Get-FileHash (Join-Path $MvndHome 'mvn/lib/maven-core-3.9.16.jar')).Hash
    if($IsWindows){
        Require (-not(Test-Path (Join-Path $MvndHome 'bin/mvnd.exe'))) 'AMD64 native client must be omitted in LOCAL prototype'
        $z=[IO.Compression.ZipFile]::OpenRead((Join-Path $MvndHome 'mvn/lib/mvnd/mvnd-native-1.0.6.jar'))
        try{$e=$z.GetEntry('org/mvndaemon/mvnd/nativ/Windows/arm64/mvndnative.dll');Require $e 'Missing packaged Windows ARM64 JNI default resource';$s=$e.Open();$m=[IO.MemoryStream]::new();try{$s.CopyTo($m);$b=$m.ToArray()}finally{$s.Dispose();$m.Dispose()};Require ([BitConverter]::ToUInt16($b,[BitConverter]::ToInt32($b,0x3c)+4)-eq0xaa64) 'JNI resource is not ARM64'}finally{$z.Dispose()}
    }else{$native=& file $plan.candidate;NativeCode $LASTEXITCODE 'Mac native client';Require ($native-match'arm64') 'Mac client not ARM64';$result.nativeClient=$native}
    foreach($engine in 'stock','daemon'){
        if($engine-eq'stock'){$env:MAVEN_OPTS='-XshowSettings:properties'}
        try{$null=Run "$engine-version" $engine @('--version') $false}finally{$env:MAVEN_OPTS=''}
        Require ((Get-Content (Join-Path $OutputDirectory "$engine-version.log") -Raw)-match'Maven 3\.9\.16') 'Matched Maven core 3.9.16 required'
        if($engine-eq'stock'){
            $result.stockRuntime=RuntimeProfile (Get-Content (Join-Path $OutputDirectory "$engine-version.log") -Raw)
            AssertRuntime $result.stockRuntime $result.selectedRuntime 'Actual stock Maven VM'
        }
        $null=Run "$engine-prep" $engine @('clean','verify') $false;Snapshot "$engine-prep" $true
    }
    $null=Run 'daemon-owned-status' 'daemon' @('--status') $false
    $status=Get-Content (Join-Path $OutputDirectory 'daemon-owned-status.log') -Raw
    $match=[regex]::Match($status,"(?m)^\s*$daemonTag\s+(\d+)\s+");Require $match.Success 'Owned daemon PID absent'
    $daemonPid=[int]$match.Groups[1].Value;$daemonStart=(Get-Process -Id $daemonPid).StartTime
    $expectedDaemon=ReadDaemonIdentity $daemonPid;$expectedDaemon.registry=$registry;$expectedDaemon.daemonId=$daemonTag
    Require (OwnedIdentityMatches $expectedDaemon $expectedDaemon) 'Owned daemon process identity unavailable'
    foreach($command in 'VM.system_properties','VM.dynlibs'){
        & $jcmd $daemonPid $command *> (Join-Path $OutputDirectory "daemon-$command.log");NativeCode $LASTEXITCODE "daemon $command"
    }
    $properties=Get-Content (Join-Path $OutputDirectory 'daemon-VM.system_properties.log') -Raw
    $result.daemonRuntime=RuntimeProfile $properties -EscapedProperties
    AssertRuntime $result.daemonRuntime $result.selectedRuntime 'Actual daemon VM'
    Require ($properties-match'(?m)^os.arch=aarch64\r?$' -and $properties-notmatch'(?m)^library.mvndnative.path=') 'Daemon ARM64/default native loading proof failed'
    $libs=Get-Content (Join-Path $OutputDirectory 'daemon-VM.dynlibs.log') -Raw
    $loaded=if($IsWindows){[regex]::Match($libs,'(?m)([A-Za-z]:[^\r\n]*mvndnative[^\r\n]*\.dll)').Groups[1].Value.Trim()}else{MacNativeLibraryPath $libs}
    Require ($loaded -and (Test-Path -LiteralPath $loaded)) 'Actual loaded JNI library path missing'
    Require ([IO.Path]::GetFullPath($loaded).StartsWith([IO.Path]::GetFullPath($tmp)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) 'JNI not default-extracted under owned temp'
    $result.loadedNative=@{path=$loaded;sha256=(Get-FileHash -LiteralPath $loaded).Hash}
    if($IsWindows){$b=[IO.File]::ReadAllBytes($loaded);Require ([BitConverter]::ToUInt16($b,[BitConverter]::ToInt32($b,0x3c)+4)-eq0xaa64) 'Loaded DLL not ARM64'}
    else{$description=& file $loaded;NativeCode $LASTEXITCODE 'loaded JNI architecture';Require ($description-match'arm64') 'Loaded Mac JNI not ARM64';$result.loadedNative.description=$description}
    foreach($pair in 0..($Samples-1)){foreach($engine in $plan.pairs[$pair]){
        $name="pair-$($pair+1)-$engine";$null=Run "$name-clean" $engine @('clean') $false
        $p=Run "$name-package" $engine @('-DskipTests','package') $true;$result.package[$engine]+=,$p.seconds;Snapshot "$name-package" $false
        $exec=Join-Path $ProjectFullClone 'target/jacoco.exec';if(Test-Path $exec){Remove-Item $exec}
        $t=Run "$name-test" $engine @('test') $true;$result.test[$engine]+=,$t.seconds
        Require ((Test-Path $exec) -and (Get-Item $exec).Length-gt0) 'Fresh JaCoCo execution data absent'
        $null=Run "$name-coverage" $engine @('jacoco:report') $false
        Copy-Item (Join-Path $ProjectFullClone 'target/site/jacoco/jacoco.xml') (Join-Path $OutputDirectory "$name-coverage.xml")
        Copy-Item (Join-Path $ProjectFullClone 'target/surefire-reports') (Join-Path $OutputDirectory "$name-surefire") -Recurse
        Snapshot "$name-test" $true
    }}
    $result.correctness=$result.snapshots[0];$result.daemon=@{id=$daemonTag;pid=$daemonPid;startTime=$daemonStart};SourceGate;$result.status='PASS'
}catch{
    $result.status='FAIL';$result.failure=$_.ToString()
    $failedReports=Join-Path $ProjectFullClone 'target/surefire-reports'
    if(Test-Path $failedReports){Copy-Item $failedReports (Join-Path $OutputDirectory 'failed-surefire') -Recurse}
}
finally{
    try{
        if(Test-Path $registry){
            & $plan.candidate "-Dmvnd.daemonStorage=$registry" --stop *> (Join-Path $OutputDirectory 'owned-stop.log');$stopCode=$LASTEXITCODE
            & $plan.candidate "-Dmvnd.daemonStorage=$registry" --status *> (Join-Path $OutputDirectory 'owned-final-status.log');$statusCode=$LASTEXITCODE
            if($statusCode-ne0 -or (Get-Content (Join-Path $OutputDirectory 'owned-final-status.log') -Raw)-match'(?m)^\s*[a-f0-9]{8}\s+\d+\s+'){$result.status='FAIL';$result.cleanupFailure='Owned registry cleanup not proved'}
            if($expectedDaemon){
                $result.cleanup+=SafeOwnedStop $expectedDaemon ${function:ReadDaemonIdentity} {
                    param($id)
                    $p=Get-Process -Id $id -ErrorAction SilentlyContinue
                    if($p -and -not $p.WaitForExit(15000)){throw [TimeoutException]::new('Owned daemon exit timeout')}
                } {param($id) Stop-Process -Id $id -ErrorAction Stop}
            }
            if($stopCode-ne0){$result.status='FAIL';$result.cleanupFailure="owned --stop returned $stopCode"}
        }
    }catch{$result.status='FAIL';$result.cleanupFailure=$_.ToString()}
    finally{if($sourcePushed){Pop-Location};foreach($n in $vars){[Environment]::SetEnvironmentVariable($n,$saved[$n])};Save}
}
if($result.status-ne'PASS'){throw $result.failure}
