[CmdletBinding()]
param(
    [string]$ProjectFullClone, [string]$JavaHome=$env:JAVA_HOME, [string]$MvndHome=$env:MVND_HOME,
    [string]$LocalCache, [string]$OutputDirectory,
    [ValidateSet('current17','normalizedHobl25')][string]$Workload='current17',
    [ValidateSet('Auto','Windows','MacOS')][string]$Platform='Auto',
    [ValidateSet('MavenVsDaemon','JacocoScope','MixedClientPackage')][string]$Comparison='MavenVsDaemon',
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
function MixedClientPlan($Plan,[string]$Mode,[int]$Count) {
    Require ($Mode-ceq'current17'-and$Count-eq3-and$Plan.platform-in@('Windows','MacOS')) 'MixedClientPackage requires current17/three pairs/supported OS'
    $Plan.comparison='MixedClientPackage';$Plan.Remove('stock');$Plan.arms=@('baseline','candidate')
    $Plan.pairs=@(@('baseline','candidate'),@('candidate','baseline'),@('baseline','candidate'))
    $Plan.client=if($Plan.platform-eq'Windows'){'JVM versus official AMD64-emulated native frontend; SAME ARM daemon'}else{'Unchanged ARM-native frontend BOTH arms; no-op control'}
    $Plan.phases=@('two full online verifies and explicit-file context gates','six online package-only samples; separate untimed cleans','native normal stop and18-state restoration')
}
function PortableEnvironmentSnapshot([Collections.IDictionary]$Values,[bool]$Windows=$IsWindows) {
    if($null-eq$Values){$Values=[Environment]::GetEnvironmentVariables('Process')}
    $map=[Collections.Hashtable]::new($(if($Windows){[StringComparer]::OrdinalIgnoreCase}else{[StringComparer]::Ordinal}))
    foreach($key in $Values.Keys){Require (-not$map.Contains([string]$key)) 'Ambiguous environment keys';$map.Add([string]$key,$Values[$key])}
    return $map
}
function RestorePortableEnvironment($Before,[string[]]$Names,[bool]$Windows=$IsWindows) {
    $Before=PortableEnvironmentSnapshot $Before $Windows;$null=PortableEnvironmentSnapshot $null $Windows
    $errors=@();foreach($name in $Names){try{if($Before.Contains($name)){[Environment]::SetEnvironmentVariable($name,$Before[$name],'Process')}elseif(Test-Path ('Env:'+$name)){Remove-Item ('Env:'+$name) -ErrorAction Stop}}catch{$errors+=,$name}}
    $after=PortableEnvironmentSnapshot $null $Windows
    $keys=@(foreach($name in $Names){@{name=$name;beforePresent=$Before.Contains($name);afterPresent=$after.Contains($name);beforeLength=$(if($Before.Contains($name)){$Before[$name].Length}else{$null});afterLength=$(if($after.Contains($name)){$after[$name].Length}else{$null});equal=($Before.Contains($name)-eq$after.Contains($name)-and[string]::Equals($Before[$name],$after[$name],[StringComparison]::Ordinal))}})
    return @{keys=$keys;errors=$errors;restored=($errors.Count-eq0-and-not@($keys|Where-Object{-not$_.equal}).Count)}
}
function InvokePortableProcess([string]$Executable,[string[]]$Arguments,[string]$Log) {
    & $Executable @Arguments *> $Log
    return $LASTEXITCODE
}
function MixedBinaryIdentity([string]$Path) {
    [byte[]]$bytes=[IO.File]::ReadAllBytes($Path)
    return @{sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes));machine=$(if($bytes.Length-ge64-and$bytes[0]-eq77-and$bytes[1]-eq90){[BitConverter]::ToUInt16($bytes,[BitConverter]::ToInt32($bytes,60)+4)}else{0})}
}
function MixedOwnedProcesses {
    if($plan.platform-eq'Windows'){return @(Get-CimInstance Win32_Process -Filter "Name='java.exe'"|Where-Object{$_.CommandLine-and($_.CommandLine.Contains($registry)-or$_.CommandLine.Contains($ProjectFullClone)-or$_.CommandLine.Contains($tmp))}|ForEach-Object{ReadDaemonIdentity ([int]$_.ProcessId)})}
    $log=Join-Path $OutputDirectory 'mixed-owned-processes.log';NativeCode (InvokePortableProcess 'ps' @('-axo','pid=,command=') $log) 'Mixed owned process set'
    return @(foreach($line in Get-Content $log){if(($line.Contains($registry)-or$line.Contains($ProjectFullClone)-or$line.Contains($tmp))-and$line-match'^\s*(\d+)\s+') {$identity=ReadDaemonIdentity ([int]$Matches[1]);if($identity-and[IO.Path]::GetFileName($identity.executable)-ceq'java'){$identity}}})
}
function ReadMixedDaemon {
    $path=Join-Path $registry 'registry.bin'
    if(-not(Test-Path $path)){return $null}
    $reader=[IO.BinaryReader]::new([IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite))
    try{
        function ReadMixedInt { $b=$reader.ReadBytes(4);Require ($b.Length-eq4) 'Truncated private registry';[Array]::Reverse($b);[BitConverter]::ToInt32($b,0) }
        $count=ReadMixedInt;Require ($count-in@(0,1)) 'Unexpected private daemon count';if($count-eq0){return $null}
        $strings=@(foreach($i in 1..3){$n=256*$reader.ReadByte()+$reader.ReadByte();[Text.UTF8Encoding]::new($false,$true).GetString($reader.ReadBytes($n))})
        $id=ReadMixedInt;$identity=ReadDaemonIdentity $id
        $comparison=if($plan.platform-eq'Windows'){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
        Require ($identity-and$strings[0]-cmatch'^[a-f0-9]{8}$'-and[string]::Equals($strings[1],$JavaHome,$comparison)-and[string]::Equals($strings[2],$MvndHome,$comparison)) 'Private daemon registry ownership rejected'
        $expectedExe=Join-Path $JavaHome $(if($plan.platform-eq'Windows'){'bin/java.exe'}else{'bin/java'})
        Require ([string]::Equals($identity.executable,$expectedExe,$comparison)-and$identity.command.Contains($registry)-and$identity.command.Contains("-Dmvnd.id=$($strings[0])")) 'Private process ownership rejected'
        $identity.registry=$registry;$identity.daemonId=$strings[0];return $identity
    }finally{$reader.Dispose()}
}
function AssertMixedDaemon {
    $current=ReadMixedDaemon;Require $current 'Expected private daemon absent'
    $anchor=if($expectedDaemon){$expectedDaemon}else{$script:mixedFirstIdentity}
    if($anchor){Require (OwnedIdentityMatches $current $anchor) 'Mixed-client daemon changed'}else{$script:mixedFirstIdentity=$current}
    return $current
}
function MixedContext([string]$Arm) {
    foreach($expression in 'os.arch','java.home'){
        $file=Join-Path $OutputDirectory "$Arm-$expression.value";Require (-not(Test-Path $file)) 'Stale Maven context output'
        $goals=@();if($expression-eq'java.home'){$goals+=,'-o'}
        $goals+=@('org.apache.maven.plugins:maven-help-plugin:3.5.1:evaluate',"-Dexpression=$expression",'-q',"-Doutput=$file")
        $null=Run "$Arm-context-$expression" 'daemon' $goals $false (MixedRoute $Arm)
        $current=AssertMixedDaemon
        Require ((Test-Path $file -PathType Leaf)-and-not((Get-Item $file -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Missing/linked Maven context output'
        [byte[]]$bytes=[IO.File]::ReadAllBytes($file);Require ($bytes.Length-gt0) 'Empty Maven context output'
        $value=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);Require ($value-notmatch'[\x00-\x1f\x7f]') 'Invalid Maven context bytes'
        if($expression-eq'os.arch'){Require ($value-ceq'aarch64') 'Wrong Maven os.arch'}else{Require ([IO.Path]::IsPathFullyQualified($value)-and[string]::Equals([IO.Path]::GetFullPath($value),[IO.Path]::GetFullPath($JavaHome),$(if($plan.platform-eq'Windows'){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}))) 'Wrong Maven java.home'}
        $result.context+=,@{arm=$Arm;expression=$expression;value=$value;bytes=$bytes.Length;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes));rawBase64=[Convert]::ToBase64String($bytes)}
    }
}
function MixedRoute([ValidateSet('baseline','candidate')][string]$Arm) {
    if($plan.platform-eq'Windows'-and$Arm-eq'baseline'){return 'jvm'};return 'native'
}
function MixedAdmission {
    Require ($plan.sourcePin-ceq'500158f732419217507c7656904b8e6aa1bcc0d6'-and$plan.javaMajor-eq17-and$plan.mavenCore-ceq'3.9.16') 'Mixed plan drift'
    SourceGate
    NativeCode (InvokePortableProcess $java @('-XshowSettings:properties','-version') (Join-Path $OutputDirectory 'mixed-java.log')) 'Mixed Java identity'
    $profile=RuntimeProfile (Get-Content (Join-Path $OutputDirectory 'mixed-java.log') -Raw)
    Require ($profile.arch-ceq'aarch64'-and$profile.vendor-ceq'Microsoft'-and$profile.runtime-ceq'17.0.21.0.2+1-LTS') 'Mixed native17 identity differs'
    $result.selectedRuntime=$profile;$result.javaIdentity=@{runtime=$profile.runtime;vendor=$profile.vendor}
    Require (Test-Path (Join-Path $MvndHome 'mvn/lib/maven-core-3.9.16.jar')) 'Mixed Maven3.9.16 core absent'
    $result.mavenCoreSha256=(Get-FileHash (Join-Path $MvndHome 'mvn/lib/maven-core-3.9.16.jar')).Hash
    Require ($result.mavenCoreSha256-ceq'5D45C72E3DBFAB8B68D15AD4F12777B7D9B5FE4D4ADC99C3BD51FB9641FAB009') 'Qualified mixed Maven core bytes differ'
    if($plan.platform-eq'Windows'){
        $pe=MixedBinaryIdentity (Join-Path $MvndHome 'bin/mvnd.exe')
        Require ($pe.machine-eq0x8664-and$pe.sha256-ceq'386B03C8DF458D8573B9241259EEBFABA894B32DDF8D0767C8CAE6168F81FAD4') 'Official mixed frontend identity differs'
        $result.nativeClient=$pe
    }else{
        $log=Join-Path $OutputDirectory 'mixed-client-file.log';NativeCode (InvokePortableProcess 'file' @($plan.candidate) $log) 'Mac native identity'
        Require ((Get-Content $log -Raw)-match'arm64') 'Mac frontend not ARM-native'
    }
}
function ObserveMixedRuntime {
    $current=AssertMixedDaemon
    foreach($command in 'VM.system_properties','VM.dynlibs'){NativeCode (InvokePortableProcess $jcmd @([string]$current.pid,$command) (Join-Path $OutputDirectory "mixed-$command.log")) $command}
    $props=Get-Content (Join-Path $OutputDirectory 'mixed-VM.system_properties.log') -Raw
    AssertRuntime (RuntimeProfile $props -EscapedProperties) $result.selectedRuntime 'Mixed daemon VM'
    $libs=Get-Content (Join-Path $OutputDirectory 'mixed-VM.dynlibs.log') -Raw
    $loaded=if($plan.platform-eq'Windows'){[regex]::Match($libs,'(?m)([A-Za-z]:[^\r\n]*mvndnative[^\r\n]*\.dll)').Groups[1].Value.Trim()}else{MacNativeLibraryPath $libs}
    Require ($loaded-and[IO.Path]::GetFullPath($loaded).StartsWith([IO.Path]::GetFullPath($tmp)+[IO.Path]::DirectorySeparatorChar,$(if($plan.platform-eq'Windows'){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}))) 'Mixed JNI not owned'
    if($plan.platform-eq'Windows'){Require ((MixedBinaryIdentity $loaded).machine-eq0xAA64) 'Mixed loaded JNI not ARM64'}else{$log=Join-Path $OutputDirectory 'mixed-jni-file.log';NativeCode (InvokePortableProcess 'file' @($loaded) $log) 'Mac JNI identity';Require ((Get-Content $log -Raw)-match'arm64') 'Mac JNI not ARM64'}
    $observed=@{path=$loaded;sha256=(Get-FileHash $loaded).Hash};if($result.loadedNative){SameCompleteArtifact $observed $result.loadedNative 'Mixed JNI changed'};$result.loadedNative=$observed
}
function InvokeMixedClientPackage {
    $names=@('JAVA_HOME','PATH','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME','MVNW_PREFER_PWSH','MVND_CLIENT','MVND_HOME','MVND_DAEMON_STORAGE','MVND_OPTS','MVND_JVM_ARGS','TMP','TEMP')
    $windows=$plan.platform-eq'Windows';$before=PortableEnvironmentSnapshot $null $windows;$cwd=(Get-Location).Path;$normal=$false;$expectedDaemon=$null;$script:mixedFirstIdentity=$null
    $result.package=@{baseline=@();candidate=@()};$result.test=@{};$result.context=@();$result.comparison='MixedClientPackage'
    try{
        foreach($name in $names|Where-Object{$_-notin@('JAVA_HOME','PATH','TMP','TEMP')}){Require (-not[Environment]::GetEnvironmentVariable($name)) "Review injected mixed option $name"}
        $env:JAVA_HOME=$JavaHome;$env:PATH=(Join-Path $JavaHome 'bin')+[IO.Path]::PathSeparator+$env:PATH;$env:MVND_HOME=$MvndHome;$env:MVND_DAEMON_STORAGE=$registry;$env:MAVEN_SKIP_RC='1';$env:TMP=$tmp;$env:TEMP=$tmp
        $env:JAVA_TOOL_OPTIONS="`"-Djava.io.tmpdir=$tmp`" `"-Dmvndnative.tmpdir=$tmp`" --enable-native-access=ALL-UNNAMED"
        Push-Location $ProjectFullClone
        try{
            MixedAdmission
            foreach($arm in 'baseline','candidate'){
                MixedContext $arm;if(-not$expectedDaemon){$expectedDaemon=$script:mixedFirstIdentity};$null=AssertMixedDaemon
                $phase=Run "$arm-prep" 'daemon' @('clean','verify') $false (MixedRoute $arm)
                $null=AssertMixedDaemon;Snapshot "$arm-prep" $true -CompleteArtifact
                $xml=[xml](Get-Content (Join-Path $ProjectFullClone 'target/site/jacoco/jacoco.xml') -Raw);$null=JacocoReportEvidence $xml
                $session=@($xml.SelectNodes('/report/sessioninfo'));Require ($session.Count-eq1-and[long]$session[0].start-ge$phase.beforeMs-and[long]$session[0].dump-le$phase.afterMs) 'Mixed prep coverage session not fresh'
                $fork=@([regex]::Matches((Get-Content $phase.log -Raw),'Starting .*? with PID (\d+)')|ForEach-Object{$_.Groups[1].Value}|Sort-Object -Unique);Require ($fork.Count-eq1) 'Mixed prep fork absent'
                $result.prep+=,@{arm=$arm;fork=$fork[0];session=$session[0].id}
                $reports=Join-Path $OutputDirectory "$arm-prep-reports";New-Item $reports -ItemType Directory|Out-Null
                Copy-Item (Join-Path $ProjectFullClone 'target/surefire-reports') (Join-Path $reports 'surefire-reports') -Recurse
                Copy-Item (Join-Path $ProjectFullClone 'target/site/jacoco') (Join-Path $reports 'jacoco') -Recurse
                Copy-Item (Join-Path $ProjectFullClone 'target/jacoco.exec') (Join-Path $reports 'jacoco.exec')
                if($arm-eq'candidate'){Require ($result.prep[0].fork-ne$fork[0]-and$result.prep[0].session-ne$session[0].id) 'Mixed prep reused fork/session';Require ((CompareCompleteArtifacts (Join-Path $OutputDirectory 'baseline-prep-complete') (Join-Path $OutputDirectory 'candidate-prep-complete')).status-eq'PASS') 'Mixed prep artifact differs'}
            }
            ObserveMixedRuntime
            foreach($pair in 0..2){foreach($arm in $plan.pairs[$pair]){
                $name="pair-$($pair+1)-$arm";$null=Run "$name-clean" 'daemon' @('clean') $false (MixedRoute $arm);$null=AssertMixedDaemon
                $phase=Run "$name-package" 'daemon' @('package','-DskipTests') $true (MixedRoute $arm);$null=AssertMixedDaemon;$result.package[$arm]+=,$phase.seconds
                Snapshot "$name-package" $false -CompleteArtifact;Require ((CompareCompleteArtifacts (Join-Path $OutputDirectory 'baseline-prep-complete') (Join-Path $OutputDirectory "$name-package-complete")).status-eq'PASS') 'Mixed sample artifact differs'
            }}
            ObserveMixedRuntime;SourceGate;$null=AssertMixedDaemon
            $null=Run 'mixed-native-stop' 'daemon' @('--stop') $false 'native' -OwnedCleanup
            Require (-not(ReadMixedDaemon)) 'Mixed native stop left registry entry'
            if($expectedDaemon-and(OwnedIdentityMatches (ReadDaemonIdentity $expectedDaemon.pid) $expectedDaemon)){$process=Get-Process -Id $expectedDaemon.pid -ErrorAction Stop;Require ($process.WaitForExit(15000)) 'Mixed native stop process exit timed out'}
            if($expectedDaemon){$identity=ReadDaemonIdentity $expectedDaemon.pid;Require (-not(OwnedIdentityMatches $identity $expectedDaemon)) 'Mixed native stop left owned process'}
            Require (-not@(MixedOwnedProcesses).Count) 'Mixed native stop left owned process set';SourceGate
            $normal=$true;$result.sourceRestored=$true;$result.correctness=$result.snapshots[0];$result.daemon=$expectedDaemon;$result.status='PASS'
        }finally{Pop-Location}
    }catch{$result.status='FAIL';$result.failure=$_.ToString()}
    finally{
        try{
            if(-not$normal){
                $owner=ReadMixedDaemon;if(-not$owner){$owner=$expectedDaemon}
                if($owner-and(OwnedIdentityMatches (ReadDaemonIdentity $owner.pid) $owner)){
                    $expectedDaemon=$owner;$result.emergencyCleanup=$true
                    try{$null=Run 'mixed-emergency-jvm-stop' 'daemon' @('--stop') $false $(if($windows){'jvm'}else{'native'}) -OwnedCleanup}catch{$result.cleanupFailure=$_.ToString()}
                    $result.cleanup+=SafeOwnedStop $owner ${function:ReadDaemonIdentity} {param($id)$p=Get-Process -Id $id -ErrorAction SilentlyContinue;if($p-and-not$p.WaitForExit(15000)){throw [TimeoutException]::new('Owned mixed timeout')}} {param($id)Stop-Process -Id $id -ErrorAction Stop}
                }
                $result.status='FAIL';$result.ownedProcessesRemaining=@(MixedOwnedProcesses).Count
            }
        }catch{$result.status='FAIL';$result.cleanupFailure=$_.ToString()}
        finally{$result.restoration=RestorePortableEnvironment $before $names $windows;$result.restoration.cwdEqual=(Get-Location).Path-eq$cwd;if(-not$result.restoration.restored-or-not$result.restoration.cwdEqual){$result.status='FAIL'};Save}
    }
}
function AssertJacocoScopePlan($Plan) {
    Require ($Plan.workload-eq'current17' -and $Plan.sourcePin-eq'500158f732419217507c7656904b8e6aa1bcc0d6') 'JaCoCo scope requires pinned current17'
    Require ($Plan.comparison-eq'JacocoScope' -and $Plan.engine-eq'daemon' -and $Plan.javaMajor-eq17) 'JaCoCo scope requires daemon and Java17'
    Require ($Plan.samples-ge1 -and $Plan.samples-le3) 'JaCoCo scope requires one to three pairs'
    Same $Plan.pairs @(@('default','candidate'),@('candidate','default'),@('default','candidate')) 'JaCoCo arm order differs'
}
function JacocoScopePlan([string]$Workload='current17',[int]$Samples=3) {
    $value=[ordered]@{comparison='JacocoScope';workload=$Workload;sourcePin='500158f732419217507c7656904b8e6aa1bcc0d6';samples=$Samples;engine='daemon';javaMajor=17;
        pairs=@(@('default','candidate'),@('candidate','default'),@('default','candidate'));reportedClasses=25;coverageCounters=750;lineRecords=333}
    AssertJacocoScopePlan $value
    return $value
}
function JacocoScopeArguments([string]$Arm) {
    $scope=switch($Arm){'default'{'*'}'candidate'{'org.springframework.samples.petclinic.*'}default{throw 'Unsupported JaCoCo arm'}}
    return "-Djacoco.instrumentation.includes=$scope"
}
function JacocoTrialPomBytes([byte[]]$Original) {
    $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Original))
    Require ($hash-in@('7979E9F7FA4123290FE657C75357FA8B54323D1F2B00A8E7C6F888E234E9D52D','7E61DF0A43D538A5404E8130A55B8085541EC8E841FCF39F81BB6D3D81DCD2F4')) 'Original pinned POM bytes differ'
    $text=[Text.Encoding]::UTF8.GetString($Original)
    if($hash-eq'7E61DF0A43D538A5404E8130A55B8085541EC8E841FCF39F81BB6D3D81DCD2F4'){$text=$text.Replace("`n","`r`n")}
    $text=$text.Replace('<jacoco.version>0.8.15</jacoco.version>',"<jacoco.version>0.8.15</jacoco.version>`n    <jacoco.instrumentation.includes>*</jacoco.instrumentation.includes>")
    $needle="            <goals>`r`n              <goal>prepare-agent</goal>`r`n            </goals>"
    Require ([regex]::Matches($text,[regex]::Escape($needle)).Count-eq1) 'Expected exactly one prepare-agent binding'
    $text=$text.Replace($needle,$needle+"`n            <configuration>`n              <includes>`n                <include>"+'${jacoco.instrumentation.includes}'+"</include>`n              </includes>`n            </configuration>")
    $bytes=[Text.Encoding]::UTF8.GetBytes($text)
    Require ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))-eq'A14A495B06D207043B9AE6B9CDE8B129357991AFD9DF0A68C94D93081E280B2F') 'Trial POM differs from audited fixture'
    return ,$bytes
}
function AssertJacocoSource([string]$Head,[string[]]$Dirty,[byte[]]$Pom,[switch]$Original) {
    Require ($Head-eq'500158f732419217507c7656904b8e6aa1bcc0d6') 'Wrong JaCoCo source pin'
    if($Original){Require ($Dirty.Count-eq0) 'Original source is dirty';$expected=@('7979E9F7FA4123290FE657C75357FA8B54323D1F2B00A8E7C6F888E234E9D52D','7E61DF0A43D538A5404E8130A55B8085541EC8E841FCF39F81BB6D3D81DCD2F4')}
    else{Require ($Dirty.Count-eq1 -and $Dirty[0]-ceq' M pom.xml') 'Unrelated source edits in JaCoCo trial';$expected=@('A14A495B06D207043B9AE6B9CDE8B129357991AFD9DF0A68C94D93081E280B2F')}
    Require ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Pom))-in$expected) 'JaCoCo common source fingerprint differs'
}
function RestoreJacocoPom([string]$Path,[byte[]]$Original) {
    AssertJacocoSource '500158f732419217507c7656904b8e6aa1bcc0d6' @() $Original -Original
    [IO.File]::WriteAllBytes($Path,$Original)
    Require ([Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))-ceq[Convert]::ToBase64String($Original)) 'Original POM byte restoration failed'
    return @{restored=$true;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Original))}
}
function JacocoSemanticElements([xml]$Xml) {
    Require ($Xml -and $Xml.DocumentElement.LocalName-eq'report') 'Missing JaCoCo report'
    $rows=@(foreach($node in $Xml.SelectNodes('/report/descendant-or-self::*')){
        if($node.LocalName-eq'sessioninfo' -and $node.ParentNode-eq$Xml.DocumentElement){continue}
        $parts=@();$current=$node
        while($current -and $current.NodeType-eq[Xml.XmlNodeType]::Element){
            $attributes=[ordered]@{};foreach($a in @($current.Attributes|Sort-Object Name)){$attributes[$a.Name]=$a.Value}
            $parts=@([ordered]@{element=$current.LocalName;attributes=$attributes})+$parts;$current=$current.ParentNode
        }
        $text=@($node.ChildNodes|Where-Object {$_.NodeType-in@([Xml.XmlNodeType]::Text,[Xml.XmlNodeType]::CDATA) -and -not[string]::IsNullOrWhiteSpace($_.Value)}|ForEach-Object Value)
        ConvertTo-Json -InputObject ([ordered]@{path=$parts;text=$text}) -Depth 30 -Compress
    })
    return @($rows|Sort-Object -CaseSensitive)
}
function JacocoReportEvidence([xml]$Xml) {
    $counters=CompleteCounters $Xml
    $classes=@($Xml.SelectNodes('/report/package/class')|ForEach-Object {$_.GetAttribute('name')}|Sort-Object -CaseSensitive)
    $lines=$Xml.SelectNodes('/report/package/sourcefile/line').Count
    Require ($classes.Count-eq25 -and $counters.Count-eq750 -and $lines-eq333) 'JaCoCo report class/counter/line universe differs'
    return @{classes=$classes;counters=$counters;lineRecords=$lines;semantics=(JacocoSemanticElements $Xml)}
}
function ClearJacocoTestOutput([string]$Project) {
    $root=(Resolve-Path -LiteralPath $Project -ErrorAction Stop).Path
    foreach($path in @([IO.Path]::GetFullPath($Project),$root)|Select-Object -Unique){
        $ancestor=$path
        while($ancestor){
            $item=Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
            Require (-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked project ancestry rejected before cleanup'
            $parent=[IO.Directory]::GetParent($ancestor)
            $ancestor=if($parent){$parent.FullName}else{$null}
        }
    }
    Require (Test-Path (Join-Path $root '.git') -PathType Container) 'Owned full project required for test-output cleanup'
    $relative=@('target/jacoco.exec','target/site/jacoco','target/surefire-reports','target/surefire')
    $paths=@(foreach($name in $relative){
        $check=$root
        foreach($part in @('')+$name.Split('/')){
            if($part){$check=Join-Path $check $part}
            $item=if(Test-Path -LiteralPath $check -ErrorAction Stop){Get-Item -LiteralPath $check -Force -ErrorAction Stop}else{$null}
            Require (-not$item -or -not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked test-output cleanup path rejected'
        }
        [IO.Path]::GetFullPath($check)
    })
    foreach($path in $paths){
        Require ($path.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) 'Test-output path outside project'
        if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop}
        Require (-not(Test-Path -LiteralPath $path)) 'Fresh test-output cleanup failed'
    }
    return @{project=$root;paths=$paths;readySinceMs=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();clean=$true}
}
function JacocoPreparedAgent([string]$Log,[string]$Arm,[string]$ExpectedExec) {
    $scope=(JacocoScopeArguments $Arm).Substring('-Djacoco.instrumentation.includes='.Length)
    $lines=@([regex]::Matches($Log,'(?m)^.*?argLine set to ([^\r\n]+)\r?$'))
    Require ($lines.Count-eq1) 'Exactly one prepared JaCoCo agent line required'
    $line=$lines[0].Groups[1].Value.Trim().Trim('"')
    $match=[regex]::Match($line,'^-javaagent:(.+org\.jacoco\.agent-0\.8\.15-runtime\.jar)=(.+)$')
    Require $match.Success 'Unknown prepared agent/runtime options'
    $options=@{}
    foreach($entry in $match.Groups[2].Value.Split(',')){
        $pair=$entry.Split('=',2)
        Require ($pair.Count-eq2 -and $pair[0]-cin@('destfile','includes') -and -not$options.ContainsKey($pair[0])) 'Unknown/duplicate prepared agent option'
        $options[$pair[0]]=$pair[1]
    }
    Require ($ExpectedExec -and $options.ContainsKey('destfile')) 'Expected execution-data destination required'
    Require ($options.destfile.Replace('\\','\').Replace('\','/')-ceq$ExpectedExec.Replace('\','/')) 'Prepared agent destination differs'
    if($options.ContainsKey('includes')){Require ($options.includes-ceq$scope) 'Prepared agent scope differs'}
    else{Require ($Arm-eq'default') 'Candidate requires explicit prepared includes'}
    return @{line=$line;declaredIncludes=$(if($options.ContainsKey('includes')){$options.includes}else{$null});implicitAll=(!$options.ContainsKey('includes'));osArgvObserved=$false;provenance='Maven prepare-agent declaration, not OS JVM argv'}
}
function JacocoExecEvidence([byte[]]$Data,[string]$Arm) {
    $null=JacocoScopeArguments $Arm
    $memory=[IO.MemoryStream]::new($Data);$reader=[IO.BinaryReader]::new($memory)
    function Take([int]$Count){$bytes=$reader.ReadBytes($Count);Require ($bytes.Length-eq$Count) 'Truncated JaCoCo exec';return ,$bytes}
    function Utf(){ $n=([int]$reader.ReadByte()-shl8)-bor[int]$reader.ReadByte();return [Text.UTF8Encoding]::new($false,$true).GetString((Take $n)) }
    function Long(){ $bytes=Take 8;[Array]::Reverse($bytes);return [BitConverter]::ToInt64($bytes,0) }
    $headers=0;$sessions=@();$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    try{
        Require ($memory.Length-ge5) 'Truncated JaCoCo exec header'
        Require ($reader.ReadByte()-eq1) 'JaCoCo exec header must be first'
        Require ([Convert]::ToHexString((Take 4))-ceq'C0C01007') 'Unsupported JaCoCo exec header'
        $headers=1
        while($memory.Position-lt$memory.Length){
            switch($reader.ReadByte()){
                1 {throw 'Unexpected later JaCoCo exec header'}
                16 {$sessions+=@{id=(Utf);start=(Long);dump=(Long)}}
                17 {
                    $null=Take 8;$name=Utf;Require ($names.Add($name)) 'Duplicate JaCoCo execution class'
                    $length=0;$shift=0
                    do{$value=$reader.ReadByte();Require ($shift-le28) 'Invalid JaCoCo probe count';$length=$length-bor(($value-band127)-shl$shift);$shift+=7}while($value-band128)
                    Require ($length-ge0) 'Invalid JaCoCo probe count';$null=Take ([int][math]::Ceiling($length/8.0))
                }
                default {throw 'Unknown JaCoCo exec block'}
            }
        }
        Require ($headers-eq1 -and $sessions.Count-eq1 -and $names.Count-gt0) 'One populated JaCoCo execution session required'
        $outside=@($names|Where-Object {-not$_.StartsWith('org/springframework/samples/petclinic/',[StringComparison]::Ordinal)}).Count
        Require ($names.Count-gt$outside) 'No application execution records'
        if($Arm-eq'candidate'){Require ($outside-eq0) 'Candidate execution records outside app prefix'}
        else{Require ($outside-gt0) 'Default external execution records not observed'}
        return @{arm=$Arm;session=$sessions[0];records=$names.Count;externalRecords=$outside;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Data));observedScope=$true;universalClassCoverageProven=$false;provenance='Observed names/session in retained exec format 0x1007; strict UTF8 names, unsupported encoding rejects'}
    }finally{$reader.Dispose();$memory.Dispose()}
}
function JacocoPostExitEvidence([string]$Log,[xml]$Report,[xml]$Properties,$Context,$ExecEvidence) {
    Require ($Report -and $Properties -and $Context.runtime -and $null-ne$Context.caseStart -and $null-ne$Context.caseEnd -and $Context.caseStart-ge0 -and $Context.caseEnd-ge$Context.caseStart) 'Missing report/runtime or invalid case bounds'
    $sessions=@($Report.SelectNodes('/report/sessioninfo|/sessioninfo'))
    Require ($sessions.Count-eq1) 'Exactly one fresh report session required'
    $node=$sessions[0];$start=0L;$dump=0L;$id=$node.GetAttribute('id')
    Require ($id -and [long]::TryParse($node.GetAttribute('start'),[ref]$start) -and [long]::TryParse($node.GetAttribute('dump'),[ref]$dump)) 'Invalid report session'
    Require ($start-ge$Context.caseStart -and $dump-le$Context.caseEnd -and $dump-ge$start) 'Session outside fresh case bounds'
    Require ($Context.seenSessions -cnotcontains$id) 'Previously seen JaCoCo session'
    $matches=@([regex]::Matches($Log,'(?m)^.*?(?<stamp>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+(?:Z|[+-]\d\d:\d\d))[^\r\n]*\bStarting [^\r\n]*\bwith PID (?<pid>\d+)\b'))
    $pids=@($matches|ForEach-Object {[long]$_.Groups['pid'].Value}|Sort-Object -Unique)
    Require ($pids.Count-eq1 -and $pids[0]-gt0) 'Exactly one timestamped reported test PID required'
    foreach($m in $matches){
        $time=[DateTimeOffset]::Parse($m.Groups['stamp'].Value,[Globalization.CultureInfo]::InvariantCulture).ToUnixTimeMilliseconds()
        Require ($time-ge$start -and $time-le$dump) 'Startup PID witness outside report session'
    }
    foreach($prior in $Context.seenForks){
        if($prior.reportedPid-eq$pids[0]){Require ($dump-lt$prior.session.start -or $start-gt$prior.session.dump) 'Reported PID/session collision'}
    }
    $profile=[ordered]@{}
    foreach($pair in @(@('home','java.home'),@('version','java.version'),@('runtime','java.runtime.version'),@('vendor','java.vendor'),@('arch','os.arch'))){
        $values=@($Properties.SelectNodes("//property[@name='$($pair[1])']")|ForEach-Object {$_.GetAttribute('value')}|Sort-Object -Unique)
        Require ($values.Count-eq1) 'Ambiguous/missing fork runtime property';$profile[$pair[0]]=$values[0]
    }
    AssertRuntime $profile $Context.runtime 'Reported test fork'
    $prepared=JacocoPreparedAgent $Log $Context.arm $Context.execPath
    if($ExecEvidence){Require ($ExecEvidence.arm-eq$Context.arm -and $ExecEvidence.session.id-ceq$id -and $ExecEvidence.session.start-eq$start -and $ExecEvidence.session.dump-eq$dump) 'Exec/report session or arm mismatch'}
    if($Context.arm-eq'candidate'){
        Require ($ExecEvidence -and $ExecEvidence.observedScope -and $ExecEvidence.externalRecords-eq0) 'Candidate observed exec scope required'
        Require $Context.referenceSemantics 'Candidate baseline report semantics required'
        $coverage=JacocoReportEvidence $Report
        Same $coverage.semantics $Context.referenceSemantics 'Candidate application report semantics differ'
    }
    return @{reportedPid=$pids[0];startupRecords=$matches.Count;session=@{id=$id;start=$start;dump=$dump};runtime=$profile;preparedAgent=$prepared;executionData=$ExecEvidence;
        osProcessCreationObserved=$false;osArgvObserved=$false;provenance='PID from raw Spring startup log; session from report/optional exec. Repeated contexts are not forks; booter tokens are not PID or creation time.'}
}
function RetainRawMetadata($Archive,[string[]]$Names,[string]$Destination) {
    New-Item $Destination -ItemType Directory -Force|Out-Null
    $records=@()
    foreach($name in $Names){
        $entries=@($Archive.Entries|Where-Object {$_.FullName-ceq$name})
        $record=[ordered]@{entry=$name;required=$true;matches=$entries.Count;status='pending';rawPath=$null;bytes=$null;sha256=$null;error=$null}
        if($entries.Count-eq0){$record.status='absent';$record.error="Missing required packaged $name"}
        elseif($entries.Count-ne1){$record.status='duplicate';$record.error="Duplicate required packaged $name"}
        elseif($entries[0].Length-eq0){$record.status='empty';$record.bytes=0;$record.error="Empty required packaged $name"}
        else{
            try{
                $stream=$entries[0].Open();$memory=[IO.MemoryStream]::new()
                try{$stream.CopyTo($memory);$bytes=$memory.ToArray()}finally{$stream.Dispose();$memory.Dispose()}
                $record.bytes=$bytes.Length
                Require ($bytes.Length-gt0) "Empty actual required packaged $name (declared $($entries[0].Length) bytes)"
                Require ($bytes.Length-eq$entries[0].Length) "Required packaged $name length mismatch: declared $($entries[0].Length), actual $($bytes.Length)"
                $record.rawPath=('{0:D2}-{1}.raw'-f($records.Count+1),[IO.Path]::GetFileName($name))
                [IO.File]::WriteAllBytes((Join-Path $Destination $record.rawPath),$bytes)
                $record.sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
                $record.status='retained'
            }catch{$record.status='error';$record.error="Failed retaining packaged ${name}: $($_.Exception.Message)"}
        }
        $records+=,$record
    }
    $failed=@($records|Where-Object status -ne 'retained')
    $manifest=[ordered]@{status=$(if($failed.Count){'FAIL'}else{'PASS'});directory=$Destination;hashAlgorithm='SHA256';representation='exact unmodified entry bytes';entries=$records}
    $manifest|ConvertTo-Json -Depth 6|Set-Content (Join-Path $Destination 'manifest.json') -Encoding utf8
    Require ($failed.Count-eq0) (($failed|ForEach-Object error)-join'; ')
    return $manifest
}
function CompleteArtifactSignature($Value) {
    ConvertTo-Json -InputObject $Value -Depth 40 -Compress -WarningAction Stop
}
function SameCompleteArtifact($Actual,$Expected,[string]$Message) {
    Require ((CompleteArtifactSignature $Actual)-ceq(CompleteArtifactSignature $Expected)) $Message
}
function ReadCompleteArtifact([string]$Jar,[string]$Main,[string]$Tests,[string]$Destination) {
    $roles=@('META-INF/MANIFEST.MF','META-INF/build-info.properties','BOOT-INF/classes/git.properties','META-INF/sbom/application.cdx.json','META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml','META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties')
    if($Destination){Require (-not(Test-Path $Destination)) 'Fresh complete-artifact directory required';New-Item $Destination -ItemType Directory|Out-Null}
    Require ((Test-Path $Jar -PathType Leaf)-and-not((Get-Item $Jar -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Missing/linked complete JAR'
    [byte[]]$jarBytes=[IO.File]::ReadAllBytes($Jar)
    $memory=[IO.MemoryStream]::new($jarBytes,$false);$zip=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Read)
    $entries=@();$metadata=@();$loose=@();$raw=[Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
    try {
        foreach($entry in $zip.Entries){
            $name=$entry.FullName
            Require ($name-and$name-notmatch'(^/|\\|:|(^|/)\.\.?(/|$))'-and-not$raw.ContainsKey($name)) 'Unsafe or duplicate physical JAR entry'
            $stream=$entry.Open();$buffer=[IO.MemoryStream]::new()
            try{$stream.CopyTo($buffer);[byte[]]$bytes=$buffer.ToArray()}finally{$stream.Dispose();$buffer.Dispose()}
            Require ($bytes.Length-eq$entry.Length) 'Physical entry length mismatch'
            $raw.Add($name,$bytes);$entries+=,[ordered]@{name=$name;bytes=$bytes.Length;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))}
        }
        Require ($entries.Count-eq330-and@($entries|Where-Object{$_.name-like'BOOT-INF/classes/*.class'}).Count-eq30-and@($entries|Where-Object{$_.name-like'BOOT-INF/lib/*.jar'}).Count-eq93) 'Current17 complete JAR universe mismatch'
        foreach($name in $roles){
            Require ($raw.ContainsKey($name)-and$raw[$name].Length-gt0) 'Missing/empty complete raw metadata role'
            $row=$entries|Where-Object name -CEQ $name
            $path=('{0:D2}.raw'-f($metadata.Count+1));$metadata+=,[ordered]@{entry=$name;rawPath=$path;bytes=$row.bytes;sha256=$row.sha256}
            if($Destination){[IO.File]::WriteAllBytes((Join-Path $Destination $path),$raw[$name])}
        }
        Require ([Text.Encoding]::UTF8.GetString($raw[$roles[2]])-match'(?m)^git.commit.id=500158f732419217507c7656904b8e6aa1bcc0d6\r?$') 'Complete artifact source pin mismatch'
        Require ([Text.Encoding]::UTF8.GetString($raw[$roles[2]])-match'(?m)^git.dirty=false\r?$') 'Complete artifact source dirty'
        $pomHash=($metadata|Where-Object entry -CEQ $roles[4]).sha256
        Require ($pomHash-in@('7979E9F7FA4123290FE657C75357FA8B54323D1F2B00A8E7C6F888E234E9D52D','7E61DF0A43D538A5404E8130A55B8085541EC8E841FCF39F81BB6D3D81DCD2F4')) 'Complete current17 POM mismatch'
        $bom=[Text.Encoding]::UTF8.GetString($raw[$roles[3]])|ConvertFrom-Json -AsHashtable
        $refs=@($bom.components|ForEach-Object{$_['bom-ref']})+@($bom.metadata.component['bom-ref'])
        Require ($bom.components.Count-eq106-and$bom.dependencies.Count-eq107-and@($refs|Sort-Object -Unique).Count-eq107) 'Complete SBOM component/reference universe mismatch'
        Require (@($bom.dependencies.ref|Sort-Object -Unique).Count-eq107) 'Duplicate/missing SBOM graph reference'
        foreach($node in $bom.dependencies){Require ($node.ref-cin$refs) 'Unknown SBOM node';foreach($dependency in $node.dependsOn){Require ($dependency-cin$refs) 'Dangling SBOM edge'}}
        foreach($scope in 'main','test'){
            $folder=if($scope-eq'main'){$Main}else{$Tests}
            Require ((Test-Path $folder -PathType Container)-and-not((Get-Item $folder -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Missing/linked loose root'
            $files=@(Get-ChildItem $folder -Recurse -Force)
            Require (-not@($files|Where-Object{$_.Attributes-band[IO.FileAttributes]::ReparsePoint}).Count) 'Linked loose artifact'
            $files=@($files|Where-Object{-not$_.PSIsContainer}|Sort-Object FullName)
            Require (@($files|Where-Object Extension -CEQ '.class').Count-eq$(if($scope-eq'main'){30}else{28})) 'Current17 loose class universe mismatch'
            foreach($file in $files){
                [byte[]]$bytes=[IO.File]::ReadAllBytes($file.FullName);$name=[IO.Path]::GetRelativePath($folder,$file.FullName).Replace('\','/')
                if($file.Extension-ceq'.class'){Require ($bytes.Length-ge8-and[BitConverter]::ToString($bytes,0,4)-ceq'CA-FE-BA-BE'-and$bytes[6]-eq0-and$bytes[7]-eq61) 'Loose class target differs'}
                $binding=if($scope-eq'main'-and$raw.ContainsKey("BOOT-INF/classes/$name")){"BOOT-INF/classes/$name"}elseif($scope-eq'main'-and$raw.ContainsKey($name)){$name}else{''}
                $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
                if($scope-eq'main'){Require ($binding-and$hash-ceq($entries|Where-Object name -CEQ $binding).sha256) 'Loose resource/class is not bound to JAR bytes'}
                $loose+=,[ordered]@{scope=$scope;name=$name;bytes=$bytes.Length;sha256=$hash;binding=$binding}
                if($Destination){$target=Join-Path $Destination "loose/$scope/$name";New-Item (Split-Path $target) -ItemType Directory -Force|Out-Null;[IO.File]::WriteAllBytes($target,$bytes)}
            }
        }
        $contract=[ordered]@{schema='portable-complete-v1';sourcePin='500158f732419217507c7656904b8e6aa1bcc0d6';jarSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($jarBytes));entries=@($entries|Sort-Object name);loose=$loose;metadata=$metadata;sbomGraph=[ordered]@{components=@($bom.components|Sort-Object 'bom-ref');dependencies=@($bom.dependencies|Sort-Object ref)}}
        $serialized=CompleteArtifactSignature $contract
        if($Destination){[IO.File]::WriteAllBytes((Join-Path $Destination 'application.jar'),$jarBytes);$serialized|Set-Content (Join-Path $Destination 'complete.json') -Encoding utf8}
        return $contract
    }finally{$zip.Dispose();$memory.Dispose()}
}
function CompareCompleteArtifacts([string]$Left,[string]$Right,[ValidateSet('SameHost','CrossHost')][string]$Scope='SameHost') {
    $actual=@()
    foreach($directory in @($Left,$Right)){
        SameCompleteArtifact @((Get-ChildItem $directory -File).Name|Sort-Object) @(@('application.jar','complete.json')+@(1..6|ForEach-Object{'{0:D2}.raw'-f$_})|Sort-Object) 'Complete retained file universe mismatch'
        $saved=Get-Content (Join-Path $directory 'complete.json') -Raw|ConvertFrom-Json -AsHashtable
        $null=CompleteArtifactSignature $saved
        $observed=ReadCompleteArtifact (Join-Path $directory 'application.jar') (Join-Path $directory 'loose/main') (Join-Path $directory 'loose/test')
        SameCompleteArtifact $saved $observed 'Complete schema/digest/inventory binding mismatch'
        foreach($role in $observed.metadata){[byte[]]$bytes=[IO.File]::ReadAllBytes((Join-Path $directory $role.rawPath));Require ($bytes.Length-eq$role.bytes-and[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))-ceq$role.sha256) 'Retained raw metadata binding mismatch'}
        $actual+=,$observed
    }
    if($Scope-eq'SameHost'){SameCompleteArtifact $actual[0] $actual[1] 'Same-host complete artifact bytes differ';return @{status='PASS';scope=$Scope;differences=@()}}
    SameCompleteArtifact $actual[0].sbomGraph $actual[1].sbomGraph 'Meaningful complete SBOM graph differs'
    $roles=@($actual[0].metadata.entry)
    SameCompleteArtifact @($actual[0].entries|Where-Object{$_.name-cnotin$roles}) @($actual[1].entries|Where-Object{$_.name-cnotin$roles}) 'Cross-host payload/resource/dependency differs'
    SameCompleteArtifact @($actual[0].loose|Where-Object{$_.binding-cnotin$roles}) @($actual[1].loose|Where-Object{$_.binding-cnotin$roles}) 'Cross-host loose payload differs'
    $differences=@(for($i=0;$i-lt6;$i++){if($actual[0].metadata[$i].sha256-cne$actual[1].metadata[$i].sha256){$roles[$i]}})
    if($differences.Count){return @{status='UNKNOWN';scope=$Scope;differences=$differences;reason='Raw cross-host metadata differs; exact field/value allowlist requires independent evidence/review; no exclusions applied'}}
    if($actual[0].jarSha256-cne$actual[1].jarSha256){return @{status='UNKNOWN';scope=$Scope;differences=@('ZIP container bytes');reason='All entry/raw/loose bytes equal, but exact ZIP-field classification is unreviewed; raw JARs retained'}}
    return @{status='PASS';scope=$Scope;differences=@()}
}
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
    $mode=if($Windows.plan.comparison){$Windows.plan.comparison}else{'MavenVsDaemon'}
    $otherMode=if($Mac.plan.comparison){$Mac.plan.comparison}else{'MavenVsDaemon'}
    Require ($mode-eq$otherMode) 'Cross-OS comparison mode mismatch'
    if($mode-eq'MixedClientPackage'){return @{status='UNKNOWN';comparison=$mode;reason='Fresh paired complete raw6/ZIP cross-host classification is not approved; no metadata exceptions applied'}}
    Require ($mode-in@('MavenVsDaemon','JacocoScope')) 'Unsupported comparison evidence mode'
    foreach($field in 'sourcePin','javaMajor','workload','mavenCore','loopbackTests'){Same $Windows.plan.$field $Mac.plan.$field "Cross-OS $field mismatch"}
    Same $Windows.deviations $Mac.deviations 'Cross-OS declared workload deviations differ'
    Same $Windows.javaIdentity $Mac.javaIdentity 'Native JDK vendor/runtime version mismatch'
    Same $Windows.mavenCoreSha256 $Mac.mavenCoreSha256 'Bundled Maven core bytes mismatch'
    Same $Windows.correctness.tests $Mac.correctness.tests 'Cross-OS test identity/status mismatch'
    Same $Windows.correctness.coverage $Mac.correctness.coverage 'Cross-OS complete coverage mismatch'
    Same $Windows.correctness.classes $Mac.correctness.classes 'Cross-OS application bytecode mismatch'
    Same $Windows.correctness.testClasses $Mac.correctness.testClasses 'Cross-OS test bytecode mismatch'
    Same $Windows.correctness.dependencies $Mac.correctness.dependencies 'Cross-OS dependency bytes mismatch'
    if($mode-eq'JacocoScope'){
        Require ($Windows.correctness.reportSemantics -and $Mac.correctness.reportSemantics) 'Full JaCoCo semantics absent'
        Same $Windows.correctness.reportSemantics $Mac.correctness.reportSemantics 'Cross-OS full reported coverage differs'
        $wd=Median $Windows.test.default;$wc=Median $Windows.test.candidate;$md=Median $Mac.test.default;$mc=Median $Mac.test.candidate
        return [ordered]@{comparison=$mode;windowsDefaultTest=$wd;windowsCandidateTest=$wc;macDefaultTest=$md;macCandidateTest=$mc;
            windowsSavedSeconds=$wd-$wc;macSavedSeconds=$md-$mc;defaultWindowsMinusMac=$wd-$md;candidateWindowsMinusMac=$wc-$mc;
            defaultWindowsToMac=$wd/$md;candidateWindowsToMac=$wc/$mc;wholeJarBytesEqual=($Windows.correctness.jarSha256-eq$Mac.correctness.jarSha256);
            limitation='Test-only candidate screen; package parity unmeasured. Unequal hosted hardware; local or common gains do not imply relative parity. Unreported third-party exec records intentionally omitted; no normalization.'}
    }
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
    function RunJacocoScopeCase([string]$Name,[string]$Arm,[string[]]$Goals,[bool]$Timed) {
        $fresh=ClearJacocoTestOutput $ProjectFullClone
        $phase=Run $Name 'daemon' (@((JacocoScopeArguments $Arm))+$Goals) $Timed
        $completed=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $phase.arm=$Arm;$phase.preparedScope=JacocoScopeArguments $Arm
        if($Timed){$result.test[$Arm]+=,$phase.seconds}
        $exec=Join-Path $ProjectFullClone 'target/jacoco.exec'
        Require (Test-Path $exec) 'Fresh execution data missing'
        $data=JacocoExecEvidence ([IO.File]::ReadAllBytes($exec)) $Arm
        if($Timed){$null=Run "$Name-report" 'daemon' @((JacocoScopeArguments $Arm),'jacoco:report') $false}
        $reportPath=Join-Path $ProjectFullClone 'target/site/jacoco/jacoco.xml'
        Require (Test-Path $reportPath) 'Fresh coverage report missing'
        [xml]$report=Get-Content $reportPath -Raw
        $files=@(Get-ChildItem (Join-Path $ProjectFullClone 'target/surefire-reports') -Filter 'TEST-*.xml'|Sort-Object Name)
        Require ($files.Count-gt0) 'Fresh Surefire output missing'
        [xml]$properties=Get-Content $files[0].FullName -Raw
        $reference=@(if($result.snapshots.Count){$result.snapshots[0].reportSemantics})
        $context=@{caseStart=$fresh.readySinceMs;caseEnd=$completed;runtime=$result.selectedRuntime;arm=$Arm;execPath=$exec;
            seenSessions=@($result.jacoco.freshness|ForEach-Object {$_.session.id});seenForks=@($result.jacoco.freshness);referenceSemantics=$reference}
        $proof=JacocoPostExitEvidence (Get-Content (Join-Path $OutputDirectory "$Name.log") -Raw) $report $properties $context $data
        $result.jacoco.freshness+=,$proof
        Copy-Item $exec (Join-Path $OutputDirectory "$Name-jacoco.exec")
        Copy-Item $reportPath (Join-Path $OutputDirectory "$Name-coverage.xml")
        Copy-Item (Join-Path $ProjectFullClone 'target/surefire-reports') (Join-Path $OutputDirectory "$Name-surefire") -Recurse
        SourceGate;Snapshot $Name $true
        $result.snapshots[-1].arm=$Arm
        $proof|ConvertTo-Json -Depth 15|Set-Content (Join-Path $OutputDirectory "$Name-freshness.json")
        Save
    }
    function PrepareJacocoScope {
        foreach($arm in 'default','candidate'){RunJacocoScopeCase "$arm-prep" $arm @('clean','verify') $false}
    }
    function MeasureJacocoScope {
        foreach($pair in 0..($Samples-1)){foreach($arm in $plan.pairs[$pair]){
            RunJacocoScopeCase "pair-$($pair+1)-$arm-test" $arm @('test') $true
        }}
    }
    function RestoreComparisonPom {
        if($originalPomBytes){
            try{
                $result.sourceRestoration=RestoreJacocoPom (Join-Path $ProjectFullClone 'pom.xml') $originalPomBytes
                $script:trialPomHash=$null
                SourceGate
            }catch{$result.status='FAIL';$result.restorationFailure=$_.ToString()}
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
if($Comparison-eq'MixedClientPackage'){MixedClientPlan $plan $Workload $Samples}
if($Comparison-eq'JacocoScope'){
    $scopePlan=JacocoScopePlan $Workload $Samples
    $plan.comparison='JacocoScope';$plan.pairs=$scopePlan.pairs;$plan.Remove('stock');$plan.arms=@('default','candidate')
    $plan.phases=@('untimed default/candidate clean verify and full package proof','fresh owned test outputs outside timer','timed mvnd test','untimed report, complete fidelity and session/exec audit')
}
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
$originalPomBytes=$null;$trialPomHash=$null
if($Comparison-eq'JacocoScope'){$result.comparison='JacocoScope';$result.test=@{default=@();candidate=@()};$result.package=@{};$result.jacoco=@{freshness=@()}}
$sourcePushed=$false
$vars=@('JAVA_HOME','MVND_HOME','MVND_CLIENT','MVND_DAEMON_STORAGE','MAVEN_SKIP_RC','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','PATH')
$saved=@{};foreach($n in $vars){$saved[$n]=[Environment]::GetEnvironmentVariable($n)}
function Save { if($Comparison-eq'MixedClientPackage'){CompleteArtifactSignature $result|Set-Content (Join-Path $OutputDirectory 'result.json') -Encoding utf8}else{$result|ConvertTo-Json -Depth 30|Set-Content (Join-Path $OutputDirectory 'result.json') -Encoding utf8} }
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
    $dirty=@(& git -C $ProjectFullClone status --porcelain --untracked-files=all);NativeCode $LASTEXITCODE 'Git status'
    if($Comparison-eq'JacocoScope' -and $trialPomHash){AssertJacocoSource $head $dirty ([IO.File]::ReadAllBytes((Join-Path $ProjectFullClone 'pom.xml')))}
    else{Require ($dirty.Count-eq0) 'Measured source is dirty'}
}
function Run([string]$Name,[string]$Engine,[string[]]$Goals,[bool]$Timed,[ValidateSet('jvm','native')][string]$ClientMode,[switch]$OwnedCleanup) {
    if($OwnedCleanup){Require ($ClientMode-and$expectedDaemon-and(OwnedIdentityMatches (ReadDaemonIdentity $expectedDaemon.pid) $expectedDaemon)-and$Goals.Count-eq1-and$Goals[0]-ceq'--stop') 'Owned cleanup admission rejected'}else{SourceGate}
    $exe=if($Engine-eq'daemon'){$plan.candidate}else{$plan.stock}
    $args=@(CommonMavenArguments $LocalCache $settings (Join-Path $ProjectFullClone 'pom.xml') ([bool]$LoopbackTests))
    if($Engine-eq'daemon'){$args+=@("-Dmvnd.daemonStorage=$registry",'--serial')}
    if($ClientMode){Require ($Comparison-ceq'MixedClientPackage'-and$Engine-ceq'daemon') 'Client route outside mixed mode';$env:MVND_CLIENT=$ClientMode;$args+=,"-Djava.home=$JavaHome"}
    $args+=$Goals;$log=Join-Path $OutputDirectory "$Name.log"
    $beforeMs=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $watch=[Diagnostics.Stopwatch]::StartNew();if($ClientMode){$code=InvokePortableProcess $exe $args $log}else{& $exe @args *> $log;$code=$LASTEXITCODE};$watch.Stop()
    $phase=[ordered]@{name=$Name;engine=$Engine;timed=$Timed;seconds=$watch.Elapsed.TotalSeconds;exitCode=$code;launcher=$exe;arguments=$args;workingDirectory=(Get-Location).Path;log=$log}
    if($ClientMode){$phase.beforeMs=$beforeMs;$phase.afterMs=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$phase.clientMode=$ClientMode}
    $result.phases+=,$phase;Save;NativeCode $code $Name
    if(-not$ClientMode -and $Engine-eq'daemon' -and $Goals -notcontains '--version' -and $Goals -notcontains '--status'){
        $tag=[regex]::Match((Get-Content $log -Raw),'Processing build on daemon ([a-f0-9]+)').Groups[1].Value
        Require $tag 'Actual daemon ID missing from invocation log'
        if($script:daemonTag){Require ($tag-eq$script:daemonTag) 'Daemon reuse changed'}else{$script:daemonTag=$tag}
        $phase.daemonId=$tag
    }
    return $phase
}
function Snapshot([string]$Name,[bool]$WithTests,[switch]$CompleteArtifact) {
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
        $rawMetadata=RetainRawMetadata $zip @('META-INF/MANIFEST.MF','META-INF/build-info.properties','BOOT-INF/classes/git.properties','META-INF/sbom/application.cdx.json','META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties') (Join-Path $OutputDirectory "$Name-raw-metadata")
        $metadata=[ordered]@{}
        foreach($path in 'META-INF/MANIFEST.MF','META-INF/build-info.properties','BOOT-INF/classes/git.properties','META-INF/sbom/application.cdx.json'){
            $e=$zip.GetEntry($path);Require ($e -and $e.Length-gt0) "Missing required packaged $path"
            $reader=[IO.StreamReader]::new($e.Open());try{$metadata[$path]=$reader.ReadToEnd()}finally{$reader.Dispose()}
        }
        $dirtyValue=if($Comparison-eq'JacocoScope'){'true'}else{'false'}
        $git=$metadata['BOOT-INF/classes/git.properties'];Require ($git-match"(?m)^git.commit.id=$($plan.sourcePin)\r?$" -and $git-match"(?m)^git.dirty=$dirtyValue\r?$") 'Packaged Git metadata mismatch'
        if($Comparison-eq'JacocoScope'){
            $pomEntry=$zip.GetEntry('META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml');Require $pomEntry 'Packaged trial POM missing'
            $s=$pomEntry.Open();try{$pomHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($s))}finally{$s.Dispose()}
            Require ($pomHash-eq$trialPomHash) 'Packaged shared trial POM differs'
        }
        $testClasses=[ordered]@{};$testRoot=Join-Path $ProjectFullClone 'target/test-classes'
        foreach($file in @(Get-ChildItem $testRoot -Filter '*.class' -Recurse -File|Sort-Object FullName)){
            $testClasses[$file.FullName.Substring($testRoot.Length).TrimStart([char[]]'\/').Replace('\','/')]=(Get-FileHash $file.FullName).Hash
        }
        Require ($testClasses.Count-gt0) 'Test compilation output missing'
        $snapshot=[ordered]@{name=$Name;jarSha256=(Get-FileHash $jar[0].FullName).Hash;classes=$classes;testClasses=$testClasses;dependencies=$deps;inventory=$inventory;metadata=$metadata;rawMetadata=$rawMetadata;sbomMode='online generated and packaged; never offline reduced workload'}
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
            if($Comparison-eq'JacocoScope'){$snapshot.reportSemantics=(JacocoReportEvidence ([xml](Get-Content (Join-Path $ProjectFullClone 'target/site/jacoco/jacoco.xml') -Raw))).semantics}
        }
        if($result.snapshots.Count){
            Same $classes $result.snapshots[0].classes 'Application class bytes changed'
            Same $testClasses $result.snapshots[0].testClasses 'Test class bytes changed'
            Same $deps $result.snapshots[0].dependencies 'Dependencies changed'
            Require ($snapshot.jarSha256-eq$result.snapshots[0].jarSha256) 'Whole JAR changed within host; no normalization allowed'
            if($WithTests){Same $snapshot.tests $result.snapshots[0].tests 'Test identities/statuses changed';Same $snapshot.coverage $result.snapshots[0].coverage 'Complete coverage changed'}
            if($Comparison-eq'JacocoScope'){Same $snapshot.reportSemantics $result.snapshots[0].reportSemantics 'Full JaCoCo semantic report changed'}
        }
        if($CompleteArtifact){
            Require ($Workload-ceq'current17'-and$Comparison-ceq'MixedClientPackage') 'Complete capture reserved for current17 mixed-client mode'
            $snapshot.completeArtifact=ReadCompleteArtifact $jar[0].FullName (Join-Path $ProjectFullClone 'target/classes') (Join-Path $ProjectFullClone 'target/test-classes') (Join-Path $OutputDirectory "$Name-complete")
        }
        if($CompleteArtifact){CompleteArtifactSignature $snapshot|Set-Content (Join-Path $OutputDirectory "$Name-artifact.json") -Encoding utf8}else{$snapshot|ConvertTo-Json -Depth 30|Set-Content (Join-Path $OutputDirectory "$Name-artifact.json")}
        $result.snapshots+=,$snapshot;Save
    }finally{$zip.Dispose()}
}
if($Comparison-eq'MixedClientPackage'){
    InvokeMixedClientPackage
    if($result.status-ne'PASS'){throw $result.failure}
    return
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
    if($Comparison-eq'JacocoScope'){
        $pom=Join-Path $ProjectFullClone 'pom.xml';$originalPomBytes=[IO.File]::ReadAllBytes($pom)
        AssertJacocoSource $plan.sourcePin @() $originalPomBytes -Original
        $trial=JacocoTrialPomBytes $originalPomBytes
        [IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'original-pom.xml'),$originalPomBytes)
        [IO.File]::WriteAllBytes($pom,$trial);[IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'fixed-trial-pom.xml'),$trial)
        $trialPomHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($trial))
        $result.sourceTransform=@{originalSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($originalPomBytes));trialSha256=$trialPomHash;scope='Common reviewed POM installed once; only prepare-agent binding; exact original restored finally'}
        $null=Run 'daemon-version' 'daemon' @('--version') $false
        Require ((Get-Content (Join-Path $OutputDirectory 'daemon-version.log') -Raw)-match'Maven 3\.9\.16') 'Matched Maven core 3.9.16 required'
        PrepareJacocoScope
    }else{foreach($engine in 'stock','daemon'){
        if($engine-eq'stock'){$env:MAVEN_OPTS='-XshowSettings:properties'}
        try{$null=Run "$engine-version" $engine @('--version') $false}finally{$env:MAVEN_OPTS=''}
        Require ((Get-Content (Join-Path $OutputDirectory "$engine-version.log") -Raw)-match'Maven 3\.9\.16') 'Matched Maven core 3.9.16 required'
        if($engine-eq'stock'){
            $result.stockRuntime=RuntimeProfile (Get-Content (Join-Path $OutputDirectory "$engine-version.log") -Raw)
            AssertRuntime $result.stockRuntime $result.selectedRuntime 'Actual stock Maven VM'
        }
        $null=Run "$engine-prep" $engine @('clean','verify') $false;Snapshot "$engine-prep" $true
    }}
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
    if($Comparison-eq'JacocoScope'){MeasureJacocoScope}else{foreach($pair in 0..($Samples-1)){foreach($engine in $plan.pairs[$pair]){
        $name="pair-$($pair+1)-$engine";$null=Run "$name-clean" $engine @('clean') $false
        $p=Run "$name-package" $engine @('-DskipTests','package') $true;$result.package[$engine]+=,$p.seconds;Snapshot "$name-package" $false
        $exec=Join-Path $ProjectFullClone 'target/jacoco.exec';if(Test-Path $exec){Remove-Item $exec}
        $t=Run "$name-test" $engine @('test') $true;$result.test[$engine]+=,$t.seconds
        Require ((Test-Path $exec) -and (Get-Item $exec).Length-gt0) 'Fresh JaCoCo execution data absent'
        $null=Run "$name-coverage" $engine @('jacoco:report') $false
        Copy-Item (Join-Path $ProjectFullClone 'target/site/jacoco/jacoco.xml') (Join-Path $OutputDirectory "$name-coverage.xml")
        Copy-Item (Join-Path $ProjectFullClone 'target/surefire-reports') (Join-Path $OutputDirectory "$name-surefire") -Recurse
        Snapshot "$name-test" $true
    }}}
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
    finally{RestoreComparisonPom;if($sourcePushed){Pop-Location};foreach($n in $vars){[Environment]::SetEnvironmentVariable($n,$saved[$n])};Save}
}
if($result.status-ne'PASS'){throw ((@($result.failure,$result.cleanupFailure,$result.restorationFailure)|Where-Object {$_})-join'; ')}
