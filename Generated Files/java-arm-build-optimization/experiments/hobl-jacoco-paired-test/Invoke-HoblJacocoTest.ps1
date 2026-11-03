param([string]$ProjectFullClone,[string]$JavaHome,[string]$LocalCache,[string]$OutputDirectory,[string]$PythonExecutable,[switch]$ExecuteAuthorized,[switch]$CandidateReviewed,[switch]$LibraryOnly)
$inputs=@{ProjectFullClone=$ProjectFullClone;JavaHome=$JavaHome;LocalCache=$LocalCache;OutputDirectory=$OutputDirectory;PythonExecutable=$PythonExecutable;ExecuteAuthorized=$ExecuteAuthorized;CandidateReviewed=$CandidateReviewed;LibraryOnly=$LibraryOnly}
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
$base=(Resolve-Path "$PSScriptRoot\..\hobl-contract\Invoke-HoblContract.ps1").ProviderPath
if((Get-FileHash $base).Hash-ne'42431D527726E18D52091A00FF4DAE38CE28110F8F43CC1E89A58E05F49A3CB2'){throw 'HOBL donor changed'}
if((Get-FileHash "$PSScriptRoot\HoblJacocoContract.psm1").Hash-ne'3428BB2747D3EC16A5A62DCD443881886E94BA26BC642374836C89F0201A03EC'){throw 'Accepted contract changed'}
if((Get-FileHash "$PSScriptRoot\Read-HoblExec.py").Hash-ne'4D25DB06B17285EDB7C9F5056DBAB67568D3C1D4992D2AE074A305A1C6B5C64A'){throw 'Accepted parser changed'}
Import-Module "$PSScriptRoot\HoblJacocoContract.psm1" -Force -DisableNameChecking
. $base -LibraryOnly
foreach($kv in $inputs.GetEnumerator()){Set-Variable $kv.Key $kv.Value}
$tokens=$null;$errors=$null;$donor=[Management.Automation.Language.Parser]::ParseFile($base,[ref]$tokens,[ref]$errors)
foreach($name in 'Phase','Snapshot'){
    $body=$donor.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true).Extent.Text
    if($name-eq'Snapshot'){$anchor="'(?m)^git\.dirty=false\r?$'";Require ($body.Contains($anchor)) 'Exact trial dirty anchor missing';$body=$body.Replace($anchor,"'(?m)^git\.dirty=true\r?$'")}
    . ([scriptblock]::Create($body))
}
function Save {$result|ConvertTo-Json -Depth 50|Set-Content (Join-Path $OutputDirectory 'result.json') -Encoding utf8}
function HoblNow {[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()}
function HoblNativePath([string]$Path){$p=Resolve-Path -LiteralPath $Path;Require ($p.Provider.Name-eq'FileSystem'-and(Test-Path $p.ProviderPath -PathType Leaf)) 'Native filesystem executable required';return $p.ProviderPath}
function HoblIdentity{
    & $script:java -XshowSettings:properties -version *> (Join-Path $OutputDirectory 'java.log');Require ($LASTEXITCODE-eq0) 'Native Java identity failed'
    $result.runtime=NativeRuntime (Get-Content (Join-Path $OutputDirectory 'java.log') -Raw)
    Require ([IO.Path]::GetFullPath($result.runtime['java.home'])-ceq[IO.Path]::GetFullPath($JavaHome)) 'Selected Java home differs'
}
function HoblJavaCandidates{
    if($IsWindows){return @(Get-Process java,javaw -ErrorAction SilentlyContinue)}
    $rows=@(& /bin/ps -axo 'pid=,command=');Require ($LASTEXITCODE-eq0) 'Process query failed';return @($rows|Where-Object {$_-match'[/ ]java(?:\s|$)'})
}
function HoblCoreIdentity{
    Require (-not(Test-Path (Join-Path $ProjectFullClone 'pwsh.exe'))) 'Project Core shadow rejected'
    $paths=@(& "$env:SystemRoot\System32\where.exe" pwsh.exe);Require ($LASTEXITCODE-eq0-and$paths.Count-gt0) 'Core unavailable; no fallback'
    $bytes=[IO.File]::ReadAllBytes($paths[0]);Require ([BitConverter]::ToUInt16($bytes,([BitConverter]::ToInt32($bytes,60)+4))-eq0xAA64) 'Native ARM64 Core required'
    $text=@(& $paths[0] -NoProfile -Command '[pscustomobject]@{edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();exe=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName}|ConvertTo-Json -Compress');Require ($LASTEXITCODE-eq0) 'Core self-query failed'
    $identity=($text-join"`n")|ConvertFrom-Json;Require ($identity.edition-ceq'Core'-and[version]$identity.version-ge[version]'7.0'-and[IO.Path]::GetFullPath($identity.exe)-ceq[IO.Path]::GetFullPath($paths[0])) 'Actual Core differs';$result.coreAvailability=$identity
}
function HoblTestArguments([ValidateSet('default','candidate')][string]$Arm,[ValidateSet('offline','verify','test','report')][string]$Goal){
    $scope=if($Arm-eq'candidate'){'org.springframework.samples.petclinic.*'}else{'*'}
    $args=@("-Dmaven.repo.local=$LocalCache",'-Dserver.address=127.0.0.1',"-Djacoco.instrumentation.includes=$scope")
    switch($Goal){offline{return $args+@('-DskipTests','dependency:go-offline')} verify{return $args+@('clean','verify')} test{return @('-o')+$args+@('test')} report{return @('-o')+$args+@('jacoco:report')}}
}
function HoblSourceCheck([bool]$Original=$false){
    $context=ReadHoblTrialContext $ProjectFullClone $script:java $script:beforeSource $script:platform
    AssertHoblTrialSource $context $script:platform -Original:$Original
}
function HoblInputHashes{
    $map=[ordered]@{}
    foreach($root in 'target/classes','target/test-classes'){
        foreach($file in @(Get-ChildItem (Join-Path $ProjectFullClone $root) -Recurse -File|Sort-Object FullName)){
            $map[[IO.Path]::GetRelativePath($ProjectFullClone,$file.FullName).Replace('\','/')]=(Get-FileHash $file.FullName).Hash
        }
    };Require ($map.Count-ge55) 'Compiled/resources inventory absent';return $map
}
function HoblCheckFrozen{Same (HoblInputHashes) $script:frozenInputs 'Compiled/resource bytes changed';Require ((Get-FileHash $script:jar).Hash-ceq$script:frozenJar) 'Frozen online JAR changed';HoblSourceCheck}
function HoblArchiveReset([string]$Name){
    $archive=Join-Path $OutputDirectory "$Name-before-reset";New-Item $archive -ItemType Directory|Out-Null
    foreach($relative in 'target/jacoco.exec','target/site/jacoco','target/surefire-reports','target/surefire'){
        $path=$ProjectFullClone
        foreach($part in $relative.Split('/')){$path=Join-Path $path $part;if(Test-Path -LiteralPath $path){Require (-not((Get-Item -LiteralPath $path -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked reset path'}}
        if(Test-Path -LiteralPath $path){
            Require (-not@(Get-ChildItem -LiteralPath $path -Recurse -Force|Where-Object {$_.Attributes-band[IO.FileAttributes]::ReparsePoint}).Count) 'Linked reset descendant'
            $destination=Join-Path $archive $relative;New-Item (Split-Path $destination) -ItemType Directory -Force|Out-Null
            Copy-Item -LiteralPath $path -Destination $destination -Recurse;Remove-Item -LiteralPath $path -Recurse -Force
        };Require (-not(Test-Path -LiteralPath $path)) 'Exact reset failed'
    }
}
function HoblTakeSnapshot([string]$Name){
    Snapshot $Name $true
    $snap=$result.snapshots[-1];AssertHoblSnapshot $snap $result.snapshots[0]
    foreach($xml in @(Get-ChildItem (Join-Path $ProjectFullClone 'target/surefire-reports') -Filter 'TEST-*.xml'|ForEach-Object {[xml](Get-Content $_.FullName -Raw)})){Require ($xml.SelectSingleNode('//properties/property[@name="server.address"]').value-ceq'127.0.0.1') 'Actual loopback missing'}
    return $snap
}
function HoblFreshEvidence([string]$Name,$Phase,[long]$Start,[long]$End,[string]$Arm){
    $dir=Join-Path $OutputDirectory $Name;$execJson=Join-Path $dir 'exec-scope.json'
    & $PythonExecutable (HoblNativePath "$PSScriptRoot\Read-HoblExec.py") (Join-Path $dir 'jacoco.exec') $Arm $execJson *> (Join-Path $dir 'exec-parser.log')
    Require ($LASTEXITCODE-eq0) 'Exec parser failed; no retry'
    $exec=Get-Content $execJson -Raw|ConvertFrom-Json
    [xml]$report=Get-Content (Join-Path $dir 'coverage.xml') -Raw
    [xml]$properties=Get-ChildItem (Join-Path $dir 'surefire') -Filter 'TEST-*.xml'|Select-Object -First 1|Get-Content -Raw
    $context=@{startMs=$Start;endMs=$End;seenPids=$script:seenPids;seenSessions=$script:seenSessions;javaHome=$JavaHome;execPath=(Join-Path $ProjectFullClone 'target/jacoco.exec')}
    $proof=AssertHoblTestExecution (Get-Content $Phase.log -Raw) $report $properties $exec $context $Arm
    $script:seenPids+=@($proof.reportedPid);$script:seenSessions+=@($proof.session.id)
    return @{freshness=$proof;execution=$exec}
}
function InvokeHoblWarmFlow{
    $script:seenPids=@();$script:seenSessions=@()
    foreach($arm in 'default','candidate'){
        HoblSourceCheck;$null=Phase "$arm-go-offline" (HoblTestArguments $arm offline)
        $start=HoblNow;$p=Phase "$arm-online-verify" (HoblTestArguments $arm verify);$end=HoblNow
        $name="$arm-online";$null=HoblTakeSnapshot $name;$evidence=HoblFreshEvidence $name $p $start $end $arm
        $result.preparations+=@{arm=$arm;evidence=$evidence}
    }
    $script:frozenInputs=HoblInputHashes;$script:jar=@(Get-ChildItem (Join-Path $ProjectFullClone 'target') -Filter '*.jar' -File)[0].FullName
    $script:frozenJar=(Get-FileHash $script:jar).Hash;$result.frozenJarSha256=$script:frozenJar;$result.frozenInputs=$script:frozenInputs
    foreach($pair in 1..3){foreach($arm in $(if($pair-eq2){@('candidate','default')}else{@('default','candidate')})){
        $name="pair-$pair-$arm";HoblCheckFrozen;HoblArchiveReset $name;HoblCheckFrozen
        $start=HoblNow;$p=Phase "$name-test" (HoblTestArguments $arm test) $true;$end=HoblNow
        $log=Get-Content $p.log -Raw;Require (([regex]::Matches($log,'(?i)Nothing to compile.*up.to.date')).Count-ge2-and$log-notmatch'Compiling \d+ source') 'Both compiles must be up-to-date'
        $null=Phase "$name-report" (HoblTestArguments $arm report)
        $null=HoblTakeSnapshot $name;$evidence=HoblFreshEvidence $name $p $start $end $arm;HoblCheckFrozen
        $result.samples+=@{pair=$pair;arm=$arm;seconds=$p.seconds;exitCode=$p.exitCode;startMs=$start;endMs=$end;preparedJarFrozen=$true;evidence=$evidence};Save
    }}
    $result.summary=HoblWarmSummary $result.samples;$result.status='PASS';Save
}
function HoblWarmSummary($Samples){
    Require (@($Samples).Count-eq6) 'Exactly six warm tests required'
    $a=@($Samples|Where-Object arm -eq default);$b=@($Samples|Where-Object arm -eq candidate)
    Require ($a.Count-eq3-and$b.Count-eq3) 'Three per arm'
    $pairs=@(foreach($i in 1..3){$x=@($a|Where-Object pair -eq $i);$y=@($b|Where-Object pair -eq $i);Require ($x.Count-eq1-and$y.Count-eq1) 'Pair mismatch';@{pair=$i;baseline=$x[0].seconds;candidate=$y[0].seconds;favorable=($y[0].seconds-lt$x[0].seconds)}})
    $am=Median @($a.seconds);$bm=Median @($b.seconds)
    return @{baselineMedian=$am;candidateMedian=$bm;absoluteSavingSeconds=($am-$bm);candidateBaselineRatio=($bm/$am);lowerPercent=(100*($am-$bm)/$am);allFavorable=(@($pairs|Where-Object {-not$_.favorable}).Count-eq0);pairs=$pairs}
}
function CompareHoblWarmResults($Windows,$Mac){
    Require ($Windows.status-ceq'PASS'-and$Mac.status-ceq'PASS'-and$Windows.platform-ceq'Windows'-and$Mac.platform-ceq'MacOS'-and$Windows.scope-ceq'HOBLDerivedWarmTest_NOT5Loop_NOTBuild'-and$Mac.scope-ceq$Windows.scope) 'Both complete actual scoped OS results required'
    foreach($r in $Windows,$Mac){Require ($r.fixtureOnly-ne$true-and$r.samples.Count-eq6-and$r.snapshots.Count-eq8-and$r.sourceRestored-and$r.environmentRestoration.restored-and$r.remainingJavaCandidates-eq0-and$r.pin-ceq'6feeae0f13e0e258eedc99832416b42bb13779b1'-and$r.trialPomSha256-ceq'D7FF6C0FB845850374020A16A65F4B2B1F1BF8E3204C65AB56BDCA2137BDA818') 'Complete unmodified fidelity/cleanup results required'}
    $w=HoblWarmSummary $Windows.samples;$m=HoblWarmSummary $Mac.samples
    return @{windows=$w;mac=$m;baselineWindowsMacRatio=($w.baselineMedian/$m.baselineMedian);candidateWindowsMacRatio=($w.candidateMedian/$m.candidateMedian);relativeRatioChange=(($w.candidateMedian/$m.candidateMedian)/($w.baselineMedian/$m.baselineMedian));advance=($w.candidateBaselineRatio-le0.95-and$w.allFavorable-and$m.candidateBaselineRatio-lt1.05);scope='Separate absolute/relative descriptive ratios, not HOBL score or build parity'}
}
function InvokeHoblWarmRun([ValidateSet('Windows','MacOS')][string]$Platform){
    foreach($path in $ProjectFullClone,$JavaHome,$LocalCache,$OutputDirectory){Require (-not[string]::IsNullOrWhiteSpace($path)) 'Explicit owned paths required';$ancestor=[IO.Path]::GetFullPath($path);while($ancestor){if(Test-Path -LiteralPath $ancestor){Require (-not((Get-Item -LiteralPath $ancestor -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked runtime ancestry'};$parent=[IO.Directory]::GetParent($ancestor);$ancestor=if($parent){$parent.FullName}else{$null}}}
    $root=[IO.Path]::GetFullPath($ProjectFullClone).TrimEnd([IO.Path]::DirectorySeparatorChar)
    foreach($path in $JavaHome,$LocalCache,$OutputDirectory){$full=[IO.Path]::GetFullPath($path);Require (-not$full.Equals($root,[StringComparison]::OrdinalIgnoreCase)-and-not$full.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) 'Cache/JDK/evidence outside source'}
    Require (@(HoblJavaCandidates).Count-eq0) 'Competing Java; none stopped'
    Require (-not(Test-Path $OutputDirectory)) 'Fresh output required';New-Item $OutputDirectory -ItemType Directory|Out-Null
    $saved=GetHoblContractEnvironment;$pom=$null;$cmd=$null;$script:platform=$Platform
    $result=@{status='RUNNING';scope='HOBLDerivedWarmTest_NOT5Loop_NOTBuild';platform=$Platform;pin='6feeae0f13e0e258eedc99832416b42bb13779b1';trialPomSha256='D7FF6C0FB845850374020A16A65F4B2B1F1BF8E3204C65AB56BDCA2137BDA818';phases=@();samples=@();snapshots=@();preparations=@();criteria='Windows>=5% median lower/all3 favorable; Mac<5% regression/full fidelity'}
    try{
        foreach($n in 'MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME','MVNW_PREFER_PWSH'){Require (-not[Environment]::GetEnvironmentVariable($n)) 'Unreviewed inherited option'}
        foreach($n in 'MVNW_REPOURL','MVNW_USERNAME','MVNW_PASSWORD','__MVNW_ARG0_NAME__'){Require (-not[Environment]::GetEnvironmentVariable($n)) 'Injected wrapper option'}
        foreach($n in '.m2/settings.xml','.mavenrc','.mavenrc_pre.cmd','.mavenrc_pre.bat','mavenrc_pre.cmd','mavenrc_pre.bat','mavenrc_post.cmd','mavenrc_post.bat'){Require (-not(Test-Path (Join-Path $HOME $n))) 'Unreviewed Maven rc/settings'}
        $script:java=HoblNativePath (Join-Path $JavaHome $(if($Platform-eq'Windows'){'bin/java.exe'}else{'bin/java'}))
        $script:beforeSource=@{javaSha256=(Get-FileHash $script:java).Hash;jvmConfigSha256=(Get-FileHash (Join-Path $ProjectFullClone '.mvn/jvm.config')).Hash;javaRuntime='25.0.5.0.2+1-LTS';arch='aarch64'}
        HoblSourceCheck $true;$pom=[IO.File]::ReadAllBytes((Join-Path $ProjectFullClone 'pom.xml'));$cmd=[IO.File]::ReadAllBytes((Join-Path $ProjectFullClone 'mvnw.cmd'));$trial=[IO.File]::ReadAllBytes("$PSScriptRoot\trial-pom.xml");AssertHoblTrialPom $pom $trial
        $env:JAVA_HOME=$JavaHome;$env:PATH=(Join-Path $JavaHome 'bin')+[IO.Path]::PathSeparator+$env:PATH;Set-Location $ProjectFullClone
        [IO.File]::WriteAllBytes((Join-Path $ProjectFullClone 'pom.xml'),$trial)
        if($Platform-eq'Windows'){HoblCoreIdentity;$candidate=HoblNativePath "$PSScriptRoot\..\hobl-pwsh-pilot\upstream-f62f442-https-license-mvnw.cmd";Require ((Get-FileHash $candidate).Hash-ceq'AAA4957C5AB29267A0D89C03D33621740A4233BF25AFEB480797023687CABB7D') 'AAA required';[IO.File]::WriteAllBytes((Join-Path $ProjectFullClone 'mvnw.cmd'),[IO.File]::ReadAllBytes($candidate));$env:MVNW_PREFER_PWSH='true'}
        $script:wrapper=HoblNativePath (Join-Path $ProjectFullClone $(if($Platform-eq'Windows'){'mvnw.cmd'}else{'mvnw'}));HoblSourceCheck
        HoblIdentity
        $version=Phase 'wrapper-version' @("-Dmaven.repo.local=$LocalCache",'--version');Require ((Get-Content $version.log -Raw)-match'Apache Maven 3\.9\.11') 'Maven3.9.11 required'
        InvokeHoblWarmFlow
    }catch{$result.status='FAIL';$result.failure=$_.ToString()}
    finally{
        $errors=@();try{if($pom){RestoreHoblTrialFiles $ProjectFullClone $pom $cmd;HoblSourceCheck $true;$result.sourceRestored=$true}}catch{$errors+=$_.ToString()}
        try{$result.environmentRestoration=RestoreHoblContractEnvironment $saved}catch{$errors+=$_.ToString()}
        try{$left=@(HoblJavaCandidates);$result.remainingJavaCandidates=$left.Count;Require ($left.Count-eq0) 'Java remains; none blindly killed'}catch{$errors+=$_.ToString()}
        if($errors.Count){$result.status='FAIL';$result.restorationFailures=$errors};Save
    };Require ($result.status-ceq'PASS') 'Warm test runner failed; no retry'
}
if($LibraryOnly){return}
Require ($ExecuteAuthorized-and$CandidateReviewed-and($IsWindows-or$IsMacOS)) 'Explicit paired-test runtime approval/native supported OS required'
$PythonExecutable=HoblNativePath $PythonExecutable
InvokeHoblWarmRun $(if($IsWindows){'Windows'}else{'MacOS'})
