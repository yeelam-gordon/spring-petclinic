function Assert-MQ($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function Get-MQReportRole([string]$Relative){
    if(-not$Relative-or$Relative.Length-gt512-or$Relative-match'[\x00-\x1f\x7f]|(^/|\\|:|//|(^|/)\.\.?(/|$))'-or$Relative-match'(?i)(^|/)(home|registry|sdk|archives|rawenv|auth)(/|$)'){return $null}
    if($Relative-cmatch'^surefire/TEST-[^/]+\.xml$'){return 'surefire-xml'}
    if($Relative-cmatch'^surefire/[^/]+\.txt$'){return 'surefire-text'}
    if($Relative-cmatch'^jacoco/(?:[A-Za-z0-9_$.-]+/)*[A-Za-z0-9_$.-]+\.(xml|html|csv|css|js|gif|png|svg)$'){return 'jacoco-'+[IO.Path]::GetExtension($Relative).Substring(1)}
    return $null
}
function New-MQReportByteWitness([string]$CaptureRoot,[string]$Phase){
    & ${function:Assert-MQ} ($Phase-cin@('baseline-verify','candidate-verify')) 'Exact capture phase required'
    $root=& ${function:Resolve-MQPath} $CaptureRoot;$rows=@()
    foreach($name in 'surefire','jacoco'){
        $directory=& ${function:Resolve-MQPath} (Join-Path $root $name)
        & ${function:Assert-MQ} ((Get-Item -LiteralPath $directory -Force)-is[IO.DirectoryInfo]) 'Ordinary report directory required'
        foreach($file in @(Get-ChildItem -LiteralPath $directory -Recurse -Force|Sort-Object FullName)){
            & ${function:Assert-MQ} (-not$file.LinkType-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked report member forbidden'
            if($file-isnot[IO.FileInfo]){continue}
            $relative=[IO.Path]::GetRelativePath($root,$file.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47)
            $role=& ${function:Get-MQReportRole} $relative
            & ${function:Assert-MQ} ($role-and$file.Length-le16777216-and$rows.Count-lt2000) 'Unknown/oversized report role'
            $null=& ${function:Resolve-MQPath} $file.FullName
            $stream=[IO.File]::OpenRead($file.FullName)
            try{
                [byte[]]$prefix=[byte[]]::new(4);$n=$stream.Read($prefix,0,4)
                & ${function:Assert-MQ} (-not($n-ge2-and(($prefix[0]-eq0x50-and$prefix[1]-eq0x4b)-or($prefix[0]-eq0x1f-and$prefix[1]-eq0x8b)-or($prefix[0]-eq0x4d-and$prefix[1]-eq0x5a)))) 'Archive/executable shaped report forbidden'
            }finally{$stream.Dispose()}
            $rows+=@{name=$relative;role=$role;type='file';bytes=$file.Length;sha256=(Microsoft.PowerShell.Utility\Get-FileHash $file.FullName).Hash}
        }
    }
    & ${function:Assert-MQ} ($rows.Count-gt0) 'Nonempty report witness required'
    @{schema='H3911.report-bytes.v1';phase=$Phase;rows=$rows}
}
function Import-MQ {
    $spec=@{
        'H3911.Source.psm1'=@('6AC4B84BEEDEED24E6330D556BFAA2954CA2D4771880F2A0C2602AEF5B91A1C0',@('Assert-H3911Source','Assert-H3911PhysicalInputs'))
        'H3911.Helpers.psm1'=@('1F1C0099CDC1A7DA6FE949BF973269418DCAAC0E1539A4598A6E5CCFE3720BAA',@('PortableEnvironmentSnapshot','RestorePortableEnvironment'))
        'H3911.CallKernel.psm1'=@('14D87CEFF68D26689C4A05D56BF503C75F8C95942ED4685538738FAD8FB9FE9F',@('Assert-H3911KernelPOM'))
        'H3911.Artifacts.psm1'=@('BD2B01750B3F6954425599F0E70F34F2A04B122E03724B1482704E76FC6B55F6',@('Save-H3911Verify','Compare-H3911Artifacts'))
        'H3911.NativeProcess.psm1'=@('6CF9CB37879428520B87738FE8A0CDECEA8E0B6AA6577C068FDABB44F038E5A3',@('Invoke-H3911DirectNative'))
        'H3911.DistributionSetup.psm1'=@('7943C480E2E73F68554BBE46A30811F54A299EBDBA5FDF7F0A430314EEF12D57',@('Expand-H3911OwnedDistribution'))
        'H3911.Darwin103.psm1'=@('05F80C9435B3E6012FAE8874A887A7F96AF8B44311EC1D4A06265ED254E7A264',@('Assert-H3911Darwin103Distribution'))
        'H3911.StockMaven3911.psm1'=@('3D8DCF80AFF694FDC716122B2E76274BBB2D5FD7D882C7D04DC61DE5EF55911D',@('Assert-H3911StockMaven3911'))
        'H3911.EffectiveOwner.psm1'=@('4979E2E0160A6DCF9C7B13E279DA712F047634AABB7F3CB021C2A25578CF7B95',@('Read-H3911DarwinEffectiveOwner'))
        'H3911.DarwinLifecycle.psm1'=@('AD420580D1F4E98350ADF94102BE43C96EEF9A5CC3086DC5C0F33DB493C5E66A',@('New-H3911DarwinPrivateStopPlan','Confirm-H3911DarwinCliStop','Read-H3911DarwinScopedCensus'))}
    $bound=@{}
    foreach($row in $spec.GetEnumerator()){
        $path=Join-Path $PSScriptRoot $row.Key
        & ${function:Assert-MQ} ((Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $path).Hash-ceq$row.Value[0]) 'Mac dependency pin differs'
        $m=Import-Module $path -Scope Local -PassThru -DisableNameChecking
        foreach($name in $row.Value[1]){$command=$m.ExportedCommands[$name];& ${function:Assert-MQ} ($command-is[Management.Automation.FunctionInfo]-and$command.Module.Path-ceq$path-and$command.Name-ceq$name) 'Mac command object origin differs';$bound[$name]=$command}
        if($row.Key-ceq'H3911.DarwinLifecycle.psm1'){$same=& $m {Get-Command Test-LifeSame -CommandType Function};& ${function:Assert-MQ} ($same-is[Management.Automation.FunctionInfo]-and$same.Module.Path-ceq$path-and$same.Name-ceq'Test-LifeSame') 'Lifecycle identity comparison origin differs';$bound['Test-LifeSame']=$same}
    }
    $bound
}
function Resolve-MQPath([string]$Path,[switch]$Missing){
    & ${function:Assert-MQ} ([IO.Path]::IsPathFullyQualified($Path)) 'Absolute native Mac qualifier path required'
    $full=[IO.Path]::GetFullPath($Path).TrimEnd([char[]]'\/');$probe=$full
    & ${function:Assert-MQ} ($Missing-or(Test-Path -LiteralPath $full)) 'Existing physical input required'
    while($probe){
        if(Test-Path -LiteralPath $probe){$i=Get-Item -LiteralPath $probe -Force;& ${function:Assert-MQ} ($i.PSProvider.Name-ceq'FileSystem'-and-not($i.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not$i.LinkType-and($probe-ceq$full-or$i-is[IO.DirectoryInfo])) 'Linked/nonphysical Mac namespace'}
        $parent=[IO.Directory]::GetParent($probe);$probe=if($parent){$parent.FullName}else{$null}
    }
    $full
}
function Assert-MQDisjoint([string]$A,[string]$B){
    $comparison=if($IsWindows){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
    & ${function:Assert-MQ} (-not([string]::Equals($A,$B,$comparison)-or$A.StartsWith($B+[IO.Path]::DirectorySeparatorChar,$comparison)-or$B.StartsWith($A+[IO.Path]::DirectorySeparatorChar,$comparison))) 'Mac project/owned/immutable trees must be disjoint'
}
function Get-MQWatch([string]$Root){
    @(@(Get-ChildItem (Join-Path $Root 'target') -File -Recurse -Force -ErrorAction SilentlyContinue)+@(foreach($name in 'nohttp-checkstyle.xml','nohttp-checkstyle-suppressions.xml'){$p=Join-Path $Root ('src/checkstyle/'+$name);if(Test-Path -LiteralPath $p){Get-Item -LiteralPath $p}})|Sort-Object FullName|ForEach-Object{@{path=$_.FullName;bytes=$_.Length;sha256=(Microsoft.PowerShell.Utility\Get-FileHash $_.FullName).Hash}})
}
function Assert-MQSdk($C,[string]$Archive){
    & ${function:Assert-MQ} ((Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Archive).Hash-ceq'C9CF199844411C8BAFD05722D2547538300523A63FF6207A440C71B175FF7873') 'Trusted Mac SDK archive differs'
    $identity=Get-Content (Join-Path $PSScriptRoot 'mac-jdk25-identity.json') -Raw|ConvertFrom-Json
    foreach($row in $identity.files){
        $path=& ${function:Resolve-MQPath} (Join-Path $C.Jdk $row.path);$file=Get-Item -LiteralPath $path -Force
        & ${function:Assert-MQ} ($file.Length-eq$row.bytes-and(Microsoft.PowerShell.Utility\Get-FileHash $path).Hash-ceq$row.sha256-and[int][IO.File]::GetUnixFileMode($path)-eq$row.tarMode) 'Native Mac SDK selected bytes/mode differ'
    }
    & ${function:Assert-MQ} ([int][IO.File]::GetUnixFileMode((Join-Path $C.Project 'mvnw'))-eq493) 'Original Unix wrapper actual executable mode differs'
}
function Read-MQOwner($C,$Commands,$Hooks){
    if($C.FixtureOnly){$owner=& $Hooks.Owner $C}else{$owner=& ($Commands['Read-H3911DarwinEffectiveOwner']) -Context $C -RuntimeApproved}
    & ${function:Assert-MQ} ($owner-and$owner.pid-gt0-and$owner.created-and$owner.daemonId-cmatch'^[a-f0-9]{8}$'-and$owner.home-ceq$C.Home-and$owner.registryFile-ceq(Join-Path $C.Registry 'registry.bin')-and$owner.executable-ceq(Join-Path $C.Jdk 'bin/java')) 'Mac private PID/id/registry owner differs'
    $owner
}
function Assert-MQSame($A,$B){
    foreach($key in 'pid','created','daemonId','home','registryFile','executable','jniPath'){& ${function:Assert-MQ} ($A[$key]-ceq$B[$key]) 'Mac owner identity changed'}
}
function Assert-MQEarlyCensus($C,$Anchor,$Census,$Commands){
    $scope='all admitted-JDK Java plus explicitly tracked PID/create identities; not universal historical descendants'
    & ${function:Assert-MQ} ($Census-is[hashtable]-and$Census.schema-is[string]-and$Census.schema-ceq'darwin-scoped-java-census-v1'-and$Census.complete-is[bool]-and$Census.complete-and$Census.errors-is[array]-and$Census.errors.Count-eq0-and$Census.scope-is[string]-and$Census.scope-ceq$scope-and$Census.jdkExecutable-is[string]-and$Census.jdkExecutable-ceq(Join-Path $C.Jdk 'bin/java')-and$Census.expectedIdentityGone-is[bool]-and-not$Census.expectedIdentityGone) 'Early scoped census incomplete/foreign/owner absent'
    & ${function:Assert-MQ} ($C.KnownOwnedIdentities-is[array]-and$Census.tracked-is[array]-and$Census.tracked.Count-eq(1+$C.KnownOwnedIdentities.Count)-and$Census.sameJdkJava-is[array]-and$Census.sameJdkJava.Count-eq1-and$Census.knownLive-is[array]-and$Census.knownLive.Count-eq1) 'Early scoped census tracked/live set differs'
    $wanted=@($Anchor)+@($C.KnownOwnedIdentities);$seen=[Collections.Generic.HashSet[int]]::new()
    foreach($identity in @($wanted)+@($Census.tracked)+@($Census.sameJdkJava)+@($Census.knownLive)){
        & ${function:Assert-MQ} ($identity-is[hashtable]-and($identity.pid-is[int]-or$identity.pid-is[long])-and$identity.pid-gt0-and$identity.pid-le[int]::MaxValue-and$identity.created-is[string]-and$identity.created-cmatch'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$'-and$identity.executable-is[string]-and$identity.executable.Length-gt0) 'Early census typed identity required'
    }
    for($i=0;$i-lt$wanted.Count;$i++){
        & ${function:Assert-MQ} ($seen.Add([int]$Census.tracked[$i].pid)-and(& ($Commands['Test-LifeSame']) $wanted[$i] $Census.tracked[$i])) 'Early tracked PID/birth/executable differs'
    }
    foreach($key in 'daemonId','home','registryFile','jniPath'){& ${function:Assert-MQ} ($Census.tracked[0][$key]-is[string]-and$Census.tracked[0][$key]-ceq$Anchor[$key]) 'Early tracked owner scope differs'}
    foreach($identity in $Census.sameJdkJava[0],$Census.knownLive[0]){& ${function:Assert-MQ} (& ($Commands['Test-LifeSame']) $Anchor $identity) 'Early live owner reused/foreign'}
    @{status='COMPLETE_OWNED_RUNNING_SCOPE_CONFIRMED';complete=$true;scope=$scope;ownerPid=$Anchor.pid;trackedCount=$Census.tracked.Count;sameJdkCount=1;knownLiveCount=1;errors=0;ownerLive=$true;absenceAsserted=$false;afterCall='daemon-project';beforeCall='baseline-maven-home';fixtureOnly=$C.FixtureOnly}
}
function Stop-MQ($C,$Commands,$Anchor,$Hooks,[switch]$Emergency){
    if(-not$Emergency){$null=& ($Commands['Assert-H3911Source']) $C;if(-not$C.FixtureOnly){$null=& ($Commands['Assert-H3911Darwin103Distribution']) $C.Home -RequireNativeModes}}
    if($C.FixtureOnly){$owner=& ${function:Read-MQOwner} $C $Commands $Hooks;& ${function:Assert-MQSame} $owner $Anchor;$plan=& $Hooks.StopPlan $C $Anchor ([bool]$Emergency)}
    else{$plan=& ($Commands['New-H3911DarwinPrivateStopPlan']) -Context $C -Expected $Anchor -RuntimeApproved -Emergency:$Emergency}
    & ${function:Assert-MQ} ($plan.exe-ceq(Join-Path $C.Home 'bin/mvnd')-and$plan.workingDirectory-ceq$C.Temp-and$plan.expectedPid-eq$Anchor.pid-and$plan.expectedCreated-ceq$Anchor.created) 'Admitted private native stop plan differs'
    $call=@{label=$(if($Emergency){'emergency-stop'}else{'normal-stop'});exit=$null;timed=$false};$C.Calls+=,$call
    $call.exit=if($C.FixtureOnly){& $Hooks.Stop $C $plan}else{& ($Commands['Invoke-H3911DirectNative']) -Exe $plan.exe -Tokens $plan.tokens -Log (Join-Path $C.Output ($call.label+'.log')) -Context @{Project=$C.Temp} -WorkingDirectory $C.Temp -Platform Posix}
    $proof=if($C.FixtureOnly){& $Hooks.Confirm $C $Anchor $call.exit ([bool]$Emergency)}else{& ($Commands['Confirm-H3911DarwinCliStop']) -Context $C -Expected $Anchor -StopExit $call.exit -RuntimeApproved -Emergency:$Emergency}
    & ${function:Assert-MQ} ($call.exit-eq0-and($Emergency-or$proof.status-ceq'NORMAL_CLI_ROUTE_SCOPED_ABSENCE_CONFIRMED')) 'Mac native CLI stop/complete scoped absence failed'
    $proof
}
function Invoke-H3911MacQualifier {
    param([string]$Project,[string]$Jdk,[string]$JdkArchive,[string]$DistributionArchive,[string]$Owned,[string]$WatchRoot,[switch]$RuntimeApproved,[switch]$FixtureOnly,[hashtable]$FixtureHooks)
    & ${function:Assert-MQ} ($RuntimeApproved-xor$FixtureOnly) 'Exactly one Mac runtime or fixture mode required'
    & ${function:Assert-MQ} (-not$RuntimeApproved-or(-not$FixtureHooks-and$IsMacOS-and[Runtime.InteropServices.RuntimeInformation]::OSArchitecture-eq'Arm64'-and[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture-eq'Arm64')) 'Native ARM64 Mac required; runtime callbacks prohibited'
    $Project=& ${function:Resolve-MQPath} $Project;$Owned=& ${function:Resolve-MQPath} $Owned -Missing
    $Jdk=& ${function:Resolve-MQPath} $Jdk;$WatchRoot=& ${function:Resolve-MQPath} $WatchRoot
    if($JdkArchive){$JdkArchive=& ${function:Resolve-MQPath} $JdkArchive}
    if($DistributionArchive){$DistributionArchive=& ${function:Resolve-MQPath} $DistributionArchive}
    & ${function:Assert-MQDisjoint} $Project $Owned
    foreach($path in @($Jdk,$JdkArchive,$DistributionArchive)|Where-Object{$_}){$physical=& ${function:Resolve-MQPath} $path;& ${function:Assert-MQDisjoint} $Project $physical;& ${function:Assert-MQDisjoint} $Owned $physical}
    & ${function:Assert-MQ} (-not(Test-Path -LiteralPath $Owned)) 'Fresh Mac owned root required'
    if($FixtureOnly){foreach($key in 'Setup','Dispatch','Owner','Census','Stock','Verify','Compare','StopPlan','Stop','Confirm'){& ${function:Assert-MQ} ($FixtureHooks[$key]-is[scriptblock]) 'Complete explicit Mac fixture hooks required'}}
    $commands=& ${function:Import-MQ}
    & ${function:Assert-MQ} ((Microsoft.PowerShell.Utility\Get-FileHash (Join-Path $PSScriptRoot 'mac-jdk25-identity.json')).Hash-ceq'B4C08E1980A986419E9B402E9DF2B8DBA2C800E62E20995B1C9420EBE031678E') 'Trusted Mac JDK manifest differs'
    $names=@('JAVA_HOME','PATH','MAVEN_USER_HOME','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MVNW_PREFER_PWSH','MVND_CLIENT','MVND_HOME','MVND_DAEMON_STORAGE','MVND_OPTS','MVND_JVM_ARGS','TMP','TEMP','TMPDIR')
    foreach($name in $names|Where-Object{$_-notin@('JAVA_HOME','PATH','TMP','TEMP','TMPDIR')}){& ${function:Assert-MQ} (-not[Environment]::GetEnvironmentVariable($name)) "Unreviewed Mac environment option $name"}
    foreach($name in 'MAVEN_PROJECTBASEDIR','MAVEN_BASEDIR','MAVEN_CONFIG','MAVEN_CMD_LINE_ARGS','MAVEN_MULTIMODULE_PROJECT_DIRECTORY','MVND_PROJECT_BASE_DIR'){& ${function:Assert-MQ} (-not[Environment]::GetEnvironmentVariable($name)) 'Project override before allocation'}
    $c=@{Project=$Project;Jdk=$Jdk;Home=(Join-Path $Owned 'home');Output=(Join-Path $Owned 'output');Cache=(Join-Path $Owned 'cache');Settings=(Join-Path $Owned 'settings.xml');Registry=(Join-Path $Owned 'registry');Temp=(Join-Path $Owned 'temp');Platform='MacOS';SourceProfile='MacOriginalWrapper';FixtureOnly=[bool]$FixtureOnly;Calls=@();Contexts=@{};KnownOwnedIdentities=@();ExpectedJavaSha256='827ECF403DBFA3CF88E7310B44AD93CB27B75C7E15A7E461DDE0CEE775BB196F';ExpectedJcmdSha256='2D4CB05FEFFBB7F81D6EB5295A84D0DA8B9098AC1A0BD9C314B87585E9498C1A'}
    $null=& ($commands['Assert-H3911Source']) $c
    if($RuntimeApproved){$null=& ${function:Assert-MQSdk} $c $JdkArchive}
    $before=& ($commands['PortableEnvironmentSnapshot']);$cwd=(Get-Location).Path;$native=[Environment]::CurrentDirectory;$watch=& ${function:Get-MQWatch} $WatchRoot
    $record=@{fixtureOnly=[bool]$FixtureOnly;runtimeQualified=$false;status='ADMISSION';plannedClientCalls=8;allBuildsUntimed=$true};$created=$false;$anchor=$null;$normal=$false;$primary=$null
    try{
        New-Item $Owned -ItemType Directory -ErrorAction Stop|Out-Null;$created=$true
        $record.setup=if($FixtureOnly){& $FixtureHooks.Setup $c}else{& ($commands['Expand-H3911OwnedDistribution']) -Platform Darwin -Archive $DistributionArchive -Destination $c.Home}
        foreach($name in 'output','cache','registry','temp','maven-user-home'){New-Item (Join-Path $Owned $name) -ItemType Directory|Out-Null}
        [IO.File]::WriteAllText($c.Settings,'<settings/>')
        foreach($name in $names|Where-Object{$_-ne'PATH'}){Remove-Item "Env:$name" -ErrorAction SilentlyContinue}
        $env:JAVA_HOME=$Jdk;$env:PATH=(Join-Path $Jdk 'bin')+[IO.Path]::PathSeparator+$env:PATH;$env:MAVEN_USER_HOME=Join-Path $Owned 'maven-user-home';$env:MAVEN_SKIP_RC='1';$env:TMPDIR=$c.Temp;$env:TMP=$c.Temp;$env:TEMP=$c.Temp;$env:MVND_HOME=$c.Home;$env:MVND_DAEMON_STORAGE=$c.Registry
        $env:JAVA_TOOL_OPTIONS="`"-Djava.io.tmpdir=$($c.Temp)`" `"-Dmvndnative.tmpdir=$($c.Temp)`" --enable-native-access=ALL-UNNAMED"
        Push-Location $Project;[Environment]::CurrentDirectory=$Project
        try{
            foreach($label in 'baseline-project','daemon-arch','daemon-home','daemon-project','baseline-maven-home','baseline-verify','candidate-verify'){
                $null=& ($commands['Assert-H3911Source']) $c
                if($RuntimeApproved){$null=& ${function:Assert-MQSdk} $c $JdkArchive;$null=& ($commands['Assert-H3911Darwin103Distribution']) $c.Home -RequireNativeModes}
                if($anchor){$now=& ${function:Read-MQOwner} $c $commands $FixtureHooks;& ${function:Assert-MQSame} $now $anchor}
                $baseline=$label.StartsWith('baseline-',[StringComparison]::Ordinal);$scalar=$label-notlike'*-verify';$valueFile=Join-Path $c.Output ($label+'.value')
                $tokens=@('--batch-mode','--no-transfer-progress',"-Dmaven.repo.local=$($c.Cache)",'--settings',$c.Settings,'--global-settings',$c.Settings,'--file',(Join-Path $Project 'pom.xml'))
                if(-not$baseline){$tokens+=@('--serial',"-Djava.home=$Jdk","-Dmvnd.daemonStorage=$($c.Registry)")}
                if($scalar){& ${function:Assert-MQ} (-not(Test-Path -LiteralPath $valueFile)) 'Fresh scalar namespace required';$expression=switch($label){daemon-arch{'os.arch'}daemon-home{'java.home'}baseline-maven-home{'maven.home'}default{'project.basedir'}};if($label-notin@('baseline-project','daemon-arch')){$tokens+='-o'};$tokens+=@('org.apache.maven.plugins:maven-help-plugin:3.5.1:evaluate',"-Dexpression=$expression",'-q',"-Doutput=$valueFile")}
                else{& ${function:Assert-MQ} ($c.Contexts.Count-eq5) 'All five contexts required before clean';$tokens+=@('clean','verify')}
                $null=& ($commands['Assert-H3911KernelPOM']) $c $tokens $Project
                $plan=@{label=$label;exe=$(if($baseline){Join-Path $Project 'mvnw'}else{Join-Path $c.Home 'bin/mvnd'});arguments=$tokens;workingDirectory=$Project;valueFile=$valueFile;timed=$false}
                $call=@{plan=$plan;log=(Join-Path $c.Output ($label+'.log'));start=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();exit=$null;timed=$false};$c.Calls+=,$call
                $call.exit=if($FixtureOnly){& $FixtureHooks.Dispatch $c $plan}else{& ($commands['Invoke-H3911DirectNative']) -Exe $plan.exe -Tokens $tokens -Log $call.log -Context $c -WorkingDirectory $Project -Platform Posix}
                $call.end=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();& ${function:Assert-MQ} ($call.exit-eq0) 'Mac client nonzero'
                if($scalar){
                    $file=Get-Item -LiteralPath $valueFile -Force;& ${function:Assert-MQ} ($file-is[IO.FileInfo]-and-not$file.LinkType-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Regular scalar file required'
                    $bytes=[IO.File]::ReadAllBytes($valueFile);$value=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
                    & ${function:Assert-MQ} ($value-and$value-notmatch'[\x00-\x1f\x7f]') 'Strict UTF8 scalar required'
                    $wanted=switch($label){daemon-arch{'aarch64'}daemon-home{$Jdk}baseline-maven-home{$value}default{$Project}}
                    & ${function:Assert-MQ} ([string]::Equals($value,$wanted,[StringComparison]::Ordinal)) 'Mac actual scalar context differs'
                    $c.Contexts[$label]=@{value=$value;bytes=$bytes.Length;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))}
                    if($label-ceq'baseline-maven-home'){
                        if($FixtureOnly){$stock=& $FixtureHooks.Stock $c $value}else{
                            $marker=[IO.File]::ReadAllText((Join-Path $value 'mvnw.url'));$inventory=Get-Content (Join-Path $PSScriptRoot 'StockMaven3911.inventory.json') -Raw|ConvertFrom-Json -AsHashtable
                            $format=@('Zip','Tar')|Where-Object{$marker-ceq($inventory.formats[$_].url+"`n")};& ${function:Assert-MQ} (@($format).Count-eq1) 'Exact Mac stock marker format required'
                            $stock=& ($commands['Assert-H3911StockMaven3911']) -MavenHome $value -PrivateWrapperCache (Join-Path $env:MAVEN_USER_HOME 'wrapper/dists') -Profile MacOriginal -Format $format
                        }
                        & ${function:Assert-MQ} ($stock.status-ceq'FULL_TRUSTED_STOCK_MAVEN3911_ADMITTED'-and$stock.archiveFiles-eq96-and$stock.physicalFiles-eq97-and$stock.directories-eq13-and$stock.inventorySha256-ceq'63382624DFFEF090C2B47C476767D9BE9F0620296193B650AE419ABE34FC4D0F') 'Full clean Mac stock admission required'
                        $record.stock=$stock
                    }
                }else{
                    $saved=if($FixtureOnly){& $FixtureHooks.Verify $c $label $call}else{& ($commands['Save-H3911Verify']) $c $label $call}
                    if(-not$FixtureOnly){$saved.reportBytes=& ${function:New-MQReportByteWitness} (Join-Path $c.Output $label) $label}
                    & ${function:Assert-MQ} ($saved.tests.Count-eq56-and$saved.counters.Count-eq726) 'Mac full verify universe differs';$record[$label]=$saved
                    if(-not$baseline){
                        foreach($key in 'tests','counters','semantics'){& ${function:Assert-MQ} (($record['baseline-verify'][$key]|ConvertTo-Json -Depth 40 -Compress)-ceq($saved[$key]|ConvertTo-Json -Depth 40 -Compress)) 'Mac full fidelity differs'}
                        & ${function:Assert-MQ} ($record['baseline-verify'].fork-ne$saved.fork-and$record['baseline-verify'].session-ne$saved.session) 'Mac fresh fork/session required'
                        if($FixtureOnly){& ${function:Assert-MQ} (& $FixtureHooks.Compare $c) 'Mac whole archive comparison failed'}else{$null=& ($commands['Compare-H3911Artifacts']) (Join-Path $c.Output 'baseline-verify') (Join-Path $c.Output 'candidate-verify') -SourceProfile MacOriginalWrapper}
                    }
                }
                if($label-ceq'daemon-arch'){$anchor=& ${function:Read-MQOwner} $c $commands $FixtureHooks}
                if($label-ceq'daemon-project'){
                    $record.earlyCensus=@{status='HOLD';afterCall=$label;beforeCall='baseline-maven-home';absenceAsserted=$false;fixtureOnly=[bool]$FixtureOnly}
                    $visibility=if($FixtureOnly){& $FixtureHooks.Census $c $anchor}else{& ($commands['Read-H3911DarwinScopedCensus']) -Context $c -Expected $anchor -RuntimeApproved}
                    $record.earlyCensus=& ${function:Assert-MQEarlyCensus} $c $anchor $visibility $commands
                }
            }
            $record.stopProof=& ${function:Stop-MQ} $c $commands $anchor $FixtureHooks
            & ${function:Assert-MQ} ($c.Calls.Count-eq8) 'Complete eight client calls required';$normal=$true;$record.status=if($FixtureOnly){'MAC_FIXTURE_ONLY_COMPLETE'}else{'MAC_UNTIMED_COMPLETE_PENDING_AUDIT'}
        }finally{Pop-Location}
    }catch{$primary=$_;$record.status='FAIL';$record.failure=$_.ToString()}
    finally{
        if(-not$normal-and$created){try{if(-not$anchor){$anchor=& ${function:Read-MQOwner} $c $commands $FixtureHooks};$record.emergency=& ${function:Stop-MQ} $c $commands $anchor $FixtureHooks -Emergency}catch{$record.cleanupFailure=$_.ToString()}}
        if($created){try{$null=& ($commands['Assert-H3911Source']) $c;$record.sourceEqual=$true}catch{$record.sourceEqual=$false;$record.status='FAIL';$record.finalSourceFailure=$_.ToString()}}
        [Environment]::CurrentDirectory=$native;$record.restoration=& ($commands['RestorePortableEnvironment']) $before $names;$record.restoration.cwdEqual=(Get-Location).Path-ceq$cwd
        $record.restoration.nativeCwdEqual=[Environment]::CurrentDirectory-ceq$native;$record.rootWatchEqual=((& ${function:Get-MQWatch} $WatchRoot)|ConvertTo-Json -Depth 6 -Compress)-ceq($watch|ConvertTo-Json -Depth 6 -Compress)
        if(-not$record.restoration.restored-or-not$record.restoration.cwdEqual-or-not$record.restoration.nativeCwdEqual-or-not$record.rootWatchEqual-or$record.cleanupFailure){$record.status='FAIL'}
        $record.calls=$c.Calls;$record.contexts=$c.Contexts;$record.owner=$anchor
        if($created){$record|ConvertTo-Json -Depth 45 -WarningAction Stop|Set-Content (Join-Path $Owned 'mac-qualifier.json')}
    }
    if($primary){throw $primary};& ${function:Assert-MQ} ($record.status-ne'FAIL') 'Mac cleanup/restoration HOLD'
    $record
}
Export-ModuleMember -Function Invoke-H3911MacQualifier
