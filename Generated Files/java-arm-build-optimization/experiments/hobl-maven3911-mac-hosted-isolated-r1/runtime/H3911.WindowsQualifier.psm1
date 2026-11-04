function Assert-WQ($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function Resolve-WQNamespace([string]$Path,[switch]$AllowMissing){
    & ${function:Assert-WQ} ([IO.Path]::IsPathFullyQualified($Path)) 'Absolute native namespace required'
    $full=[IO.Path]::GetFullPath($Path).TrimEnd([char[]]'\/')
    & ${function:Assert-WQ} ($full-notmatch'(^|[\\/])[^\\/]*([. ]|~[0-9][^\\/]*)($|[\\/])'-and$full-notmatch'^\\\\[?.]\\') 'Noncanonical Windows namespace spelling'
    & ${function:Assert-WQ} ($AllowMissing-or(Test-Path -LiteralPath $full)) 'Existing namespace input required'
    $probe=$full
    while($probe){
        if(Test-Path -LiteralPath $probe){
            $item=Get-Item -LiteralPath $probe -Force -ErrorAction Stop
            & ${function:Assert-WQ} ($item.PSProvider.Name-ceq'FileSystem'-and-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not$item.LinkType-and($probe-ceq$full-or$item-is[IO.DirectoryInfo])) 'Linked/nonphysical namespace ancestry'
        }
        $parent=[IO.Directory]::GetParent($probe);$probe=if($parent){$parent.FullName}else{$null}
    }
    return $full
}
function Assert-WQDisjoint([string]$Left,[string]$Right){
    $comparison=[StringComparison]::OrdinalIgnoreCase;$separator=[IO.Path]::DirectorySeparatorChar
    & ${function:Assert-WQ} (-not([string]::Equals($Left,$Right,$comparison)-or$Left.StartsWith($Right+$separator,$comparison)-or$Right.StartsWith($Left+$separator,$comparison))) 'Project/owned/immutable input trees must be disjoint'
}
function Import-WQ {
    $spec=@{
        'H3911.CallKernel.psm1'=@('14D87CEFF68D26689C4A05D56BF503C75F8C95942ED4685538738FAD8FB9FE9F',@('New-H3911CallKernelContext','Invoke-H3911CallKernel'))
        'H3911.Helpers.psm1'=@('1F1C0099CDC1A7DA6FE949BF973269418DCAAC0E1539A4598A6E5CCFE3720BAA',@('PortableEnvironmentSnapshot','RestorePortableEnvironment'))
        'H3911.Artifacts.psm1'=@('BD2B01750B3F6954425599F0E70F34F2A04B122E03724B1482704E76FC6B55F6',@('Save-H3911Verify','Compare-H3911Artifacts'))
        'H3911.DistributionSetup.psm1'=@('7943C480E2E73F68554BBE46A30811F54A299EBDBA5FDF7F0A430314EEF12D57',@('Expand-H3911OwnedDistribution'))
        'H3911.Source.psm1'=@('6AC4B84BEEDEED24E6330D556BFAA2954CA2D4771880F2A0C2602AEF5B91A1C0',@('Assert-H3911Source','Assert-H3911Inventory'))
        'H3911.NativeProcess.psm1'=@('6CF9CB37879428520B87738FE8A0CDECEA8E0B6AA6577C068FDABB44F038E5A3',@('Invoke-H3911DirectNative'))
        'H3911.StockMaven3911.psm1'=@('3D8DCF80AFF694FDC716122B2E76274BBB2D5FD7D882C7D04DC61DE5EF55911D',@('Assert-H3911StockMaven3911'))}
    $commands=@{}
    foreach($row in $spec.GetEnumerator()){
        $path=Join-Path $PSScriptRoot $row.Key;& ${function:Assert-WQ} ((Microsoft.PowerShell.Utility\Get-FileHash $path).Hash-ceq$row.Value[0]) 'Qualifier dependency pin differs'
        $m=Import-Module $path -Scope Local -PassThru -DisableNameChecking
        foreach($name in $row.Value[1]){$command=$m.ExportedCommands[$name];& ${function:Assert-WQ} ($command-is[Management.Automation.FunctionInfo]-and$command.Module.Path-ceq$path-and$command.Name-ceq$name) 'Qualifier command object differs';$commands[$name]=$command}
    }
    return $commands
}
function Read-WQOwner($C){
    $rows=@(Get-CimInstance Win32_Process -Filter "Name='java.exe'"|Where-Object {$_.CommandLine-and$_.CommandLine.Contains($C.Registry)})
    & ${function:Assert-WQ} ($rows.Count-le1) 'Ambiguous private Java owner'
    if(-not$rows.Count){return $null}
    $row=$rows[0];& ${function:Assert-WQ} ([string]::Equals($row.ExecutablePath,(Join-Path $C.Jdk 'bin/java.exe'),[StringComparison]::OrdinalIgnoreCase)-and$row.CommandLine.Contains($C.Home)-and$row.CommandLine-match'-Dmvnd.id=([a-f0-9]{8})') 'Foreign private Java identity'
    $id=$Matches[1];$modules=@((Get-Process -Id $row.ProcessId).Modules|Where-Object ModuleName -like '*mvndnative*')
    & ${function:Assert-WQ} ($modules.Count-eq1-and$modules[0].FileName.StartsWith($C.Temp+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) 'Private loaded JNI absent/foreign'
    $bytes=[IO.File]::ReadAllBytes($modules[0].FileName);$hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
    & ${function:Assert-WQ} ($hash-ceq'728F9A0F7A8A74D15C6DE37DBE32A73CF8013605D2E881098692E1C88A0F4C2D'-and[BitConverter]::ToUInt16($bytes,[BitConverter]::ToInt32($bytes,60)+4)-eq0xAA64) 'Qualified Windows JNI differs'
    @{pid=[int]$row.ProcessId;id=$id;created=$row.CreationDate.ToString('o');executable=$row.ExecutablePath;jni=$hash}
}
function Same-WQOwner($Actual,$Expected){
    & ${function:Assert-WQ} ($Actual-and$Expected-and$Actual.pid-eq$Expected.pid-and$Actual.id-ceq$Expected.id-and$Actual.created-ceq$Expected.created-and$Actual.executable-ceq$Expected.executable-and$Actual.jni-ceq$Expected.jni) 'Private daemon owner changed'
}
function Get-WQWatch([string]$Root){
    $paths=@(Get-ChildItem (Join-Path $Root 'target') -File -Recurse -Force -ErrorAction SilentlyContinue)
    foreach($name in 'nohttp-checkstyle.xml','nohttp-checkstyle-suppressions.xml'){$p=Join-Path $Root "src/checkstyle/$name";if(Test-Path $p){$paths+=Get-Item $p}}
    @($paths|Sort-Object FullName|ForEach-Object{@{path=$_.FullName;bytes=$_.Length;sha256=(Microsoft.PowerShell.Utility\Get-FileHash $_.FullName).Hash}})
}
function Invoke-WQWindowsStopProcess {
    param($C,$Owner,$Anchor,[string[]]$Tokens,[switch]$Emergency,[ValidateRange(1,600000)][int]$WaitMilliseconds=600000,[ValidateRange(1,10000)][int]$ExitWaitMilliseconds=10000)
    & ${function:Assert-WQ} ($IsWindows-and$C.Platform-ceq'Windows'-and$C.Lifecycle-ceq'WindowsUntimedQualifier'-and($C.RuntimeApproved-xor$C.FixtureOnly)) 'Explicit Windows qualifier owned-stop context required'
    & ${function:Same-WQOwner} $Owner $Anchor
    & ${function:Assert-WQ} ($Owner.pid-gt0-and$Owner.created-and$Owner.id-cmatch'^[a-f0-9]{8}$'-and$Owner.jni-ceq'728F9A0F7A8A74D15C6DE37DBE32A73CF8013605D2E881098692E1C88A0F4C2D'-and[string]::Equals($Owner.executable,(Join-Path $C.Jdk 'bin/java.exe'),[StringComparison]::OrdinalIgnoreCase)) 'Admitted private owner identity required'
    $expected=@('--batch-mode','--no-transfer-progress','--serial',"-Djava.home=$($C.Jdk)","-Dmvnd.daemonStorage=$($C.Registry)",'--stop')
    & ${function:Assert-WQ} (($Tokens-join"`0")-ceq($expected-join"`0")) 'Exact private stop arguments required'
    $exe=& ${function:Resolve-WQNamespace} (Join-Path $C.Home 'bin/mvnd.cmd')
    $cwd=& ${function:Resolve-WQNamespace} $C.Temp
    $output=& ${function:Resolve-WQNamespace} $C.Output
    & ${function:Assert-WQ} ((Test-Path -LiteralPath $exe -PathType Leaf)-and(Test-Path -LiteralPath $cwd -PathType Container)-and(Test-Path -LiteralPath $output -PathType Container)) 'Physical private stop executable/cwd/output required'
    & ${function:Assert-WQ} ([IO.Path]::IsPathFullyQualified($env:ComSpec)-and(Test-Path -LiteralPath $env:ComSpec -PathType Leaf)) 'Existing absolute ComSpec required'
    $comspec=(Resolve-Path -LiteralPath $env:ComSpec -ErrorAction Stop).ProviderPath
    foreach($token in @($exe)+$Tokens){& ${function:Assert-WQ} ($token-and$token-notmatch'[%!&|<>^"\x00-\x1f]') 'Unsafe private stop token'}
    $label=if($Emergency){'emergency-stop'}else{'normal-stop'};$log=Join-Path $output ($label+'.log')
    foreach($suffix in '','.stderr','.process.json','.failure.json','.observer-cleanup.json','.namespace.lock','.observer-ready','.observer-parent','.observer-done','.core-witness.json'){
        & ${function:Assert-WQ} (-not(Test-Path -LiteralPath ($log+$suffix))) 'Fresh complete private stop namespace required'
    }
    & ${function:Assert-WQ} (-not@(Get-ChildItem -LiteralPath $output -Force|Where-Object{$_.Name.StartsWith($label+'.log.observer-',[StringComparison]::OrdinalIgnoreCase)}).Count) 'Fresh private stop observer namespace required'
    $command='"'+$exe+'" '+(($Tokens|ForEach-Object{'"'+$_+'"'})-join' ')
    $info=[Diagnostics.ProcessStartInfo]::new($comspec,('/d /s /c "'+$command+'"'))
    $info.WorkingDirectory=$cwd;$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $files=@{};$p=$null;$a=$null;$b=$null;$clock=$null;$primary=$null;$cleanup=[Collections.Generic.List[string]]::new()
    $pidOwned=$null;$created=$null;$normal=$false;$timeout=$false;$exit=$null;$gone=$true;$kill=$false;$completeA=$false;$completeB=$false
    try{
        foreach($suffix in '.namespace.lock','','.stderr','.process.json','.failure.json','.observer-cleanup.json'){$files[$suffix]=[IO.File]::Open($log+$suffix,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)}
        $clock=[Diagnostics.Stopwatch]::StartNew();$p=[Diagnostics.Process]::Start($info);$gone=$false;$pidOwned=$p.Id;$created=$p.StartTime.ToUniversalTime().ToString('o')
        $a=$p.StandardOutput.BaseStream.CopyToAsync($files['']);$b=$p.StandardError.BaseStream.CopyToAsync($files['.stderr'])
        $normal=$p.WaitForExit($WaitMilliseconds);$clock.Stop();$timeout=-not$normal
        if($timeout){throw 'HOLD: Owned private stop launcher timeout'}
        $exit=$p.ExitCode;$gone=$true;$completeA=$a.Wait($ExitWaitMilliseconds);$completeB=$b.Wait($ExitWaitMilliseconds)
        & ${function:Assert-WQ} ($completeA-and$completeB) 'Private stop exit/output unconfirmed'
    }catch{$primary=$_}
    finally{
        if($clock-and$clock.IsRunning){$clock.Stop()}
        if($p){try{if(-not$p.HasExited){$p.Kill($true);$kill=$true};$gone=$p.WaitForExit($ExitWaitMilliseconds);if(-not$gone){$cleanup.Add('Exact owned CMD termination unconfirmed')}}catch{$cleanup.Add($_.ToString())}}
        foreach($task in $a,$b){if($task){try{$done=$task.Wait($ExitWaitMilliseconds);if(-not$done){$cleanup.Add('Private stop output drain unconfirmed')}}catch{$cleanup.Add($_.ToString())}}}
        if($a){$completeA=$a.IsCompletedSuccessfully};if($b){$completeB=$b.IsCompletedSuccessfully}
        foreach($suffix in '', '.stderr'){if($files.ContainsKey($suffix)){try{$files[$suffix].Flush()}catch{$cleanup.Add($_.ToString())}}}
        $record=@{label=$label;pid=$pidOwned;createdUtc=$created;exe=$comspec;batch=$exe;arguments=$Tokens;rawArguments=$info.Arguments;argumentTransport='WindowsCMD.RawArguments';workingDirectory=$cwd;fixtureOnly=[bool]$C.FixtureOnly;timed=$false;elapsedSeconds=$(if($clock){$clock.Elapsed.TotalSeconds}else{$null});timeout=$timeout;exit=$exit;stdoutComplete=$completeA;stderrComplete=$completeB;cmdGone=$gone;cmdKill=$kill;observer=$null;observerGone=$true;observerKill=$false;originalError=$(if($primary){$primary.ToString()}else{$null});cleanupErrors=@($cleanup)}
        foreach($pair in @(@{suffix='.process.json';value=$record},@{suffix='.failure.json';value=@{originalError=$record.originalError;cleanupErrors=@($cleanup)}},@{suffix='.observer-cleanup.json';value=@{allocated=$false;gone=$true;killRequested=$false}})){
            if($files.ContainsKey($pair.suffix)){try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($pair.value|ConvertTo-Json -Depth 8));$files[$pair.suffix].Write($bytes,0,$bytes.Length);$files[$pair.suffix].Flush()}catch{$cleanup.Add($_.ToString())}}
        }
        foreach($sink in $files.Values){try{$sink.Dispose()}catch{}}
        if($p){$p.Dispose()}
    }
    if($primary){throw $primary}
    & ${function:Assert-WQ} ($gone-and$completeA-and$completeB-and$cleanup.Count-eq0) 'Owned private stop process/output cleanup failed; receipts retained'
    return [int]$exit
}
function Invoke-WQStop($C,$Commands,$Anchor,[hashtable]$Hooks,[switch]$Emergency){
    if(-not$Emergency){$null=& ($Commands['Assert-H3911Source']) $C;if(-not$C.FixtureOnly){$null=& ($Commands['Assert-H3911Inventory']) $C.Home}}
    $owner=if($C.FixtureOnly){& $Hooks.Owner $C}else{& ${function:Read-WQOwner} $C}
    & ${function:Same-WQOwner} $owner $Anchor
    $tokens=@('--batch-mode','--no-transfer-progress','--serial',"-Djava.home=$($C.Jdk)","-Dmvnd.daemonStorage=$($C.Registry)",'--stop')
    $attempt=@{label=$(if($Emergency){'emergency-stop'}else{'normal-stop'});exit=$null;arguments=$tokens;timed=$false;fixtureOnly=$C.FixtureOnly};$C.Calls+=,$attempt
    try{
        $exit=if($C.FixtureOnly){& $Hooks.Stop $C $tokens}else{& ${function:Invoke-WQWindowsStopProcess} -C $C -Owner $owner -Anchor $Anchor -Tokens $tokens -Emergency:$Emergency}
        $attempt.exit=$exit
    }catch{$attempt.failure=$_.ToString();throw}
    & ${function:Assert-WQ} ($exit-eq0) 'Private CLI stop nonzero'
    if($C.FixtureOnly){& ${function:Assert-WQ} (& $Hooks.Absence $C) 'Fixture private absence failed'}
    else{
        $p=Get-Process -Id $Anchor.pid -ErrorAction SilentlyContinue
        if($p){& ${function:Assert-WQ} ($p.WaitForExit(10000)) 'Private Java exit unconfirmed'}
        $bytes=[IO.File]::ReadAllBytes((Join-Path $C.Registry 'registry.bin'));& ${function:Assert-WQ} ($bytes.Length-ge4-and-not@($bytes[0..3]|Where-Object{$_-ne0}).Count) 'Private registry count nonzero'
        $remaining=@(Get-CimInstance Win32_Process -Filter "Name='java.exe'"|Where-Object {$_.CommandLine-and($_.CommandLine.Contains($C.Registry)-or$_.CommandLine.Contains($C.Home)-or$_.CommandLine.Contains($C.Temp))})
        & ${function:Assert-WQ} ($remaining.Count-eq0) 'Independent owned Java census nonempty'
    }
    return @{label=$(if($Emergency){'emergency-stop'}else{'normal-stop'});exit=0;ownerGone=$true;fixtureOnly=$C.FixtureOnly}
}
function Invoke-H3911WindowsQualifier {
    param([string]$Project,[string]$Jdk,[string]$DistributionArchive,[string]$WindowsInputs,[string]$Owned,[string]$CoreExe,[string]$WatchRoot,[ValidateSet('Windows',IgnoreCase=$false)][string]$Platform='Windows',[switch]$RuntimeApproved,[switch]$FixtureOnly,[switch]$ReviewedHostedDefaults,[hashtable]$FixtureHooks,[hashtable]$BaselineInventoryBinding)
    & ${function:Assert-WQ} ($IsWindows-and($RuntimeApproved-xor$FixtureOnly)) 'Windows plus exactly one explicit authority/fixture mode required'
    & ${function:Assert-WQ} (-not$RuntimeApproved-or-not$FixtureHooks) 'Runtime callbacks prohibited'
    foreach($path in $Project,$Jdk,$Owned,$CoreExe,$WatchRoot){& ${function:Assert-WQ} ([IO.Path]::IsPathFullyQualified($path)) 'Absolute native qualifier inputs required'}
    $Project=& ${function:Resolve-WQNamespace} $Project
    $Owned=& ${function:Resolve-WQNamespace} $Owned -AllowMissing
    & ${function:Assert-WQDisjoint} $Project $Owned
    foreach($inputPath in @($Jdk,$CoreExe,$DistributionArchive,$WindowsInputs)|Where-Object{$_}){
        $physical=& ${function:Resolve-WQNamespace} $inputPath
        & ${function:Assert-WQDisjoint} $Owned $physical
        & ${function:Assert-WQDisjoint} $Project $physical
    }
    & ${function:Assert-WQ} (-not(Test-Path -LiteralPath $Owned)) 'Fresh owned root required; never reused'
    $commands=& ${function:Import-WQ};$names=@('JAVA_HOME','PATH','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME','MVNW_PREFER_PWSH','MVND_CLIENT','MVND_HOME','MVND_DAEMON_STORAGE','MVND_OPTS','MVND_JVM_ARGS','TMP','TEMP')
    $before=& ($commands['PortableEnvironmentSnapshot']);$cwd=(Get-Location).Path;$native=[Environment]::CurrentDirectory
    foreach($name in $names|Where-Object{$_-notin@('JAVA_HOME','PATH','TMP','TEMP')}){
        $value=[Environment]::GetEnvironmentVariable($name)
        & ${function:Assert-WQ} (-not$value-or($name-ceq'MAVEN_OPTS'-and$ReviewedHostedDefaults-and$value-ceq'-Xms256m')) "Unreviewed injected $name"
    }
    & ${function:Assert-WQ} (-not$BaselineInventoryBinding) 'Caller baseline bindings forbidden; fixed stock module/inventory authority required'
    & ${function:Assert-WQ} ((Microsoft.PowerShell.Utility\Get-FileHash (Join-Path $PSScriptRoot 'StockMaven3911.inventory.json')).Hash-ceq'63382624DFFEF090C2B47C476767D9BE9F0620296193B650AE419ABE34FC4D0F') 'Fixed baseline inventory pin differs'
    if($RuntimeApproved){
        $java=Join-Path $Jdk 'bin/java.exe';$bytes=[IO.File]::ReadAllBytes($java)
        & ${function:Assert-WQ} ((Microsoft.PowerShell.Utility\Get-FileHash $java).Hash-ceq'094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0'-and[BitConverter]::ToUInt16($bytes,[BitConverter]::ToInt32($bytes,60)+4)-eq0xAA64) 'Exact native25 Java differs'
    }else{& ${function:Assert-WQ} ($FixtureHooks.Setup-and$FixtureHooks.Dispatch-and$FixtureHooks.Owner-and$FixtureHooks.Verify-and$FixtureHooks.Compare-and$FixtureHooks.BaselineInventory-and$FixtureHooks.Stop-and$FixtureHooks.Absence) 'Complete explicit fixture hooks required'}
    $watch=& ${function:Get-WQWatch} $WatchRoot;$created=$false;$c=$null;$anchor=$null;$normal=$false;$primary=$null;$cleanupError=$null;$record=@{status='ADMISSION';fixtureOnly=[bool]$FixtureOnly;plannedBuildClientCalls=8;runtimeQualified=$false;scope='WINDOWS_UNTIMED_ONLY_NOT_SCREEN'}
    try{
        New-Item $Owned -ItemType Directory -ErrorAction Stop|Out-Null;$created=$true
        $home=Join-Path $Owned 'home'
        if($RuntimeApproved){$record.setup=& ($commands['Expand-H3911OwnedDistribution']) -Platform Windows -Archive $DistributionArchive -Destination $home -WindowsInputs $WindowsInputs}else{$record.setup=& $FixtureHooks.Setup $home}
        foreach($name in 'output','cache','registry','temp','maven-user-home'){New-Item (Join-Path $Owned $name) -ItemType Directory|Out-Null}
        $settings=Join-Path $Owned 'settings.xml';[IO.File]::WriteAllText($settings,'<settings/>')
        $args=@{Project=$Project;Jdk=$Jdk;Home=$home;Output=(Join-Path $Owned 'output');Cache=(Join-Path $Owned 'cache');Settings=$settings;Registry=(Join-Path $Owned 'registry');CoreExe=$CoreExe;Platform='Windows';RuntimeApproved=$RuntimeApproved;FixtureOnly=$FixtureOnly}
        $c=& ($commands['New-H3911CallKernelContext']) @args;$c.Temp=Join-Path $Owned 'temp';$c.Lifecycle='WindowsUntimedQualifier';$c.PrivateWrapperCache=Join-Path $Owned 'maven-user-home/wrapper/dists'
        foreach($name in $names|Where-Object{$_-notin@('JAVA_HOME','PATH','TMP','TEMP')}){Remove-Item "Env:$name" -ErrorAction SilentlyContinue}
        $env:JAVA_HOME=$Jdk;$env:MVND_HOME=$home;$env:MVND_DAEMON_STORAGE=$c.Registry;$env:MAVEN_USER_HOME=Join-Path $Owned 'maven-user-home';$env:MAVEN_SKIP_RC='1';$env:TMP=$c.Temp;$env:TEMP=$c.Temp;$env:MVND_CLIENT='jvm';$env:MVNW_PREFER_PWSH='true'
        $env:PATH=(Split-Path $CoreExe)+';'+$env:PATH;$c.BoundPath=$env:PATH
        $env:JAVA_TOOL_OPTIONS="`"-Djava.io.tmpdir=$($c.Temp)`" `"-Dmvndnative.tmpdir=$($c.Temp)`" --enable-native-access=ALL-UNNAMED"
        Push-Location $Project;[Environment]::CurrentDirectory=$Project
        try{
            foreach($label in 'baseline-project','daemon-arch','daemon-home','daemon-project','baseline-maven-home','baseline-verify','candidate-verify'){
                $splat=@{Context=$c;Label=$label};if($FixtureOnly){$splat.FixtureDispatch={param($plan)& $FixtureHooks.Dispatch $c $plan}.GetNewClosure()}
                $call=& ($commands['Invoke-H3911CallKernel']) @splat
                if($label-ne'baseline-project'){
                    $owner=if($FixtureOnly){& $FixtureHooks.Owner $c}else{& ${function:Read-WQOwner} $c}
                    if(-not$anchor){& ${function:Assert-WQ} $owner 'Owned daemon absent';$anchor=$owner}else{& ${function:Same-WQOwner} $owner $anchor}
                }
                if($label-ceq'baseline-maven-home'){
                    $root=$c.Contexts[$label].value
                    $binding=if($FixtureOnly){& $FixtureHooks.BaselineInventory $root $c.PrivateWrapperCache}else{& ($commands['Assert-H3911StockMaven3911']) -MavenHome $root -PrivateWrapperCache $c.PrivateWrapperCache -Profile WindowsCore -Format Zip}
                    & ${function:Assert-WQ} ($binding.status-ceq'FULL_TRUSTED_STOCK_MAVEN3911_ADMITTED'-and$binding.archiveFiles-eq96-and$binding.physicalFiles-eq96-and$binding.directories-eq13-and$binding.inventorySha256-ceq'63382624DFFEF090C2B47C476767D9BE9F0620296193B650AE419ABE34FC4D0F'-and$binding.coreSha256-ceq'93D3C0523DDA6C86C6620D9E692E7DF39D0E2E4E4CD860061A8C0D274C2AD185') 'Complete baseline Maven3911 inventory REQUIRED, core/URL alone insufficient'
                    $record.baselineInventory=$binding
                }
                if($label-in@('baseline-verify','candidate-verify')){
                    $saved=if($FixtureOnly){& $FixtureHooks.Verify $c $label $call}else{& ($commands['Save-H3911Verify']) $c $label $call}
                    & ${function:Assert-WQ} ($saved.tests.Count-eq56-and$saved.counters.Count-eq726) 'Full verify contract differs'
                    $record[$label]=$saved
                    if($label-ceq'candidate-verify'){
                        & ${function:Assert-WQ} ($record['baseline-verify'].fork-ne$saved.fork-and$record['baseline-verify'].session-ne$saved.session) 'Fresh distinct forks/sessions required'
                        foreach($key in 'tests','counters','semantics'){& ${function:Assert-WQ} (($record['baseline-verify'][$key]|ConvertTo-Json -Depth 40 -Compress -WarningAction Stop)-ceq($saved[$key]|ConvertTo-Json -Depth 40 -Compress -WarningAction Stop)) 'Full online fidelity differs'}
                        if($FixtureOnly){& ${function:Assert-WQ} (& $FixtureHooks.Compare $c) 'Fixture archive comparison failed'}else{$null=& ($commands['Compare-H3911Artifacts']) (Join-Path $c.Output 'baseline-verify') (Join-Path $c.Output 'candidate-verify') -SourceProfile ReviewedHttpsCoreWrapper}
                    }
                }
            }
            $record.stopProof=& ${function:Invoke-WQStop} $c $commands $anchor $FixtureHooks
            $actualLabels=@($c.Calls|ForEach-Object{if($_.plan){$_.plan.label}else{$_.label}})
            & ${function:Assert-WQ} ($record.stopProof.ownerGone-is[bool]-and$record.stopProof.ownerGone-and$record.stopProof.label-ceq'normal-stop'-and($actualLabels-join',')-ceq'baseline-project,daemon-arch,daemon-home,daemon-project,baseline-maven-home,baseline-verify,candidate-verify,normal-stop') 'Complete eight-call order and actual private stop/absence proof required'
            $normal=$true;$record.status=if($FixtureOnly){'FIXTURE_ONLY_COMPLETE_NOT_RUNTIME'}else{'WINDOWS_QUALIFIED_UNTIMED_PENDING_AUDIT'};$record.runtimeQualified=[bool]$RuntimeApproved
        }finally{Pop-Location}
    }catch{$primary=$_;$record.status='FAIL';$record.failure=$_.ToString()}
    finally{
        if($c-and-not$normal){
            try{
                $owner=if($FixtureOnly){& $FixtureHooks.Owner $c}else{& ${function:Read-WQOwner} $c}
                if($owner){if(-not$anchor){$anchor=$owner};& ${function:Same-WQOwner} $owner $anchor;$record.emergencyStopProof=& ${function:Invoke-WQStop} $c $commands $anchor $FixtureHooks -Emergency;$record.emergency=$true}
            }catch{$cleanupError=$_.ToString();$record.cleanupFailure=$cleanupError}
        }
        if($c){try{$null=& ($commands['Assert-H3911Source']) $c;if($RuntimeApproved){$null=& ($commands['Assert-H3911Inventory']) $c.Home};$record.inputsUnchanged=$true}catch{$record.inputsUnchanged=$false;$record.finalIdentityFailure=$_.ToString();$record.status='FAIL'}}
        [Environment]::CurrentDirectory=$native
        $record.restoration=& ($commands['RestorePortableEnvironment']) $before $names;$record.restoration.cwdEqual=(Get-Location).Path-ceq$cwd;$record.restoration.nativeCwdEqual=[Environment]::CurrentDirectory-ceq$native
        $record.rootWatchEqual=((& ${function:Get-WQWatch} $WatchRoot)|ConvertTo-Json -Depth 8 -Compress)-ceq($watch|ConvertTo-Json -Depth 8 -Compress)
        if($c){$record.calls=$c.Calls;$record.contexts=$c.Contexts;$record.owner=$anchor}
        if(-not$record.restoration.restored-or-not$record.restoration.cwdEqual-or-not$record.restoration.nativeCwdEqual-or-not$record.rootWatchEqual-or$cleanupError){$record.status='FAIL'}
        if($created){$record|ConvertTo-Json -Depth 45 -WarningAction Stop|Set-Content (Join-Path $Owned 'qualifier.json')}
    }
    if($primary){throw $primary};& ${function:Assert-WQ} ($record.status-ne'FAIL') 'Qualifier cleanup/state failed'
    return $record
}
Export-ModuleMember -Function Invoke-H3911WindowsQualifier
