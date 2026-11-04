function Assert-Kernel($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function Import-KernelCommands {
    $spec=@{
        'H3911.Source.psm1'=@('6AC4B84BEEDEED24E6330D556BFAA2954CA2D4771880F2A0C2602AEF5B91A1C0',@('Assert-H3911Source','Assert-H3911PhysicalInputs','Assert-H3911Inventory'))
        'H3911.Helpers.psm1'=@('1F1C0099CDC1A7DA6FE949BF973269418DCAAC0E1539A4598A6E5CCFE3720BAA',@('PortableEnvironmentSnapshot','RestorePortableEnvironment'))
        'H3911.Artifacts.psm1'=@('BD2B01750B3F6954425599F0E70F34F2A04B122E03724B1482704E76FC6B55F6',@('Save-H3911Verify'))
        'H3911.NativeProcess.psm1'=@('6CF9CB37879428520B87738FE8A0CDECEA8E0B6AA6577C068FDABB44F038E5A3',@('Invoke-H3911DirectNative'))
        'H3911.Darwin103.psm1'=@('05F80C9435B3E6012FAE8874A887A7F96AF8B44311EC1D4A06265ED254E7A264',@('Assert-H3911Darwin103Distribution'))}
    $bound=@{}
    foreach($row in $spec.GetEnumerator()){
        $path=Join-Path $PSScriptRoot $row.Key
        Assert-Kernel ((Microsoft.PowerShell.Utility\Get-FileHash $path).Hash-ceq$row.Value[0]) 'Dependency file pin differs'
        $loaded=@(Import-Module $path -Scope Local -PassThru -DisableNameChecking)
        Assert-Kernel ($loaded.Count-eq1) 'Ambiguous dependency module'
        foreach($name in $row.Value[1]){
            $command=$loaded[0].ExportedCommands[$name]
            Assert-Kernel ($command-is[Management.Automation.FunctionInfo]-and$command.Name-ceq$name-and$command.Module.Path-ceq$path) 'Dependency command object/origin differs'
            $bound[$name]=$command
        }
    }
    return $bound
}
function New-H3911CallKernelContext {
    param([string]$Project,[string]$Jdk,[string]$Home,[string]$Output,[string]$Cache,[string]$Settings,[string]$Registry,[ValidateSet('Windows','MacOS')][string]$Platform,[string]$CoreExe,[switch]$RuntimeApproved,[switch]$FixtureOnly)
    Assert-Kernel ($RuntimeApproved-xor$FixtureOnly) 'Choose real authority or explicit fixture-only context'
    foreach($path in $Project,$Jdk,$Home,$Output,$Cache,$Settings,$Registry){Assert-Kernel ([IO.Path]::IsPathFullyQualified($path)) 'Absolute native context paths required'}
    $deps=& ${function:Import-KernelCommands}
    $c=@{Project=$Project;Jdk=$Jdk;Home=$Home;Output=$Output;Cache=$Cache;Settings=$Settings;Registry=$Registry;Platform=$Platform;CoreExe=$CoreExe;RuntimeApproved=[bool]$RuntimeApproved;FixtureOnly=[bool]$FixtureOnly;Dependencies=$deps;SourceProfile=$(if($Platform-ceq'Windows'){'ReviewedHttpsCoreWrapper'}else{'MacOriginalWrapper'});Contexts=@{};Calls=@();Lifecycle='UNWIRED_PENDING_ACCEPTANCE';ExpectedBuildClientCalls=24}
    if($CoreExe){$c.CoreHash=(Microsoft.PowerShell.Utility\Get-FileHash $CoreExe).Hash}
    $null=& ($deps['Assert-H3911Source']) $c
    return $c
}
function Assert-H3911KernelPOM {
    param([hashtable]$Context,[string[]]$Tokens,[string]$WorkingDirectory)
    $comparison=if($Context.Platform-ceq'Windows'){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
    Assert-Kernel ([IO.Path]::IsPathFullyQualified($WorkingDirectory)) 'Absolute native cwd required'
    $resolved=Resolve-Path -LiteralPath $WorkingDirectory -ErrorAction Stop
    Assert-Kernel ($resolved.Provider.Name-ceq'FileSystem'-and[string]::Equals($resolved.ProviderPath,[IO.Path]::GetFullPath($Context.Project),$comparison)) 'Foreign native cwd'
    $ancestor=Get-Item $resolved.ProviderPath -Force
    while($ancestor){Assert-Kernel (-not($ancestor.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked native cwd ancestry';$ancestor=$ancestor.Parent}
    foreach($name in 'MAVEN_PROJECTBASEDIR','MAVEN_BASEDIR','MAVEN_CONFIG','MAVEN_CMD_LINE_ARGS','MAVEN_MULTIMODULE_PROJECT_DIRECTORY','MVND_PROJECT_BASE_DIR'){Assert-Kernel (-not[Environment]::GetEnvironmentVariable($name)) "Reject project override $name"}
    foreach($token in @($Tokens)+@($env:JAVA_TOOL_OPTIONS,$env:JDK_JAVA_OPTIONS,$env:_JAVA_OPTIONS,$env:MAVEN_OPTS,$env:MAVEN_ARGS,$env:MVND_OPTS,$env:MVND_JVM_ARGS)){Assert-Kernel ($token-notmatch'(?i)-D(user\.dir|basedir|project\.basedir|maven\.(multiModuleProjectDirectory|projectBasedir))=') 'Reject project property override'}
    $selectors=@(0..($Tokens.Count-1)|Where-Object{$Tokens[$_]-ceq'--file'})
    Assert-Kernel ($selectors.Count-eq1-and$selectors[0]+1-lt$Tokens.Count-and$Tokens[$selectors[0]+1]-ceq(Join-Path $Context.Project 'pom.xml')-and-not@($Tokens|Where-Object{$_-ceq'-f'-or$_-like'--file=*'-or$_-cmatch'^-f.+'}).Count) 'Exact admitted POM selector required'
}
function Invoke-H3911WindowsKernelProcess {
    param([string]$Exe,[string[]]$Tokens,[string]$Log,[hashtable]$Context,[switch]$ObserveCore,[ValidateRange(1,600000)][int]$WaitMilliseconds=600000,[ValidateRange(1,10000)][int]$ExitWaitMilliseconds=10000)
    Assert-Kernel $IsWindows 'Windows CMD transport on non-Windows host'
    Assert-Kernel ('--stop'-cnotin$Tokens) 'Lifecycle stop transport UNWIRED'
    Assert-Kernel ([IO.Path]::IsPathFullyQualified($Context.Project)) 'Absolute native cwd required'
    foreach($token in @($Exe)+$Tokens){Assert-Kernel ($token-and$token-notmatch'[%!&|<>^"\x00-\x1f]') 'Unsafe CMD token'}
    $cwd=(Resolve-Path -LiteralPath $Context.Project).ProviderPath
    Assert-Kernel ([IO.Path]::IsPathFullyQualified($Exe)-and(Test-Path -LiteralPath $Exe -PathType Leaf)) 'Existing absolute launcher target required'
    Assert-Kernel ([IO.Path]::IsPathFullyQualified($env:ComSpec)-and(Test-Path -LiteralPath $env:ComSpec -PathType Leaf)) 'Existing absolute ComSpec required before observer'
    $comspec=(Resolve-Path -LiteralPath $env:ComSpec).ProviderPath
    Assert-Kernel ([IO.Path]::IsPathFullyQualified($Log)-and(Test-Path -LiteralPath (Split-Path $Log) -PathType Container)) 'Absolute owned output directory required'
    $suffixes=@('','.stderr','.process.json','.failure.json','.observer-cleanup.json','.namespace.lock','.observer-ready','.observer-parent','.observer-done','.core-witness.json')
    foreach($suffix in $suffixes){Assert-Kernel (-not(Test-Path -LiteralPath ($Log+$suffix))) 'Fresh complete process/observer namespace required'}
    $prefix=(Split-Path $Log -Leaf)+'.observer-'
    Assert-Kernel (-not@(Get-ChildItem -LiteralPath (Split-Path $Log) -Force|Where-Object {$_.Name.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)}).Count) 'Fresh complete process/observer namespace required'
    $command='"'+$Exe+'" '+(($Tokens|ForEach-Object{'"'+$_+'"'})-join' ')
    $info=[Diagnostics.ProcessStartInfo]::new($comspec,('/d /s /c "'+$command+'"'));$info.WorkingDirectory=$cwd;$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $observer=$null;$oi=$null
    if($ObserveCore){
        Assert-Kernel ($Context.CoreExe-and$env:MVNW_PREFER_PWSH-ceq'true') 'Unchecked Core selection'
        $selected=(Get-Command pwsh.exe -CommandType Application|Select-Object -First 1).Source
        [byte[]]$image=[IO.File]::ReadAllBytes($Context.CoreExe)
        Assert-Kernel ($selected-ceq$Context.CoreExe-and(Microsoft.PowerShell.Utility\Get-FileHash $selected).Hash-ceq$Context.CoreHash-and[BitConverter]::ToUInt16($image,[BitConverter]::ToInt32($image,60)+4)-eq0xAA64-and(Get-Item $selected).VersionInfo.ProductVersion-match'^7\.') 'Native Core selection/fallback differs'
        $script=Join-Path $PSScriptRoot 'Observe-KernelCore.ps1'
        Assert-Kernel ((Microsoft.PowerShell.Utility\Get-FileHash $script).Hash-ceq'712EFE8B3A60FC7DC29173B1207EB762C9F1DB2C362CE77EBB108027BA94A40C') 'Observer source pin differs'
        $oi=[Diagnostics.ProcessStartInfo]::new($Context.CoreExe);$oi.UseShellExecute=$false
        foreach($arg in @('-NoProfile','-NonInteractive','-File',$script,'-Prefix',$Log,'-Expected',$Context.CoreExe,'-Project',$Context.Project)){$oi.ArgumentList.Add($arg)}
    }
    $files=@{};$p=$null;$clock=$null;$primary=$null;$cleanup=[Collections.Generic.List[string]]::new()
    $owned=$null;$created=$null;$observerIdentity=$null;$normal=$false;$completeA=$false;$completeB=$false;$timeout=$false;$exit=$null
    $observerGone=$true;$observerKill=$false;$cmdGone=$true;$cmdKill=$false;$a=$null;$b=$null
    try{
        foreach($suffix in '.namespace.lock','','.stderr','.process.json','.failure.json','.observer-cleanup.json'){
            $files[$suffix]=[IO.File]::Open($Log+$suffix,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        }
        if($ObserveCore){
            $observer=[Diagnostics.Process]::Start($oi);$observerGone=$false
            $observerIdentity=@{pid=$observer.Id;createdUtc=$observer.StartTime.ToUniversalTime().ToString('o');executable=$Context.CoreExe;prefix=$Log}
            $ready=[Diagnostics.Stopwatch]::StartNew()
            while(-not(Test-Path ($Log+'.observer-ready'))-and$ready.ElapsedMilliseconds-lt10000-and-not$observer.HasExited){Start-Sleep -Milliseconds 25}
            Assert-Kernel (Test-Path ($Log+'.observer-ready')) 'Core observer unavailable'
        }
        $clock=[Diagnostics.Stopwatch]::StartNew();$p=[Diagnostics.Process]::Start($info);$cmdGone=$false;$owned=$p.Id;$created=$p.StartTime.ToUniversalTime().ToString('o')
        $a=$p.StandardOutput.BaseStream.CopyToAsync($files['']);$b=$p.StandardError.BaseStream.CopyToAsync($files['.stderr'])
        if($observer){[IO.File]::WriteAllText($Log+'.observer-parent',[string]$owned)}
        $normal=$p.WaitForExit($WaitMilliseconds);$clock.Stop();$timeout=-not$normal
        if($timeout){throw 'HOLD: Owned launcher timeout'}
        $exit=$p.ExitCode;$cmdGone=$true
        $completeA=$a.Wait($ExitWaitMilliseconds);$completeB=$b.Wait($ExitWaitMilliseconds)
        Assert-Kernel ($completeA-and$completeB) 'CMD exit/output unconfirmed'
        if($observer){
            [IO.File]::WriteAllText($Log+'.observer-done','done')
            Assert-Kernel ($observer.WaitForExit($ExitWaitMilliseconds)) 'Core observer completion unconfirmed'
            $observerGone=$true
            $w=Get-Content ($Log+'.core-witness.json') -Raw|ConvertFrom-Json
            Assert-Kernel ($w.observed-and$w.matchesExpected-and$w.parentPid-eq$owned) 'Core child witness missed/mismatch'
        }
    }catch{$primary=$_}
    finally{
        if($clock-and$clock.IsRunning){$clock.Stop()}
        foreach($entry in @(@{kind='CMD';process=$p},@{kind='observer';process=$observer})){
            $child=$entry.process;if(-not$child){continue}
            try{
                if(-not$child.HasExited){$child.Kill($true);if($entry.kind-eq'observer'){$observerKill=$true}else{$cmdKill=$true}}
                $gone=$child.WaitForExit($ExitWaitMilliseconds)
                if($entry.kind-eq'observer'){$observerGone=$gone}else{$cmdGone=$gone}
                if(-not$gone){$cleanup.Add("$($entry.kind) owned termination unconfirmed")}
            }catch{$cleanup.Add("$($entry.kind): $($_.ToString())")}
        }
        foreach($task in $a,$b){if($task){try{$null=$task.Wait($ExitWaitMilliseconds)}catch{$cleanup.Add('Output drain: '+$_.ToString())}}}
        foreach($suffix in '', '.stderr'){if($files.ContainsKey($suffix)){try{$files[$suffix].Flush()}catch{$cleanup.Add('Output flush: '+$_.ToString())}}}
        $record=@{pid=$owned;createdUtc=$created;exe=$Exe;arguments=$Tokens;workingDirectory=$cwd;elapsedSeconds=$(if($clock){$clock.Elapsed.TotalSeconds}else{$null});validClock=($normal-and$completeA-and$completeB-and-not$primary-and$cleanup.Count-eq0);timeout=$timeout;exit=$exit;stdoutComplete=$completeA;stderrComplete=$completeB;cmdGone=$cmdGone;cmdKill=$cmdKill;observer=$observerIdentity;observerGone=$observerGone;observerKill=$observerKill;originalError=$(if($primary){$primary.ToString()}else{$null});cleanupErrors=@($cleanup);clockBoundary='immediately before Process.Start through normal WaitForExit; drain/observer completion excluded'}
        foreach($pair in @(@{suffix='.process.json';value=$record},@{suffix='.failure.json';value=@{originalError=$record.originalError;originalPosition=$(if($primary){$primary.InvocationInfo.PositionMessage}else{$null});cleanupErrors=@($cleanup)}},@{suffix='.observer-cleanup.json';value=@{identity=$observerIdentity;allocated=[bool]$observer;gone=$observerGone;killRequested=$observerKill;cleanupErrors=@($cleanup)}})){
            if($files.ContainsKey($pair.suffix)){try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($pair.value|ConvertTo-Json -Depth 8));$files[$pair.suffix].Write($bytes,0,$bytes.Length);$files[$pair.suffix].Flush()}catch{$cleanup.Add('Receipt: '+$_.ToString())}}
        }
        foreach($sink in $files.Values){try{$sink.Dispose()}catch{}}
    }
    if($primary){throw $primary}
    Assert-Kernel ($cleanup.Count-eq0) 'Owned process/output cleanup failed; receipt retained'
    return [int]$exit
}
function Invoke-H3911CallKernel {
    param([hashtable]$Context,[string]$Label,[scriptblock]$FixtureDispatch)
    Assert-Kernel (-not$Context.RuntimeApproved-or(-not$Context.FixtureOnly-and-not$FixtureDispatch)) 'Runtime callbacks prohibited'
    Assert-Kernel ($Label-notin@('stop','cleanup','package','sample')) 'Lifecycle/samples UNWIRED pending accepted integration'
    $labels=@('baseline-project','daemon-arch','daemon-home','daemon-project','baseline-maven-home','baseline-verify','candidate-verify','baseline-clean','candidate-clean')
    Assert-Kernel ($Label-cin$labels) 'Unknown call label'
    $deps=& ${function:Import-KernelCommands}
    $null=& ($deps['Assert-H3911Source']) $Context
    if($Context.RuntimeApproved){
        if($Context.Platform-ceq'Windows'){$null=& ($deps['Assert-H3911Inventory']) $Context.Home}else{$null=& ($deps['Assert-H3911Darwin103Distribution']) $Context.Home -RequireNativeModes}
        Assert-Kernel ($Context.Platform-ceq'Windows'-and$Context.Lifecycle-ceq'WindowsUntimedQualifier') 'Real dispatch requires Windows qualifier lifecycle integration'
        Assert-Kernel ((Microsoft.PowerShell.Utility\Get-FileHash (Join-Path $Context.Jdk 'bin/java.exe')).Hash-ceq'094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0') 'Exact native25 Java input changed'
    }
    if(-not$Context.RuntimeApproved){Assert-Kernel ($Context.FixtureOnly-and$FixtureDispatch) 'Explicit fixture dispatcher required; no implicit Java launch'}
    $a=$Label.StartsWith('baseline-',[StringComparison]::Ordinal)
    $route=if($a){'A'}else{'B'}
    $valueFile=Join-Path $Context.Output ($Label+'.value')
    $contextLabels=@('baseline-project','daemon-arch','daemon-home','daemon-project','baseline-maven-home')
    if($Label-in$contextLabels){Assert-Kernel (-not(Test-Path $valueFile)) 'Stale context output'}
    if($Label-notin$contextLabels){foreach($required in $contextLabels){Assert-Kernel $Context.Contexts.ContainsKey($required) 'Both projects/native25/home/baseline Maven home required before ANY clean'}}
    $tokens=@('--batch-mode','--no-transfer-progress','-Dserver.address=127.0.0.1',"-Dmaven.repo.local=$($Context.Cache)",'--settings',$Context.Settings,'--global-settings',$Context.Settings,'--file',(Join-Path $Context.Project 'pom.xml'))
    if(-not$a){$tokens+=@('--serial',"-Djava.home=$($Context.Jdk)","-Dmvnd.daemonStorage=$($Context.Registry)")}
    if($Label-in$contextLabels){
        $expression=switch($Label){'daemon-arch'{'os.arch'}'daemon-home'{'java.home'}'baseline-maven-home'{'maven.home'}default{'project.basedir'}}
        if($Label-notin@('baseline-project','daemon-arch')){$tokens+='-o'}
        $tokens+=@('org.apache.maven.plugins:maven-help-plugin:3.5.1:evaluate',"-Dexpression=$expression",'-q',"-Doutput=$valueFile")
    }else{$tokens+=if($Label.EndsWith('-verify')){@('clean','verify')}else{@('-o','clean')}}
    $exe=if($a){Join-Path $Context.Project $(if($Context.Platform-ceq'Windows'){'mvnw.cmd'}else{'mvnw'})}else{Join-Path $Context.Home $(if($Context.Platform-ceq'Windows'){'bin/mvnd.cmd'}else{'bin/mvnd'})}
    $null=& ${function:Assert-H3911KernelPOM} $Context $tokens $Context.Project
    $plan=@{label=$Label;route=$route;exe=$exe;arguments=$tokens;workingDirectory=$Context.Project;valueFile=$valueFile;clientMode=$(if($Context.Platform-ceq'Windows'){'jvm'}else{'native'});observeCore=($a-and$Context.Platform-ceq'Windows');timed=$false;fixtureOnly=[bool]$Context.FixtureOnly}
    $start=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$log=Join-Path $Context.Output ($Label+'.log')
    if($Context.RuntimeApproved){
        Assert-Kernel ($env:PATH-ceq$Context.BoundPath-and$env:MVNW_PREFER_PWSH-ceq'true') 'Qualifier Core/PATH scope changed'
        $null=& ($deps['Assert-H3911PhysicalInputs']) $Context
        $exit=& ${function:Invoke-H3911WindowsKernelProcess} $exe $tokens $log $Context -ObserveCore:$plan.observeCore
    }else{$exit=& $FixtureDispatch $plan}
    $call=@{plan=$plan;exit=$exit;fixtureOnly=[bool]$Context.FixtureOnly;start=$start;end=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();log=$log;timed=$false};$Context.Calls+=,$call
    Assert-Kernel ($exit-eq0) 'Call child nonzero'
    if($Label-in$contextLabels){
        $file=Get-Item -LiteralPath $valueFile -Force
        Assert-Kernel ($file-is[IO.FileInfo]-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Missing/linked scalar context'
        $bytes=[IO.File]::ReadAllBytes($valueFile);$value=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        Assert-Kernel ($bytes.Length-gt0-and$value-notmatch'[\x00-\x1f\x7f]') 'Fresh UTF8 scalar required'
        $expected=switch($Label){'daemon-arch'{'aarch64'}'daemon-home'{$Context.Jdk}'baseline-maven-home'{$value}default{$Context.Project}}
        $comparison=if($Context.Platform-ceq'Windows'){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
        Assert-Kernel ([string]::Equals($value,$expected,$comparison)) 'Actual context differs'
        if($Label-ceq'baseline-maven-home'){Assert-Kernel ([IO.Path]::IsPathFullyQualified($value)) 'Absolute baseline Maven home required'}
        $Context.Contexts[$Label]=@{value=$value;bytes=$bytes.Length;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes));rawBase64=[Convert]::ToBase64String($bytes);fixtureOnly=[bool]$Context.FixtureOnly}
    }
    return $call
}
function Invoke-H3911KernelDirectProcess {
    param([string]$Exe,[string[]]$Tokens,[string]$Log,[hashtable]$Context,[string]$WorkingDirectory,[ValidateSet('Windows','Posix')][string]$Platform,[int]$WaitMilliseconds=600000)
    Assert-Kernel ('--stop'-cnotin$Tokens) 'Lifecycle stop transport UNWIRED'
    $deps=& ${function:Import-KernelCommands}
    & ($deps['Invoke-H3911DirectNative']) -Exe $Exe -Tokens $Tokens -Log $Log -Context $Context -WorkingDirectory $WorkingDirectory -Platform $Platform -WaitMilliseconds $WaitMilliseconds
}
Export-ModuleMember -Function New-H3911CallKernelContext,Assert-H3911KernelPOM,Invoke-H3911WindowsKernelProcess,Invoke-H3911CallKernel,Invoke-H3911KernelDirectProcess
