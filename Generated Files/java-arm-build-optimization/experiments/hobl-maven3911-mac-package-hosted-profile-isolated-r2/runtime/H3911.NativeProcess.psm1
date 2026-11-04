function Get-H3911NativePathRules {
    param([ValidateSet('Windows','Posix')][string]$Platform=$(if($IsWindows){'Windows'}else{'Posix'}))
    @{platform=$Platform;comparison=$(if($Platform-ceq'Windows'){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal});pathListSeparator=$(if($Platform-ceq'Windows'){';'}else{':'})}
}

function Resolve-H3911NativeItem {
    param([Parameter(Mandatory)][string]$Path,[switch]$Directory)
    if(-not[IO.Path]::IsPathFullyQualified($Path)){throw 'Explicit absolute native path required'}
    $resolved=Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $item=Get-Item -LiteralPath $resolved.ProviderPath -Force -ErrorAction Stop
    if($resolved.Provider.Name-cne'FileSystem'-or($Directory-and$item-isnot[IO.DirectoryInfo])-or(-not$Directory-and$item-isnot[IO.FileInfo])-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Regular native filesystem item required'}
    $ancestor=if($Directory){$item}else{$item.Directory}
    while($ancestor){if((Get-Item -LiteralPath $ancestor.FullName -Force).Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Linked native ancestry'};$ancestor=$ancestor.Parent}
    $resolved.ProviderPath
}

function Invoke-H3911DirectNative {
    param(
        [Parameter(Mandatory)][string]$Exe,
        [AllowEmptyCollection()][AllowEmptyString()][string[]]$Tokens=@(),
        [Parameter(Mandatory)][string]$Log,
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [switch]$StopOnly,
        [ValidateSet('Windows','Posix')][string]$Platform=$(if($IsWindows){'Windows'}else{'Posix'}),
        [ValidateRange(1,600000)][int]$WaitMilliseconds=600000,
        [ValidateRange(1,10000)][int]$ExitWaitMilliseconds=10000
    )
    # Source, POM-selector/override and private-stop ownership admissions belong to the caller.
    $rules=Get-H3911NativePathRules $Platform
    $cwd=Resolve-H3911NativeItem $WorkingDirectory -Directory
    $boundPath=if($StopOnly){$Context.Temp}else{$Context.Project}
    $bound=Resolve-H3911NativeItem $boundPath -Directory
    if(-not[string]::Equals($cwd,$bound,$rules.comparison)){throw 'Foreign native working directory'}
    $executable=Resolve-H3911NativeItem $Exe
    if(-not[IO.Path]::IsPathFullyQualified($Log)){throw 'Absolute owned log path required'}
    $parent=Resolve-H3911NativeItem (Split-Path -Parent $Log) -Directory
    $nativeLog=Join-Path $parent (Split-Path -Leaf $Log)
    foreach($path in $nativeLog,($nativeLog+'.stderr'),($nativeLog+'.process.json')){if(Test-Path -LiteralPath $path){throw 'Fresh caller-owned output paths required'}}
    $info=[Diagnostics.ProcessStartInfo]::new($executable)
    $info.WorkingDirectory=$cwd;$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    foreach($token in $Tokens){if($null-eq$token-or$token.Contains([char]0)){throw 'Null/NUL native argument'};$info.ArgumentList.Add($token)}
    $stdout=$null;$stderr=$null;$p=$null;$clock=$null;$normal=$false;$confirmed=$false;$requested=$false;$timedOut=$false
    $stdoutComplete=$false;$stderrComplete=$false;$terminationError=$null;$failure=$null;$pidOwned=$null;$created=$null;$exit=$null
    try {
        $stdout=[IO.File]::Open($nativeLog,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        $stderr=[IO.File]::Open($nativeLog+'.stderr',[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        $clock=[Diagnostics.Stopwatch]::StartNew()
        $p=[Diagnostics.Process]::Start($info)
        $pidOwned=$p.Id;$created=$p.StartTime.ToUniversalTime().ToString('o')
        $a=$p.StandardOutput.BaseStream.CopyToAsync($stdout);$b=$p.StandardError.BaseStream.CopyToAsync($stderr)
        $normal=$p.WaitForExit($WaitMilliseconds);$clock.Stop()
        $timedOut=-not$normal;$confirmed=$normal
        if(-not$normal){
            $requested=$true
            try{$p.Kill($true)}catch{$terminationError=$_.ToString()}
            try{$confirmed=$p.WaitForExit($ExitWaitMilliseconds)}catch{$terminationError=$_.ToString()}
        }
        try{$stdoutComplete=$a.Wait($ExitWaitMilliseconds)}catch{$failure='stdout drain failed: '+$_.ToString()}
        try{$stderrComplete=$b.Wait($ExitWaitMilliseconds)}catch{$failure='stderr drain failed: '+$_.ToString()}
        if($confirmed){$exit=$p.ExitCode}
    }catch{
        $failure=$_.ToString();if($clock-and$clock.IsRunning){$clock.Stop()}
        if($p){try{if(-not$p.HasExited){$requested=$true;$p.Kill($true)};$confirmed=$p.WaitForExit($ExitWaitMilliseconds)}catch{$terminationError=$_.ToString()}}
    }
    finally {
        if($clock-and$clock.IsRunning){$clock.Stop()}
        # Incremental file copies preserve received bytes even when EOF/drain cannot be confirmed.
        foreach($sink in $stdout,$stderr){if($sink){try{$sink.Flush()}finally{$sink.Dispose()}}}
        if($p){$p.StandardOutput.Dispose();$p.StandardError.Dispose()}
    }
    $outItem=Get-Item -LiteralPath $nativeLog -ErrorAction Stop;$errItem=Get-Item -LiteralPath ($nativeLog+'.stderr') -ErrorAction Stop
    $record=@{
        pid=$pidOwned;createdUtc=$created;exe=$executable;arguments=$Tokens;workingDirectory=$cwd;project=$Context.Project
        platform=$Platform;pathListSeparator=$rules.pathListSeparator;transport='direct executable / ArgumentList / no shell'
        elapsedSeconds=$(if($clock){$clock.Elapsed.TotalSeconds}else{$null});clockBoundary='immediately before Process.Start through normal WaitForExit'
        validClock=($normal-and$confirmed-and$stdoutComplete-and$stderrComplete-and-not$failure)
        timeout=$timedOut;killRequested=$requested;exitConfirmed=$confirmed;exit=$exit;terminationError=$terminationError;failure=$failure
        stdoutComplete=$stdoutComplete;stderrComplete=$stderrComplete;stdoutBytes=$outItem.Length;stderrBytes=$errItem.Length
        stdoutSha256=(Get-FileHash -LiteralPath $nativeLog).Hash;stderrSha256=(Get-FileHash -LiteralPath ($nativeLog+'.stderr')).Hash
    }
    $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath ($nativeLog+'.process.json')
    if($timedOut){throw 'Owned launcher timeout'}
    if($failure-or-not$confirmed-or-not$stdoutComplete-or-not$stderrComplete){throw 'Launcher exit/output unconfirmed'}
    return [int]$exit
}

Export-ModuleMember -Function Get-H3911NativePathRules,Invoke-H3911DirectNative
