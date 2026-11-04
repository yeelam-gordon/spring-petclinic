function Assert-EffectiveOwner($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function ConvertFrom-EffectiveJavaEscape([string]$Value){
    $out=[Text.StringBuilder]::new()
    for($i=0;$i-lt$Value.Length;$i++){
        $c=$Value[$i]
        if($c-eq'\'){
            $i++;Assert-EffectiveOwner ($i-lt$Value.Length) 'Truncated Java escape/unsupported continuation';$c=$Value[$i]
            if($c-eq'u'){Assert-EffectiveOwner ($i+4-lt$Value.Length-and$Value.Substring($i+1,4)-cmatch'^[0-9A-Fa-f]{4}$') 'Invalid Java Unicode escape';$c=[char][Convert]::ToInt32($Value.Substring($i+1,4),16);$i+=4}
            else{$c=switch($c){t{"`t"}n{"`n"}r{"`r"}f{[char]12}default{$c}}}
        }
        $null=$out.Append($c)
    }
    $out.ToString()
}
function Get-EffectiveJcmdBody([string]$Text,[int]$ExpectedPid){
    Assert-EffectiveOwner ($ExpectedPid-gt0) 'Positive expected probe PID required'
    $lines=@($Text-split'\r?\n');$index=0
    while($index-lt$lines.Count-and$lines[$index]-match'^Picked up (JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS):'){$index++}
    Assert-EffectiveOwner ($index-lt$lines.Count-and[string]::Equals($lines[$index],("$ExpectedPid"+':'),[StringComparison]::Ordinal)) 'Probe PID/header/preamble differs'
    @($lines|Select-Object -Skip ($index+1))
}
function ConvertFrom-H3911EffectiveVmProperties {
    param([Parameter(Mandatory)][string]$Text,[Parameter(Mandatory)][int]$ExpectedPid)
    $map=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach($line in @(Get-EffectiveJcmdBody $Text $ExpectedPid)){
        if($line.Length-eq0-or$line.StartsWith('#')-or$line.StartsWith('!')){continue}
        $separator=-1;$escaped=$false
        for($i=0;$i-lt$line.Length;$i++){if(-not$escaped-and$line[$i]-eq'='){$separator=$i;break};if($line[$i]-eq'\'){$escaped=-not$escaped}else{$escaped=$false}}
        Assert-EffectiveOwner ($separator-gt0) 'Unsupported/malformed Java property row'
        $key=ConvertFrom-EffectiveJavaEscape $line.Substring(0,$separator)
        $value=ConvertFrom-EffectiveJavaEscape $line.Substring($separator+1)
        Assert-EffectiveOwner ($key.Length-gt0-and$map.TryAdd($key,$value)) 'Duplicate decoded Java property key'
    }
    @{pid=$ExpectedPid;properties=$map;kind='parsed-jcmd-format-not-owner-qualification'}
}
function ConvertFrom-H3911EffectiveDynlibs {
    param([Parameter(Mandatory)][string]$Text,[Parameter(Mandatory)][int]$ExpectedPid)
    $lines=@(Get-EffectiveJcmdBody $Text $ExpectedPid)
    Assert-EffectiveOwner ($lines.Count-gt0-and[string]::Equals($lines[0],'Dynamic libraries:',[StringComparison]::Ordinal)) 'Unknown dynlibs format'
    $paths=@()
    foreach($line in @($lines|Select-Object -Skip 1)){
        if($line.Length-eq0){continue}
        Assert-EffectiveOwner ($line-cmatch'^0x[0-9A-Fa-f]+[ \t]+(?<nativePath>/[^\r\n]+)$') 'Unknown dynlibs row'
        $paths+=,$Matches.nativePath
    }
    $jni=@($paths|Where-Object{$_.Contains('mvndnative',[StringComparison]::Ordinal)-and$_.EndsWith('.jnilib',[StringComparison]::Ordinal)})
    Assert-EffectiveOwner ($jni.Count-eq1) 'Ambiguous/missing mapped mvnd JNI'
    @{pid=$ExpectedPid;jniPath=$jni[0];kind='parsed-dynlibs-format-not-owner-qualification'}
}
function Assert-EffectivePath([string]$Path){
    Assert-EffectiveOwner ($Path-and$Path.StartsWith('/')-and$Path-notmatch'[\x00-\x1f\\]|//|(^|/)\.\.?(/|$)'-and$Path-notmatch'/$') 'Canonical absolute Darwin path required'
}
function Assert-H3911EffectiveOwnerFacts {
    param([hashtable]$Context,[hashtable]$Registry,[hashtable]$Before,[hashtable]$After,[hashtable]$Properties,[hashtable]$Dynlibs,[byte[]]$JniBytes)
    Assert-EffectiveOwner ($Registry.schema-ceq'mvnd103-registry'-and$Registry.count-eq1-and$Registry.records.Count-eq1) 'Complete single private103 registry required'
    $row=$Registry.records[0]
    Assert-EffectiveOwner ($row.pid-is[int]-and$row.pid-gt0-and$row.id-cmatch'^[a-f0-9]{8}$') 'Registry identity malformed'
    foreach($path in $Context.Jdk,$Context.Home,$Context.Registry,$Context.Temp){Assert-EffectivePath $path}
    foreach($p in @(@($row.javaHome,$Context.Jdk),@($row.home,$Context.Home))){Assert-EffectiveOwner ([string]::Equals($p[0],$p[1],[StringComparison]::Ordinal)) 'Registry Java/home differs'}
    foreach($identity in $Before,$After){
        Assert-EffectiveOwner ($identity.status-ceq'present'-and($identity.pid-is[int]-or$identity.pid-is[long])-and$identity.pid-eq$row.pid-and$identity.created-is[string]-and-not[string]::IsNullOrWhiteSpace($identity.created)-and[string]::Equals($identity.executable,($Context.Jdk+'/bin/java'),[StringComparison]::Ordinal)) 'Native process identity unavailable/foreign'
    }
    Assert-EffectiveOwner ([string]::Equals($Before.created,$After.created,[StringComparison]::Ordinal)-and$Properties.pid-eq$row.pid-and$Dynlibs.pid-eq$row.pid) 'PID reuse/probe PID differs'
    foreach($pair in @(@('mvnd.id',$row.id),@('mvnd.home',$Context.Home),@('maven.home',($Context.Home+'/mvn')),@('mvnd.daemonStorage',$Context.Registry),@('mvnd.registry',($Context.Registry+'/registry.bin')),@('java.home',$Context.Jdk),@('mvnd.java.home',$Context.Jdk),@('java.io.tmpdir',$Context.Temp),@('mvndnative.tmpdir',$Context.Temp),@('os.arch','aarch64'),@('java.vendor','Microsoft'),@('java.runtime.version','25.0.5.0.2+1-LTS'))){
        $keys=@($Properties.properties.Keys|Where-Object{[string]::Equals($_,$pair[0],[StringComparison]::Ordinal)})
        Assert-EffectiveOwner ($keys.Count-eq1-and[string]::Equals($Properties.properties[$pair[0]],$pair[1],[StringComparison]::Ordinal)) 'Required effective Java key/value differs'
    }
    Assert-EffectivePath $Dynlibs.jniPath
    Assert-EffectiveOwner ($Dynlibs.jniPath.StartsWith($Context.Temp+'/',[StringComparison]::Ordinal)-and$JniBytes.Length-ge32-and[BitConverter]::ToUInt32($JniBytes,0)-eq4277009103-and[BitConverter]::ToUInt32($JniBytes,4)-eq0x0100000C-and[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($JniBytes))-ceq'72F98DFA637267E89161F984F6BAB2B9E5653B5F888A41C7733F237070EBE6E9') 'Mapped JNI boundary/hash/ARM differs'
    @{pid=$row.pid;created=$Before.created;executable=$Before.executable;daemonId=$row.id;home=$Context.Home;registryFile=($Context.Registry+'/registry.bin');jniPath=$Dynlibs.jniPath;evidenceKind='validated-effective-facts-model-not-runtime-authority';originalArgvOrPomConfigProven=$false}
}
function Resolve-EffectivePhysical([string]$Path,[switch]$Directory){
    Assert-EffectivePath $Path
    $resolved=Resolve-Path -LiteralPath $Path -ErrorAction Stop;$item=Get-Item -LiteralPath $resolved.ProviderPath -Force
    Assert-EffectiveOwner ($resolved.Provider.Name-ceq'FileSystem'-and[string]::Equals($resolved.ProviderPath,$Path,[StringComparison]::Ordinal)-and(($Directory-and$item-is[IO.DirectoryInfo])-or((-not$Directory)-and$item-is[IO.FileInfo]))-and-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-and($Directory-or-not$item.LinkType)) 'Noncanonical/linked physical owner path'
    $parent=if($Directory){$item}else{$item.Directory}
    while($parent){Assert-EffectiveOwner (-not((Get-Item -LiteralPath $parent.FullName -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked owner ancestry';$parent=$parent.Parent}
    $resolved.ProviderPath
}
function Get-EffectiveOsIdentity([int]$ProcessId){
    try{$p=Microsoft.PowerShell.Management\Get-Process -Id $ProcessId -ErrorAction Stop;$path=$p.Path;$created=$p.StartTime.ToUniversalTime().ToString('o')}catch{throw 'HOLD: native PID/start/executable unavailable'}
    Assert-EffectiveOwner ($path-and$created) 'Native process path/start missing'
    @{status='present';pid=$ProcessId;created=$created;executable=$path}
}
function Import-EffectiveDependencies {
    $pins=@{'H3911.DarwinOwner.psm1'='E9A8FD932AC839119FDD0B810533E8FB69BA314CB038E7345C484A7988A36E1E';'H3911.NativeProcess.psm1'='6CF9CB37879428520B87738FE8A0CDECEA8E0B6AA6577C068FDABB44F038E5A3';'H3911.Darwin103.psm1'='05F80C9435B3E6012FAE8874A887A7F96AF8B44311EC1D4A06265ED254E7A264'}
    $exports=@{'H3911.DarwinOwner.psm1'='Read-H3911Registry103';'H3911.NativeProcess.psm1'='Invoke-H3911DirectNative';'H3911.Darwin103.psm1'='Assert-H3911Darwin103Distribution'}
    $bound=@{}
    foreach($p in $pins.GetEnumerator()){
        $path=Join-Path $PSScriptRoot $p.Key;Assert-EffectiveOwner ((Get-FileHash $path).Hash-ceq$p.Value) 'Pinned effective-owner dependency differs'
        $loaded=@(Import-Module $path -Scope Local -PassThru)
        Assert-EffectiveOwner ($loaded.Count-eq1) 'Ambiguous private dependency module'
        $name=$exports[$p.Key];$command=$loaded[0].ExportedCommands[$name]
        Assert-EffectiveOwner ($command-is[Management.Automation.FunctionInfo]-and[string]::Equals($command.Name,$name,[StringComparison]::Ordinal)-and[string]::Equals($command.Module.Path,$path,[StringComparison]::Ordinal)) 'Pinned dependency command object/origin differs'
        $bound[$name]=$command
    }
    $bound
}
function Read-H3911DarwinEffectiveOwner {
    param([Parameter(Mandatory)][hashtable]$Context,[switch]$RuntimeApproved)
    Assert-EffectiveOwner ($IsMacOS-and$RuntimeApproved) 'Native Mac plus explicit RuntimeApproved required'
    $dependencies=Import-EffectiveDependencies
    foreach($path in $Context.Jdk,$Context.Home,$Context.Registry,$Context.Temp,$Context.Output){$null=Resolve-EffectivePhysical $path -Directory}
    foreach($immutable in $Context.Jdk,$Context.Home,$Context.Registry){Assert-EffectiveOwner (-not[string]::Equals($Context.Output,$immutable,[StringComparison]::Ordinal)-and-not$Context.Output.StartsWith($immutable+'/',[StringComparison]::Ordinal)) 'Probe output cannot modify SDK/distribution/registry'}
    $null=& ($dependencies['Assert-H3911Darwin103Distribution']) $Context.Home -RequireNativeModes
    $java=Resolve-EffectivePhysical ($Context.Jdk+'/bin/java');$jcmd=Resolve-EffectivePhysical ($Context.Jdk+'/bin/jcmd')
    Assert-EffectiveOwner ($Context.ExpectedJavaSha256-is[string]-and$Context.ExpectedJavaSha256-cmatch'^[A-F0-9]{64}$'-and(Get-FileHash $java).Hash-ceq$Context.ExpectedJavaSha256) 'Caller source-pinned native25 Java hash required'
    Assert-EffectiveOwner ($Context.ExpectedJcmdSha256-is[string]-and$Context.ExpectedJcmdSha256-cmatch'^[A-F0-9]{64}$'-and(Get-FileHash $jcmd).Hash-ceq$Context.ExpectedJcmdSha256) 'Caller source-pinned native25 jcmd hash required'
    [byte[]]$image=[IO.File]::ReadAllBytes($java)
    Assert-EffectiveOwner ($image.Length-ge32-and[BitConverter]::ToUInt32($image,0)-eq4277009103-and[BitConverter]::ToUInt32($image,4)-eq0x0100000C) 'Native Java is not ARM64 Mach-O'
    $registryPath=Resolve-EffectivePhysical ($Context.Registry+'/registry.bin')
    [byte[]]$bytes=[IO.File]::ReadAllBytes($registryPath);$digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
    $registry=& ($dependencies['Read-H3911Registry103']) $bytes
    Assert-EffectiveOwner ($registry-is[hashtable]-and$registry.ContainsKey('schema')-and$registry.ContainsKey('count')-and$registry.ContainsKey('records')-and$registry.schema-ceq'mvnd103-registry'-and$registry.count-is[int]-and$registry.count-eq1-and$registry.records-is[array]-and$registry.records.Count-eq1) 'Complete parsed single private registry required'
    Assert-EffectiveOwner ([string]::Equals($registry.records[0].javaHome,$Context.Jdk,[StringComparison]::Ordinal)-and[string]::Equals($registry.records[0].home,$Context.Home,[StringComparison]::Ordinal)) 'Foreign registry Java/home before probes'
    $id=$registry.records[0].pid;$before=Get-EffectiveOsIdentity $id
    $e=Join-Path $Context.Output ('effective-owner-'+[guid]::NewGuid().ToString('N'));New-Item $e -ItemType Directory -ErrorAction Stop|Out-Null
    $launch=@{Project=$Context.Temp}
    foreach($probe in 'VM.system_properties','VM.dynlibs'){
        $pre=Get-EffectiveOsIdentity $id
        Assert-EffectiveOwner ($pre.created-ceq$before.created-and[string]::Equals($pre.executable,$java,[StringComparison]::Ordinal)) 'PID reused/foreign before probe'
        $log=Join-Path $e ($probe+'.log')
        $exit=& ($dependencies['Invoke-H3911DirectNative']) $jcmd @([string]$id,$probe) $log -Context $launch -WorkingDirectory $Context.Temp -Platform Posix -WaitMilliseconds 30000
        Assert-EffectiveOwner ($exit-eq0) 'Native jcmd failed'
        $post=Get-EffectiveOsIdentity $id
        Assert-EffectiveOwner ($post.created-ceq$before.created-and[string]::Equals($post.executable,$java,[StringComparison]::Ordinal)) 'PID reused/foreign after probe'
    }
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $properties=ConvertFrom-H3911EffectiveVmProperties ($utf8.GetString([IO.File]::ReadAllBytes((Join-Path $e 'VM.system_properties.log')))) $id
    $libs=ConvertFrom-H3911EffectiveDynlibs ($utf8.GetString([IO.File]::ReadAllBytes((Join-Path $e 'VM.dynlibs.log')))) $id
    $null=Resolve-EffectivePhysical $libs.jniPath
    $facts=Assert-H3911EffectiveOwnerFacts $Context $registry $before $post $properties $libs ([IO.File]::ReadAllBytes($libs.jniPath))
    Assert-EffectiveOwner ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($registryPath)))-ceq$digest) 'Private registry changed across probes'
    $null=& ($dependencies['Assert-H3911Darwin103Distribution']) $Context.Home -RequireNativeModes
    $facts.evidenceKind='native-mac-effective-owner';$facts.probeStarts=2;$facts.probesUntimed=$true;$facts.receipts=$e
    $facts
}
Export-ModuleMember -Function ConvertFrom-H3911EffectiveVmProperties,ConvertFrom-H3911EffectiveDynlibs,Assert-H3911EffectiveOwnerFacts,Read-H3911DarwinEffectiveOwner
