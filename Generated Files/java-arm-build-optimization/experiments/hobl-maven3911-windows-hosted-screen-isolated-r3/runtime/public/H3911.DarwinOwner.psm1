function Assert-DarwinOwner($Value,[string]$Message){if(-not$Value){throw $Message}}
function Assert-DarwinOwnerPid($Value){Assert-DarwinOwner (($Value-is[int]-or$Value-is[long])-and$Value-gt0-and$Value-le[int]::MaxValue) 'Explicit positive integer PID required'}
function Assert-DarwinOwnerCreation($Value){
    $stamp=[DateTimeOffset]::MinValue
    Assert-DarwinOwner ($Value-is[string]-and$Value-cmatch'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$'-and[DateTimeOffset]::TryParse($Value,[ref]$stamp)) 'Explicit nonempty ISO creation witness required'
}
function Assert-DarwinOwnerRegistry($Registry){
    Assert-DarwinOwner ($Registry-is[hashtable]-and$Registry.schema-ceq'mvnd103-registry'-and($Registry.count-is[int]-or$Registry.count-is[long])-and$Registry.count-in@(0,1)-and$Registry.records-is[array]-and$Registry.records.Count-eq$Registry.count) 'Explicit complete parsed registry required'
}
function Assert-DarwinOwnerIdentity($Identity){
    Assert-DarwinOwner ($Identity-is[hashtable]) 'Explicit owner identity required'
    Assert-DarwinOwnerPid $Identity.pid;Assert-DarwinOwnerCreation $Identity.created
    Assert-DarwinOwner ($Identity.daemonId-is[string]-and$Identity.daemonId-cmatch'^[a-f0-9]{8}$') 'Explicit daemon id required'
    foreach($key in 'executable','home','registry','registryFile','temp','jniPath'){Assert-DarwinOwner ($Identity[$key]-is[string]) 'Explicit owner path required';Assert-DarwinAbsolute $Identity[$key]}
    Assert-DarwinOwner ($Identity.jniSha256-is[string]-and$Identity.jniSha256-cmatch'^[A-F0-9]{64}$'-and$Identity.fixtureOnly-is[bool]-and$Identity.fixtureOnly-and$Identity.runtimeAuthorized-is[bool]-and-not$Identity.runtimeAuthorized) 'Explicit fixture identity/JNI/authority witnesses required'
}
function Read-H3911Registry103 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    Assert-DarwinOwner ($Bytes.Length-ge8-and$Bytes.Length-le2097152) 'Malformed/truncated1.0.3 registry'
    $stream=[IO.MemoryStream]::new($Bytes,$false);$reader=[IO.BinaryReader]::new($stream)
    function Take([int]$N){$b=$reader.ReadBytes($N);Assert-DarwinOwner ($b.Length-eq$N) 'Truncated1.0.3 registry';return ,$b}
    function Int32BE {[byte[]]$b=Take 4;if([BitConverter]::IsLittleEndian){[Array]::Reverse($b)};[BitConverter]::ToInt32($b,0)}
    function LongBE {[byte[]]$b=Take 8;if([BitConverter]::IsLittleEndian){[Array]::Reverse($b)};[BitConverter]::ToInt64($b,0)}
    function Utf103 {
        $n=256*[int]$reader.ReadByte()+[int]$reader.ReadByte()
        # Valid UTF8 BMP subset of Java modified UTF8; unsupported NUL/surrogates fail, never guessed.
        [byte[]]$b=Take $n;$s=[Text.UTF8Encoding]::new($false,$true).GetString($b)
        Assert-DarwinOwner ($s-notmatch'[\x00-\x1f\uD800-\uDFFF]') 'Unsupported modified-UTF8/control/non-BMP text in registry'
        $s
    }
    try{
        $count=Int32BE;Assert-DarwinOwner ($count-in@(0,1)) 'Private registry must contain zero or one daemon'
        $records=@()
        for($i=0;$i-lt$count;$i++){
            $id=Utf103;$java=Utf103;$home=Utf103;$processId=Int32BE;$address=Utf103
            $null=Take 16;$locale=Utf103;$optionsCount=Int32BE
            Assert-DarwinOwner ($id-cmatch'^[a-f0-9]{8}$'-and$processId-gt0-and$optionsCount-ge0-and$optionsCount-le256) 'Malformed daemon record'
            $options=@();for($j=0;$j-lt$optionsCount;$j++){$options+=,(Utf103)}
            $state=$reader.ReadByte();Assert-DarwinOwner ($state-le5) 'Unknown1.0.3 daemon state'
            $idle=LongBE;$busy=LongBE
            $records+=,@{id=$id;javaHome=$java;home=$home;pid=$processId;address=$address;locale=$locale;options=$options;state=$state;lastIdle=$idle;lastBusy=$busy}
        }
        $stops=Int32BE;Assert-DarwinOwner ($stops-ge0-and$stops-le128) 'Malformed stop-event count'
        for($i=0;$i-lt$stops;$i++){$null=Utf103;$null=LongBE;$status=$reader.ReadByte();Assert-DarwinOwner ($status-in@(0,1,2,3,255)) 'Unknown1.0.3 stop status';$null=Utf103}
        Assert-DarwinOwner ($stream.Position-eq$stream.Length) 'Trailing/unknown1.0.3 registry bytes'
        @{schema='mvnd103-registry';count=$count;records=$records;stopEvents=$stops;tokenOmitted=$true}
    }finally{$reader.Dispose();$stream.Dispose()}
}
function Assert-DarwinAbsolute($Path){
    Assert-DarwinOwner ($Path-is[string]-and$Path-and$Path.StartsWith('/',[StringComparison]::Ordinal)-and$Path-notmatch'[\x00-\x1f\\]|//|(^|/)\.\.?(/|$)'-and$Path-notmatch'/$') 'Canonical absolute Darwin path required'
}
function Assert-H3911DarwinOwnerFixture {
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][hashtable]$Registry,[Parameter(Mandatory)][hashtable]$Telemetry,[Parameter(Mandatory)][byte[]]$JniBytes)
    Assert-DarwinOwner ($Telemetry.origin-ceq'SYNTHETIC_FIXTURE'-and-not$Context.RuntimeApproved) 'Fixture telemetry cannot authorize real runtime'
    Assert-DarwinOwnerRegistry $Registry
    Assert-DarwinOwner ($Registry.count-eq1-and$Telemetry.origin-is[string]-and$Telemetry.processStatus-is[string]-and$Telemetry.processStatus-ceq'present'-and$Telemetry.ContainsKey('errors')-and$Telemetry.errors-is[array]-and$Telemetry.errors.Count-eq0-and$Telemetry.properties-is[hashtable]-and$Telemetry.argv-is[array]) 'Missing/unknown process telemetry'
    Assert-DarwinOwnerPid $Context.ExpectedPid;Assert-DarwinOwnerCreation $Context.ExpectedCreated
    foreach($key in 'pid','propertiesPid','dynlibsPid'){Assert-DarwinOwnerPid $Telemetry[$key]}
    Assert-DarwinOwnerCreation $Telemetry.created;Assert-DarwinOwnerCreation $Telemetry.createdAfterProbes
    Assert-DarwinOwner ($Telemetry.executable-is[string]-and$Context.DaemonId-is[string]-and$Context.DaemonId-cmatch'^[a-f0-9]{8}$') 'Explicit Java/daemon identity required'
    foreach($path in $Context.Jdk,$Context.Home,$Context.Registry,$Context.Temp){Assert-DarwinAbsolute $path}
    $row=$Registry.records[0];$java=$Context.Jdk+'/bin/java'
    Assert-DarwinOwnerPid $row.pid
    Assert-DarwinOwner ($row.pid-eq$Context.ExpectedPid-and$row.id-ceq$Context.DaemonId-and$Telemetry.pid-eq$row.pid-and$Telemetry.propertiesPid-eq$row.pid-and$Telemetry.dynlibsPid-eq$row.pid) 'PID/daemon/probe identity differs'
    foreach($pair in @(@($row.javaHome,$Context.Jdk),@($row.home,$Context.Home),@($Telemetry.executable,$java),@($Telemetry.created,$Context.ExpectedCreated),@($Telemetry.createdAfterProbes,$Context.ExpectedCreated))){Assert-DarwinOwner ([string]::Equals($pair[0],$pair[1],[StringComparison]::Ordinal)) 'Creation/java/home identity differs'}
    foreach($p in @(@('mvnd.id',$row.id),@('mvnd.home',$Context.Home),@('mvnd.daemonStorage',$Context.Registry),@('mvnd.registry',($Context.Registry+'/registry.bin')),@('java.home',$Context.Jdk),@('java.io.tmpdir',$Context.Temp),@('mvndnative.tmpdir',$Context.Temp),@('os.arch','aarch64'))){
        Assert-DarwinOwner (@($Telemetry.properties.Keys|Where-Object{$_-is[string]-and[string]::Equals($_,$p[0],[StringComparison]::Ordinal)}).Count-eq1) 'Exact case-sensitive Java VM property key absent'
        Assert-DarwinOwner ([string]::Equals($Telemetry.properties[$p[0]],$p[1],[StringComparison]::Ordinal)) 'Exact VM ownership property differs'
    }
    foreach($p in @(@('mvnd.id',$row.id),@('mvnd.home',$Context.Home),@('mvnd.daemonStorage',$Context.Registry))){
        $prefix='-D'+$p[0]+'=';$matches=@($Telemetry.argv|Where-Object{$_.StartsWith($prefix,[StringComparison]::Ordinal)})
        Assert-DarwinOwner ($matches.Count-eq1-and[string]::Equals($matches[0],($prefix+$p[1]),[StringComparison]::Ordinal)) 'Exact process ownership token differs'
    }
    Assert-DarwinAbsolute $Telemetry.jniPath
    Assert-DarwinOwner ($Telemetry.jniPath.StartsWith($Context.Temp+'/',[StringComparison]::Ordinal)-and$JniBytes.Length-ge32-and[BitConverter]::ToUInt32($JniBytes,0)-eq4277009103-and[BitConverter]::ToUInt32($JniBytes,4)-eq0x0100000C-and[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($JniBytes))-ceq'72F98DFA637267E89161F984F6BAB2B9E5653B5F888A41C7733F237070EBE6E9') 'Loaded JNI path/hash/ARM identity differs'
    @{pid=$row.pid;created=$Telemetry.created;executable=$java;daemonId=$row.id;home=$Context.Home;registry=$Context.Registry;registryFile=($Context.Registry+'/registry.bin');temp=$Context.Temp;jniPath=$Telemetry.jniPath;jniSha256='72F98DFA637267E89161F984F6BAB2B9E5653B5F888A41C7733F237070EBE6E9';fixtureOnly=$true;runtimeAuthorized=$false}
}
function Assert-H3911DarwinRevalidation {
    param([Parameter(Mandatory)][hashtable]$Expected,[Parameter(Mandatory)][hashtable]$Current)
    Assert-DarwinOwnerIdentity $Expected;Assert-DarwinOwnerIdentity $Current
    foreach($key in 'pid','created','executable','daemonId','home','registry','registryFile','temp','jniPath','jniSha256'){Assert-DarwinOwner ([string]::Equals([string]$Expected[$key],[string]$Current[$key],[StringComparison]::Ordinal)) 'PID reused/foreign identity: do not stop or kill'}
    Assert-DarwinOwner ($Expected.fixtureOnly-and$Current.fixtureOnly-and-not$Expected.runtimeAuthorized-and-not$Current.runtimeAuthorized) 'Unqualified native telemetry HOLD'
    $true
}
function New-H3911DarwinStopFixture {
    param([hashtable]$Context,[hashtable]$Registry,[hashtable]$Expected,[hashtable]$Current,[switch]$Emergency)
    $null=Assert-H3911DarwinRevalidation $Expected $Current
    Assert-DarwinOwnerRegistry $Registry;Assert-DarwinAbsolute $Context.Jdk
    Assert-DarwinOwner ($Registry.count-eq1-and$Registry.records[0].pid-eq$Expected.pid-and$Registry.records[0].id-ceq$Expected.daemonId) 'Stop would include foreign registry owner'
    @{exe=$Expected.home+'/bin/mvnd';tokens=@("-Dmvnd.daemonStorage=$($Expected.registry)","-Dmvnd.registry=$($Expected.registryFile)","-Djava.home=$($Context.Jdk)",'--stop');workingDirectory=$Expected.temp;emergency=[bool]$Emergency;sourceIndependent=$true;fixtureOnly=$true;runtimeAuthorized=$false;cliSemantics='1.0.3 destroys registered PID forcibly then removes registry record; separate disappearance proof required'}
}
function Confirm-H3911DarwinStopFixture {
    param([hashtable]$Registry,[hashtable]$After,[object]$StopExit,[switch]$Forced,[switch]$Emergency)
    Assert-DarwinOwner ($PSBoundParameters.ContainsKey('StopExit')-and($StopExit-is[int]-or$StopExit-is[long])-and$StopExit-ge[int]::MinValue-and$StopExit-le[int]::MaxValue) 'Explicit observed integer StopExit required'
    Assert-DarwinOwnerRegistry $Registry
    Assert-DarwinOwner ($After.ContainsKey('ownedPids')-and$After.ownedPids-is[array]-and$After.ContainsKey('errors')-and$After.errors-is[array]-and$After.scanComplete-is[bool]) 'Explicit census/error arrays and scan witness required'
    Assert-DarwinOwner ($After.origin-is[string]-and$After.origin-ceq'SYNTHETIC_FIXTURE'-and$After.processStatus-is[string]-and$After.scanComplete-and$After.errors.Count-eq0-and$After.processStatus-ceq'absent'-and$After.ownedPids.Count-eq0-and$Registry.count-eq0) 'Registry empty/root exit is not complete daemon/descendant cleanup'
    @{status=$(if($StopExit-eq0-and-not$Forced-and-not$Emergency){'FIXTURE_NORMAL_CLI_STOP_CONFIRMED'}else{'FAIL_FORCED_OR_EMERGENCY_NOT_NORMAL_STOP'});fixtureOnly=$true;runtimeAuthorized=$false}
}
function Get-H3911DarwinOwnerProbePlan {
    param([hashtable]$Context)
    foreach($path in $Context.Jdk,$Context.Home,$Context.Registry,$Context.Temp){Assert-DarwinAbsolute $path}
    @{status='HOLD_NATIVE_MAC_TELEMETRY_FORMAT_UNQUALIFIED';outsideAllTimers=$true;nativeCommands=5;commands=@(
        @{exe='/bin/ps';tokens=@('-p',[string]$Context.ExpectedPid,'-o','lstart=,command=');phase='before';purpose='OS creation/executable/argv needs actual Mac format qualification'},
        @{exe=$Context.Jdk+'/bin/jcmd';tokens=@([string]$Context.ExpectedPid,'VM.system_properties')},
        @{exe='/bin/ps';tokens=@('-p',[string]$Context.ExpectedPid,'-o','lstart=,command=');phase='between'},
        @{exe=$Context.Jdk+'/bin/jcmd';tokens=@([string]$Context.ExpectedPid,'VM.dynlibs')},
        @{exe='/bin/ps';tokens=@('-p',[string]$Context.ExpectedPid,'-o','lstart=,command=');phase='after'}
    );nativeGetProcessExecutableAndCreationBindingAlsoRequired=$true;runtimeAuthorized=$false}
}
function Read-H3911DarwinOwner {
    param([hashtable]$Context,[switch]$RuntimeApproved)
    throw 'HOLD: native Mac ps/Get-Process and jcmd properties/dynlibs formats require actual approved captures; fixture substitution is forbidden'
}
Export-ModuleMember -Function Read-H3911Registry103,Assert-H3911DarwinOwnerFixture,Assert-H3911DarwinRevalidation,New-H3911DarwinStopFixture,Confirm-H3911DarwinStopFixture,Get-H3911DarwinOwnerProbePlan,Read-H3911DarwinOwner
