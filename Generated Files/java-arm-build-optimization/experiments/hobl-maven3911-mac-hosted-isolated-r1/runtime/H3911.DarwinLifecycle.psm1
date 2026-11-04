function Assert-DarwinLife($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function Assert-LifePath($Value){
    Assert-DarwinLife ($Value-is[string]-and$Value.StartsWith('/',[StringComparison]::Ordinal)-and$Value-notmatch'[\x00-\x1f\\]|//|(^|/)\.\.?(/|$)'-and$Value-notmatch'/$') 'Canonical Darwin path required'
}
function Assert-LifeIdentity($Value){
    Assert-DarwinLife ($Value-is[hashtable]-and($Value.pid-is[int]-or$Value.pid-is[long])-and$Value.pid-gt0-and$Value.pid-le[int]::MaxValue) 'Explicit positive PID identity required'
    $stamp=[DateTimeOffset]::MinValue
    Assert-DarwinLife ($Value.created-is[string]-and$Value.created-cmatch'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$'-and[DateTimeOffset]::TryParse($Value.created,[ref]$stamp)) 'Explicit ISO creation required'
    Assert-LifePath $Value.executable
}
function Assert-LifeContext($Context,$Expected){
    foreach($p in $Context.Jdk,$Context.Home,$Context.Registry,$Context.Temp){Assert-LifePath $p}
    Assert-LifeIdentity $Expected
    Assert-DarwinLife ($Expected.daemonId-is[string]-and$Expected.daemonId-cmatch'^[a-f0-9]{8}$') 'Explicit daemon id required'
    foreach($p in @(@($Expected.executable,($Context.Jdk+'/bin/java')),@($Expected.home,$Context.Home),@($Expected.registryFile,($Context.Registry+'/registry.bin')))){
        Assert-DarwinLife ([string]::Equals($p[0],$p[1],[StringComparison]::Ordinal)) 'Expected effective owner scope differs'
    }
    Assert-LifePath $Expected.jniPath
    Assert-DarwinLife ($Expected.jniPath.StartsWith($Context.Temp+'/',[StringComparison]::Ordinal)) 'Expected effective-owner temp boundary differs'
    Assert-DarwinLife ($Context.ContainsKey('KnownOwnedIdentities')-and$Context.KnownOwnedIdentities-is[array]) 'Explicit known-owned identity array required'
    $seen=[Collections.Generic.HashSet[int]]::new()
    foreach($identity in @($Expected)+@($Context.KnownOwnedIdentities)){Assert-LifeIdentity $identity;Assert-DarwinLife ($seen.Add([int]$identity.pid)) 'Duplicate tracked PID'}
}
function Assert-LifeRegistry($Registry,[int]$Count){
    Assert-DarwinLife ($Registry-is[hashtable]-and$Registry.ContainsKey('schema')-and$Registry.schema-is[string]-and$Registry.schema-ceq'mvnd103-registry'-and$Registry.ContainsKey('count')-and$Registry.count-is[int]-and$Registry.count-eq$Count-and$Registry.records-is[array]-and$Registry.records.Count-eq$Count) 'Complete parsed103 registry witness required'
}
function Test-LifeCreationInstant([string]$A,[string]$B){
    [DateTimeOffset]::Parse($A,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime.Ticks-eq[DateTimeOffset]::Parse($B,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime.Ticks
}
function Test-LifeSame($A,$B){
    ($A.pid-eq$B.pid)-and(Test-LifeCreationInstant $A.created $B.created)-and[string]::Equals($A.executable,$B.executable,[StringComparison]::Ordinal)
}
function Assert-LifeCredentialIdentity($Facts,$Identity,$Uid){
    Assert-DarwinLife ($Identity-is[hashtable]-and($Identity.pid-is[int]-or$Identity.pid-is[long])-and$Identity.pid-gt0-and$Identity.pid-le[int]::MaxValue-and$Identity.created-is[string]-and$Identity.created-cmatch'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$') 'Typed credential PID/birth identity required'
    Assert-DarwinLife ($Facts-is[hashtable]) 'Kernel credential facts required'
    $null=& ${function:ConvertFrom-LifeBsdFacts} @([int]136,[int]0,$Facts.pid,$Facts.parentPid,$Facts.realUid,$Facts.effectiveUid,$Facts.savedUid,$Facts.birthSeconds,$Facts.birthMicroseconds) $Identity.pid $Uid
    $delta=[DateTimeOffset]::Parse($Identity.created,[Globalization.CultureInfo]::InvariantCulture).UtcTicks-[DateTimeOffset]::UnixEpoch.UtcTicks
    $remainder=0L;$seconds=[Math]::DivRem([long]$delta,10000000L,[ref]$remainder)
    Assert-DarwinLife ($remainder-ge0-and$remainder%10-eq0) 'Kernel microsecond birth cannot bind metadata'
    $unused=0L;$microseconds=[Math]::DivRem($remainder,10L,[ref]$unused)
    & ${function:Assert-LifeCredentialBinding} $Facts $Identity.pid $Uid $seconds $microseconds
}
function Get-LifeUidCommands {
    $map=@{}
    foreach($name in 'Read-LifeSelfCredential','Read-LifeOwnerCredential','Read-LifeOwnUidPids','Get-LifeCurrent','Read-LifePresence','Read-LifeRegistry'){
        $command=$ExecutionContext.SessionState.InvokeCommand.GetCommand($name,[Management.Automation.CommandTypes]::Function)
        Assert-DarwinLife ($command-is[Management.Automation.FunctionInfo]-and$command.Module.Path-ceq$ExecutionContext.SessionState.Module.Path) 'Private UID command origin differs';$map[$name]=$command
    };$map
}
function Read-LifeUidSelf($Commands){
    $credential=& $Commands['Read-LifeSelfCredential'] -RuntimeApproved
    $identity=& $Commands['Get-LifeCurrent'] ([int]$credential.pid)
    & ${function:Assert-LifeCredentialIdentity} $credential $identity $credential.effectiveUid
    @{credential=$credential;identity=$identity;uid=$credential.effectiveUid}
}
function Assert-LifeUidCensus($Context,$Expected,$Census){
    Assert-DarwinLife ($Context.KnownOwnedIdentities-is[array]) 'Explicit tracked set required for UID proof'
    Assert-DarwinLife ($Census-is[hashtable]-and$Census.schema-ceq'darwin-launch-uid-java-census-v2'-and$Census.scope-ceq'launch-effective-UID admitted-JDK Java plus explicitly tracked identities'-and$Census.complete-is[bool]-and$Census.complete-and$Census.errors-is[array]-and$Census.errors.Count-eq0-and$Census.expectedIdentityGone-is[bool]) 'Versioned UID scoped census required; no v1 authority'
    $proof=$Census.uidProof
    Assert-DarwinLife ($proof.universalHistory-is[bool]-and-not$proof.universalHistory) 'No universal-history authority'
    Assert-DarwinLife ($proof-is[hashtable]-and$proof.schema-ceq'darwin-launch-uid-proof-v2'-and$proof.filter-is[int]-and$proof.filter-eq5-and$proof.observationBasis-ceq'INITIAL_ELIGIBLE_PID_NUMBERS_THEN_UID_SURVIVORS_PLUS_KNOWN_ESRCH_RECHECK'-and$proof.atomicEndpoint-is[bool]-and-not$proof.atomicEndpoint-and$proof.newbornCoverage-is[bool]-and-not$proof.newbornCoverage) 'Typed UID observation basis required'
    & ${function:Assert-LifeCredentialIdentity} $proof.selfCredential $proof.selfIdentity $proof.admittedUid
    foreach($field in 'selectedPidCount','knownPidCount','unionPidCount','validatedPidCount','missingAtRecheckCount','presenceRecheckAttempts'){Assert-DarwinLife (($proof[$field]-is[int]-or$proof[$field]-is[long])-and$proof[$field]-ge0-and$proof[$field]-le4096) 'Bounded UID accounting required'}
    Assert-DarwinLife ($proof.knownPidCount-eq(1+$Context.KnownOwnedIdentities.Count)-and$proof.unionPidCount-ge$proof.selectedPidCount-and$proof.unionPidCount-ge$proof.knownPidCount-and$proof.unionPidCount-le($proof.selectedPidCount+$proof.knownPidCount)-and$proof.validatedPidCount+$proof.missingAtRecheckCount-eq$proof.unionPidCount-and$proof.presenceRecheckAttempts-ge$proof.missingAtRecheckCount-and$proof.presenceRecheckAttempts-le$proof.unionPidCount) 'UID union/validation/ESRCH accounting differs'
    Assert-DarwinLife ($proof.selectedPidCount-gt0) 'Nonempty caller-containing UID selection required'
    if(-not$Census.expectedIdentityGone){& ${function:Assert-LifeCredentialIdentity} $proof.ownerCredential $Expected $proof.admittedUid}else{Assert-DarwinLife ($null-eq$proof.ownerCredential-and$proof.missingAtRecheckCount-ge1) 'Gone owner requires explicit failed-row ESRCH accounting, not invented credentials'}
}
function New-H3911DarwinStopPlanFacts {
    param([hashtable]$Context,[hashtable]$Expected,[hashtable]$Registry,[hashtable]$Current,[switch]$Emergency)
    Assert-LifeContext $Context $Expected;Assert-LifeRegistry $Registry 1;Assert-LifeIdentity $Current
    Assert-DarwinLife (Test-LifeSame $Expected $Current) 'PID reuse/foreign identity: no stop'
    $row=$Registry.records[0];Assert-LifeIdentity @{pid=$row.pid;created=$Current.created;executable=$Current.executable}
    foreach($p in @(@($row.id,$Expected.daemonId),@($row.javaHome,$Context.Jdk),@($row.home,$Context.Home))){Assert-DarwinLife ([string]::Equals($p[0],$p[1],[StringComparison]::Ordinal)) 'Registry owner differs'}
    Assert-DarwinLife ($row.pid-eq$Expected.pid) 'Foreign registry PID'
    @{exe=($Context.Home+'/bin/mvnd');tokens=@("-Dmvnd.daemonStorage=$($Context.Registry)","-Dmvnd.registry=$($Expected.registryFile)","-Djava.home=$($Context.Jdk)",'--stop');workingDirectory=$Context.Temp;expectedPid=$Expected.pid;expectedCreated=$Expected.created;emergency=[bool]$Emergency;sourceIndependent=$true;runtimeAuthorized=$false;evidenceKind='validated-stop-plan-model';cliSemantics='1.0.3 destroyForcibly then registry removal; not graceful shutdown; later absence proof mandatory'}
}
function ConvertTo-H3911DarwinScopedCensus {
    param([hashtable]$Context,[hashtable]$Expected,[hashtable]$Observation)
    Assert-LifeContext $Context $Expected
    Assert-DarwinLife ($Observation-is[hashtable]-and$Observation.complete-is[bool]-and$Observation.complete-and$Observation.ContainsKey('errors')-and$Observation.errors-is[array]-and$Observation.errors.Count-eq0-and$Observation.ContainsKey('processes')-and$Observation.processes-is[array]) 'Explicit complete enumeration/error/process arrays required'
    $java=$Context.Jdk+'/bin/java';$sameJdk=@();$knownLive=@();$tracked=@($Expected)+@($Context.KnownOwnedIdentities);$seen=[Collections.Generic.HashSet[int]]::new()
    foreach($identity in $Observation.processes){
        Assert-LifeIdentity $identity;Assert-DarwinLife ($seen.Add([int]$identity.pid)) 'Duplicate enumerated PID'
        if([string]::Equals($identity.executable,$java,[StringComparison]::Ordinal)){$sameJdk+=,$identity}
        foreach($known in $tracked){if($known.pid-eq$identity.pid-and(Test-LifeCreationInstant $known.created $identity.created)){$knownLive+=,$identity}}
    }
    $expectedLive=@($knownLive|Where-Object pid -eq $Expected.pid)
    $result=@{schema='darwin-scoped-java-census-v1';complete=$true;errors=@();jdkExecutable=$java;sameJdkJava=$sameJdk;knownLive=$knownLive;expectedIdentityGone=($expectedLive.Count-eq0);tracked=$tracked;evidenceKind='validated-census-model';scope='all admitted-JDK Java plus explicitly tracked PID/create identities; not universal historical descendants'}
    if($Observation.schema-ceq'darwin-launch-uid-observation-v2'){
        Assert-DarwinLife ($Observation.processes.Count-eq$Observation.uidProof.validatedPidCount) 'Validated row accounting differs'
        foreach($row in $Observation.processes){& ${function:Assert-LifeCredentialIdentity} $row.credential $row $Observation.uidProof.admittedUid;foreach($known in $tracked){if($row.pid-eq$known.pid){Assert-DarwinLife (Test-LifeSame $known $row) 'Known PID reuse/foreign identity HOLD'}}}
        $result.schema='darwin-launch-uid-java-census-v2';$result.scope='launch-effective-UID admitted-JDK Java plus explicitly tracked identities';$result.uidProof=$Observation.uidProof;$result.evidenceKind='validated-uid-census-model'
        & ${function:Assert-LifeUidCensus} $Context $Expected $result
    };$result
}
function Confirm-H3911DarwinAbsenceFacts {
    param([hashtable]$Context,[hashtable]$Expected,[hashtable]$Registry,[hashtable]$Census,[object]$StopExit,[switch]$Forced,[switch]$Emergency)
    Assert-LifeContext $Context $Expected;Assert-LifeRegistry $Registry 0
    Assert-DarwinLife ($PSBoundParameters.ContainsKey('StopExit')-and($StopExit-is[int]-or$StopExit-is[long])-and$StopExit-ge[int]::MinValue-and$StopExit-le[int]::MaxValue) 'Explicit observed integer CLI StopExit required'
    Assert-DarwinLife ($Census-is[hashtable]-and$Census.schema-is[string]-and$Census.schema-cin@('darwin-scoped-java-census-v1','darwin-launch-uid-java-census-v2')-and$Census.complete-is[bool]-and$Census.complete-and$Census.errors-is[array]-and$Census.errors.Count-eq0-and$Census.sameJdkJava-is[array]-and$Census.knownLive-is[array]-and$Census.tracked-is[array]-and$Census.expectedIdentityGone-is[bool]) 'Complete typed scoped census required'
    if($Census.schema-ceq'darwin-launch-uid-java-census-v2'){& ${function:Assert-LifeUidCensus} $Context $Expected $Census}
    Assert-DarwinLife ([string]::Equals($Census.jdkExecutable,($Context.Jdk+'/bin/java'),[StringComparison]::Ordinal)-and$Census.tracked.Count-eq1+$Context.KnownOwnedIdentities.Count) 'Census scope/tracked witnesses differ'
    $wanted=@($Expected)+@($Context.KnownOwnedIdentities)
    for($i=0;$i-lt$wanted.Count;$i++){Assert-LifeIdentity $Census.tracked[$i];Assert-DarwinLife (Test-LifeSame $wanted[$i] $Census.tracked[$i]) 'Census tracked identity differs'}
    Assert-DarwinLife ($Census.expectedIdentityGone-and$Census.sameJdkJava.Count-eq0-and$Census.knownLive.Count-eq0) 'Possible Java/known descendant survivor; empty registry/root exit is insufficient'
    @{status=$(if($StopExit-eq0-and-not$Forced-and-not$Emergency){'NORMAL_CLI_ROUTE_SCOPED_ABSENCE_CONFIRMED'}else{'FAIL_NONZERO_FORCED_OR_EMERGENCY'});runtimeAuthorized=$false;evidenceKind='validated-absence-model';scope=$Census.scope;universalHistoricalDescendantsAbsent=$false}
}
function ConvertTo-LifePresenceReason($Status,$Errno){
    if($Status-isnot[int]-or$Errno-isnot[int]){return 'UNKNOWN'}
    if($Status-eq0){return 'PRESENT'}
    if($Status-eq-1-and$Errno-eq3){return 'MISSING_ESRCH'}
    if($Status-eq-1-and$Errno-eq1){return 'PRESENT_EPERM'}
    'UNKNOWN'
}
function Get-LifeNativeType([switch]$RuntimeApproved){
    if(-not$IsMacOS-or-not$RuntimeApproved){throw 'HOLD: native Mac approved signal0 presence only'}
    $cached=Get-Variable -Name LifePresenceType -Scope Script -ErrorAction SilentlyContinue
    if($cached-and($cached.Value-isnot[type]-or-not[object]::ReferenceEquals($cached.Value,('H3911.MacNativeUidV3'-as[type])))){throw 'HOLD: native presence cache identity mismatch'}
    if(-not$cached){
        if('H3911.MacNativeUidV3'-as[type]){throw 'HOLD: native presence type collision'}
        $built=@(Add-Type -PassThru -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace H3911 {
    public static class MacNativeUidV3 {
        private const int BsdSize = 136, KinfoSize = 648, MaxBytes = 1048576, Headroom = 3240;
        [StructLayout(LayoutKind.Explicit, Size=BsdSize)]
        private struct BsdInfo {
            [FieldOffset(12)] public uint Pid; [FieldOffset(16)] public uint Parent;
            [FieldOffset(20)] public uint Effective; [FieldOffset(28)] public uint Real; [FieldOffset(36)] public uint Saved;
            [FieldOffset(120)] public ulong Seconds; [FieldOffset(128)] public ulong Microseconds;
        }
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint="kill", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
        private static extern int Kill(int pid, int signal);
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint="getpid", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl)]
        private static extern int SelfPid();
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint="getuid", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl)]
        private static extern uint RealUid();
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint="geteuid", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl)]
        private static extern uint EffectiveUid();
        [DllImport("/usr/lib/libproc.dylib", EntryPoint="proc_pidinfo", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
        private static extern int PidInfo(int pid, int flavor, ulong arg, IntPtr buffer, int bytes);
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint="sysctl", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
        private static extern int Sysctl([In] int[] name, uint count, IntPtr buffer, ref UIntPtr bytes, IntPtr newValue, UIntPtr newBytes);
        private static void MacAbi() {
            if (!OperatingSystem.IsMacOS() || IntPtr.Size != 8 || RuntimeInformation.ProcessArchitecture != Architecture.Arm64 || Marshal.SizeOf<BsdInfo>() != BsdSize) throw new PlatformNotSupportedException("HOLD: unsupported Mac ABI");
        }
        public static int[] Read(int pid) {
            if (pid <= 0) throw new ArgumentOutOfRangeException(nameof(pid));
            if (!OperatingSystem.IsMacOS()) throw new PlatformNotSupportedException();
            int status = Kill(pid, 0);
            int error = Marshal.GetLastPInvokeError();
            return new int[] { status, error };
        }
        public static long[] ReadBsd(int pid) {
            if (pid <= 0) throw new ArgumentOutOfRangeException(nameof(pid)); MacAbi();
            IntPtr b = IntPtr.Zero;
            try {
                b = Marshal.AllocHGlobal(BsdSize);
                for (int i=0; i<BsdSize; i+=4) Marshal.WriteInt32(b,i,0);
                int n = PidInfo(pid,3,0,b,BsdSize);
                int error = Marshal.GetLastPInvokeError();
                if (n != BsdSize) throw new InvalidOperationException("HOLD: BSD record error/size");
                BsdInfo v = Marshal.PtrToStructure<BsdInfo>(b);
                if (v.Pid != pid || v.Parent > Int32.MaxValue || v.Seconds == 0 || v.Seconds > 253402300799UL || v.Microseconds > 999999) throw new InvalidOperationException("HOLD: BSD identity/clock");
                return new long[] { n,error,v.Pid,v.Parent,v.Real,v.Effective,v.Saved,(long)v.Seconds,(long)v.Microseconds };
            } finally { if (b != IntPtr.Zero) Marshal.FreeHGlobal(b); }
        }
        public static long[] ReadSelf() {
            MacAbi(); int pid = SelfPid(); uint real = RealUid(), effective = EffectiveUid();
            long[] b = ReadBsd(pid), result = new long[11]; Array.Copy(b,result,9); result[9]=real; result[10]=effective; return result;
        }
        public static long[] ListOwnUid(uint uid) {
            if (uid == 0) throw new ArgumentOutOfRangeException(nameof(uid)); MacAbi();
            int self = SelfPid(); if (self <= 0 || EffectiveUid() != uid) throw new InvalidOperationException("HOLD: caller UID/PID");
            int[] mib = new int[] {1,14,5,unchecked((int)uid)}; UIntPtr length = UIntPtr.Zero;
            int status = Sysctl(mib,4,IntPtr.Zero,ref length,IntPtr.Zero,UIntPtr.Zero);
            int sizingError = Marshal.GetLastPInvokeError();
            ulong needed = length.ToUInt64();
            if (status != 0 || needed == 0 || needed % KinfoSize != 0 || needed > MaxBytes-Headroom) throw new InvalidOperationException("HOLD: UID sizing/error");
            int sizing = checked((int)needed), capacity = checked(sizing+Headroom); IntPtr b = IntPtr.Zero;
            try {
                b = Marshal.AllocHGlobal(capacity); length = (UIntPtr)(uint)capacity;
                status = Sysctl(mib,4,b,ref length,IntPtr.Zero,UIntPtr.Zero);
                int error = Marshal.GetLastPInvokeError();
                ulong filled = length.ToUInt64();
                if (status != 0 || filled == 0 || filled % KinfoSize != 0 || filled >= (ulong)capacity) throw new InvalidOperationException("HOLD: UID sysctl error/length/saturation");
                return ParseUidRecords(b,uid,self,sizing,capacity,checked((int)filled));
            } finally { if (b != IntPtr.Zero) Marshal.FreeHGlobal(b); }
        }
        private static long[] ParseUidRecords(IntPtr b, uint uid, int self, int sizing, int capacity, int n) {
            if (uid == 0 || self <= 0 || b == IntPtr.Zero || sizing <= 0 || sizing % KinfoSize != 0 || sizing > MaxBytes-Headroom || capacity != checked(sizing+Headroom) || n <= 0 || n % KinfoSize != 0 || n >= capacity) throw new InvalidOperationException("HOLD: UID record bounds");
            int count = n/KinfoSize; long[] result = new long[8+count]; var seen = new HashSet<int>(); bool own = false;
            result[0]=KinfoSize; result[1]=uid; result[2]=self; result[3]=sizing; result[4]=capacity; result[5]=n; result[6]=count; result[7]=0;
            for (int i=0;i<count;i++) { int offset=checked(i*KinfoSize), pid=Marshal.ReadInt32(b,offset+40); uint actual=unchecked((uint)Marshal.ReadInt32(b,offset+420)); if(pid<=0 || actual!=uid || !seen.Add(pid)) throw new InvalidOperationException("HOLD: invalid/duplicate PID or UID mutation"); result[8+i]=pid; own |= pid==self; }
            if (!own) throw new InvalidOperationException("HOLD: caller PID absent from UID set");
            return result;
        }
    }
}
'@)
        $root=@($built|Where-Object {$_.FullName-ceq'H3911.MacNativeUidV3'})
        if($root.Count-ne1-or$built.Count-ne2-or@($built|Where-Object {$_.FullName-cnotin@('H3911.MacNativeUidV3','H3911.MacNativeUidV3+BsdInfo')-or-not[object]::ReferenceEquals($_.Assembly,$root[0].Assembly)}).Count){throw 'HOLD: native presence type origin unavailable'}
        $script:LifePresenceType=$root[0]
    }
    $script:LifePresenceType
}
function Read-LifePresence([ValidateRange(1,2147483647)][int]$ProcessId,[switch]$RuntimeApproved){
    $type=& ${function:Get-LifeNativeType} -RuntimeApproved:$RuntimeApproved
    $facts=$type::Read($ProcessId)
    & ${function:ConvertTo-LifePresenceReason} $facts[0] $facts[1]
}
function ConvertFrom-LifeBsdFacts($Wire,$ExpectedPid,$ExpectedUid){
    Assert-DarwinLife ($Wire-is[array]-and$Wire.Count-in@(9,11)) 'Exact BSD fact wire required'
    foreach($n in $Wire){Assert-DarwinLife (($n-is[int]-or$n-is[long])) 'Integer BSD facts required'}
    Assert-DarwinLife (($ExpectedPid-is[int]-or$ExpectedPid-is[long])-and$ExpectedPid-gt0-and$ExpectedPid-le[int]::MaxValue-and($ExpectedUid-is[int]-or$ExpectedUid-is[long])-and$ExpectedUid-gt0-and$ExpectedUid-le[uint32]::MaxValue-and$Wire[0]-eq136-and$Wire[2]-eq$ExpectedPid-and$Wire[3]-ge0-and$Wire[3]-le[int]::MaxValue) 'BSD size/PID/parent/expected UID mismatch'
    foreach($index in 4,5,6){Assert-DarwinLife ($Wire[$index]-eq$ExpectedUid) 'Nonroot real/effective/saved UID invariant required'}
    Assert-DarwinLife ($Wire[7]-gt0-and$Wire[7]-le253402300799-and$Wire[8]-ge0-and$Wire[8]-le999999) 'BSD birth outside supported range'
    if($Wire.Count-eq11){Assert-DarwinLife ($Wire[9]-eq$ExpectedUid-and$Wire[10]-eq$ExpectedUid) 'getuid/geteuid/kernel disagreement'}
    @{pid=[int]$Wire[2];parentPid=[int]$Wire[3];realUid=$Wire[4];effectiveUid=$Wire[5];savedUid=$Wire[6];birthSeconds=$Wire[7];birthMicroseconds=$Wire[8]}
}
function Assert-LifeCredentialBinding($Facts,$ExpectedPid,$ExpectedUid,$Seconds,$Microseconds){
    Assert-DarwinLife (($ExpectedPid-is[int]-or$ExpectedPid-is[long])-and($ExpectedUid-is[int]-or$ExpectedUid-is[long])-and($Seconds-is[int]-or$Seconds-is[long])-and($Microseconds-is[int]-or$Microseconds-is[long])-and$Facts.pid-eq$ExpectedPid-and$Facts.effectiveUid-eq$ExpectedUid-and$Facts.birthSeconds-eq$Seconds-and$Facts.birthMicroseconds-eq$Microseconds) 'Kernel PID/UID/birth binding mismatch'
}
function ConvertFrom-LifeUidPidFacts($Wire,$ExpectedUid,$CallerPid){
    Assert-DarwinLife ($Wire-is[array]-and$Wire.Count-ge9) 'Nonempty sysctl UID PID wire required'
    foreach($n in $Wire){Assert-DarwinLife (($n-is[int]-or$n-is[long])) 'Integer UID PID facts required'}
    Assert-DarwinLife (($ExpectedUid-is[int]-or$ExpectedUid-is[long])-and$ExpectedUid-gt0-and$ExpectedUid-le[uint32]::MaxValue-and($CallerPid-is[int]-or$CallerPid-is[long])-and$CallerPid-gt0-and$CallerPid-le[int]::MaxValue-and$Wire[0]-eq648-and$Wire[1]-eq$ExpectedUid-and$Wire[2]-eq$CallerPid-and$Wire[3]-gt0-and$Wire[3]%648-eq0-and$Wire[3]-le1045336-and$Wire[4]-eq($Wire[3]+3240)-and$Wire[4]-le1048576-and$Wire[5]-gt0-and$Wire[5]%648-eq0-and$Wire[5]-lt$Wire[4]-and$Wire[6]-eq($Wire[5]/648)-and$Wire[7]-eq0-and$Wire.Count-eq(8+$Wire[6])) 'Sysctl UID byte/status/capacity mismatch'
    $seen=[Collections.Generic.HashSet[int]]::new();$pids=@()
    foreach($n in $Wire[8..($Wire.Count-1)]){Assert-DarwinLife ($n-gt0-and$n-le[int]::MaxValue-and$seen.Add([int]$n)) 'Invalid/duplicate UID PID';$pids+=[int]$n}
    Assert-DarwinLife ($seen.Contains([int]$CallerPid)) 'Caller PID absent; not empty success'
    @{effectiveUid=$ExpectedUid;callerPid=$CallerPid;filter=5;api='sysctl(KERN_PROC_UID)';pids=$pids;sizingBytes=$Wire[3];capacityBytes=$Wire[4];returnedBytes=$Wire[5];initialPidCount=$Wire[6];atomicEndpoint=$false;newbornCoverage=$false}
}
function Read-LifeSelfCredential([switch]$RuntimeApproved){
    $type=& ${function:Get-LifeNativeType} -RuntimeApproved:$RuntimeApproved;$wire=$type::ReadSelf()
    & ${function:ConvertFrom-LifeBsdFacts} $wire $wire[2] $wire[10]
}
function Read-LifeOwnerCredential([ValidateRange(1,2147483647)][int]$ProcessId,[ValidateRange(1,4294967295)][long]$ExpectedUid,[switch]$RuntimeApproved){
    $type=& ${function:Get-LifeNativeType} -RuntimeApproved:$RuntimeApproved
    try{$wire=$type::ReadBsd($ProcessId)}catch{throw 'HOLD: kernel credential read unavailable [credentialReadUnavailable=true]'}
    & ${function:ConvertFrom-LifeBsdFacts} $wire $ProcessId $ExpectedUid
}
function Read-LifeOwnUidPids([ValidateRange(1,4294967295)][long]$ExpectedUid,[switch]$RuntimeApproved){
    $type=& ${function:Get-LifeNativeType} -RuntimeApproved:$RuntimeApproved;$wire=$type::ListOwnUid([uint32]$ExpectedUid)
    & ${function:ConvertFrom-LifeUidPidFacts} $wire $ExpectedUid $wire[2]
}
function Get-LifeOsProcesses {
    param([hashtable]$Context,[hashtable]$Expected,[switch]$RuntimeApproved)
    if(-not$IsMacOS-or-not$RuntimeApproved){throw 'HOLD: native Mac approved census required'}
    Assert-LifeContext $Context $Expected
    $commands=& ${function:Get-LifeUidCommands};$self=& ${function:Read-LifeUidSelf} $commands
    $selection=& $commands['Read-LifeOwnUidPids'] -ExpectedUid $self.uid -RuntimeApproved
    $tracked=@($Expected)+@($Context.KnownOwnedIdentities);$all=[Collections.Generic.HashSet[int]]::new()
    foreach($id in $selection.pids){$null=$all.Add([int]$id)};foreach($known in $tracked){$null=$all.Add([int]$known.pid)}
    Assert-DarwinLife ($all.Count-le4096) 'UID union exceeds bounded census'
    $rows=@();$rechecks=0;$missing=0
    foreach($id in $all){
        $p=$null;$phase='lookup';$pidText=$id.ToString([Globalization.CultureInfo]::InvariantCulture);$failed=$false;$missingConfirmed=$false;$presence='NOT_ATTEMPTED';$semantic=$false
        try{
            $p=[Diagnostics.Process]::GetProcessById($id)
            $phase='start-time';$created=$p.StartTime.ToUniversalTime().ToString('o')
            $phase='main-module';$module=$p.MainModule;if($null-eq$module){throw 'Unavailable module value'}
            $phase='module-file-name';$executable=$module.FileName;if($null-eq$executable){throw 'Unavailable executable value'}
            $phase='kernel-credential';$semantic=$true
            $credential=& $commands['Read-LifeOwnerCredential'] -ProcessId $id -ExpectedUid $self.uid -RuntimeApproved
            $phase='identity';$row=@{pid=$id;created=$created;executable=$executable;credential=$credential};Assert-LifeIdentity $row
            & ${function:Assert-LifeCredentialIdentity} $credential $row $self.uid
            foreach($known in $tracked){if($known.pid-eq$id){Assert-DarwinLife (Test-LifeSame $known $row) 'Known PID reuse/foreign identity HOLD'}}
            $rows+=,$row
        }
        catch{
            $failed=$true
            if($semantic-and-not($_.Exception.Message.Contains('[credentialReadUnavailable=true]'))){throw ('HOLD: UID/lifetime invariant [reason=CENSUS_ROW_FAILED;phase='+$phase+';pid='+$pidText+';scanComplete=false]')}
            $rechecks++;try{$presence=& $commands['Read-LifePresence'] -ProcessId ([int]$id) -RuntimeApproved:$RuntimeApproved}catch{$presence='UNKNOWN'}
            $missingConfirmed=$presence-is[string]-and$presence-ceq'MISSING_ESRCH'
            if(-not$missingConfirmed){throw ('HOLD: unreadable/exited/ambiguous native process identity during full census [reason=CENSUS_ROW_FAILED;phase='+$phase+';pid='+$pidText+';scanComplete=false] [presence='+$presence+';missingAtRecheck='+$missing+';presenceAttempts='+$rechecks+']')}
        }
        finally{if($p){try{$p.Dispose()}catch{if($missingConfirmed){throw ('HOLD: census read and disposal failed [reason=CENSUS_ROW_FAILED;phase='+$phase+';pid='+$pidText+';scanComplete=false] [presence=MISSING_ESRCH;dispose=failed;missingAtRecheck='+$missing+';presenceAttempts='+$rechecks+']')};if(-not$failed){throw ('HOLD: native process disposal failed [reason=CENSUS_DISPOSE_FAILED;phase=dispose;pid='+$pidText+';scanComplete=false] [missingAtRecheck='+$missing+';presenceAttempts='+$rechecks+']')}}}}
        if($missingConfirmed){$missing++}
    }
    $ownerCredential=@($rows|Where-Object pid -eq $Expected.pid|ForEach-Object credential)
    $proof=@{schema='darwin-launch-uid-proof-v2';admittedUid=$self.uid;filter=5;selfIdentity=$self.identity;selfCredential=$self.credential;ownerCredential=$(if($ownerCredential.Count-eq1){$ownerCredential[0]}else{$null});selectedPidCount=$selection.pids.Count;knownPidCount=$tracked.Count;unionPidCount=$all.Count;validatedPidCount=$rows.Count;missingAtRecheckCount=$missing;presenceRecheckAttempts=$rechecks;observationBasis='INITIAL_ELIGIBLE_PID_NUMBERS_THEN_UID_SURVIVORS_PLUS_KNOWN_ESRCH_RECHECK';atomicEndpoint=$false;newbornCoverage=$false}
    $proof.universalHistory=$false
    @{schema='darwin-launch-uid-observation-v2';complete=$true;errors=@();processes=$rows;uidProof=$proof}
}
function Get-LifeCurrent([int]$ProcessId){
    $pidText=if($ProcessId-gt0){$ProcessId.ToString([Globalization.CultureInfo]::InvariantCulture)}else{'unavailable'}
    try{$p=[Diagnostics.Process]::GetProcessById($ProcessId)}catch{throw ('HOLD: native identity missing/unavailable before stop admission [reason=CURRENT_LOOKUP_FAILED;phase=lookup;pid='+$pidText+';scanComplete=false]')}
    $phase='pid';$failed=$false
    try{
        $id=$p.Id;if($null-eq$id){throw 'Unavailable PID value'}
        $phase='start-time';$created=$p.StartTime.ToUniversalTime().ToString('o')
        $phase='main-module';$module=$p.MainModule;if($null-eq$module){throw 'Unavailable module value'}
        $phase='module-file-name';$executable=$module.FileName;if($null-eq$executable){throw 'Unavailable executable value'}
        $phase='identity';$r=@{pid=$id;created=$created;executable=$executable};Assert-LifeIdentity $r;$r
    }catch{$failed=$true;throw ('HOLD: native identity read failed before stop admission [reason=CURRENT_IDENTITY_FAILED;phase='+$phase+';pid='+$pidText+';scanComplete=false]')}
    finally{try{$p.Dispose()}catch{if(-not$failed){throw ('HOLD: native process disposal failed [reason=CURRENT_DISPOSE_FAILED;phase=dispose;pid='+$pidText+';scanComplete=false]')}}}
}
function Assert-LifeNativePaths($Context){
    foreach($path in $Context.Jdk,$Context.Home,$Context.Registry,$Context.Temp){
        $resolved=Resolve-Path -LiteralPath $path -ErrorAction Stop;$item=Get-Item -LiteralPath $resolved.ProviderPath -Force
        Assert-DarwinLife ($resolved.Provider.Name-ceq'FileSystem'-and$item-is[IO.DirectoryInfo]-and[string]::Equals($resolved.ProviderPath,$path,[StringComparison]::Ordinal)) 'Canonical physical private directory required'
        $parent=$item;while($parent){Assert-DarwinLife (-not((Get-Item -LiteralPath $parent.FullName -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked private lifecycle ancestry';$parent=$parent.Parent}
    }
}
function Get-LifeRegistryCommand {
    $path=Join-Path $PSScriptRoot 'H3911.DarwinOwner.psm1'
    Assert-DarwinLife ((Get-FileHash $path).Hash-ceq'E9A8FD932AC839119FDD0B810533E8FB69BA314CB038E7345C484A7988A36E1E') 'Pinned Registry103 dependency differs'
    $m=Import-Module $path -Scope Local -PassThru;$command=$m.ExportedCommands['Read-H3911Registry103']
    Assert-DarwinLife ($command-is[Management.Automation.FunctionInfo]-and[string]::Equals($command.Module.Path,$path,[StringComparison]::Ordinal)) 'Private registry command origin differs';$command
}
function Read-LifeRegistry($Context){
    $path=$Context.Registry+'/registry.bin';$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    Assert-DarwinLife ($item-is[IO.FileInfo]-and-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not$item.LinkType) 'Regular private registry file required'
    $parent=$item.Directory;while($parent){Assert-DarwinLife (-not((Get-Item -LiteralPath $parent.FullName -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked private registry ancestry';$parent=$parent.Parent}
    [byte[]]$bytes=[IO.File]::ReadAllBytes($path);$command=Get-LifeRegistryCommand
    @{registry=(& $command $bytes);digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))}
}
function Read-H3911DarwinScopedCensus {
    param([hashtable]$Context,[hashtable]$Expected,[switch]$RuntimeApproved)
    if(-not$IsMacOS-or-not$RuntimeApproved){throw 'HOLD: Native Mac plus RuntimeApproved required'}
    Assert-LifeContext $Context $Expected
    Assert-LifeNativePaths $Context
    Assert-DarwinLife ($Expected.evidenceKind-is[string]-and$Expected.evidenceKind-ceq'native-mac-effective-owner') 'Prior native effective-owner evidence required'
    $osReader=$ExecutionContext.SessionState.InvokeCommand.GetCommand('Get-LifeOsProcesses',[Management.Automation.CommandTypes]::Function)
    Assert-DarwinLife ([string]::Equals($osReader.Module.Path,$ExecutionContext.SessionState.Module.Path,[StringComparison]::Ordinal)) 'Native OS census command origin differs'
    $observation=& $osReader -Context $Context -Expected $Expected -RuntimeApproved
    $result=& ($ExecutionContext.SessionState.Module.ExportedCommands['ConvertTo-H3911DarwinScopedCensus']) $Context $Expected $observation
    & ${function:Assert-LifeUidCensus} $Context $Expected $result
    if(-not$result.expectedIdentityGone){$commands=& ${function:Get-LifeUidCommands};$snapshot=& $commands['Read-LifeRegistry'] $Context;$current=@($result.knownLive|Where-Object pid -eq $Expected.pid)[0];$null=& ($ExecutionContext.SessionState.Module.ExportedCommands['New-H3911DarwinStopPlanFacts']) $Context $Expected $snapshot.registry $current;$Expected.launchUidAdmission=$result.uidProof}
    $result.evidenceKind='native-mac-launch-uid-census-v2';$result
}
function New-H3911DarwinPrivateStopPlan {
    param([hashtable]$Context,[hashtable]$Expected,[switch]$RuntimeApproved,[switch]$Emergency)
    if(-not$IsMacOS-or-not$RuntimeApproved){throw 'HOLD: Native Mac plus RuntimeApproved required'}
    Assert-LifeContext $Context $Expected
    Assert-LifeNativePaths $Context
    Assert-DarwinLife ($Expected.evidenceKind-is[string]-and$Expected.evidenceKind-ceq'native-mac-effective-owner') 'Prior native effective-owner evidence required'
    $registryReader=$ExecutionContext.SessionState.InvokeCommand.GetCommand('Read-LifeRegistry',[Management.Automation.CommandTypes]::Function)
    $osReader=$ExecutionContext.SessionState.InvokeCommand.GetCommand('Get-LifeCurrent',[Management.Automation.CommandTypes]::Function)
    foreach($command in $registryReader,$osReader){Assert-DarwinLife ([string]::Equals($command.Module.Path,$ExecutionContext.SessionState.Module.Path,[StringComparison]::Ordinal)) 'Native lifecycle command origin differs'}
    $snapshot=& $registryReader $Context;$current=& $osReader ([int]$Expected.pid)
    $commands=& ${function:Get-LifeUidCommands};$self=& ${function:Read-LifeUidSelf} $commands
    $credential=& $commands['Read-LifeOwnerCredential'] -ProcessId ([int]$Expected.pid) -ExpectedUid $self.uid -RuntimeApproved
    & ${function:Assert-LifeCredentialIdentity} $credential $current $self.uid
    $plan=& ($ExecutionContext.SessionState.Module.ExportedCommands['New-H3911DarwinStopPlanFacts']) $Context $Expected $snapshot.registry $current -Emergency:$Emergency
    Assert-DarwinLife ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($Context.Registry+'/registry.bin')))-ceq$snapshot.digest) 'Registry changed during stop admission'
    $Expected.launchUidAdmission=@{schema='darwin-launch-uid-live-admission-v2';admittedUid=$self.uid;ownerCredential=$credential}
    $plan.evidenceKind='native-private-cli-stop-plan';$plan.requiresImmediateRevalidationBeforeInvocation=$true;$plan
}
function Confirm-H3911DarwinCliStop {
    param([hashtable]$Context,[hashtable]$Expected,[object]$StopExit,[switch]$RuntimeApproved,[switch]$Forced,[switch]$Emergency)
    Assert-DarwinLife ($PSBoundParameters.ContainsKey('StopExit')-and($StopExit-is[int]-or$StopExit-is[long])) 'Explicit observed CLI StopExit required'
    if(-not$IsMacOS-or-not$RuntimeApproved){throw 'HOLD: Native Mac plus RuntimeApproved required'}
    Assert-LifeContext $Context $Expected;Assert-LifeNativePaths $Context
    $registryReader=$ExecutionContext.SessionState.InvokeCommand.GetCommand('Read-LifeRegistry',[Management.Automation.CommandTypes]::Function)
    Assert-DarwinLife ([string]::Equals($registryReader.Module.Path,$ExecutionContext.SessionState.Module.Path,[StringComparison]::Ordinal)) 'Native registry command origin differs'
    $snapshot=& $registryReader $Context
    $census=& ($ExecutionContext.SessionState.Module.ExportedCommands['Read-H3911DarwinScopedCensus']) $Context $Expected -RuntimeApproved
    & ${function:Assert-LifeUidCensus} $Context $Expected $census
    Assert-DarwinLife ($Expected.launchUidAdmission-is[hashtable]-and$Expected.launchUidAdmission.schema-cin@('darwin-launch-uid-proof-v2','darwin-launch-uid-live-admission-v2')-and$Expected.launchUidAdmission.admittedUid-eq$census.uidProof.admittedUid) 'Prior actual live-owner UID admission required after exit'
    & ${function:Assert-LifeCredentialIdentity} $Expected.launchUidAdmission.ownerCredential $Expected $census.uidProof.admittedUid
    try{$result=& ($ExecutionContext.SessionState.Module.ExportedCommands['Confirm-H3911DarwinAbsenceFacts']) $Context $Expected $snapshot.registry $census $StopExit -Forced:$Forced -Emergency:$Emergency}
    catch{throw ($_.ToString()+' [observationBasis='+$census.uidProof.observationBasis+';missingAtRecheck='+$census.uidProof.missingAtRecheckCount+';presenceAttempts='+$census.uidProof.presenceRecheckAttempts+']')}
    Assert-DarwinLife ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($Context.Registry+'/registry.bin')))-ceq$snapshot.digest) 'Registry changed during absence census'
    $result.schema='darwin-launch-uid-absence-v2';$result.uidProof=$census.uidProof;$result.knownOwnedIdentities=$Context.KnownOwnedIdentities
    $result.evidenceKind='native-scoped-absence-result';$result
}
Export-ModuleMember -Function New-H3911DarwinStopPlanFacts,ConvertTo-H3911DarwinScopedCensus,Confirm-H3911DarwinAbsenceFacts,Read-H3911DarwinScopedCensus,New-H3911DarwinPrivateStopPlan,Confirm-H3911DarwinCliStop
