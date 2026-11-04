function Get-QualifierPrivatePropertyFacts {
    param([hashtable]$Scope,[string]$CommandLine)
    if([string]::IsNullOrWhiteSpace($CommandLine)-or$CommandLine-match'[\x00-\x08\x0a-\x1f]'){return @{valid=$false;reason='Unreadable/control-bearing ownership command'}}
    $values=@{'mvnd.home'=@();'mvnd.daemonStorage'=@();'mvnd.id'=@()}
    $tokens=[regex]::Matches($CommandLine,'\G\s*(?<token>(?:[^"\s]+|"[^"]*")+)')
    $end=0
    foreach($match in $tokens){
        $end=$match.Index+$match.Length;$raw=$match.Groups['token'].Value;$decoded=$raw.Replace('"','')
        foreach($key in @('mvnd.home','mvnd.daemonStorage','mvnd.id')){
            $prefix="-D$key="
            if([string]::Equals($decoded,"-D$key",[StringComparison]::Ordinal)){return @{valid=$false;reason='Ownership property lacks equals/value'}}
            if(-not$decoded.StartsWith($prefix,[StringComparison]::Ordinal)){continue}
            $value=$decoded.Substring($prefix.Length)
            $forms=@($decoded,('"'+$decoded+'"'),($prefix+'"'+$value+'"'))
            if(-not@($forms|Where-Object{[string]::Equals($raw,$_,[StringComparison]::Ordinal)}).Count){return @{valid=$false;reason='Malformed ownership property quoting'}}
            $values[$key]+=,$value
        }
    }
    if($CommandLine.Substring($end).Trim().Length){return @{valid=$false;reason='Malformed/unclosed command token'}}
    # 824a1fd Connector440+461 adds HOME explicitly and through DISCRIMINATING; no other duplicates are admitted.
    if($values['mvnd.home'].Count-notin@(1,2)-or$values['mvnd.daemonStorage'].Count-ne1-or$values['mvnd.id'].Count-ne1){return @{valid=$false;reason='Ownership property occurrence count differs'}}
    foreach($pair in @(@('mvnd.home',$Scope.Home),@('mvnd.daemonStorage',$Scope.Registry))){
        foreach($value in $values[$pair[0]]){if(-not[string]::Equals($value,$pair[1],[StringComparison]::OrdinalIgnoreCase)){return @{valid=$false;reason='Conflicting/foreign ownership property value'}}}
    }
    if($values['mvnd.id'][0]-cnotmatch'^[a-f0-9]{8}$'){return @{valid=$false;reason='Exact unique daemon id unavailable'}}
    @{valid=$true;id=$values['mvnd.id'][0];homeOccurrences=$values['mvnd.home'].Count;storageOccurrences=1}
}
function Get-QualifierJavaCensusFacts {
    param([hashtable]$Scope,[hashtable]$Observation,[hashtable]$Anchor)
    if($Observation.complete-isnot[bool]-or-not$Observation.complete-or$Observation.errors-isnot[array]-or$Observation.errors.Count-or$Observation.rows-isnot[array]){return @{status='HOLD';complete=$false;errors=@('Missing/unknown enumeration');unknown=@();candidates=@()}}
    $unknown=@();$candidate=@();$foreign=@();$expected=Join-Path $Scope.Jdk 'bin\java.exe'
    foreach($row in $Observation.rows){
        if(($row.ProcessId-isnot[int]-and$row.ProcessId-isnot[long]-and$row.ProcessId-isnot[uint32])-or$row.ProcessId-le0-or$row.ProcessId-gt[int]::MaxValue-or$row.CommandLine-isnot[string]-or[string]::IsNullOrWhiteSpace($row.CommandLine)-or$row.ExecutablePath-isnot[string]-or[string]::IsNullOrWhiteSpace($row.ExecutablePath)){$unknown+=,@{pid=$row.ProcessId;reason='Unreadable Java identity/command, retained even if anchored'};continue}
        $anchored=$Anchor-and$row.ProcessId-eq$Anchor.pid
        $hint=$false;foreach($path in $Scope.Home,$Scope.Registry,$Scope.Temp){if($row.CommandLine.IndexOf($path,[StringComparison]::OrdinalIgnoreCase)-ge0){$hint=$true}}
        $sameJdk=[string]::Equals($row.ExecutablePath,$expected,[StringComparison]::OrdinalIgnoreCase)
        if(-not$anchored-and-not$hint-and-not$sameJdk){$foreign+=,@{pid=$row.ProcessId;reason='Readable different Java executable and no private scope text'};continue}
        $properties=& ${function:Get-QualifierPrivatePropertyFacts} $Scope $row.CommandLine
        $exact=$properties.valid
        if(-not$sameJdk-or-not$exact){$unknown+=,@{pid=$row.ProcessId;reason='Potential/anchored/same-JDK Java not exact private-token owned'};continue}
        $candidate+=,$row
    }
    $status=if($unknown.Count-or$candidate.Count-gt1){'HOLD'}elseif($candidate.Count-eq1){'candidate'}else{'absent'}
    @{status=$status;complete=$true;errors=@();unknown=$unknown;candidates=$candidate;foreign=$foreign;count=$candidate.Count}
}
function Assert-QualifierOwnerWitness {
    param([hashtable]$Scope,[hashtable]$Witness,[hashtable]$Observer,[string]$NotBefore)
    if($Observer.exitConfirmed-isnot[bool]-or-not$Observer.exitConfirmed-or$Observer.exit-isnot[int]-or$Observer.exit-ne0-or$Observer.jsonPresent-isnot[bool]-or-not$Observer.jsonPresent){throw 'HOLD: successful observer exit and present JSON required'}
    & ${function:Assert-QualifierOwnerWitnessContent} $Scope $Witness $NotBefore
}
function Assert-QualifierOwnerWitnessContent {
    param([hashtable]$Scope,[hashtable]$Witness,[string]$NotBefore)
    if($Witness.status-isnot[string]-or$Witness.status-cne'owned'-or($Witness.pid-isnot[int]-and$Witness.pid-isnot[long])-or$Witness.pid-le0-or$Witness.pid-gt[int]::MaxValue-or$Witness.id-isnot[string]-or$Witness.id-cnotmatch'^[a-f0-9]{8}$'-or($Witness.jniMachine-isnot[int]-and$Witness.jniMachine-isnot[long])){throw 'HOLD: typed independent owner witness required'}
    foreach($key in 'created','observedUtc'){$stamp=[DateTimeOffset]::MinValue;if($Witness[$key]-isnot[string]-or-not[DateTimeOffset]::TryParse($Witness[$key],[ref]$stamp)){throw 'HOLD: owner timestamps missing'}}
    $cimStamp=[DateTimeOffset]::MinValue
    if($Witness.cimCreated-isnot[string]-or-not[DateTimeOffset]::TryParse($Witness.cimCreated,[ref]$cimStamp)){throw 'HOLD: CIM birth timestamp required'}
    $birth=& ${function:Get-QualifierBirthIdentity} ([DateTimeOffset]::Parse($Witness.created).UtcDateTime) $cimStamp.UtcDateTime
    foreach($key in 'nativeCreatedTicks','cimCreatedTicks'){if($Witness[$key]-isnot[string]-or-not[string]::Equals($Witness[$key],$birth[$key],[StringComparison]::Ordinal)){throw 'HOLD: exact birth ticks inconsistent'}}
    if(-not$birth.valid){throw 'HOLD: native/CIM birth correlation failed'}
    if([DateTimeOffset]::Parse($Witness.observedUtc)-lt[DateTimeOffset]::Parse($NotBefore)-or[DateTimeOffset]::Parse($Witness.observedUtc)-gt[DateTimeOffset]::UtcNow.AddSeconds(1)){throw 'HOLD: stale/future owner observation'}
    foreach($pair in @(@($Witness.executable,(Join-Path $Scope.Jdk 'bin\java.exe')),@($Witness.home,$Scope.Home),@($Witness.registry,$Scope.Registry),@($Witness.temp,$Scope.Temp))){if(-not[string]::Equals($pair[0],$pair[1],[StringComparison]::OrdinalIgnoreCase)){throw 'HOLD: witness scope differs'}}
    if($Witness.jniPath-isnot[string]-or-not$Witness.jniPath.StartsWith($Scope.Temp+'\',[StringComparison]::OrdinalIgnoreCase)-or$Witness.jniPath-match'\\\.\.\\'-or$Witness.jniSha256-cne'728F9A0F7A8A74D15C6DE37DBE32A73CF8013605D2E881098692E1C88A0F4C2D'-or$Witness.javaSha256-cne'094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0'-or$Witness.jniMachine-ne0xAA64){throw 'HOLD: native JNI/Java witness missing or mismatched'}
    @{valid=$true;metadataOnly=$true}
}
function Read-QualifierPrivateJava {
    param([hashtable]$Scope,[hashtable]$Anchor)
    $reason='CENSUS_INCOMPLETE';$boundary=$null
    try{
        $rows=@(CimCmdlets\Get-CimInstance Win32_Process -Filter "Name='java.exe'" -OperationTimeoutSec 5 -ErrorAction Stop)
        $census=Get-QualifierJavaCensusFacts $Scope @{complete=$true;errors=@();rows=$rows} $Anchor
        if($census.status-cne'candidate'){$census.reasonCode=if($census.status-ceq'absent'){'ABSENT'}elseif(-not$census.complete){'CENSUS_INCOMPLETE'}elseif($census.candidates.Count-gt1){'MULTIPLE_CANDIDATES'}else{'CENSUS_UNKNOWN'};return $census}
        $reason='NATIVE_IDENTITY_ERROR';$row=$census.candidates[0];$expectedJava=Join-Path $Scope.Jdk 'bin\java.exe'
        if(-not[string]::Equals($row.ExecutablePath,$expectedJava,[StringComparison]::OrdinalIgnoreCase)){throw 'Foreign executable in potential scope'}
        $properties=& ${function:Get-QualifierPrivatePropertyFacts} $Scope $row.CommandLine
        if(-not$properties.valid){$reason='PROPERTY_REJECT';throw 'Property admission failed'}
        $p=[Diagnostics.Process]::GetProcessById([int]$row.ProcessId)
        try{
            $birth=& ${function:Get-QualifierBirthIdentity} $p.StartTime.ToUniversalTime() $row.CreationDate.ToUniversalTime()
            $boundary=@{pid=[int]$row.ProcessId;created=$birth.created;nativeCreatedTicks=$birth.nativeCreatedTicks;cimCreated=$birth.cimCreated;cimCreatedTicks=$birth.cimCreatedTicks;birthDelta100ns=$birth.birthDelta100ns;executableMatches=$true}
            if(-not$birth.valid){$reason='BIRTH_MISMATCH';throw 'Birth correlation failed'}
            $reason='JNI_UNAVAILABLE'
            $modules=@($p.Modules|Where-Object{$_.ModuleName-like'*mvndnative*'})
            if($modules.Count-ne1-or-not$modules[0].FileName.StartsWith($Scope.Temp+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Owned temp loaded JNI unavailable'}
            $reason='JNI_IDENTITY';[byte[]]$jni=[IO.File]::ReadAllBytes($modules[0].FileName)
            if([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($jni))-cne'728F9A0F7A8A74D15C6DE37DBE32A73CF8013605D2E881098692E1C88A0F4C2D'-or[BitConverter]::ToUInt16($jni,[BitConverter]::ToInt32($jni,60)+4)-ne0xAA64){throw 'JNI byte/machine mismatch'}
            $reason='JAVA_IDENTITY'
            if((Microsoft.PowerShell.Utility\Get-FileHash $expectedJava).Hash-cne'094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0'){throw 'Native25 Java bytes differ'}
            $reason='NATIVE_IDENTITY_ERROR'
            if(-not(& ${function:Test-QualifierExactNativeBirth} $p.StartTime.ToUniversalTime() $birth)){throw 'Native birth changed during observation'}
            @{status='owned';complete=$true;errors=@();unknown=@();count=1;pid=[int]$row.ProcessId;created=$birth.created;nativeCreatedTicks=$birth.nativeCreatedTicks;cimCreated=$birth.cimCreated;cimCreatedTicks=$birth.cimCreatedTicks;observedUtc=[DateTime]::UtcNow.ToString('o');id=$properties.id;executable=$row.ExecutablePath;home=$Scope.Home;registry=$Scope.Registry;temp=$Scope.Temp;jniPath=$modules[0].FileName;jniSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($jni));javaSha256='094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0';jniMachine=0xAA64;reasonCode='OBSERVED';diagnosticBirth=$boundary}
        }finally{$p.Dispose()}
    }catch{@{status='HOLD';complete=$false;errors=@($reason);unknown=@(@{reason=$reason});candidates=@();reasonCode=$reason;diagnosticBirth=$boundary}}
}
function Stop-RevalidatedQualifierJava {
    param([hashtable]$Scope,[hashtable]$Expected)
    if($Expected.status-cne'owned'){return @{status='HOLD';killed=$false;reason='No exact owned identity'}}
    $current=Read-QualifierPrivateJava $Scope $Expected
    foreach($key in 'pid','created','nativeCreatedTicks','cimCreatedTicks','id','executable','home','registry','temp','jniPath','jniSha256'){if(-not[string]::Equals([string]$Expected[$key],[string]$current[$key],[StringComparison]::Ordinal)){return @{status='HOLD';killed=$false;reason='Identity changed; foreign/reused process untouched'}}}
    $p=[Diagnostics.Process]::GetProcessById([int]$Expected.pid)
    try{
        if(-not(& ${function:Test-QualifierExactNativeBirth} $p.StartTime.ToUniversalTime() $Expected)){return @{status='HOLD';killed=$false;reason='Process handle creation changed'}}
        $fresh=Read-QualifierPrivateJava $Scope $Expected
        if($fresh.status-cne'owned'-or$fresh.pid-ne$Expected.pid-or$fresh.created-cne$Expected.created-or$fresh.nativeCreatedTicks-cne$Expected.nativeCreatedTicks){return @{status='HOLD';killed=$false;reason='Last revalidation failed'}}
        $p.Kill($true);$gone=$p.WaitForExit(10000)
        @{status='FAIL_OWNED_PID_BACKSTOP_NOT_NORMAL_STOP';killed=$true;pid=$Expected.pid;created=$Expected.created;exitConfirmed=$gone;parentCliCalls=0}
    }finally{$p.Dispose()}
}
Export-ModuleMember -Function Get-QualifierJavaCensusFacts,Assert-QualifierOwnerWitness,Assert-QualifierOwnerWitnessContent,Read-QualifierPrivateJava,Stop-RevalidatedQualifierJava
function Get-QualifierBirthIdentity {
    param($NativeUtc,$CimUtc)
    if($NativeUtc-isnot[DateTime]-or$CimUtc-isnot[DateTime]-or$NativeUtc.Kind-ne[DateTimeKind]::Utc-or$CimUtc.Kind-ne[DateTimeKind]::Utc){return @{valid=$false;reasonCode='BIRTH_MISMATCH'}}
    [long]$nativeTicks=$NativeUtc.Ticks;[long]$cimTicks=$CimUtc.Ticks;[long]$delta=$nativeTicks-$cimTicks
    @{valid=($cimTicks%[long]10-eq0-and$delta-ge0-and$delta-lt10);created=$NativeUtc.ToString('o');nativeCreatedTicks=$nativeTicks.ToString([Globalization.CultureInfo]::InvariantCulture);cimCreated=$CimUtc.ToString('o');cimCreatedTicks=$cimTicks.ToString([Globalization.CultureInfo]::InvariantCulture);birthDelta100ns=$delta}
}
function Test-QualifierExactNativeBirth {
    param($NativeUtc,[hashtable]$Expected)
    [long]$ticks=0
    if($NativeUtc-isnot[DateTime]-or$NativeUtc.Kind-ne[DateTimeKind]::Utc-or$Expected.nativeCreatedTicks-isnot[string]-or-not[long]::TryParse($Expected.nativeCreatedTicks,[Globalization.NumberStyles]::None,[Globalization.CultureInfo]::InvariantCulture,[ref]$ticks)){return $false}
    return $NativeUtc.Ticks-eq$ticks
}
