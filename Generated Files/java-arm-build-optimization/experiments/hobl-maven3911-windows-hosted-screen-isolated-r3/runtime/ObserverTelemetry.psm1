function New-QualifierObserverTelemetry {
    $counts=[ordered]@{};$first=[ordered]@{};$last=[ordered]@{}
    foreach($code in 'ABSENT','CENSUS_UNKNOWN','CENSUS_INCOMPLETE','MULTIPLE_CANDIDATES','PROPERTY_REJECT','BIRTH_MISMATCH','JNI_UNAVAILABLE','JNI_IDENTITY','JAVA_IDENTITY','OBSERVED','NATIVE_IDENTITY_ERROR','WITNESS_PARSE','WITNESS_VALIDATION'){$counts[$code]=0;$first[$code]=$null;$last[$code]=$null}
    @{complete=$true;totalPolls=0;reasonCounts=$counts;reasonFirstUtc=$first;reasonLastUtc=$last;firstUtc=$null;lastUtc=$null;candidateBoundaries=@();candidateCap=4;overflowCandidates=0;captureErrors=0;lastCandidateCount=$null;lastUnknownCount=$null}
}
function Add-QualifierObserverTelemetry {
    param([hashtable]$State,[hashtable]$Observation)
    $now=[DateTime]::UtcNow.ToString('o');$State.totalPolls++;$State.lastUtc=$now
    if(-not$State.firstUtc){$State.firstUtc=$now}
    $code=$Observation.reasonCode
    if($code-isnot[string]-or-not$State.reasonCounts.Contains($code)){$code='NATIVE_IDENTITY_ERROR';$State.complete=$false;$State.captureErrors++}
    $State.reasonCounts[$code]++
    if(-not$State.reasonFirstUtc[$code]){$State.reasonFirstUtc[$code]=$now};$State.reasonLastUtc[$code]=$now
    $State.lastCandidateCount=if($Observation.candidates-is[array]){$Observation.candidates.Count}elseif($Observation.status-ceq'owned'){1}else{$null}
    $State.lastUnknownCount=if($Observation.unknown-is[array]){$Observation.unknown.Count}else{$null}
    $b=$Observation.diagnosticBirth
    if($null-eq$b){return}
    if($b-isnot[hashtable]-or($b.pid-isnot[int]-and$b.pid-isnot[long])-or$b.pid-le0-or$b.pid-gt[int]::MaxValue-or$b.executableMatches-isnot[bool]-or($b.birthDelta100ns-isnot[int]-and$b.birthDelta100ns-isnot[long])){$State.complete=$false;$State.captureErrors++;return}
    foreach($key in 'created','cimCreated','nativeCreatedTicks','cimCreatedTicks'){if($b[$key]-isnot[string]-or$b[$key].Length-gt40){$State.complete=$false;$State.captureErrors++;return}}
    if($b.nativeCreatedTicks-cnotmatch'^[0-9]{1,19}$'-or$b.cimCreatedTicks-cnotmatch'^[0-9]{1,19}$'){$State.complete=$false;$State.captureErrors++;return}
    foreach($key in 'created','cimCreated'){$stamp=[DateTimeOffset]::MinValue;if(-not[DateTimeOffset]::TryParse($b[$key],[ref]$stamp)){$State.complete=$false;$State.captureErrors++;return}}
    $safe=@{pid=$b.pid;created=$b.created;cimCreated=$b.cimCreated;nativeCreatedTicks=$b.nativeCreatedTicks;cimCreatedTicks=$b.cimCreatedTicks;birthDelta100ns=$b.birthDelta100ns;executableMatches=$b.executableMatches;observedUtc=$now}
    $existing=@($State.candidateBoundaries|Where-Object{$_.pid-eq$b.pid-and$_.nativeCreatedTicks-ceq$b.nativeCreatedTicks})
    if($existing.Count){$existing[0].last=$safe;return}
    if($State.candidateBoundaries.Count-ge4){$State.overflowCandidates++;return}
    $State.candidateBoundaries+=@{pid=$b.pid;nativeCreatedTicks=$b.nativeCreatedTicks;first=$safe;last=$safe}
}
Export-ModuleMember -Function New-QualifierObserverTelemetry,Add-QualifierObserverTelemetry
