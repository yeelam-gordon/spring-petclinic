$ErrorActionPreference='Stop';$here=$PSScriptRoot;$output=Join-Path $here 'actual-supervision'
$authority=Get-Content (Join-Path $here 'stage.json') -Raw|ConvertFrom-Json
if(-not$authority.launcherReview.approved-or-not$authority.runtimeAllocation.approved){throw 'UNALLOCATED_BOUNDARY_COMPONENT_ONLY'}
Import-Module (Join-Path $here 'ObserverTelemetry.psm1') -Force
$telemetry=New-QualifierObserverTelemetry
try{
    $stage=Get-Content (Join-Path $here 'stage.json') -Raw|ConvertFrom-Json
    Import-Module (Join-Path $here 'OwnedJavaBackstop.psm1') -Force
    $scope=@{Jdk=$stage.jdk;Home=(Join-Path $stage.owned 'home');Registry=(Join-Path $stage.owned 'registry');Temp=(Join-Path $stage.owned 'temp')}
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($watch.Elapsed.TotalSeconds-lt1800-and-not(Test-Path (Join-Path $output 'observation-done'))){
        $candidate=Read-QualifierPrivateJava $scope
        Add-QualifierObserverTelemetry $telemetry $candidate
        if(-not$telemetry.complete){throw 'BOUNDED_METADATA_CAPTURE_INCOMPLETE'}
        if($candidate.status-ceq'owned'){$candidate|ConvertTo-Json|Set-Content (Join-Path $output 'independent-owned-daemon.json');@{status='OBSERVED';observed=$true}|ConvertTo-Json|Set-Content (Join-Path $output 'observer-outcome.json');exit 0}
        Start-Sleep -Milliseconds 250
    }
    @{status='HOLD_MISSED_OWNER';observed=$false}|ConvertTo-Json|Set-Content (Join-Path $output 'observer-outcome.json');exit 1
}catch{$telemetry.complete=$false;$telemetry.captureErrors++;@{status='HOLD_OBSERVER_ERROR';observed=$false;reasonCode='NATIVE_IDENTITY_ERROR';captureComplete=$false}|ConvertTo-Json|Set-Content (Join-Path $output 'observer-outcome.json');exit 1}
finally{$telemetry|ConvertTo-Json -Depth 10|Set-Content (Join-Path $output 'observer-telemetry.json')}
