param([Parameter(Mandatory)][string]$FixtureRoot)
$ErrorActionPreference='Stop'
$runtime=Join-Path $PSScriptRoot 'runtime';$run=Join-Path $FixtureRoot 'run';$recordFile=Join-Path $run 'qualification\mac-qualifier.json'
if(-not(Test-Path (Join-Path $FixtureRoot 'SYNTHETIC_TEST_DATA_NOT_NATIVE.json'))){throw 'Explicit synthetic provenance required'}
$q=Import-Module (Join-Path $runtime 'H3911.MacQualifier.psm1') -PassThru;$commands=& $q {Get-MQSamplingCommands}
$hosted=Import-Module (Join-Path $PSScriptRoot 'H3911.MacHosted.psm1') -PassThru
$bind=& $hosted {Get-Command Get-HostedCaptureBinding -CommandType Function}
$reports=& $hosted {Get-Command Add-HostedReportByteBindings -CommandType Function}
$record=Get-Content $recordFile -Raw|ConvertFrom-Json -AsHashtable -DateKind String
$owned=Join-Path $run 'qualification';$proof=@();$blocked=@()
foreach($phase in 'baseline-verify','candidate-verify'){
    $failure=$null;try{$bound=& $bind (Join-Path $PSScriptRoot '') $run $phase}catch{$failure=$_.Exception.Message}
    if($record[$phase].artifact.entries.Count-ne335-or$record[$phase].tests.Count-ne56-or$record[$phase].counters.Count-ne726-or$record[$phase].reportBytes.rows.Count-lt2){throw 'Complete physical online fixture missing'}
    if($failure){
        if($failure-notlike'*Surefire membership/state binding differs*'){throw $failure}
        $actualTests=& $commands['TestKeys'] @([xml](Get-Content (Join-Path $owned "output\$phase\surefire\TEST-ModelTest0.xml") -Raw))
        $semantic=& $commands['Get-H3911RetainedProtocol'].Module {Get-Command Assert-PScreenTestFacts};$null=& $semantic $actualTests $record[$phase].tests
        $blocked+=@{phase=$phase;reason=$failure;actualFirst=($actualTests[0]|ConvertTo-Json -Compress);retainedFirst=($record[$phase].tests[0]|ConvertTo-Json -Compress);semanticTriplesIdentical=$true}
    }
    $allowed=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $null=& $reports (Join-Path $PSScriptRoot '') (Join-Path $owned "output\$phase") $phase $record[$phase] $allowed
    $proof+=@{case=($phase+'-physical-report-witness');passed=$true;reportMembers=$allowed.Count;completeCaptureBindingPassed=(-not$failure);synthetic=$true}
}
$owned=Join-Path $run 'qualification';$ctx=@{Project=(Join-Path $run 'project');Jdk=(Join-Path $run 'MODEL-JDK');Home=(Join-Path $owned 'home');Registry=(Join-Path $owned 'registry');Temp=(Join-Path $owned 'temp');Output=(Join-Path $owned 'output');Cache=(Join-Path $owned 'cache');Settings=(Join-Path $owned 'settings.xml');ScreenOwner=$record.owner;ScreenNotBefore=$record.screenNotBefore;Calls=$record.calls;ScreenVerification=@{baseline=$record['baseline-verify'];candidate=$record['candidate-verify']};SourceProfile='MacOriginalWrapper';FixtureOnly=$false}
# Comparison-only copy selects the OS-free strict file-validation branch; retained data stays FixtureOnly.
$comparison=$record.sampling|ConvertTo-Json -Depth 40|ConvertFrom-Json -AsHashtable -DateKind String;$comparison.fixtureOnly=$false
$validate=& $q {Get-Command Assert-MQSamplingEvidence -CommandType Function}
$null=& $validate $ctx $comparison $false
if(@($comparison.auxiliaryLedger.receipt.path|Select-Object -Unique).Count-ne28){throw 'Probe receipt bindings not distinct'}
$proof+=@{case='strict-pure-return-file-validation';passed=$true;modeledProcessMetadata=$true;nativePipelineInvoked=$false}
foreach($case in 'receipt-pid','receipt-hash','extra-offline-class','report-witness-missing','link-escape','sdk-shaped-file'){
    $restore=$null;$path=$null;$failure=$null
    try{
        if($case-in@('receipt-pid','receipt-hash')){
            $bad=$comparison|ConvertTo-Json -Depth 40|ConvertFrom-Json -AsHashtable -DateKind String
            if($case-eq'receipt-pid'){$bad.clientCalls[0].processEvidence.pid++}else{$bad.clientCalls[0].processEvidence.stdout.sha256='0'*64}
            $null=& $validate $ctx $bad $false
        }elseif($case-eq'extra-offline-class'){
            $path=Join-Path $ctx.Output 'mac-package-screen\warmup-1-A\classes\EXTRA.class';[IO.File]::WriteAllBytes($path,[byte[]]@(202,254,186,190,0,0,0,61));$null=& $validate $ctx $comparison $false
        }elseif($case-eq'report-witness-missing'){
            $bad=$record['baseline-verify']|ConvertTo-Json -Depth 45|ConvertFrom-Json -AsHashtable -DateKind String
            $bad.reportBytes.rows=@($bad.reportBytes.rows|Select-Object -Skip 1)
            $null=& $reports (Join-Path $PSScriptRoot '') (Join-Path $ctx.Output 'baseline-verify') 'baseline-verify' $bad ([Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal))
        }elseif($case-eq'link-escape'){
            $target=Join-Path $FixtureRoot 'SYNTHETIC-sentinel.txt';[IO.File]::WriteAllText($target,'NOT_CAPTURE_DATA')
            $path=Join-Path $ctx.Output 'baseline-verify\classes\LINK_ESCAPE.txt';New-Item -ItemType SymbolicLink -Path $path -Target $target|Out-Null
            $null=& $bind (Join-Path $PSScriptRoot '') $run 'baseline-verify'
        }else{
            $path=Join-Path $ctx.Output 'baseline-verify\classes\SDK-shaped.dll';[IO.File]::WriteAllText($path,'SYNTHETIC_NOT_SDK')
            $null=& $bind (Join-Path $PSScriptRoot '') $run 'baseline-verify'
        }
    }catch{$failure=$_.Exception.Message}
    finally{if($restore){[IO.File]::WriteAllBytes($recordFile,$restore)};if($path-and(Test-Path -LiteralPath $path)){Remove-Item -LiteralPath $path}}
    if(-not$failure-or$failure-like'*Surefire membership/state binding differs*'){throw "Strict fixture mutation did not reach intended check $case"};$proof+=@{case=$case;passed=$true;rejected=$failure}
}
$null=& $validate $ctx $comparison $false
@{verdict=$(if($blocked.Count){'HOLD_COMPLETE_HOSTED_BINDING_JSON_ORDER'}else{'PASS'});cases=$proof;blockedCompleteCaptureBindings=$blocked;fixtureOnly=$true;actualOSProcessIdentities=$false;nativeMacCalls=0;nativeJcmdStarts=0;runtimeApprovedEntryInvoked=$false}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $FixtureRoot 'fixture-validation.json')
Write-Output "SYNTHETIC_RETENTION_PHYSICAL_PASS cases=$($proof.Count); online335/offline333x8/report witnesses/28 distinct modeled receipts; NOT_NATIVE"
if($blocked.Count){throw 'HOLD: complete hosted binding compares JSON member order despite identical semantic test triples; runtime source untouched'}
