param([Parameter(Mandatory)][string]$SourceRoot,[Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not[IO.Path]::IsPathFullyQualified($OutputDirectory)-or(Test-Path $OutputDirectory)){throw 'Fresh absolute retention boundary fixture required'}
New-Item $OutputDirectory -ItemType Directory|Out-Null
$m=Import-Module (Join-Path $SourceRoot 'H3911.MacHosted.psm1') -Scope Local -PassThru -Force -DisableNameChecking
$copy=$m.ExportedCommands['Copy-H3911MacHostedRetention'];$source=$m.ExportedCommands['Assert-H3911MacHostedSource']
$policy=Get-Content (Join-Path $SourceRoot 'hosted-payload-sha256.json') -Raw|ConvertFrom-Json
$proof=@();$emptyRun=Join-Path $OutputDirectory 'empty-run';$emptySetup=Join-Path $OutputDirectory 'empty-setup'
New-Item $emptyRun,$emptySetup -ItemType Directory|Out-Null
function CopyPublic([string]$Name){
    $dst=Join-Path $OutputDirectory $Name;New-Item $dst -ItemType Directory|Out-Null
    foreach($row in $policy){$to=Join-Path $dst $row.file;New-Item (Split-Path $to) -ItemType Directory -Force|Out-Null;Copy-Item -LiteralPath (Join-Path $SourceRoot $row.file) -Destination $to}
    $dst
}
foreach($case in 'control-link','ancestor-link','source-checksum'){
    $real=CopyPublic ($case+'-source');$inputRoot=$real
    if($case-eq'control-link'){
        $outside=Join-Path $OutputDirectory 'OUTSIDE-SYNTHETIC-SENTINEL.txt';[IO.File]::WriteAllText($outside,'OUTSIDE_ALLOWLIST_SENTINEL')
        $leaf=Join-Path $real 'Test-MacHosted.ps1';Remove-Item -LiteralPath $leaf
        New-Item -ItemType SymbolicLink -Path $leaf -Target $outside|Out-Null
    }elseif($case-eq'ancestor-link'){
        $inputRoot=Join-Path $OutputDirectory 'source-ancestor-link';New-Item -ItemType SymbolicLink -Path $inputRoot -Target $real|Out-Null
    }else{[IO.File]::AppendAllText((Join-Path $real 'runtime/H3911.NativeProcess.psm1'),'MUTATED_SYNTHETIC_SOURCE')}
    $failure=$null;try{$null=& $source $inputRoot}catch{$failure=$_.Exception.Message}
    if(-not$failure){throw "Execution source admission accepted $case"}
    $dst=Join-Path $OutputDirectory ($case+'-retained')
    $result=& $copy -SourceRoot $inputRoot -RunRoot $emptyRun -SetupRoot $emptySetup -Destination $dst
    $receipt=Get-Content (Join-Path $dst 'retention.json') -Raw|ConvertFrom-Json
    if($result.status-cne'FAILED_SOURCE_ADMISSION'-or$receipt.executionAdmission-cne'FAIL'-or@($receipt.files).Count-or@(Get-ChildItem $dst -File -Recurse).Count-ne1){throw "Curated failure uploaded source/link bytes or disappeared $case"}
    if($case-eq'source-checksum'){
        $row=@($receipt.diagnostics|Where-Object file -eq 'runtime/H3911.NativeProcess.psm1')[0]
        if(-not$row.expectedSha256-or-not$row.actualSha256-or$row.expectedSha256-ceq$row.actualSha256){throw 'Safe expected/actual source hash diagnosis missing'}
    }
    $proof+=@{case=$case;passed=$true;sourceAdmission='FAIL';failureArtifact='PRESENT_METADATA_ONLY'}
}
foreach($case in 'unexpected-sdk.jar','unbound-resource.txt','surefire/unbound.txt','jacoco/unbound.html','manifest-mutation'){
    $run=Join-Path $OutputDirectory ($case.Replace('/','-')+'-run');$phase=Join-Path $run 'qualification/output/baseline-verify'
    New-Item $phase -ItemType Directory -Force|Out-Null
    $relative=if($case-eq'manifest-mutation'){'artifact.json'}elseif($case.Contains('/')){$case}else{'classes/'+$case}
    $path=Join-Path $phase $relative;New-Item (Split-Path $path) -ItemType Directory -Force|Out-Null
    $bytes=[Text.Encoding]::UTF8.GetBytes('SYNTHETIC_UNBOUND_NOT_SDK_NOT_COMPILED')
    [IO.File]::WriteAllBytes($path,$bytes)
    if($case-eq'manifest-mutation'){
        @{schema='mac-original-A41-online-v1';loose=@(@{scope='classes';name='unexpected-sdk.jar';sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))})}|ConvertTo-Json -Depth 5|Set-Content $path
    }
    $dst=Join-Path $OutputDirectory ($case.Replace('/','-')+'-retained')
    $result=& $copy -SourceRoot $SourceRoot -RunRoot $run -SetupRoot $emptySetup -Destination $dst
    if($result.status-cne'FAILED_EVIDENCE_BINDING'-or(Test-Path (Join-Path $dst ('Run/qualification/output/baseline-verify/'+$relative)))){throw "Unbound capture bytes copied $case"}
    $receipt=Get-Content (Join-Path $dst 'retention.json') -Raw|ConvertFrom-Json
    if(-not@($receipt.diagnostics|Where-Object reason -eq 'UNBOUND_MEMBER_BYTES_NOT_RETAINED').Count){throw "Unbound failure/hash diagnosis lost $case"}
    $proof+=@{case=$case;passed=$true;unknownBytesCopied=$false;failureArtifact='PRESENT'}
}
@{verdict='PASS';cases=$proof;scope='Actual public source links/checksum and tiny unbound capture files; no SDK/Java/provisioning'}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $OutputDirectory 'proof.json')
Write-Output "MAC_RETENTION_BOUNDARIES_PASS cases=$($proof.Count); no out-of-role bytes, curated failures persist"
