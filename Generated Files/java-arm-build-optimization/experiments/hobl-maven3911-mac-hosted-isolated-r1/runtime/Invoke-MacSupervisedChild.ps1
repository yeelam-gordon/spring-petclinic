param([Parameter(Mandatory)][string]$Request,[Parameter(Mandatory)][string]$RequestSha256,[Parameter(Mandatory)][string]$Nonce,[ValidateSet('Main','Cleanup','Proof',IgnoreCase=$false)][string]$Role,[switch]$RootRuntimeApproved,[switch]$ProofOnly)
$ErrorActionPreference='Stop'
if($RootRuntimeApproved-eq$ProofOnly){throw 'Exactly one child authority mode required'}
if($Role-ceq'Proof'){
    if(-not$ProofOnly){throw 'Proof child authority mismatch'}
}elseif(-not$RootRuntimeApproved-or-not$IsMacOS-or[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture-ne'Arm64'-or[Runtime.InteropServices.RuntimeInformation]::OSArchitecture-ne'Arm64'){throw 'Native ARM64 Mac and root runtime approval required'}
if((Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Request).Hash-cne$RequestSha256){throw 'Bound request hash differs'}
$r=Get-Content -LiteralPath $Request -Raw|ConvertFrom-Json -AsHashtable -DateKind String
if($r.nonce-cne$Nonce-or$r.role-cne$Role-or$r.schema-cne'mac-supervisor-request-v1'){throw 'Bound request scope differs'}
$modulePath=Join-Path $PSScriptRoot 'H3911.MacSupervisor.psm1'
if((Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $modulePath).Hash-cne$r.supervisorSha256){throw 'Supervisor source differs from allocated request'}
$m=Import-Module $modulePath -Scope Local -PassThru -DisableNameChecking
$validate=& $m {Get-Command Read-SupScope -CommandType Function}
$null=& $validate $r
$result=@{schema='mac-supervisor-result-v1';role=$Role;proofOnly=[bool]$ProofOnly;qualified=$false;status='FAIL'}
$code=1
try{
    if($ProofOnly){
        [Console]::Out.WriteLine('harmless-proof-stdout');[Console]::Error.WriteLine('harmless-proof-stderr')
        switch($r.proofCase){
            Normal0{$result.status='PROOF_ONLY_COMPLETE';$code=0}
            Nonzero1{$result.status='PROOF_ONLY_NONZERO';$code=1}
            Timeout{[Threading.Thread]::Sleep(300000)}
            PostAllocationFailure{[Threading.Thread]::Sleep(300000)}
            MissingResult{exit 0}
            NullResult{[IO.File]::WriteAllText($r.result,'null');exit 0}
            IncompleteResult{$result.status='PROOF_ONLY_COMPLETE';$code=0}
            default{throw 'Unknown proof case'}
        }
        if($r.proofCase-cne'IncompleteResult'){$result.complete=$true}
    }elseif($Role-ceq'Main'){
        $check=& $m {Get-Command Assert-SupBase -CommandType Function};$null=& $check
        $q=Import-Module (Join-Path $PSScriptRoot 'H3911.MacQualifier.psm1') -Scope Local -PassThru -DisableNameChecking
        $record=& ($q.ExportedCommands['Invoke-H3911MacQualifier']) -Project $r.inputs.Project -Jdk $r.inputs.Jdk -JdkArchive $r.inputs.JdkArchive -DistributionArchive $r.inputs.DistributionArchive -Owned $r.qualifierOwned -WatchRoot $r.inputs.WatchRoot -RuntimeApproved
        $check=& $m {Get-Command Assert-SupQualification -CommandType Function};$null=& $check $record
        $result.status='QUALIFICATION_RETURNED_PENDING_AUDIT';$result.complete=$true;$result.qualified=$true;$code=0
    }else{
        $cleanup=& $m {Get-Command Invoke-SupNativeCleanup -CommandType Function}
        $result.cleanup=& $cleanup $r
        $result.status=$result.cleanup.status;$result.complete=$true;$code=0
    }
}catch{$result.status='FAIL';$result.errorKind=$_.FullyQualifiedErrorId;$code=1}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 10))
$f=[IO.File]::Open($r.result,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$f.Write($bytes,0,$bytes.Length)}finally{$f.Dispose()}
exit $code
