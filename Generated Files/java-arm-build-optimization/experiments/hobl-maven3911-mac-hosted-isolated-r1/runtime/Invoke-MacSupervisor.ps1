param([Parameter(Mandatory)][string]$Owned,[Parameter(Mandatory)][string]$Nonce,[string]$Project,[string]$Jdk,[string]$JdkArchive,[string]$DistributionArchive,[string]$WatchRoot,[switch]$RootRuntimeApproved,[switch]$ProofOnly,[string]$ProofCase='Normal0',[int]$DeadlineMilliseconds=600000)
$ErrorActionPreference='Stop'
$argsBound=@{};foreach($p in $PSBoundParameters.GetEnumerator()){$argsBound[$p.Key]=$p.Value}
$m=Import-Module (Join-Path $PSScriptRoot 'H3911.MacSupervisor.psm1') -Scope Local -PassThru -DisableNameChecking
$result=& ($m.ExportedCommands['Invoke-H3911MacSupervisor']) @argsBound
@{status=$result.status;qualified=$result.qualified;proofOnly=$result.proofOnly;nativeCensus=$result.nativeCensus}|ConvertTo-Json
if($result.qualified-or($result.proofOnly-and$result.status-ceq'PROOF_ONLY_COMPLETE_NOT_QUALIFICATION')){exit 0}
exit 1
