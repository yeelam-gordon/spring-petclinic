param([string]$Project,[string]$Jdk,[string]$DistributionArchive,[string]$WindowsInputs,[string]$Owned,[string]$CoreExe,[string]$WatchRoot,[string]$IndependentWitnessRoot,[ValidateSet('Qualify','PackageScreen',IgnoreCase=$false)][string]$Mode='Qualify',[ValidateSet('Windows',IgnoreCase=$false)][string]$Platform='Windows',[switch]$RuntimeApproved,[switch]$FixtureOnly,[switch]$ReviewedHostedDefaults,[hashtable]$FixtureHooks,[hashtable]$BaselineInventoryBinding)
$ErrorActionPreference='Stop'
$argsBefore=@{};foreach($p in $PSBoundParameters.GetEnumerator()){$argsBefore[$p.Key]=$p.Value}
$file=Join-Path $PSScriptRoot 'H3911.WindowsQualifier.psm1'
$module=Import-Module $file -Scope Local -PassThru -Force -DisableNameChecking
& $module.ExportedCommands['Invoke-H3911WindowsQualifier'] @argsBefore
