param([string]$Project,[string]$Jdk,[string]$JdkArchive,[string]$DistributionArchive,[string]$Owned,[string]$WatchRoot,[switch]$RuntimeApproved,[switch]$FixtureOnly,[hashtable]$FixtureHooks,[ValidateSet('Qualify','PackageScreen',IgnoreCase=$false)][string]$Mode='Qualify')
$arguments=@{};foreach($p in $PSBoundParameters.GetEnumerator()){$arguments[$p.Key]=$p.Value}
$m=Import-Module (Join-Path $PSScriptRoot 'H3911.MacQualifier.psm1') -Scope Local -PassThru -DisableNameChecking
& ($m.ExportedCommands['Invoke-H3911MacQualifier']) @arguments
