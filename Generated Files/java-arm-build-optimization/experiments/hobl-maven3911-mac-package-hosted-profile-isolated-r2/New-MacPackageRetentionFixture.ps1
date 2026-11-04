param([Parameter(Mandatory)][string]$RepositorySource,[Parameter(Mandatory)][string]$OutputRoot)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Synthetic-MacPackageData.ps1')
if(-not[IO.Path]::IsPathFullyQualified($RepositorySource)-or-not[IO.Path]::IsPathFullyQualified($OutputRoot)-or(Test-Path $OutputRoot)){throw 'Absolute repository/fresh owned output required'}
New-Item $OutputRoot -ItemType Directory|Out-Null
@{marker='SYNTHETIC_TEST_DATA_NOT_NATIVE';origin='Existing hermetic generator plus explicit synthetic suite/session/path materialization';compiledJava=$false;actualOSProcessIdentities=$false;nativeMacAuthority=$false;runtimeQualified=$false;layout=@{generated='generated';run='run';record='run/qualification/mac-qualifier.json';parent='run/parent-model.json'}}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $OutputRoot 'SYNTHETIC_TEST_DATA_NOT_NATIVE.json')
$targets=Join-Path $OutputRoot 'generated';$null=New-SyntheticMacTargets $RepositorySource $targets
& ([Environment]::ProcessPath) -NoLogo -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'Test-MacPackageScreen.ps1') -RepositorySource $RepositorySource -OutputRoot (Join-Path $OutputRoot 'run') -MaterializedRoot $targets -OnlySuccess
if($LASTEXITCODE-ne0){throw 'Isolated fixture caller transport failed'}
if(-not(Test-Path (Join-Path $OutputRoot 'run\qualification\mac-qualifier.json'))){throw 'Complete fixture was not materialized'}
