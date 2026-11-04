param([switch]$ValidateOnly,[switch]$ExecutionApproved,[ValidateSet('Qualify','PackageScreen',IgnoreCase=$false)][string]$Mode='Qualify')
$ErrorActionPreference='Stop'
$stage=Get-Content (Join-Path $PSScriptRoot 'stage.json') -Raw|ConvertFrom-Json
foreach($pin in $stage.files){if((Get-FileHash $pin.path).Hash-cne$pin.sha256){throw 'Reviewed full candidate source/input pin differs'}}
$q=Import-Module (Join-Path $PSScriptRoot 'public\H3911.WindowsQualifier.psm1') -Scope Local -PassThru -Force
$bound=& $q {& ${function:Import-WQ}}
$null=& ($bound['Assert-H3911Source']) @{Project=$stage.project;SourceProfile='ReviewedHttpsCoreWrapper'}
if(Test-Path $stage.owned){throw 'Fresh screen owned root required'}
if($ValidateOnly){@{status='VALIDATED_SOURCE_ONLY_UNALLOCATED';mode=$stage.mode;nativeCalls=0};return}
if(-not$ExecutionApproved-or-not$stage.launcherReview.approved-or-not$stage.runtimeAllocation.approved-or$stage.runtimeAllocation.status-cne'ROOT_ALLOCATED_EXACT_RUN'){throw 'UNALLOCATED_SCREEN_CANDIDATE'}
& (Join-Path $PSScriptRoot 'public\Invoke-WindowsQualifier.ps1') -Project $stage.project -Jdk $stage.jdk -DistributionArchive $stage.archive -WindowsInputs $stage.windowsInputs -Owned $stage.owned -CoreExe $stage.coreExe -WatchRoot $stage.watchRoot -IndependentWitnessRoot (Join-Path $PSScriptRoot 'actual-supervision') -Mode $stage.mode -Platform Windows -RuntimeApproved
