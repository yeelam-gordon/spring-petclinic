param([Parameter(Mandatory)][string]$Root,[Parameter(Mandatory)][string]$RepositorySource,[Parameter(Mandatory)][string]$Jdk,[Parameter(Mandatory)][string]$DistributionArchive,[Parameter(Mandatory)][string]$CoreExe,[Parameter(Mandatory)][string]$WatchRoot)
$ErrorActionPreference='Stop'
function Require($Ok,[string]$Why){if(-not$Ok){throw "HOLD: $Why"}}
Require ($IsWindows-and[Runtime.InteropServices.RuntimeInformation]::OSArchitecture-eq'Arm64'-and[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture-eq'Arm64') 'Native Windows ARM64 required; no fallback'
Require ([IO.Path]::IsPathFullyQualified($Root)-and$Root.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase)-and-not(Test-Path $Root)-and[IO.DriveInfo]::new('C:\').DriveFormat-ceq'NTFS') 'Fresh absolute C NTFS job root required'
$pins=Join-Path $PSScriptRoot 'runtime-pins.json'
Require ((Get-FileHash $pins).Hash-ceq'B1F2515CE28CD7CEA8B7244D52EED911DF2C2D425361CDD051FE1D314E49050A') 'Reviewed30 manifest differs'
$rows=Get-Content $pins -Raw|ConvertFrom-Json -AsHashtable -DateKind String
Require ($rows.Count-eq30) 'Exact accepted30 required'
foreach($r in $rows){Require ($r.file-notmatch'(^[/\\]|\\|:|(^|/)\.\.?(/|$))'-and(Get-FileHash (Join-Path (Join-Path $PSScriptRoot 'runtime') $r.file)).Hash-ceq$r.sha256) 'Runtime source bytes differ'}
$q=Import-Module (Join-Path $PSScriptRoot 'runtime\public\H3911.WindowsQualifier.psm1') -Scope Local -PassThru -Force
foreach($path in $Root,$RepositorySource,$Jdk,$DistributionArchive,$CoreExe,$WatchRoot){$null=& $q {param($p)& ${function:Resolve-WQNamespace} $p -AllowMissing} $path}
foreach($pair in @(@((Join-Path $Jdk 'bin\java.exe'),'094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0'),@($CoreExe,'BBDF538AEA81C09F60732219B451A26C64F6F2B22BEE05EEECE13DBA909D36E4'),@($DistributionArchive,'EFE788E475F8433E855AC05F92E129DC3790517B58002620BA4DD8D264DCD511'))){Require ((Get-FileHash $pair[0]).Hash-ceq$pair[1]) 'Exact native JDK/Core/archive prerequisite missing; hosted toolchain owner must supply it'}
foreach($path in @((Join-Path $Jdk 'bin\java.exe'),$CoreExe)){[byte[]]$b=[IO.File]::ReadAllBytes($path);Require ([BitConverter]::ToUInt16($b,[BitConverter]::ToInt32($b,60)+4)-eq0xAA64) 'Native AA64 executable required'}
$inputRoot=Join-Path $PSScriptRoot 'windows-arm64-jvm'
Require ((Get-FileHash (Join-Path $inputRoot 'provenance.json')).Hash-ceq'A314822B548A08EBC3426E878A3FAB38BB45F81E153FBCAA1F067B7C29AB515F') 'Exact JNI transport provenance required'
$provenance=Get-Content (Join-Path $inputRoot 'provenance.json') -Raw|ConvertFrom-Json
foreach($r in $provenance.files){Require ((Get-FileHash (Join-Path $inputRoot $r.file)).Hash-ceq$r.sha256) 'JNI transport bytes differ'}
$wrapper=Join-Path $PSScriptRoot 'runtime\public\fixtures\Reviewed-AAA-mvnw.cmd'
Require ((Get-FileHash $wrapper).Hash-ceq'AAA4957C5AB29267A0D89C03D33621740A4233BF25AFEB480797023687CABB7D') 'Accepted AAA wrapper required'
$disjoint=& $q {Microsoft.PowerShell.Core\Get-Command Assert-WQDisjoint -CommandType Function}
Require ($disjoint-is[Management.Automation.FunctionInfo]-and$disjoint.Name-ceq'Assert-WQDisjoint'-and$disjoint.Module.Path-ceq$q.Path) 'Pinned private namespace checker origin differs'
$outputs=@($Root,(Join-Path $Root 'project'),(Join-Path $Root 'run'),(Join-Path $Root 'controller'))
foreach($output in $outputs){foreach($immutable in @($Jdk,$CoreExe,$DistributionArchive,$inputRoot,$PSScriptRoot)){
    & $disjoint ([IO.Path]::GetFullPath($output).TrimEnd('\')) ([IO.Path]::GetFullPath($immutable).TrimEnd('\'))
}}
New-Item $Root -ItemType Directory -ErrorAction Stop|Out-Null
$controller=Join-Path $Root 'controller';New-Item $controller -ItemType Directory|Out-Null
$bound=@();foreach($r in $rows){$from=Join-Path (Join-Path $PSScriptRoot 'runtime') $r.file;$to=Join-Path $controller $r.file;New-Item (Split-Path $to) -ItemType Directory -Force|Out-Null;Copy-Item $from $to;Require ((Get-FileHash $to).Hash-ceq$r.sha256) 'Copied runtime differs';$bound+=@{path=$to;sha256=$r.sha256}}
$project=Join-Path $Root 'project'
git clone --quiet --local --no-hardlinks --no-checkout $RepositorySource $project;Require ($LASTEXITCODE-eq0) 'Ordinary full local source clone failed'
git -C $project config --local core.autocrlf false;Require ($LASTEXITCODE-eq0) 'False policy setup failed'
git -C $project remote set-url origin 'https://github.com/spring-projects/spring-petclinic.git'
git -C $project checkout --quiet --detach 6feeae0f13e0e258eedc99832416b42bb13779b1;Require ($LASTEXITCODE-eq0) 'Pinned6fee checkout failed'
Copy-Item $wrapper (Join-Path $project 'mvnw.cmd')
$stage=@{state='HOSTED_PACKAGE_SCREEN_PREPARED_UNALLOCATED';mode='PackageScreen';project=$project;owned=(Join-Path $Root 'run');jdk=$Jdk;archive=$DistributionArchive;windowsInputs=$inputRoot;coreExe=$CoreExe;watchRoot=$WatchRoot;files=$bound;approvedQualifierDriver=(Join-Path $controller 'Invoke-ScreenCandidate.ps1');approvedQualifierDriverSha256='2647C477FE436284E590ED9E6E2B0C7EA1B0B71B5B8245519E01F40449C887D7';launcherReview=@{approved=$false};runtimeAllocation=@{approved=$false;status='UNALLOCATED';plannedChildCalls=24;maxChildCalls=25;parentCliCalls=0;hardSeconds=1800;retryAllowed=$false}}
$stage|ConvertTo-Json -Depth 10|Set-Content (Join-Path $controller 'stage.json')
& (Join-Path $controller 'Invoke-ScreenCandidate.ps1') -ValidateOnly
@{status='PREPARED_SOURCE_ONLY_NO_MAVEN';root=$Root;controller=$controller;sourceOrigin='ordinary local clone from explicit RepositorySource; canonical remote URL is configuration';ownedAbsent=(-not(Test-Path $stage.owned));runtimeAllocated=$false}|ConvertTo-Json|Set-Content (Join-Path $Root 'preparation.json')
