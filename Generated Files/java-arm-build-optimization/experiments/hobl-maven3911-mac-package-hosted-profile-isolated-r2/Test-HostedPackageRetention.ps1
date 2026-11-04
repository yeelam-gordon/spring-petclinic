param([Parameter(Mandatory)][string]$RepositorySource,[Parameter(Mandatory)][string]$OutputRoot)
$ErrorActionPreference='Stop'
if(Test-Path $OutputRoot){throw 'Fresh hosted package proof root required'}
New-Item $OutputRoot -ItemType Directory|Out-Null
$fixture=Join-Path $OutputRoot 'fixture'
& (Join-Path $PSScriptRoot 'New-MacPackageRetentionFixture.ps1') -RepositorySource $RepositorySource -OutputRoot $fixture|Out-Null
$m=Import-Module (Join-Path $PSScriptRoot 'H3911.MacHosted.psm1') -PassThru -Scope Local
$get=$m.ExportedCommands['Get-H3911MacHostedContract'];$guard=$m.ExportedCommands['Assert-H3911MacHostedGuard'];$copy=$m.ExportedCommands['Copy-H3911MacHostedRetention']
$run=Join-Path $fixture 'run';$setup=Join-Path $OutputRoot 'setup';New-Item $setup -ItemType Directory|Out-Null
$project=Join-Path $run 'project';$recordFile=Join-Path $run 'qualification/mac-qualifier.json';$original=[IO.File]::ReadAllBytes($recordFile)
$q=& $get $OutputRoot;$pkg=& $get $OutputRoot PackageScreen
if($q.mode-cne'Qualify'-or$q.clientsPlanned-ne8-or$q.clientsMaximum-ne9-or$q.auxiliaryJcmdMaximum-ne14-or$q.supervisorMilliseconds-ne600000-or$pkg.clientsPlanned-ne24-or$pkg.clientsMaximum-ne25-or$pkg.auxiliaryJcmdMaximum-ne30-or$pkg.mainMilliseconds-ne1680000-or$pkg.cleanupReserveMilliseconds-ne120000){throw 'Closed profile contract regression'}
$sha='a'*40
$context=@{event='workflow_dispatch';repository='yeelam-gordon/spring-petclinic';owner='yeelam-gordon';actor='yeelam-gordon';fork=$true;attempt=1;ref='refs/heads/perf/arm64-matched-comparison';sha=$sha;reviewedSha=$sha;reviewed=$true;environment='matched-comparison-approval';mode='PackageScreen';contract=$pkg.modeContract;ack='I_APPROVE_1_MAC_ARM_PACKAGESCREEN_24_MAX25_1800S_AUX30_NO_RETRY'}
$null=& $guard $context $sha PackageScreen
$bad=$context.Clone();$bad.contract=$pkg.modeContract.Clone();$bad.contract.totalAuxMaximum=31
$rejected=$false;try{$null=& $guard $bad $sha PackageScreen}catch{$rejected=$true};if(-not$rejected){throw 'Auxiliary bound relaxed'}
$rejected=$false;try{$null=& $guard $context $sha}catch{$rejected=$true};if(-not$rejected){throw 'Omitted package Mode fell back to Qualify'}
$proof=@(@{case='typed-profile-contracts-and-explicit-mode-guards';passed=$true})
$out=Join-Path $OutputRoot 'retained-positive'
$r=& $copy -SourceRoot $PSScriptRoot -RunRoot $run -SetupRoot $setup -Destination $out -Project $project -Mode PackageScreen
if($r.status-cne'ALLOWLIST_RETAINED_NOT_QUALIFICATION'-or$r.runtimeQualified){throw "Complete package binding failed: $($r.status)"}
$rows=(Get-Content (Join-Path $out 'retention.json') -Raw|ConvertFrom-Json).files
foreach($label in 'warmup-1-A','warmup-2-B','sample-3-A','sample-4-B','sample-5-B','sample-6-A','sample-7-A','sample-8-B'){if(-not(Test-Path (Join-Path $out "Run/qualification/output/mac-package-screen/$label/application.jar"))){throw 'Offline tree omitted'}}
$proof+=@{case='complete-package-byte-bound-positive';passed=$true;retainedFiles=$rows.Count;runtimeQualified=$false;fixtureOnly=$true}
foreach($case in 'missing','extra','hash','link','escape','sdk','wrongMode','aux-contract'){
    $changed=$null;$bytes=$null;$created=$null;$failure=$null
    try{
        $base=Join-Path $run 'qualification/output/mac-package-screen/warmup-1-A'
        switch($case){
            missing{$changed=Join-Path $base '01.raw';$bytes=[IO.File]::ReadAllBytes($changed);Remove-Item $changed}
            extra{$created=Join-Path $base 'EXTRA.txt';[IO.File]::WriteAllText($created,'unbound')}
            hash{$changed=Join-Path $base '01.raw';$bytes=[IO.File]::ReadAllBytes($changed);[IO.File]::AppendAllText($changed,'changed')}
            link{$created=Join-Path $base 'classes/LINK.txt';[IO.File]::CreateSymbolicLink($created,$recordFile)|Out-Null}
            sdk{$created=Join-Path $base 'test-classes/SDK.jar';[IO.File]::WriteAllText($created,'not an SDK')}
            default{
                $changed=$recordFile;$bytes=$original;$record=Get-Content $recordFile -Raw|ConvertFrom-Json -AsHashtable -DateKind String
                if($case-eq'escape'){$record.sampling.auxiliaryLedger[0].stdout.path=Join-Path $OutputRoot 'OUTSIDE.log'}
                elseif($case-eq'wrongMode'){$record.mode='Qualify'}
                else{$record.contract.totalAuxMaximum=31}
                $record|ConvertTo-Json -Depth 50|Set-Content $recordFile
            }
        }
        $dest=Join-Path $OutputRoot ('retained-'+$case)
        $r=& $copy -SourceRoot $PSScriptRoot -RunRoot $run -SetupRoot $setup -Destination $dest -Project $project -Mode PackageScreen
        if($r.status-cne'FAILED_EVIDENCE_BINDING'-or@(Get-ChildItem (Join-Path $dest 'Run') -Recurse -Filter '*.jar' -File -ErrorAction SilentlyContinue).Count){throw "Unsafe package failure copy: $case"}
        $proof+=@{case=$case;passed=$true;metadataOnly=$true;runtimeQualified=$false}
    }finally{
        if($changed-and$bytes){[IO.File]::WriteAllBytes($changed,$bytes)}
        if($created-and(Test-Path -LiteralPath $created)){Remove-Item -LiteralPath $created}
    }
}
$r=& $copy -SourceRoot $PSScriptRoot -RunRoot $run -SetupRoot $setup -Destination (Join-Path $OutputRoot 'omitted-mode') -Project $project
if($r.status-cne'FAILED_EVIDENCE_BINDING'){throw 'Package record silently retained under default mode'}
$proof+=@{case='retention-omitted-mode-rejects-package-record';passed=$true}
@{verdict='PASS';cases=$proof;scope='Synthetic physical335/333 trees and modeled receipts, strict pure binding only; no native authority';nativeCalls=0}|ConvertTo-Json -Depth 7|Set-Content (Join-Path $OutputRoot 'hosted-package-proof.json')
Write-Output "HOSTED_PACKAGE_RETENTION_PASS cases=$($proof.Count) offline8/logs16/probes28/source26; NOT_NATIVE"
