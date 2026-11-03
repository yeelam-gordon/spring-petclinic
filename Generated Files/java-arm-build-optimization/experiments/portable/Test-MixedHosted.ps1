param([Parameter(Mandatory)][string]$FixtureRoot)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot;$results=@()
$workflow=Get-Content (Join-Path $root 'mixed-client-package.workflow.yml') -Raw
if(Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue){
    $yaml=$workflow|ConvertFrom-Yaml
    if($yaml.jobs.Count-ne1-or$yaml.jobs.paired.strategy.matrix.include.Count-ne2-or$yaml.jobs.paired.'timeout-minutes'-ne60-or$yaml.jobs.paired.strategy.'fail-fast'-ne$false){throw 'Wrong paired job budget'}
    if((@($yaml.jobs.paired.strategy.matrix.include.runner)-join',')-cne'windows-11-arm,macos-26'){throw 'Exact alternate-pool matrix differs'}
    $blocks=@($yaml.jobs.paired.steps|Where-Object run|ForEach-Object run)
}else{
    if([regex]::Matches($workflow,'(?m)^          - runner: (windows-11-arm|macos-26)\r?$').Count-ne2-or$workflow-notmatch'timeout-minutes: 60'-or$workflow-notmatch'fail-fast: false'){throw 'Literal template budget mismatch'}
    $blocks=@([regex]::Matches($workflow,'(?m)^        run: \|\r?\n((?:          [^\r\n]*\r?\n)+)')|ForEach-Object{[regex]::Replace($_.Groups[1].Value,'(?m)^          ','')})
}
if($blocks.Count-ne4){throw 'Expected four literal workflow PowerShell blocks'}
foreach($block in $blocks){$t=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($block,[ref]$t,[ref]$errors);if($errors){throw 'Workflow PowerShell syntax'}}
if($workflow-notmatch'inputs.payload_sha == github.sha'-or$workflow-notmatch'github.repository_owner == github.actor'-or$workflow-notmatch'I_APPROVE_2_JOBS_60_MINUTES_NO_RETRY'){throw 'Workflow authority guard missing'}
$refMatch=[regex]::Match($workflow,"github.ref == '([^']+)'")
$authorityMatch=[regex]::Match($workflow,"inputs.authority == '([^']+)'")
if(-not$refMatch.Success-or$refMatch.Groups[1].Value-cne'refs/heads/perf/arm64-matched-comparison'-or$workflow-notmatch'github.event.repository.fork == true'-or$workflow-match'startsWith\(github.ref'){throw 'Environment-approved exact ref guard missing'}
$guardProof=@()
foreach($case in 'approved','main','old-prefix','wrong-sha','wrong-actor','not-fork','wrong-authority'){
    $ref=switch($case){'main'{'refs/heads/main'}'old-prefix'{'refs/heads/experiments/mixed-client-current17-r1'}default{'refs/heads/perf/arm64-matched-comparison'}}
    $authority=if($case-eq'wrong-authority'){'UNAPPROVED'}else{'I_APPROVE_2_JOBS_60_MINUTES_NO_RETRY'}
    $sha='a'*40;$reviewed=if($case-eq'wrong-sha'){'b'*40}else{$sha}
    $actor=if($case-eq'wrong-actor'){'other'}else{'owner'};$fork=$case-ne'not-fork'
    $admitted=$ref-ceq$refMatch.Groups[1].Value-and$authority-ceq$authorityMatch.Groups[1].Value-and$reviewed-ceq$sha-and$actor-ceq'owner'-and$fork
    if($admitted-ne($case-eq'approved')){throw 'Source-bound dispatch guard truth table failed'}
    $guardProof+=,@{case=$case;ref=$ref;admitted=$admitted}
}
New-Item $FixtureRoot -ItemType Directory -Force|Out-Null
$guardProof|ConvertTo-Json|Set-Content (Join-Path $FixtureRoot 'dispatch-guard-proof.json')
foreach($os in 'Windows','MacOS'){
 foreach($case in 'positive','bad-hash','source-fail','child-fail','jdk-positive','jdk-bad-hash'){
  $module=New-Module -ArgumentList $root,$FixtureRoot,$os,$case -ScriptBlock {
   param($root,$FixtureRoot,$os,$case)
   Export-ModuleMember -Function @() -Alias @() -Variable @()
   . (Join-Path $root 'Invoke-MixedHosted.ps1') -LibraryOnly
   function TestFixtureWindowsInvocation($Event,[string]$ComSpec){
    if($Event.kind-cne'native'){return $false}
    $file=[string]$Event.file
    Require (-not[string]::IsNullOrWhiteSpace($file)) 'Native fixture event has no command'
    return ((-not[string]::IsNullOrWhiteSpace($ComSpec)-and[string]::Equals($file,$ComSpec,[StringComparison]::OrdinalIgnoreCase))-or$file-imatch'(^|[\\/])cmd\.exe$')
   }
   $owned=Join-Path $FixtureRoot ("$os-$case-"+[guid]::NewGuid().ToString('N'));$jdk=Join-Path $owned 'native jdk'
   New-Item $jdk -ItemType Directory -Force|Out-Null
   $events=@()
   function MixedHostedHost {@{platform=$os;osArchitecture='Arm64';processArchitecture='Arm64';hardware='SYNTHETIC'}}
   function MixedHostedDownload($Url,$Path){[IO.File]::WriteAllText($Path,'SYNTHETIC_DOWNLOAD');$script:events+=,@{kind='download';url=$Url}}
   function MixedHostedHash($Path,$Algorithm='SHA256'){
    $name=Split-Path $Path -Leaf;$pins=MixedHostedPins $os
    if($name-ceq$pins.jdk){if($case-eq'jdk-bad-hash'){return 'BAD'};return $pins.jdkHash}
    switch($name){
     'vendor.zip'{if($case-eq'bad-hash'){return 'BAD'};if($Algorithm-eq'SHA512'){return $pins.vendorHash};return 'CABA9E00736B8C0C62B9238EE75BC64294A0DF42E45ECD513FEE1914DA3FD6CF'}
     'mvnd.exe'{return '386B03C8DF458D8573B9241259EEBFABA894B32DDF8D0767C8CAE6168F81FAD4'}
     'mvndnative.c'{return '31198B329118419DB30A8178FB438F44953B33F346C30E1BF313DF2F4E6A021E'}
     'mvndnative.h'{return 'E12BE1E39BB5FD0755B87D151D91712D9606D1118B1F6CCAB6BC2CB0857AA9DF'}
     default{return (Get-FileHash $Path -Algorithm $Algorithm).Hash}
    }
   }
   function MixedBinaryIdentity($Path){@{machine=$(if($Path-like'*.dll'){0xAA64}else{0x8664})}}
   function MixedHostedUnzip($Path,$Destination){
    $driver=Join-Path $Destination "maven-mvnd-1.0.6-$((MixedHostedPins $os).flavor)"
    New-Item (Join-Path $driver 'mvn/lib/mvnd'),(Join-Path $driver 'bin') -ItemType Directory -Force|Out-Null
    [IO.File]::WriteAllText((Join-Path $driver 'bin/mvnd.exe'),'SYNTHETIC_NOT_EXECUTED')
    $zip=[IO.Compression.ZipFile]::Open((Join-Path $driver 'mvn/lib/mvnd/mvnd-native-1.0.6.jar'),[IO.Compression.ZipArchiveMode]::Create);$null=$zip.CreateEntry('vendor');$zip.Dispose()
   }
   function MixedHostedNative($File,$Arguments,$Log){
    $script:events+=,@{kind='native';file=$File;arguments=$Arguments}
    if($File-like'*vswhere.exe'){[IO.File]::WriteAllText($Log,'C:\synthetic VS');return 0}
    if($File-eq$env:ComSpec){New-Item (Join-Path $owned 'native') -ItemType Directory -Force|Out-Null;[IO.File]::WriteAllText((Join-Path $owned 'native/mvndnative.dll'),'SYNTHETIC');[IO.File]::WriteAllText($Log,'SYNTHETIC ARM64 compiler');return 0}
    if($File-eq'git'){
     $info=[Diagnostics.ProcessStartInfo]::new([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName);$info.UseShellExecute=$false
     foreach($a in @('-NoProfile','-Command',$(if($case-eq'child-fail'){'exit 1'}else{'exit 0'}))){$info.ArgumentList.Add($a)}
     $child=[Diagnostics.Process]::Start($info);$child.WaitForExit();$script:actualChildExit=$child.ExitCode
     if($child.ExitCode){return $child.ExitCode}
     if($case-eq'source-fail'-and$Arguments-contains'checkout'){throw 'SYNTHETIC_PIN_CHECKOUT_FAILURE'}
     if($Arguments-contains'clone'){New-Item (Join-Path $owned 'project') -ItemType Directory|Out-Null}
    }
    [IO.File]::WriteAllText($Log,'SYNTHETIC');return 0
   }
   $before=PortableEnvironmentSnapshot;$cwd=(Get-Location).Path;$caught=$null;$stage=if($case-like'jdk-*'){'Jdk'}else{'Execute'}
   $env:GITHUB_OUTPUT=Join-Path $owned 'synthetic-actions-output'
   Remove-Item Env:MAVEN_OPTS -ErrorAction SilentlyContinue
   if($os-eq'Windows'-and-not${env:ProgramFiles(x86)}){${env:ProgramFiles(x86)}=Join-Path $owned 'synthetic Program Files'}
   try{InvokeMixedHosted $stage $os $owned $jdk -OnlyPlan}catch{$caught=$_.ToString()}
   finally{$null=RestorePortableEnvironment $before @('GITHUB_OUTPUT','ProgramFiles(x86)','MAVEN_OPTS')}
   $record=Get-Content (Join-Path $owned "setup-evidence/$stage-result.json") -Raw|ConvertFrom-Json
   Require ($record.restoration.restored-and$record.restoration.keys.Count-eq18-and$record.restoration.cwdEqual) 'Hosted finalizer did not restore18 states'
   if($case-eq'positive'){
    Require ($record.status-eq'PASS'-and-not$caught) "Hosted positive failed: $caught"
    $plan=Get-Content (Join-Path $owned 'setup-evidence/collector-entrypoint-output.log') -Raw|ConvertFrom-Json
    Require ($plan.comparison-eq'MixedClientPackage'-and$plan.sourcePin-eq'500158f732419217507c7656904b8e6aa1bcc0d6'-and$plan.samples-eq3-and$plan.loopbackTests) 'Actual collector entrypoint forwarding failed'
    if($os-eq'Windows'){Require ($plan.candidate.EndsWith('mvnd.cmd')) 'Windows JVM route differs'}
    else{
     @{candidate=$plan.candidate;comSpecPresent=[Environment]::GetEnvironmentVariables().Contains('ComSpec');comSpecEmpty=[string]::IsNullOrEmpty($env:ComSpec);events=$events}|ConvertTo-Json -Depth 10|Set-Content (Join-Path $owned 'setup-evidence/native-route-observation.json')
     Require (-not(TestFixtureWindowsInvocation @{kind='download';url='fixture'} $null)-and-not(TestFixtureWindowsInvocation @{kind='download';url='fixture'} '')) 'Metadata mistaken for a native command'
     Require (TestFixtureWindowsInvocation @{kind='native';file='cmd.exe'} $null) 'Windows command without ComSpec was missed'
     Require (TestFixtureWindowsInvocation @{kind='native';file='C:\synthetic\cmd.exe'} 'C:\synthetic\cmd.exe') 'Defined Windows command was missed'
     $ambiguousRejected=$false;try{$null=TestFixtureWindowsInvocation @{kind='native';file=$null} $null}catch{$ambiguousRejected=$_.ToString()-like'*Native fixture event has no command*'}
     Require $ambiguousRejected 'Ambiguous native command was accepted'
     Require ($plan.candidate.EndsWith('bin/mvnd')-and-not@($events|Where-Object{TestFixtureWindowsInvocation $_ $env:ComSpec}).Count) 'Unix/native route crossed Windows API boundary'
    }
   }elseif($case-eq'jdk-positive'){Require ($record.status-eq'PASS'-and-not$caught-and(Get-Content (Join-Path $owned 'synthetic-actions-output') -Raw)-match'javaVersion=17.0.21') 'JDK output forwarding failed'}
   else{Require ($record.status-eq'FAIL'-and$caught) 'Setup/child failure became success'}
   if($case-eq'bad-hash'){Require (Test-Path (Join-Path $owned 'setup-evidence/mismatched-bytes/vendor.zip')) 'Bad actual bytes lost'}
   if($case-eq'jdk-bad-hash'){Require (Test-Path (Join-Path $owned "setup-evidence/mismatched-bytes/$((MixedHostedPins $os).jdk)")) 'Bad JDK actual bytes lost'}
   if($case-eq'source-fail'){Require ($record.error-like'*SYNTHETIC_PIN_CHECKOUT_FAILURE*'-and$actualChildExit-eq0) 'Wrong source-failure prefix'}
   if($case-eq'child-fail'){Require ($record.error-like'*Fresh full project clone returned native exit 1*'-and$actualChildExit-eq1) 'Genuine child1 was not propagated'}
   $script:proof=@{os=$os;case=$case;record=$record;events=$events;actualChildExit=$actualChildExit;syntheticProvisioning=$true;actualCollectorEntrypointPlanOnly=$true}
  }
  $results+=,(& $module {$proof});Remove-Module $module
 }
}
$results|ConvertTo-Json -Depth 30|Set-Content (Join-Path $FixtureRoot 'hosted-fixtures.json')
. (Join-Path $root 'Invoke-MixedHosted.ps1') -LibraryOnly
$actualHost=MixedHostedHost
if($actualHost.hostname-ceq'UNKNOWN'){Require (-not[string]::IsNullOrWhiteSpace($actualHost.hostnameError)) 'Unknown hostname needs explicit observation error'}
else{Require (-not[string]::IsNullOrWhiteSpace($actualHost.hostname)-and$null-eq$actualHost.hostnameError) 'Actual hostname witness is invalid'}
@{hostname=$actualHost.hostname;hostnameError=$actualHost.hostnameError;source='System.Net.Dns.GetHostName, actual current host';notGitPropertyEcho=$true}|ConvertTo-Json|Set-Content (Join-Path $FixtureRoot 'actual-host-witness.json')
$repo=Join-Path $FixtureRoot 'git-source';New-Item $repo -ItemType Directory -Force|Out-Null
$names=@((Get-Content (Join-Path $root 'mixed-payload-sha256.json') -Raw|ConvertFrom-Json).file)+@('mixed-payload-sha256.json')
foreach($name in $names){Copy-Item (Join-Path $root $name) (Join-Path $repo $name)}
& git -c core.longpaths=true init --quiet $repo;if($LASTEXITCODE){throw 'Fixture git init failed'}
& git -C $repo config core.longpaths true
& git -C $repo config core.autocrlf false
& git -C $repo add -- .
$message="Pure mixed payload byte fixture`n`nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
New-Item (Join-Path $repo 'empty-hooks') -ItemType Directory|Out-Null
& git -C $repo -c user.name=CopilotFixture -c user.email=fixture@example.invalid -c commit.gpgsign=false -c core.hooksPath=empty-hooks commit --quiet -m $message
if($LASTEXITCODE){throw 'Fixture local commit failed'}
$gitProof=@()
foreach($value in 'false','true'){
    $clone=Join-Path $FixtureRoot "git-checkout-$value"
    & git -c core.longpaths=true clone --quiet --no-hardlinks --config core.longpaths=true --config "core.autocrlf=$value" $repo $clone
    if($LASTEXITCODE){throw 'Fresh fixture checkout failed'}
    foreach($name in $names){Require ((Get-FileHash (Join-Path $clone $name)).Hash-ceq(Get-FileHash (Join-Path $root $name)).Hash) 'Fresh Git payload bytes changed'}
    $gitProof+=,@{autocrlf=$value;allPayloadBytesEqual=$true;clone=$clone}
}
$badClone=Join-Path $FixtureRoot 'git-checkout-true';$mutated=Join-Path $badClone 'Invoke-MatchedComparison.ps1'
[IO.File]::AppendAllText($mutated,"`n# SYNTHETIC_HASH_MISMATCH")
$badSetup=Join-Path $FixtureRoot 'payload-failure';New-Item $badSetup -ItemType Directory|Out-Null
$rejected=$false;try{AssertMixedHostedPayload $badClone $badSetup}catch{$rejected=$true}
Require ($rejected-and(Test-Path (Join-Path $badSetup 'mismatched-bytes/Invoke-MatchedComparison.ps1'))) 'Payload actual mismatch bytes not retained'
$gitProof|ConvertTo-Json|Set-Content (Join-Path $FixtureRoot 'git-byte-proof.json')
$capture=Join-Path $FixtureRoot 'future-visible-capture';New-Item $capture -ItemType Directory|Out-Null
AssertMixedHostedPayload $repo $capture
$uploadFiles=@(Get-ChildItem $capture -Recurse -Force -File|Where-Object{
    $relative=[IO.Path]::GetRelativePath($capture,$_.FullName)
    -not@($relative.Split([IO.Path]::DirectorySeparatorChar)|Where-Object{$_.StartsWith('.')}).Count
})
$rows=Get-Content (Join-Path $repo 'mixed-payload-sha256.json') -Raw|ConvertFrom-Json
$visibleProof=@()
foreach($row in $rows){
    $safe=MixedHostedEvidenceName $row.file;$copy=Join-Path $capture "payload-actual/$safe";$receipt=Join-Path $capture "$safe.SHA256.hash.json"
    Require ($copy-cin$uploadFiles.FullName-and$receipt-cin$uploadFiles.FullName) 'Default hidden-path filtering dropped required payload or receipt'
    $record=Get-Content $receipt -Raw|ConvertFrom-Json
    Require ($record.logicalName-ceq$row.file-and$record.expected-ceq$row.sha256-and$record.actual-ceq$row.sha256-and$record.retainedActual-ceq$row.sha256-and$record.copyBound-and$record.bytes-eq(Get-Item $copy).Length-and(Get-FileHash $copy).Hash-ceq$row.sha256) 'Logical/copy/hash receipt binding differs'
    $visibleProof+=,@{logicalName=$row.file;retained=$copy;receipt=$receipt;sha256=$record.actual;bytes=$record.bytes;survivesDefaultHiddenExclusion=$true}
}
foreach($badName in @('.env','../escape','..\escape','.','..')){$rejected=$false;try{$null=MixedHostedEvidenceName $badName}catch{$rejected=$true};Require $rejected 'Unknown/unsafe evidence role admitted'}
$attribute=Join-Path $repo '.gitattributes';$expectedAttribute=(Get-FileHash $attribute).Hash
$copyFailure=Join-Path $FixtureRoot 'copy-binding-failure';New-Item $copyFailure -ItemType Directory|Out-Null
$wrongCopy=Join-Path $copyFailure 'wrong-copy.raw';[IO.File]::WriteAllText($wrongCopy,'SYNTHETIC_COPY_DISCREPANCY')
$rejected=$false;try{AssertMixedHostedHash $attribute $expectedAttribute $copyFailure SHA256 $wrongCopy}catch{$rejected=$true}
Require ($rejected-and-not(Get-Content (Join-Path $copyFailure 'allowlisted-gitattributes.SHA256.hash.json') -Raw|ConvertFrom-Json).copyBound) 'Source/copy discrepancy silently accepted'
[IO.File]::AppendAllText($attribute,"`n# SYNTHETIC_ATTRIBUTE_HASH_MISMATCH")
$badCapture=Join-Path $FixtureRoot 'attribute-mismatch';New-Item $badCapture -ItemType Directory|Out-Null
$rejected=$false;try{AssertMixedHostedPayload $repo $badCapture}catch{$rejected=$true}
$badBytes=Join-Path $badCapture 'mismatched-bytes/allowlisted-gitattributes';$badReceipt=Join-Path $badCapture 'allowlisted-gitattributes.SHA256.hash.json'
$record=Get-Content $badReceipt -Raw|ConvertFrom-Json
Require ($rejected-and(Test-Path $badBytes)-and$record.logicalName-ceq'.gitattributes'-and$record.actual-ceq(Get-FileHash $badBytes).Hash-and$record.actual-cne$record.expected-and$record.copyBound) 'Hidden attribute mismatch lost actual bytes/receipt or did not fail'
@{scope='FUTURE_CAPTURE_ONLY_not_original_artifact';payloads=$visibleProof;logicalPayloads=8;visibleReceipts=8;attributeMismatchRejected=$true;actualMismatchBytes=$badBytes;actualMismatchReceipt=$badReceipt;copyDiscrepancyRejected=$true;uploadModel='Exclude any path segment starting dot; no broad hidden-file enablement'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $FixtureRoot 'future-hidden-retention-proof.json')
Write-Output 'HOSTED_REAL_CONTROLLER_TO_ACTUAL_ENTRYPOINT_PURE_PASS'
