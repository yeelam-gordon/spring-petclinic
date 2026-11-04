function Assert-Hosted($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function Assert-H3911MacHostedGuard($Context,[string]$ReviewedSha,[ValidateSet('Qualify','PackageScreen',IgnoreCase=$false)][string]$Mode='Qualify'){
    $pkg=$Mode-ceq'PackageScreen';$ack=if($pkg){'I_APPROVE_1_MAC_ARM_PACKAGESCREEN_24_MAX25_1800S_AUX30_NO_RETRY'}else{'I_APPROVE_1_MAC_ARM_QUALIFICATION_JOB_30MIN_600S_9MAX_14AUX_NO_RETRY'}
    if($Context.ContainsKey('mode')){& ${function:Assert-Hosted} ($Context.mode-is[string]-and$Context.mode-ceq$Mode) 'Explicit hosted Mode differs'}
    if($pkg){& ${function:Assert-Hosted} ($Context.mode-ceq'PackageScreen') 'PackageScreen Mode cannot be omitted';$expected=(& ${function:Get-H3911MacHostedContract} ([IO.Path]::GetPathRoot($PSScriptRoot)) $Mode).modeContract;& ${function:Assert-HostedContract} $Context.contract $expected}
    foreach($name in 'event','repository','owner','actor','ref','sha','reviewedSha','environment','ack'){& ${function:Assert-Hosted} ($Context[$name]-is[string]) 'Scalar hosted guard fields required'}
    & ${function:Assert-Hosted} ($ReviewedSha-cmatch'^[a-f0-9]{40}$'-and$Context.event-is[string]-and$Context.event-ceq'workflow_dispatch'-and$Context.repository-ceq'yeelam-gordon/spring-petclinic'-and$Context.owner-ceq'yeelam-gordon'-and$Context.actor-ceq$Context.owner-and$Context.fork-is[bool]-and$Context.fork-and($Context.attempt-is[int]-or$Context.attempt-is[long])-and$Context.attempt-eq1-and$Context.ref-ceq'refs/heads/perf/arm64-matched-comparison'-and$Context.sha-ceq$ReviewedSha-and$Context.reviewedSha-ceq$ReviewedSha-and$Context.reviewed-is[bool]-and$Context.reviewed-and$Context.environment-ceq'matched-comparison-approval'-and$Context.ack-ceq$ack) 'Exact fork/actor/ref/SHA/manual/environment/budget guards required'
    @{guarded=$true;executionAuthorityGranted=$false}
}
function Assert-HostedContract($Actual,$Expected){
    & ${function:Assert-Hosted} ($Actual-is[Collections.IDictionary]-and$Actual.Count-eq8) 'Exact typed Mode contract required'
    foreach($key in $Actual.Keys){& ${function:Assert-Hosted} ($key-cin@($Expected.Keys)) 'Unknown Mode contract field'}
    foreach($key in $Expected.Keys){$ok=if($key-ceq'mode'){$Actual[$key]-is[string]-and$Actual[$key]-ceq$Expected[$key]}else{($Actual[$key]-is[int]-or$Actual[$key]-is[long])-and$Actual[$key]-eq$Expected[$key]};& ${function:Assert-Hosted} $ok 'Mode budget/contract differs'}
}
function Get-H3911MacHostedContract([string]$Workspace,[ValidateSet('Qualify','PackageScreen',IgnoreCase=$false)][string]$Mode='Qualify'){
    & ${function:Assert-Hosted} ([IO.Path]::IsPathFullyQualified($Workspace)) 'Absolute native workspace required'
    $pkg=$Mode-ceq'PackageScreen';$root=Join-Path $Workspace $(if($pkg){'mac3911-package-owned'}else{'mac3911-owned'})
    $contract=@{mode=$Mode;normalMaximum=$(if($pkg){24}else{8});emergencyMaximum=$(if($pkg){25}else{9});mainAuxMaximum=$(if($pkg){28}else{12});parentAuxMaximum=2;totalAuxMaximum=$(if($pkg){30}else{14});deadlineMilliseconds=$(if($pkg){1800000}else{600000});hostedJobProposalMinutes=$(if($pkg){40}else{30})}
    @{mode=$Mode;modeContract=$contract;mainMilliseconds=($contract.deadlineMilliseconds-120000);cleanupReserveMilliseconds=120000;root=$root;archives=(Join-Path $root 'archives');setup=(Join-Path $root 'setup-evidence');project=(Join-Path $root 'project');run=(Join-Path $root 'run');retained=(Join-Path $Workspace $(if($pkg){'mac3911-package-retained'}else{'mac3911-retained'}));sourcePin='6feeae0f13e0e258eedc99832416b42bb13779b1';supervisorMilliseconds=$contract.deadlineMilliseconds;clientsPlanned=$contract.normalMaximum;clientsMaximum=$contract.emergencyMaximum;auxiliaryJcmdMaximum=$contract.totalAuxMaximum;runtimeAllocated=$false;downloads=@(
        @{kind='jdk';file='microsoft-jdk-25.0.5.0.2-macos-aarch64.tar.gz';url='https://aka.ms/download-jdk/microsoft-jdk-25.0.5.0.2-macos-aarch64.tar.gz';sha256='C9CF199844411C8BAFD05722D2547538300523A63FF6207A440C71B175FF7873'},
        @{kind='mvnd';file='maven-mvnd-1.0.3-darwin-aarch64.tar.gz';url='https://github.com/apache/maven-mvnd/releases/download/1.0.3/maven-mvnd-1.0.3-darwin-aarch64.tar.gz';sha256='B5528C92D5B0E14A8A47DDFF138C19D93AC01F6CB8A28514F8FA40F2CEB65194'}
    )}
}
function Get-HostedRegular([string]$Root,[string]$Relative){
    & ${function:Assert-Hosted} ([IO.Path]::IsPathFullyQualified($Root)-and$Relative-and$Relative-notmatch'(^[/\\]|\\|:|(^|/)\.\.?(/|$)|//)') 'Bound ordinary relative source/evidence required'
    $base=[IO.Path]::GetFullPath($Root).TrimEnd([char[]]'\/');$path=[IO.Path]::GetFullPath((Join-Path $base $Relative))
    $comparison=if($IsWindows){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
    & ${function:Assert-Hosted} ($path.StartsWith($base+[IO.Path]::DirectorySeparatorChar,$comparison)) 'Outside admitted source/evidence root'
    $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;$probe=$item
    & ${function:Assert-Hosted} ($item-is[IO.FileInfo]) 'Ordinary file required'
    while($probe){& ${function:Assert-Hosted} (-not($probe.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not$probe.LinkType) 'Linked source/evidence ancestor or leaf';$probe=if($probe-is[IO.FileInfo]){$probe.Directory}else{$probe.Parent}}
    $item
}
function Get-HostedSourcePolicy {
    $file=& ${function:Get-HostedRegular} $PSScriptRoot 'hosted-payload-sha256.json'
    $rows=Get-Content $file.FullName -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    & ${function:Assert-Hosted} ($rows-is[array]-and$rows.Count-eq39) 'Exact module-owned source policy required'
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($row in $rows){& ${function:Assert-Hosted} ($row.file-is[string]-and($row.file-cmatch'^runtime/[^./\\][^/\\:]*$'-or$row.file-cin@('.gitattributes','runtime-pins.json','H3911.MacHosted.psm1','mac-qualification.workflow.yml','mac-package-screen.workflow.yml','Test-MacHosted.ps1','Test-MacRetentionBoundaries.ps1','New-MacPackageRetentionFixture.ps1','Synthetic-MacPackageData.ps1','Make-SyntheticFixtures.py','Test-MacPackageScreen.ps1','Test-SyntheticRetention.ps1','Test-HostedPackageRetention.ps1'))-and$row.sha256-is[string]-and$row.sha256-cmatch'^[A-F0-9]{64}$'-and$seen.Add($row.file)) 'Closed source policy role differs'}
    $rows
}
function Assert-H3911MacHostedSource([string]$SourceRoot){
    $policy=@(& ${function:Get-HostedSourcePolicy})
    foreach($row in $policy){$file=& ${function:Get-HostedRegular} $SourceRoot $row.file;& ${function:Assert-Hosted} ($file.Length-eq$row.bytes-and(Microsoft.PowerShell.Utility\Get-FileHash $file.FullName).Hash-ceq$row.sha256) 'All runtime/control source byte pins required'}
    $names=@($policy.file)+@('hosted-payload-sha256.json');$actual=@(Get-ChildItem -LiteralPath $SourceRoot -Recurse -File -Force)
    & ${function:Assert-Hosted} ($actual.Count-eq$names.Count) 'Unadmitted source role/count'
    foreach($file in $actual){$name=[IO.Path]::GetRelativePath($SourceRoot,$file.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47);& ${function:Assert-Hosted} ($name-cin$names) 'Unadmitted source role'}
    $pins=Join-Path $SourceRoot 'runtime-pins.json'
    & ${function:Assert-Hosted} ((Microsoft.PowerShell.Utility\Get-FileHash $pins).Hash-ceq'B7C9BDEC09EF61E176DD858A28C866BBAC14FC8890A01D62C84892FA0C8B9615') 'Closed hosted runtime manifest differs'
    $rows=Get-Content $pins -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    & ${function:Assert-Hosted} ($rows.Count-eq26) 'Exact required runtime/source-identity closure required'
    foreach($row in $rows){
        & ${function:Assert-Hosted} ($row.file-is[string]-and$row.file-notmatch'[/\\:]|^\.') 'Unsafe runtime source role'
        $file=Get-Item -LiteralPath (Join-Path (Join-Path $SourceRoot 'runtime') $row.file) -Force
        & ${function:Assert-Hosted} ($file-is[IO.FileInfo]-and-not$file.LinkType-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$file.Length-eq$row.bytes-and(Microsoft.PowerShell.Utility\Get-FileHash $file.FullName).Hash-ceq$row.sha256) 'Actual runtime source byte pin differs'
    }
    & ${function:Assert-Hosted} ((Microsoft.PowerShell.Utility\Get-FileHash (Join-Path $SourceRoot '.gitattributes')).Hash-ceq'8B9C3028D6467FF3BE7C793141927841D70F47F52D0590677438F488CA154992') 'Actual byte-preserving attributes differ'
    @{status='CLOSED_SOURCE_BYTES_MATCH';rows=26;runtimeQualified=$false}
}
function Invoke-H3911MacHostedFixture {
    param([Parameter(Mandatory)][switch]$FixtureOnly,[hashtable]$Context,[string]$ReviewedSha,[string]$Workspace)
    & ${function:Assert-Hosted} ([bool]$FixtureOnly) 'Explicit FixtureOnly required; no runtime callbacks'
    $guard=& ${function:Assert-H3911MacHostedGuard} $Context $ReviewedSha
    $contract=& ${function:Get-H3911MacHostedContract} $Workspace
    @{mode='FIXTURE_ONLY_NOT_PROVISIONING';guard=$guard;contract=$contract;nativeCalls=0;executionAuthorityGranted=$false}
}
function Get-H3911MacRetentionRole([ValidateSet('Run','Setup')][string]$Area,[string]$Relative,[ValidateSet('Qualify','PackageScreen',IgnoreCase=$false)][string]$Mode='Qualify'){
    & ${function:Assert-Hosted} ($Relative-and$Relative-notmatch'(^[/\\]|\\|:|(^|/)\.\.?(/|$)|//)') 'Unsafe retention relative path'
    if($Relative-match'(?i)(^|/)(\.git|\.m2|registry|home|sdk|archives|rawenv|authentries)(/|$)|(^|/)(registry\.bin|settings\.xml|\.env|rawenv[^/]*|credentials[^/]*|auth[^/]*)(/|$)|\.(zip|tar|gz|pdb|dmp)$'){return $null}
    if($Relative-match'(?i)\.jar$'-and$Relative-cnotmatch'^qualification/output/(baseline-verify|candidate-verify)/application\.jar$'){return $null}
    if($Area-ceq'Setup'){
        if($Relative-cmatch'^(host|payload-checkout|jdk-archive|mvnd-archive|source-admission|setup-failure)\.json$'-or$Relative-ceq'clone.log'){return 'setup'}
        return $null
    }
    if($Relative-cmatch'^(scope|supervisor)\.json$|^(Main|Cleanup)\.(request\.json|result\.json|stdout|stderr)$'){return 'supervisor'}
    if($Relative-ceq'qualification/mac-qualifier.json'){return 'qualification'}
    if($Mode-ceq'PackageScreen'-and$Relative-ceq'qualification/output/mac-package-screen/operator.json'){return 'package-metadata'}
    if($Mode-ceq'PackageScreen'-and$Relative-cmatch'^qualification/output/mac-package-screen/(warmup-[12]-[AB]|sample-[3-8]-[AB])(?:-clean)?\.log(?:\.stderr|\.process\.json)?$'){return 'package-clock'}
    if($Mode-ceq'PackageScreen'-and$Relative-cmatch'^qualification/output/mac-package-screen/(warmup-[12]-[AB]|sample-[3-8]-[AB])/(application\.jar|artifact\.json|0[1-5]\.raw|(?:classes|test-classes)/.+)$'){return 'offline-capture'}
    if($Relative-cmatch'^qualification/output/(baseline-project|daemon-arch|daemon-home|daemon-project|baseline-maven-home)\.value$'){return 'context'}
    if($Relative-cmatch'^qualification/output/(baseline-project|daemon-arch|daemon-home|daemon-project|baseline-maven-home|baseline-verify|candidate-verify|normal-stop|emergency-stop)\.log(\.stderr|\.process\.json|\.failure\.json|\.namespace\.lock|\.observer-cleanup\.json)?$'){return 'client-log'}
    if($Relative-cmatch'^(qualification/output|native-cleanup)/effective-owner-[a-f0-9]{32}/VM\.(system_properties|dynlibs)\.log(\.stderr|\.process\.json)?$'){return 'owner-probe'}
    if($Relative-cmatch'^qualification/output/(baseline-verify|candidate-verify)/(application\.jar|artifact\.json|0[1-6]\.raw|jacoco\.exec)$'){return 'full-online-artifact'}
    if($Relative-cmatch'^qualification/output/(baseline-verify|candidate-verify)/(classes|test-classes|surefire|jacoco)/[^.][^\x00-\x1f]*$'){return 'capture-requires-binding'}
    return $null
}
function Add-HostedReportByteBindings([string]$SourceRoot,[string]$CaptureRoot,[string]$Phase,$PhaseRecord,$Allowed){
    $w=$PhaseRecord.reportBytes
    & ${function:Assert-Hosted} ($w-is[Collections.IDictionary]-and$w.schema-is[string]-and$w.schema-ceq'H3911.report-bytes.v1'-and$w.phase-is[string]-and$w.phase-ceq$Phase-and$w.rows-is[array]-and$w.rows.Count-gt0-and$w.rows.Count-le2000) 'Producer report-byte witness required'
    $mq=Import-Module (Join-Path $SourceRoot 'runtime/H3911.MacQualifier.psm1') -Scope Local -PassThru -DisableNameChecking
    $roleCommand=& $mq {Microsoft.PowerShell.Core\Get-Command Get-MQReportRole -CommandType Function}
    & ${function:Assert-Hosted} ($roleCommand-is[Management.Automation.FunctionInfo]-and$roleCommand.Module.Path-ceq(Join-Path $SourceRoot 'runtime/H3911.MacQualifier.psm1')-and$roleCommand.Name-ceq'Get-MQReportRole') 'Report role command origin differs'
    $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($row in $w.rows){
        & ${function:Assert-Hosted} ($row.name-is[string]-and$row.type-is[string]-and$row.type-ceq'file'-and$row.role-is[string]-and($row.bytes-is[int]-or$row.bytes-is[long])-and$row.bytes-ge0-and$row.bytes-le16777216-and$row.sha256-is[string]-and$row.sha256-cmatch'^[A-F0-9]{64}$'-and$names.Add($row.name)) 'Malformed/duplicate report witness row'
        $role=& $roleCommand $row.name
        & ${function:Assert-Hosted} ($role-and[string]::Equals($role,$row.role,[StringComparison]::Ordinal)) 'Report witness scope/role differs'
        $file=& ${function:Get-HostedRegular} $CaptureRoot $row.name
        & ${function:Assert-Hosted} ($file.Length-eq$row.bytes-and(Microsoft.PowerShell.Utility\Get-FileHash $file.FullName).Hash-ceq$row.sha256) 'Producer report bytes changed'
        $Allowed.Add($row.name,$row.sha256)
    }
    $actual=@()
    foreach($name in 'surefire','jacoco'){
        $directory=Get-Item -LiteralPath (Join-Path $CaptureRoot $name) -Force
        & ${function:Assert-Hosted} ($directory-is[IO.DirectoryInfo]-and-not$directory.LinkType-and-not($directory.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Ordinary report root required'
        foreach($file in @(Get-ChildItem -LiteralPath $directory.FullName -Recurse -Force)){
            & ${function:Assert-Hosted} (-not$file.LinkType-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked report member forbidden'
            if($file-is[IO.FileInfo]){$relative=[IO.Path]::GetRelativePath($CaptureRoot,$file.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47);$null=& ${function:Get-HostedRegular} $CaptureRoot $relative;$actual+=,$relative;& ${function:Assert-Hosted} ($names.Contains($relative)) 'Unwitnessed extra report member'}
        }
    }
    & ${function:Assert-Hosted} ($actual.Count-eq$names.Count) 'Missing report member'
}
function Copy-HostedBoundCaptureFile([string]$Root,[string]$Relative,[string]$Destination,[string]$ExpectedSha256){
    $file=& ${function:Get-HostedRegular} $Root $Relative
    & ${function:Assert-Hosted} ((Microsoft.PowerShell.Utility\Get-FileHash $file.FullName).Hash-ceq$ExpectedSha256) 'Bound digest changed immediately before copy'
    New-Item (Split-Path $Destination) -ItemType Directory -Force|Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $Destination
    & ${function:Assert-Hosted} ((Microsoft.PowerShell.Utility\Get-FileHash $Destination).Hash-ceq$ExpectedSha256) 'Copied capture differs from producer digest'
}
function Assert-HostedSuiteReport([string]$Root,[IO.FileInfo]$Report,$Artifact){
    $file=& ${function:Get-HostedRegular} $Root ('surefire/'+$Report.Name)
    & ${function:Assert-Hosted} ($file.FullName-ceq$Report.FullName-and$Report.Name.StartsWith('TEST-',[StringComparison]::Ordinal)-and$Report.Extension-ceq'.xml') 'Bound suite report file required'
    $suite=$Report.BaseName.Substring(5)
    $compiled=@($Artifact.loose|Where-Object {$_.scope-ceq'test-classes'-and$_.name-ceq($suite.Replace('.','/')+'.class')})
    & ${function:Assert-Hosted} ($compiled.Count-eq1) 'Unknown compiled suite identity'
    $class=& ${function:Get-HostedRegular} $Root ('test-classes/'+$compiled[0].name)
    & ${function:Assert-Hosted} ($class.Length-eq$compiled[0].bytes-and(Microsoft.PowerShell.Utility\Get-FileHash $class.FullName).Hash-ceq$compiled[0].sha256) 'Compiled suite byte binding differs'
    $xml=[xml](Get-Content $file.FullName -Raw)
    $node=$xml.SelectSingleNode('/testsuite')
    & ${function:Assert-Hosted} ($node-and$node.GetAttribute('name')-ceq$suite) 'Suite XML identity differs'
}
function Get-HostedCaptureBinding([string]$SourceRoot,[string]$RunRoot,[string]$Phase){
    $relative='qualification/output/'+$Phase;$dir=Join-Path $RunRoot $relative
    $members=@(Get-Item -LiteralPath $dir -Force)+@(Get-ChildItem -LiteralPath $dir -Recurse -Force)
    & ${function:Assert-Hosted} ($members.Count-le2000) 'Bounded capture file universe required'
    foreach($member in $members){$probe=$member;while($probe){& ${function:Assert-Hosted} (-not($probe.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not$probe.LinkType) 'Linked capture member/ancestry';$probe=if($probe-is[IO.FileInfo]){$probe.Directory}else{$probe.Parent}}}
    $files=@($members|Where-Object {$_-is[IO.FileInfo]})
    foreach($file in $files){$null=& ${function:Get-HostedRegular} $dir ([IO.Path]::GetRelativePath($dir,$file.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47))}
    $a=Import-Module (Join-Path $SourceRoot 'runtime/H3911.Artifacts.psm1') -Scope Local -PassThru -DisableNameChecking
    $h=Import-Module (Join-Path $SourceRoot 'runtime/H3911.Helpers.psm1') -Scope Local -PassThru -DisableNameChecking
    $null=& ($a.ExportedCommands['Compare-H3911Artifacts']) $dir $dir -SourceProfile MacOriginalWrapper
    $artifact=Get-Content (Join-Path $dir 'artifact.json') -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    $recordFile=& ${function:Get-HostedRegular} $RunRoot 'qualification/mac-qualifier.json'
    $record=Get-Content $recordFile.FullName -Raw|ConvertFrom-Json -AsHashtable -DateKind String;$phaseRecord=$record[$Phase]
    & ${function:Assert-Hosted} ((& ($a.ExportedCommands['ConvertTo-H3911ArtifactJson']) $phaseRecord.artifact)-ceq(& ($a.ExportedCommands['ConvertTo-H3911ArtifactJson']) $artifact)) 'Captured artifact differs from qualification record'
    $allowed=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $allowed.Add('application.jar',$artifact.jarSha256);$allowed.Add('artifact.json',(Microsoft.PowerShell.Utility\Get-FileHash (Join-Path $dir 'artifact.json')).Hash)
    foreach($row in $artifact.raw){$allowed.Add($row.file,$row.sha256)}
    foreach($row in $artifact.loose){$name=$row.scope+'/'+$row.name;& ${function:Assert-Hosted} ($name-notmatch'(?i)\.(jar|zip|gz|tar|exe|dll|dylib|jnilib)$') 'Undeclared executable/archive loose resource';$allowed.Add($name,$row.sha256)}
    $reports=@();$reportFiles=@(Get-ChildItem (Join-Path $dir 'surefire') -Filter 'TEST-*.xml' -File)
    foreach($file in $reportFiles){$reports+=,[xml](Get-Content $file.FullName -Raw)}
    $tests=& ($h.ExportedCommands['TestKeys']) $reports
    & ${function:Assert-Hosted} ($tests.Count-eq56-and@($tests|Where-Object state -eq passed).Count-eq54-and@($tests|Where-Object state -eq skipped).Count-eq2) 'Surefire membership/state binding differs'
    $testModuleFile=& ${function:Get-HostedRegular} $SourceRoot 'runtime/H3911.PackageSampling.psm1'
    & ${function:Assert-Hosted} ((Microsoft.PowerShell.Utility\Get-FileHash $testModuleFile.FullName).Hash-ceq'CA1E15176728C26C5ED009F53ADEECBF19E9D16B89913FC388A0631F9D96FC22') 'Pinned ordered test-fact dependency differs'
    $testModule=Import-Module $testModuleFile.FullName -Scope Local -PassThru -DisableNameChecking
    $testFacts=& $testModule {Microsoft.PowerShell.Core\Get-Command Assert-PScreenTestFacts -CommandType Function}
    & ${function:Assert-Hosted} ($testFacts-is[Management.Automation.FunctionInfo]-and$testFacts.Name-ceq'Assert-PScreenTestFacts'-and$testFacts.Module.Path-ceq$testModuleFile.FullName-and$testFacts.ScriptBlock) 'Ordered test-fact command origin differs'
    $null=& $testFacts $tests $phaseRecord.tests
    foreach($file in $reportFiles){& ${function:Assert-HostedSuiteReport} $dir $file $artifact}
    $xml=[xml](Get-Content (Join-Path $dir 'jacoco/jacoco.xml') -Raw);$counters=& ($h.ExportedCommands['CoverageKeys']) $xml;$semantics=& ($h.ExportedCommands['CoverageSemantics']) $xml
    & ${function:Assert-Hosted} ($counters.Count-eq726-and$phaseRecord.counters-is[Collections.IDictionary]-and$phaseRecord.counters.Count-eq726-and$semantics-ceq$phaseRecord.semantics) 'Coverage report binding differs'
    $coverageFacts=& $testModule {Microsoft.PowerShell.Core\Get-Command Assert-PScreenCoverageFacts -CommandType Function}
    & ${function:Assert-Hosted} ($coverageFacts-is[Management.Automation.FunctionInfo]-and$coverageFacts.Name-ceq'Assert-PScreenCoverageFacts'-and$coverageFacts.Module.Path-ceq$testModuleFile.FullName-and$coverageFacts.ScriptBlock) 'Coverage-fact command origin differs'
    $null=& $coverageFacts $counters $phaseRecord.counters
    $exec=& ($h.ExportedCommands['JacocoExecEvidence']) ([IO.File]::ReadAllBytes((Join-Path $dir 'jacoco.exec'))) default
    & ${function:Assert-Hosted} ($phaseRecord.exec.sha256-is[string]-and$exec.sha256-ceq$phaseRecord.exec.sha256) 'Coverage exec byte binding differs'
    $allowed.Add('jacoco.exec',$exec.sha256)
    $null=& ${function:Add-HostedReportByteBindings} $SourceRoot $dir $Phase $phaseRecord $allowed
    return ,$allowed
}
function Get-HostedPackageBindings([string]$SourceRoot,[string]$RunRoot,[string]$Project){
    $r=Get-Content (& ${function:Get-HostedRegular} $RunRoot 'qualification/mac-qualifier.json').FullName -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    & ${function:Assert-Hosted} ($r.mode-is[string]-and$r.mode-ceq'PackageScreen'-and$r.contexts-is[hashtable]-and$r.contexts.Count-eq5-and$r.sampling-is[hashtable]) 'Explicit complete PackageScreen record required'
    $expected=(& ${function:Get-H3911MacHostedContract} ([IO.Path]::GetPathRoot($RunRoot)) PackageScreen).modeContract
    & ${function:Assert-HostedContract} $r.contract $expected
    & ${function:Assert-Hosted} ($Project-and$r.contexts['baseline-project'].value-ceq$Project-and$r.contexts['daemon-project'].value-ceq$Project) 'Caller project contexts differ'
    $owned=Join-Path $RunRoot 'qualification'
    $c=@{Output=(Join-Path $owned 'output');Project=$Project;Jdk=$r.contexts['daemon-home'].value;Home=(Join-Path $owned 'home');Registry=(Join-Path $owned 'registry');Temp=(Join-Path $owned 'temp');Cache=(Join-Path $owned 'cache');Settings=(Join-Path $owned 'settings.xml');ScreenOwner=$r.owner;ScreenNotBefore=$r.screenNotBefore;Calls=$r.calls;SourceProfile='MacOriginalWrapper';FixtureOnly=$false}
    $m=Import-Module (Join-Path $SourceRoot 'runtime/H3911.MacQualifier.psm1') -Scope Local -PassThru
    $commands=& $m {Get-MQSamplingCommands};$validate=& $m {Get-Command Assert-MQSamplingEvidence -CommandType Function}
    $null=& $validate $c $r.sampling ([bool]$r.sampling.fixtureOnly)
    $operatorFile=& ${function:Get-HostedRegular} $RunRoot 'qualification/output/mac-package-screen/operator.json'
    $operator=Get-Content $operatorFile.FullName -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    $null=& $validate $c $operator ([bool]$operator.fixtureOnly)
    foreach($kind in @(@{name='clientCalls';count=16},@{name='auxiliaryLedger';count=28})){
        for($i=0;$i-lt$kind.count;$i++){$a=$operator[$kind.name][$i];$b=$r.sampling[$kind.name][$i];$a=if($kind.name-ceq'clientCalls'){$a.processEvidence}else{$a};$b=if($kind.name-ceq'clientCalls'){$b.processEvidence}else{$b};foreach($part in 'receipt','stdout','stderr'){foreach($key in 'path','bytes','sha256'){& ${function:Assert-Hosted} ($a[$part][$key]-ceq$b[$part][$key]) 'Operator/caller seal differs'}}}
    }
    foreach($pair in @(@('baseline-verify','baseline'),@('candidate-verify','candidate'))){$null=& $commands['Assert-PScreenFullGate'] $c $commands $pair[0] $r[$pair[0]]}
    $allowed=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $allowed.Add('qualification/output/mac-package-screen/operator.json',(Get-FileHash $operatorFile.FullName).Hash)
    $steps=@((& $commands['Get-H3911RetainedProtocol'] -Mode PackageScreen -Platform MacOS).calls|Where-Object {$_.kind-in@('clean','package')})
    for($i=0;$i-lt16;$i++){
        $step=$steps[$i];$claim=$r.sampling.clientCalls[$i];$log=Join-Path $c.Output ('mac-package-screen/'+$step.label+'.log')
        $tokens=@('--batch-mode','--no-transfer-progress','-Dserver.address=127.0.0.1',"-Dmaven.repo.local=$($c.Cache)",'--settings',$c.Settings,'--global-settings',$c.Settings,'--file',(Join-Path $Project 'pom.xml'),'-o')
        if($step.route-ceq'B'){$tokens+=@('--serial',"-Djava.home=$($c.Jdk)","-Dmvnd.daemonStorage=$($c.Registry)")};$tokens+=if($step.kind-ceq'clean'){@('clean')}else{@('-DskipTests','package')}
        $exe=if($step.route-ceq'A'){Join-Path $Project 'mvnw'}else{Join-Path $c.Home 'bin/mvnd'}
        $seal=& $commands['Assert-MPackageClock'] $commands $log $exe $tokens $Project ([DateTimeOffset]$c.ScreenNotBefore)
        & ${function:Assert-Hosted} (($claim.processEvidence.pid-is[int]-or$claim.processEvidence.pid-is[long])-and$claim.processEvidence.pid-eq$seal.pid-and($claim.processEvidence.seconds-is[double]-or$claim.processEvidence.seconds-is[decimal]-or$claim.processEvidence.seconds-is[int]-or$claim.processEvidence.seconds-is[long])-and$claim.processEvidence.seconds-eq$seal.seconds) 'Package clock claim differs'
        foreach($key in 'createdUtc','exe','workingDirectory'){& ${function:Assert-Hosted} ($claim.processEvidence[$key]-is[string]-and$claim.processEvidence[$key]-ceq$seal[$key]) 'Package process identity differs'}
        foreach($part in 'receipt','stdout','stderr'){& ${function:Assert-Hosted} ($claim.processEvidence[$part]-is[hashtable]-and$claim.processEvidence[$part].path-is[string]-and$claim.processEvidence[$part].sha256-is[string]-and($claim.processEvidence[$part].bytes-is[int]-or$claim.processEvidence[$part].bytes-is[long])-and$claim.processEvidence[$part].path-ceq$seal[$part].path-and$claim.processEvidence[$part].sha256-ceq$seal[$part].sha256-and$claim.processEvidence[$part].bytes-eq$seal[$part].bytes) 'Package receipt seal differs';$relative=[IO.Path]::GetRelativePath($RunRoot,$seal[$part].path).Replace([IO.Path]::DirectorySeparatorChar,[char]47);$null=& ${function:Get-HostedRegular} $RunRoot $relative;$allowed.Add($relative,$seal[$part].sha256)}
    }
    $reopened=@()
    foreach($probe in $r.sampling.auxiliaryLedger){
        & ${function:Assert-Hosted} ($probe.probe-is[string]-and$probe.probe-cin@('VM.system_properties','VM.dynlibs')-and($probe.targetPid-is[int]-or$probe.targetPid-is[long])-and$probe.targetPid-eq$r.owner.pid) 'Closed probe target differs'
        $relative=[IO.Path]::GetRelativePath($RunRoot,$probe.stdout.path).Replace([IO.Path]::DirectorySeparatorChar,[char]47);& ${function:Assert-Hosted} ($relative-cmatch'^qualification/output/effective-owner-[a-f0-9]{32}/VM\.(system_properties|dynlibs)\.log$') 'Probe outside exact owned namespace';$null=& ${function:Get-HostedRegular} $RunRoot $relative
        $seal=& $commands['Assert-MPackageClock'] $commands $probe.stdout.path (Join-Path $c.Jdk 'bin/jcmd') @([string]$r.owner.pid,$probe.probe) $c.Temp ([DateTimeOffset]$c.ScreenNotBefore)
        & ${function:Assert-Hosted} (($probe.pid-is[int]-or$probe.pid-is[long])-and$probe.pid-eq$seal.pid-and$probe.createdUtc-is[string]-and$probe.createdUtc-cmatch'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$'-and[DateTimeOffset]::Parse($probe.createdUtc,[Globalization.CultureInfo]::InvariantCulture).UtcTicks-eq[DateTimeOffset]::Parse($seal.createdUtc,[Globalization.CultureInfo]::InvariantCulture).UtcTicks) 'Reopened probe identity differs'
        foreach($part in 'receipt','stdout','stderr'){& ${function:Assert-Hosted} ($probe[$part]-is[hashtable]-and$probe[$part].path-is[string]-and($probe[$part].bytes-is[int]-or$probe[$part].bytes-is[long])-and$probe[$part].sha256-is[string]-and$probe[$part].path-ceq$seal[$part].path-and$probe[$part].bytes-eq$seal[$part].bytes-and$probe[$part].sha256-ceq$seal[$part].sha256) 'Reopened probe bytes differ';$relative=[IO.Path]::GetRelativePath($RunRoot,$seal[$part].path).Replace([IO.Path]::DirectorySeparatorChar,[char]47);$null=& ${function:Get-HostedRegular} $RunRoot $relative;if(-not$allowed.ContainsKey($relative)){$allowed.Add($relative,$seal[$part].sha256)}}
        $reopened+=,$seal
    }
    $cleanupRoot=Join-Path $RunRoot 'native-cleanup'
    $parentLogs=if(Test-Path $cleanupRoot){@(Get-ChildItem $cleanupRoot -Recurse -Filter 'VM.*.log' -File)}else{@()}
    & ${function:Assert-Hosted} ($parentLogs.Count-le2) 'Parent auxiliary maximum exceeded'
    foreach($log in $parentLogs){
        & ${function:Assert-Hosted} ($log.BaseName-cin@('VM.system_properties','VM.dynlibs')) 'Unknown parent probe'
        $relative=[IO.Path]::GetRelativePath($RunRoot,$log.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47);& ${function:Assert-Hosted} ($relative-cmatch'^native-cleanup/effective-owner-[a-f0-9]{32}/VM\.(system_properties|dynlibs)\.log$') 'Parent probe namespace differs';$null=& ${function:Get-HostedRegular} $RunRoot $relative
        $seal=& $commands['Assert-MPackageClock'] $commands $log.FullName (Join-Path $c.Jdk 'bin/jcmd') @([string]$r.owner.pid,$log.BaseName) $c.Temp ([DateTimeOffset]$c.ScreenNotBefore)
        foreach($part in 'receipt','stdout','stderr'){$relative=[IO.Path]::GetRelativePath($RunRoot,$seal[$part].path).Replace([IO.Path]::DirectorySeparatorChar,[char]47);$null=& ${function:Get-HostedRegular} $RunRoot $relative;$allowed.Add($relative,$seal[$part].sha256)}
        $reopened+=,$seal
    }
    $null=& $commands['Assert-MPackageProbeLedger'] $reopened
    $onlineDir=Join-Path $c.Output 'baseline-verify';$online=& $commands['Read-H3911Artifact'] (Join-Path $onlineDir 'application.jar') (Join-Path $onlineDir 'classes') (Join-Path $onlineDir 'test-classes') -SourceProfile MacOriginalWrapper
    $reference=$null
    foreach($capture in $r.sampling.offlineCaptures){
        $dir=Join-Path $c.Output ('mac-package-screen/'+$capture.label)
        $null=& $commands['Compare-H3911Artifacts'] $dir $dir -SourceProfile MacOriginalWrapper -Offline
        $actual=& $commands['Read-H3911Artifact'] (Join-Path $dir 'application.jar') (Join-Path $dir 'classes') (Join-Path $dir 'test-classes') -SourceProfile MacOriginalWrapper -Offline
        $null=& $commands['Assert-H3911OfflineDelta'] $online $onlineDir $actual $dir
        if($reference){$null=& $commands['Compare-H3911Artifacts'] $reference $dir -SourceProfile MacOriginalWrapper -Offline}else{$reference=$dir}
        & ${function:Assert-Hosted} ($actual.jarSha256-ceq$capture.jarSha256) 'Offline return/JAR differs'
        $members=@{'application.jar'=$actual.jarSha256;'artifact.json'=(Get-FileHash (Join-Path $dir 'artifact.json')).Hash}
        foreach($row in $actual.raw){$members.Add($row.file,$row.sha256)}
        foreach($row in $actual.loose){$name=$row.scope+'/'+$row.name;& ${function:Assert-Hosted} ($name-notmatch'(?i)\.(jar|zip|gz|tar|exe|dll|dylib|jnilib)$') 'SDK/archive loose member forbidden';$members.Add($name,$row.sha256)}
        $files=@(Get-ChildItem $dir -Recurse -Force)
        foreach($file in $files){& ${function:Assert-Hosted} (-not$file.LinkType-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked offline member';if($file-is[IO.FileInfo]){$name=[IO.Path]::GetRelativePath($dir,$file.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47);& ${function:Assert-Hosted} ($members.ContainsKey($name)) 'Extra offline member'}}
        & ${function:Assert-Hosted} (@($files|Where-Object{$_-is[IO.FileInfo]}).Count-eq$members.Count) 'Missing offline member'
        foreach($name in $members.Keys){$relative='qualification/output/mac-package-screen/'+$capture.label+'/'+$name;$f=& ${function:Get-HostedRegular} $RunRoot $relative;& ${function:Assert-Hosted} ((Get-FileHash $f.FullName).Hash-ceq$members[$name]) 'Offline physical digest differs';$allowed.Add($relative,$members[$name])}
    }
    $parentFiles=if(Test-Path $cleanupRoot){@(Get-ChildItem $cleanupRoot -Directory -Filter 'effective-owner-*'|Get-ChildItem -Recurse -File)}else{@()}
    foreach($file in @(Get-ChildItem (Join-Path $c.Output 'mac-package-screen') -Recurse -Force -File)+@(Get-ChildItem $c.Output -Directory -Filter 'effective-owner-*'|Get-ChildItem -Recurse -File)+$parentFiles){
        $relative=[IO.Path]::GetRelativePath($RunRoot,$file.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47)
        & ${function:Assert-Hosted} ($allowed.ContainsKey($relative)) 'Extra package/probe member'
    }
    return ,$allowed
}
function Copy-H3911MacHostedRetention([string]$SourceRoot,[string]$RunRoot,[string]$SetupRoot,[string]$Destination,[string]$Project,[ValidateSet('Qualify','PackageScreen',IgnoreCase=$false)][string]$Mode='Qualify'){
    foreach($path in $SourceRoot,$RunRoot,$SetupRoot,$Destination){& ${function:Assert-Hosted} ([IO.Path]::IsPathFullyQualified($path)) 'Absolute native retention root required'}
    $comparison=if($IsWindows){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
    foreach($root in @($SourceRoot,$RunRoot,$SetupRoot,$Project)|Where-Object{$_}){
        $a=[IO.Path]::GetFullPath($root).TrimEnd([char[]]'\/');$b=[IO.Path]::GetFullPath($Destination).TrimEnd([char[]]'\/')
        & ${function:Assert-Hosted} (-not([string]::Equals($a,$b,$comparison)-or$a.StartsWith($b+[IO.Path]::DirectorySeparatorChar,$comparison)-or$b.StartsWith($a+[IO.Path]::DirectorySeparatorChar,$comparison))) 'Retention root must be disjoint'
    }
    & ${function:Assert-Hosted} (-not(Test-Path -LiteralPath $Destination)) 'Fresh retention root required'
    New-Item $Destination -ItemType Directory -ErrorAction Stop|Out-Null
    $diagnostics=@();$policy=@();$sourceAdmitted=$true
    try{
        $policy=@(& ${function:Get-HostedSourcePolicy})
        foreach($row in $policy){
            $actual=$null;$reason=$null
            try{$file=& ${function:Get-HostedRegular} $SourceRoot $row.file;if($file.Length-gt1048576){$reason='SOURCE_SIZE_BOUND_NO_BYTES_READ'}else{$actual=(Microsoft.PowerShell.Utility\Get-FileHash $file.FullName).Hash;if($actual-cne$row.sha256-or$file.Length-ne$row.bytes){$reason='SOURCE_CHECKSUM_MISMATCH'}}}
            catch{$reason='SOURCE_MISSING_LINKED_OR_UNREADABLE'}
            $diagnostics+=@{role='source';file=$row.file;expectedSha256=$row.sha256;actualSha256=$actual;admitted=(-not$reason);reason=$reason}
            if($reason){$sourceAdmitted=$false}
        }
        $null=& ${function:Assert-H3911MacHostedSource} $SourceRoot
    }catch{$sourceAdmitted=$false;$diagnostics+=@{role='source';reason='EXECUTION_SOURCE_ADMISSION_FAILED';errorKind=$_.FullyQualifiedErrorId}}
    if(-not$sourceAdmitted){
        @{status='FAILED_SOURCE_ADMISSION';executionAdmission='FAIL';files=@();diagnostics=$diagnostics;runtimeQualified=$false;untrustedBytesCopied=$false}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Destination 'retention.json')
        return @{status='FAILED_SOURCE_ADMISSION';files=0;runtimeQualified=$false}
    }
    $rows=@();$candidates=@();$bindings=@();$packageBindings=$null;$packageFailed=$false
    $bindings=@{}
    foreach($phase in 'baseline-verify','candidate-verify'){
        if(Test-Path (Join-Path $RunRoot ('qualification/output/'+$phase))){
            try{$bindings[$phase]=& ${function:Get-HostedCaptureBinding} $SourceRoot $RunRoot $phase}
            catch{$diagnostics+=@{role='capture';phase=$phase;reason='CAPTURE_CONTRACT_UNBOUND';errorKind=$_.FullyQualifiedErrorId}}
        }
    }
        if($Mode-ceq'PackageScreen'){
            try{& ${function:Assert-Hosted} ($bindings.Count-eq2) 'Both complete online captures required';$packageBindings=& ${function:Get-HostedPackageBindings} $SourceRoot $RunRoot $Project}
            catch{$packageFailed=$true;$diagnostics+=@{role='package';reason='PACKAGE_BINDING_FAILED_METADATA_ONLY';errorKind=$_.FullyQualifiedErrorId}}
        }else{
            try{if(Test-Path (Join-Path $RunRoot 'qualification/mac-qualifier.json')){$r=Get-Content (Join-Path $RunRoot 'qualification/mac-qualifier.json') -Raw|ConvertFrom-Json -AsHashtable -DateKind String;if($r.mode-and$r.mode-cne'Qualify'){$packageFailed=$true;$diagnostics+=@{role='mode';reason='MODE_RECORD_MISMATCH_METADATA_ONLY'}}}}catch{$packageFailed=$true;$diagnostics+=@{role='mode';reason='MODE_RECORD_UNREADABLE_METADATA_ONLY'}}
        }
    if(Test-Path $RunRoot){
        $candidates+=@(Get-ChildItem -LiteralPath $RunRoot -File -Force|ForEach-Object{@{area='Run';root=$RunRoot;file=$_}})
        foreach($relative in 'qualification/output','native-cleanup'){
            $folder=Join-Path $RunRoot $relative
            if(Test-Path $folder){$candidates+=@(Get-ChildItem -LiteralPath $folder -Recurse -File -Force|ForEach-Object{@{area='Run';root=$RunRoot;file=$_}})}
        }
        $q=Join-Path $RunRoot 'qualification/mac-qualifier.json';if(Test-Path $q){$candidates+=@{area='Run';root=$RunRoot;file=(Get-Item $q)}}
    }
    if(Test-Path $SetupRoot){$candidates+=@(Get-ChildItem -LiteralPath $SetupRoot -File -Force|ForEach-Object{@{area='Setup';root=$SetupRoot;file=$_}})}
    foreach($candidate in $candidates){
        $file=$candidate.file;$relative=[IO.Path]::GetRelativePath($candidate.root,$file.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47)
        $role=& ${function:Get-H3911MacRetentionRole} $candidate.area $relative $Mode
        if($packageFailed-and$candidate.area-ceq'Run'-and$relative-cnotmatch'^(scope|supervisor)\.json$|^(Main|Cleanup)\.(request|result)\.json$|^qualification/mac-qualifier\.json$'){continue}
        $packageFile=$Mode-ceq'PackageScreen'-and($relative.StartsWith('qualification/output/mac-package-screen/',[StringComparison]::Ordinal)-or$relative-cmatch'^(qualification/output|native-cleanup)/effective-owner-[a-f0-9]{32}/')
        if($packageFile){
            if($packageFailed-or-not$packageBindings.ContainsKey($relative)){$diagnostics+=@{role='package';file=$relative;reason='UNBOUND_PACKAGE_MEMBER_NOT_RETAINED'};continue}
            $file=& ${function:Get-HostedRegular} $candidate.root $relative
            $to=Join-Path (Join-Path $Destination $candidate.area) $relative
            $null=& ${function:Copy-HostedBoundCaptureFile} $candidate.root $relative $to $packageBindings[$relative]
            $rows+=@{role=$role;file=($candidate.area+'/'+$relative);bytes=$file.Length;sha256=$packageBindings[$relative]};continue
        }
        $capture=[regex]::Match($relative,'^qualification/output/(baseline-verify|candidate-verify)/(.+)$')
        if($capture.Success){
            $phase=$capture.Groups[1].Value;$member=$capture.Groups[2].Value;$binding=$bindings[$phase]
            if(-not$role-or-not$binding-or-not$binding.ContainsKey($member)){
                $hash=$null;try{$safe=& ${function:Get-HostedRegular} $RunRoot $relative;if($safe.Length-le1048576-and$relative-notmatch'(?i)registry|auth|credentials|rawenv'){$hash=(Microsoft.PowerShell.Utility\Get-FileHash $safe.FullName).Hash}}catch{}
                $diagnostics+=@{role='capture';file=$relative;reason='UNBOUND_MEMBER_BYTES_NOT_RETAINED';actualSha256=$hash};continue
            }
        }
        if(-not$role){continue}
        try{$file=& ${function:Get-HostedRegular} $candidate.root $relative}
        catch{$diagnostics+=@{role=$role;file=$relative;reason='LINKED_OR_UNREADABLE_BYTES_NOT_RETAINED'};continue}
        if($capture.Success-and(Microsoft.PowerShell.Utility\Get-FileHash $file.FullName).Hash-cne$binding[$member]){$diagnostics+=@{role=$role;file=$relative;reason='BOUND_DIGEST_CHANGED'};continue}
        $to=Join-Path (Join-Path $Destination $candidate.area) $relative
        if($capture.Success){$null=& ${function:Copy-HostedBoundCaptureFile} $candidate.root $relative $to $binding[$member]}
        else{New-Item (Split-Path $to) -ItemType Directory -Force|Out-Null;Copy-Item -LiteralPath $file.FullName -Destination $to}
        $hash=(Microsoft.PowerShell.Utility\Get-FileHash $to).Hash;& ${function:Assert-Hosted} ($hash-ceq(Microsoft.PowerShell.Utility\Get-FileHash $file.FullName).Hash) 'Retained byte binding differs'
        $rows+=@{role=$role;file=($candidate.area+'/'+$relative);bytes=$file.Length;sha256=$hash}
    }
    $source=Join-Path $Destination 'source';New-Item $source -ItemType Directory|Out-Null
    foreach($entry in $policy|Where-Object {$_.file-cne'.gitattributes'}){
        $name=$entry.file;$file=& ${function:Get-HostedRegular} $SourceRoot $name;$from=$file.FullName;$to=Join-Path $source $name
        & ${function:Assert-Hosted} ((Microsoft.PowerShell.Utility\Get-FileHash $from).Hash-ceq$entry.sha256) 'Admitted control source changed before copy'
        New-Item (Split-Path $to) -ItemType Directory -Force|Out-Null;Copy-Item -LiteralPath $from -Destination $to
        $hash=(Microsoft.PowerShell.Utility\Get-FileHash $to).Hash;& ${function:Assert-Hosted} ($hash-ceq(Microsoft.PowerShell.Utility\Get-FileHash $from).Hash) 'Actual source copy differs'
        $rows+=@{role='actual-source';file=('source/'+$name);bytes=(Get-Item $from).Length;sha256=$hash}
    }
    if($Project-and(Test-Path $Project)){
        & ${function:Assert-Hosted} ([IO.Path]::IsPathFullyQualified($Project)) 'Absolute application source required'
        $app=Join-Path $Destination 'application-source';New-Item $app -ItemType Directory|Out-Null;$appRows=@()
        foreach($pair in @(@('pom.xml','pom.xml'),@('mvnw','mvnw.actual.txt'),@('mvnw.cmd','mvnw.cmd.actual.txt'),@('.mvn/jvm.config','jvm.config.actual.txt'),@('.mvn/wrapper/maven-wrapper.properties','maven-wrapper.properties.actual.txt'),@('.gitattributes','gitattributes.actual.txt'))){
            $from=Join-Path $Project $pair[0];if(-not(Test-Path -LiteralPath $from)){continue}
            try{$file=& ${function:Get-HostedRegular} $Project $pair[0]}
            catch{$diagnostics+=@{role='application-source';file=$pair[0];reason='LINKED_OR_UNREADABLE_BYTES_NOT_RETAINED'};continue}
            $expected=@{'pom.xml'='A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D';'mvnw'='4B9C75F9D4829F2368319B767B119D4CB17F84974A149CE703B28FB637241791';'mvnw.cmd'='5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A';'.mvn/jvm.config'='0E8B638C4F6EB6B951AB213FB1AF5BED05FBCAF80FFEB3ABA3B39EAE12235E3D';'.mvn/wrapper/maven-wrapper.properties'='8F2A4438810348270D9D98F8D6D530541DDB7271E373DB207E8AC381E0E35B62';'.gitattributes'='BF25544E3FCCF82FE3CF2CAFBD744FF2302619C24001FDF566BA813392618EE8'}
            $observed=(Microsoft.PowerShell.Utility\Get-FileHash $from).Hash
            if($observed-cne$expected[$pair[0]]){$diagnostics+=@{role='application-source';file=$pair[0];reason='UNBOUND_APPLICATION_CONTROL';expectedSha256=$expected[$pair[0]];actualSha256=$observed};continue}
            $to=Join-Path $app $pair[1];Copy-Item -LiteralPath $from -Destination $to;$hash=(Microsoft.PowerShell.Utility\Get-FileHash $from).Hash
            & ${function:Assert-Hosted} ($hash-ceq(Microsoft.PowerShell.Utility\Get-FileHash $to).Hash) 'Application source copy differs'
            $appRows+=@{logical=$pair[0];retained=$pair[1];bytes=$file.Length;sha256=$hash;copyBound=$true}
        }
        $appRows|ConvertTo-Json|Set-Content (Join-Path $app 'actual-source-receipts.json')
    }
    $attribute=(& ${function:Get-HostedRegular} $SourceRoot '.gitattributes').FullName;$visible=Join-Path $source 'payload-attributes.actual.txt';Copy-Item -LiteralPath $attribute -Destination $visible
    $h=(Microsoft.PowerShell.Utility\Get-FileHash $attribute).Hash;$copy=(Microsoft.PowerShell.Utility\Get-FileHash $visible).Hash
    & ${function:Assert-Hosted} ($h-ceq$copy) 'Actual/visible attributes differ'
    @{logicalName='.gitattributes';actualSha256=$h;retainedSha256=$copy;bytes=(Get-Item $visible).Length;copyBound=$true}|ConvertTo-Json|Set-Content (Join-Path $source 'payload-attributes.receipt.json')
    $status=if($diagnostics|Where-Object {$_.reason}){'FAILED_EVIDENCE_BINDING'}else{'ALLOWLIST_RETAINED_NOT_QUALIFICATION'}
    @{status=$status;executionAdmission='SOURCE_PINS_PASS_NOT_RUNTIME';files=$rows;diagnostics=$diagnostics;excluded='Unbound bytes/SDK/archive/registry/auth/home/.git/rawenv';runtimeQualified=$false}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Destination 'retention.json')
    @{status=$status;files=$rows.Count;runtimeQualified=$false}
}
Export-ModuleMember -Function Assert-H3911MacHostedGuard,Get-H3911MacHostedContract,Assert-H3911MacHostedSource,Invoke-H3911MacHostedFixture,Get-H3911MacRetentionRole,Copy-H3911MacHostedRetention
