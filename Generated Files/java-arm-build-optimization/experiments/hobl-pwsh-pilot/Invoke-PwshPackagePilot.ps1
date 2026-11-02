#requires -Version 7.5
[CmdletBinding()]
param([string]$Project,[string]$Cache,[string]$JavaHome,[string]$Output,
    [string]$CandidateWrapper,
    [ValidateSet('Prototype334','UpstreamF62f442','UpstreamF62f442HttpsLicense')][string]$CandidateRevision='Prototype334',
    [switch]$ExecuteAuthorized,[switch]$CandidateReviewed,[switch]$LibraryOnly)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
$pilotInputs=@{Project=$Project;Cache=$Cache;JavaHome=$JavaHome;Output=$Output;CandidateWrapper=$CandidateWrapper;CandidateRevision=$CandidateRevision;ExecuteAuthorized=[bool]$ExecuteAuthorized;CandidateReviewed=[bool]$CandidateReviewed;LibraryOnly=[bool]$LibraryOnly}
. "$PSScriptRoot\..\hobl-wrapper-diagnostic\Invoke-WrapperBoundary.ps1" -LibraryOnly
foreach($item in $pilotInputs.GetEnumerator()){Set-Variable -Name $item.Key -Value $item.Value}
function PilotCandidateRevision([ValidateSet('Prototype334','UpstreamF62f442','UpstreamF62f442HttpsLicense')][string]$Revision='Prototype334',[string]$Path){
    if($Revision-eq'Prototype334'){
        $spec=@{revision=$Revision;file='candidate-mvnw.cmd';expectedSha256='655A91268C8DE0B8B233492F49014F9F3975BCABE7B0B8B2DC5C22A8E26EAEBA';wrapperVersion='3.3.4';provenance='Previously qualified retained HOBL prototype; unchanged default'}
    }else{
        $spec=@{revision=$Revision;file='upstream-f62f442-mvnw.cmd';expectedSha256='84D9DA5A6FE003DCACAA0D269FBA1BB4780D1BC49F97D36B6CC71D852CAD4FE9';wrapperVersion='3.3.5-SNAPSHOT';sourceCommit='f62f4422387ff1e4aa90b03de698893f83ba79ae';sourceResource='maven-wrapper-distribution/src/resources/only-mvnw.cmd';sourceResourceSha256='6B5933A5DF6AA7853EDFA80E3B4E06F70382E6FDD76484ECF57720A449785441';patchSha256='4438759FE3D0ECD2670A226F495AB410AA1BDD639FC7B8ECB5F2C160AA5B7366';render='ONLY @@project.version@@ -> 3.3.5-SNAPSHOT'}
        if($Revision-eq'UpstreamF62f442HttpsLicense'){
            $spec.file='upstream-f62f442-https-license-mvnw.cmd'
            $spec.expectedSha256='AAA4957C5AB29267A0D89C03D33621740A4233BF25AFEB480797023687CABB7D'
            $spec.parentRenderedSha256='84D9DA5A6FE003DCACAA0D269FBA1BB4780D1BC49F97D36B6CC71D852CAD4FE9'
            $spec.httpsPolicyPatchSha256='876F9583F9103DB0C4EB58BB77DCE55511D679DD773B44BBB75D048D646C71B0'
            $spec.policyDelta='Exactly one inherited Apache license URL scheme changed to HTTPS; all other rendered bytes unchanged'
            $spec.render='Version-token-only parent84D9 render PLUS separately named one-line HTTPS license policy delta'
            $spec.notExactOriginalPort=$true
            $spec.localPolicyQualification='r3 unchanged offline validate: original HTTP1/specific NoHTTP11:10, HTTPS0/zero violations; not package/performance proof'
        }
    }
    $spec.path=if([string]::IsNullOrWhiteSpace($Path)){Join-Path $PSScriptRoot $spec.file}else{[IO.Path]::GetFullPath($Path)}
    return $spec
}
function AssertPilotCandidateFile($Spec){
    Require ((Get-FileHash -LiteralPath $Spec.path).Hash-eq$Spec.expectedSha256) "Candidate bytes do not match selected revision $($Spec.revision)"
}
function SetPwshPilotArm([ValidateSet('baseline','candidate')][string]$Arm){
    if($Arm-eq'baseline'){Remove-Item Env:MVNW_PREFER_PWSH -ErrorAction SilentlyContinue}
    else{[Environment]::SetEnvironmentVariable('MVNW_PREFER_PWSH','true','Process')}
    Require ($(if($Arm-eq'baseline'){-not(Test-Path Env:MVNW_PREFER_PWSH)}else{$env:MVNW_PREFER_PWSH-ceq'true'})) 'Selector not in required state'
}
function PilotPayload($Artifact){
    $map=[Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach($entry in $Artifact.entries){
        if($entry.name-notin@('META-INF/MANIFEST.MF','BOOT-INF/classes/git.properties','META-INF/build-info.properties','META-INF/sbom/application.cdx.json')){$map.Add($entry.name,$entry.sha)}
    }
    return ,$map
}
function PilotProperties([string]$Label,[string]$EntryName){
    $zip=[IO.Compression.ZipFile]::OpenRead("$Output\$Label.jar")
    try{$bytes=StreamBytes $zip.GetEntry($EntryName)}finally{$zip.Dispose()}
    $map=@{};foreach($line in ([Text.Encoding]::UTF8.GetString($bytes)-split'\r?\n')){
        if(-not$line-or$line.StartsWith('#')){continue}
        $pair=$line.Split('=',2);Require ($pair.Count-eq2-and-not$map.ContainsKey($pair[0])) 'Unsupported/duplicate metadata property'
        $map[$pair[0]]=$pair[1]
    };return $map
}
function CanonicalPilotJson($Value){
    if($Value-is[Collections.IDictionary]){
        $map=[ordered]@{};[string[]]$keys=@($Value.Keys);[Array]::Sort($keys,[StringComparer]::Ordinal)
        foreach($key in $keys){$map[$key]=CanonicalPilotJson $Value[$key]};return $map
    }
    if($Value-is[Collections.IList]){
        $items=[Collections.Generic.List[object]]::new()
        foreach($item in $Value){$items.Add((CanonicalPilotJson $item))};return ,$items.ToArray()
    }
    return $Value
}
function PilotBom([string]$Label,[bool]$Online){
    $zip=[IO.Compression.ZipFile]::OpenRead("$Output\$Label.jar")
    try{
        $entry=$zip.GetEntry('META-INF/sbom/application.cdx.json')
        Require ([bool]$entry-eq$Online) 'Actual SBOM presence differs from declared online/offline mode'
        if(-not$Online){return $null}
        $bom=[Text.Encoding]::UTF8.GetString((StreamBytes $entry))|ConvertFrom-Json -AsHashtable -Depth 100 -DateKind String
    }finally{$zip.Dispose()}
    Require ($bom-is[Collections.IDictionary]-and$bom.components.Count-eq108-and$bom.dependencies.Count-eq109) 'Pinned online SBOM universe differs'
    $ignored=@{}
    if(@($bom.Keys)-ccontains'serialNumber'){$ignored.serialNumber=@{present=$true;value=$bom['serialNumber']};$null=$bom.Remove('serialNumber')}else{$ignored.serialNumber=@{present=$false}}
    if(@($bom.Keys)-ccontains'metadata'){
        Require ($bom['metadata']-is[Collections.IDictionary]) 'Required SBOM metadata must be an object'
        if(@($bom['metadata'].Keys)-ccontains'timestamp'){$ignored['metadata.timestamp']=@{present=$true;value=$bom['metadata']['timestamp']};$null=$bom['metadata'].Remove('timestamp')}
    }
    if(-not$ignored.ContainsKey('metadata.timestamp')){$ignored['metadata.timestamp']=@{present=$false}}
    return @{content=(CanonicalPilotJson $bom);ignored=$ignored}
}
function ComparePilotBom($Actual,$Expected,[string]$ActualLabel,[string]$ExpectedLabel){
    Require ($Actual.online-is[bool]-and$Expected.online-is[bool]-and($Actual.online-or$Expected.online)) 'SBOM comparison requires an explicit online anchor'
    $a=PilotBom $ActualLabel $Actual.online;$b=PilotBom $ExpectedLabel $Expected.online
    if($Actual.online-and$Expected.online){
        Require ((ConvertTo-Json -InputObject $a.content -Depth 100 -Compress)-ceq(ConvertTo-Json -InputObject $b.content -Depth 100 -Compress)) 'Meaningful online SBOM content/dependency graph differs'
        return @(foreach($path in 'serialNumber','metadata.timestamp'){
            if((Json $a.ignored[$path])-cne(Json $b.ignored[$path])){@{entry='META-INF/sbom/application.cdx.json';path=$path;actual=$a.ignored[$path];reference=$b.ignored[$path];classification='explicit nonsemantic SBOM metadata; raw bytes retained'}}
        })
    }
    $offline=if($Actual.online){$Expected}else{$Actual}
    Require ($offline.offlineSbomSkipObserved-eq$true) 'Offline SBOM omission lacks logged requires-online skip'
    return ,@{entry='META-INF/sbom/application.cdx.json';classification='intentional online/offline omission with logged requires-online skip; not online content equivalence'}
}
function PilotManifest([string]$Label,$Artifact){
    Require ($Artifact.online-is[bool]) 'Explicit manifest SBOM mode required'
    $zip=[IO.Compression.ZipFile]::OpenRead("$Output\$Label.jar")
    try{
        $bytes=StreamBytes $zip.GetEntry('META-INF/MANIFEST.MF')
        Require ([bool]$zip.GetEntry('META-INF/sbom/application.cdx.json')-eq$Artifact.online) 'Manifest mode differs from actual SBOM entry'
    }finally{$zip.Dispose()}
    if(-not$Artifact.online){Require ($Artifact.offlineSbomSkipObserved-eq$true) 'Manifest omission requires logged offline SBOM skip'}
    $sections=[Collections.Generic.List[object]]::new();$section=[ordered]@{}
    $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$previous=$null
    foreach($line in ([Text.UTF8Encoding]::new($false,$true).GetString($bytes)-split'\r\n|\n|\r')){
        if($line.Length-eq0){
            if($section.Count){$sections.Add($section);$section=[ordered]@{};$names.Clear();$previous=$null}
        }elseif($line.StartsWith(' ')){
            Require ($null-ne$previous) 'Orphan manifest continuation';$section[$previous]+=$line.Substring(1)
        }else{
            $match=[regex]::Match($line,'^([A-Za-z0-9_-]+): (.*)$')
            Require ($match.Success-and$names.Add($match.Groups[1].Value)) 'Malformed/duplicate manifest attribute'
            $previous=$match.Groups[1].Value;$section[$previous]=$match.Groups[2].Value
        }
    }
    if($section.Count){$sections.Add($section)}
    Require ($sections.Count-gt0-and$sections[0].Contains('Manifest-Version')) 'Missing main manifest section'
    foreach($attribute in @(@('Sbom-Location','META-INF/sbom/application.cdx.json'),@('Sbom-Format','CycloneDX'))){
        if($Artifact.online){Require ($sections[0].Contains($attribute[0])-and$sections[0][$attribute[0]]-ceq$attribute[1]) 'Unexpected online SBOM manifest attribute'}
        else{Require (-not$sections[0].Contains($attribute[0])) 'Offline manifest must omit only declared SBOM attributes'}
    }
    return @{sections=$sections.ToArray();rawSha256=(HashBytes $bytes)}
}
function ComparePilotManifest($Actual,$Expected,[string]$ActualLabel,[string]$ExpectedLabel){
    $a=PilotManifest $ActualLabel $Actual;$b=PilotManifest $ExpectedLabel $Expected
    $changes=@()
    if($Actual.online-ne$Expected.online){
        foreach($attribute in 'Sbom-Location','Sbom-Format'){
            $actualPresent=$a.sections[0].Contains($attribute);$expectedPresent=$b.sections[0].Contains($attribute)
            $changes+=@{entry='META-INF/MANIFEST.MF';attribute=$attribute;actualPresent=$actualPresent;actual=$a.sections[0][$attribute];referencePresent=$expectedPresent;reference=$b.sections[0][$attribute];actualRawSha256=$a.rawSha256;referenceRawSha256=$b.rawSha256;classification='exact SBOM attribute omission at proven online/offline boundary; raw bytes retained'}
            $a.sections[0].Remove($attribute);$b.sections[0].Remove($attribute)
        }
    }
    Same (CanonicalPilotJson $a.sections) (CanonicalPilotJson $b.sections) 'Meaningful manifest attributes/sections differ'
    return $changes
}
function ComparePilotPayload($Actual,$Expected,[string]$ActualLabel,[string]$ExpectedLabel){
    foreach($field in 'classes','testClasses','dependencies'){Same $Actual[$field] $Expected[$field] "Required code/dependency bytes differ: $field"}
    $changes=@(ComparePilotBom $Actual $Expected $ActualLabel $ExpectedLabel)
    $changes+=@(ComparePilotManifest $Actual $Expected $ActualLabel $ExpectedLabel)
    Same (PilotPayload $Actual) (PilotPayload $Expected) 'Required complete payload/resources differ'
    foreach($entry in 'BOOT-INF/classes/git.properties','META-INF/build-info.properties'){
        $changeCount=$changes.Count
        $a=PilotProperties $ActualLabel $entry;$b=PilotProperties $ExpectedLabel $entry
        Same @($a.Keys|Sort-Object) @($b.Keys|Sort-Object) 'Metadata keys differ'
        foreach($key in $a.Keys){if($a[$key]-cne$b[$key]){
            Require (($entry-eq'BOOT-INF/classes/git.properties'-and$key-eq'git.build.time')-or($entry-eq'META-INF/build-info.properties'-and$key-eq'build.time')) "Unexpected metadata difference: $entry/$key"
            $changes+=@{entry=$entry;key=$key;actual=$a[$key];reference=$b[$key];classification='expected build-time metadata; raw bytes retained'}
        }}
        $actualRaw=@($Actual.raw|Where-Object name -eq $entry)[0]
        $expectedRaw=@($Expected.raw|Where-Object name -eq $entry)[0]
        Require ($actualRaw.sha-eq$expectedRaw.sha-or$changes.Count-gt$changeCount) 'Raw metadata differs without an explicitly classified time-field change'
    };return $changes
}
function PilotArtifact([string]$Label,[bool]$Online){
    $artifact=BoundaryArtifact $Label $Online $true
    if(-not$Online){
        $artifact.offlineSbomSkipObserved=((Get-Content "$Output\$Label-package.log" -Raw)-match'Goal makeAggregateBom requires online mode.*skipping')
        Require $artifact.offlineSbomSkipObserved 'Missing original offline SBOM skip evidence'
    }
    $zip=[IO.Compression.ZipFile]::OpenRead("$Output\$Label.jar")
    try{
        Require ($zip.Entries.Count-eq$(if($Online){335}else{333})) 'Wrong complete/reduced ZIP entry count'
        if($Online){
            $bom=[Text.Encoding]::UTF8.GetString((StreamBytes $zip.GetEntry('META-INF/sbom/application.cdx.json')))|ConvertFrom-Json
            Require ($bom.components.Count-eq108-and$bom.dependencies.Count-eq109) 'Pinned SBOM component/graph universe differs'
        }
    }finally{$zip.Dispose()};return $artifact
}
function PilotSource([bool]$Dirty){
    Require ((BoundaryGit @('-C',$Project,'rev-parse','HEAD'))-eq'6feeae0f13e0e258eedc99832416b42bb13779b1') 'Wrong HOBL pin'
    $state=BoundaryGit @('-C',$Project,'status','--porcelain','--untracked-files=all')
    Require ($(if($Dirty){$state-ceq' M mvnw.cmd'}else{[string]::IsNullOrEmpty($state)})) 'Unexpected source changes'
    Require ((Get-FileHash "$Project\pom.xml").Hash-eq'A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D') 'Pinned POM changed'
    Require ((BoundaryGit @('-C',$Project,'remote','get-url','origin'))-eq'https://github.com/spring-projects/spring-petclinic.git') 'Wrong origin'
    if($Dirty){Require ((Get-FileHash "$Project\mvnw.cmd").Hash-eq$candidateSpec.expectedSha256) 'Common selected-revision wrapper changed'}
}
function PilotCall([string]$Label,[string[]]$Arguments,[bool]$Timed=$false){
    $log="$Output\$Label.log"
    $startMs=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $duration=Measure-Command {& $wrapper @Arguments *> $log;$script:nativeCode=$LASTEXITCODE}
    $endMs=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $phase=@{name=$Label;arguments=$Arguments;timed=$Timed;seconds=$duration.TotalSeconds;exitCode=$script:nativeCode;log=$log;startMs=$startMs;endMs=$endMs}
    $record.phases+=,$phase;$record|ConvertTo-Json -Depth 35|Set-Content "$Output\result.json"
    Require ($script:nativeCode-eq0) "$Label native failure=$script:nativeCode; no retry"
    return $phase
}
function PilotPreparation([string]$Arm){
    SetPwshPilotArm $Arm
    $null=PilotCall "$Arm-go-offline" ($base+@('-DskipTests','dependency:go-offline'))
    $verify=PilotCall "$Arm-clean-verify" ($base+@('clean','verify'))
    $artifact=PilotArtifact "$Arm-online" $true
    $reports=@(Get-ChildItem "$Project\target\surefire-reports\TEST-*.xml"|ForEach-Object {[xml](Get-Content $_ -Raw)})
    $ids=TestKeys $reports
    Require ($ids.Count-eq56-and@($ids|Where-Object state -eq passed).Count-eq54-and@($ids|Where-Object state -eq skipped).Count-eq2) 'Prep test identities/states differ'
    foreach($report in $reports){foreach($expected in @(@('java.home',$JavaHome),@('java.vendor','Microsoft'),@('java.runtime.version','25.0.5.0.2+1-LTS'),@('os.arch','aarch64'),@('server.address','127.0.0.1'))){
        Require ($report.SelectSingleNode("//properties/property[@name='$($expected[0])']").GetAttribute('value')-eq$expected[1]) 'Actual native test runtime/loopback differs'
    }}
    $coverage=BoundaryCoverage ([xml](Get-Content "$Project\target\site\jacoco\jacoco.xml" -Raw))
    Copy-Item "$Project\target\surefire-reports" "$Output\$Arm-surefire" -Recurse
    Copy-Item "$Project\target\site\jacoco\jacoco.xml" "$Output\$Arm-coverage.xml"
    Copy-Item "$Project\target\jacoco.exec" "$Output\$Arm-jacoco.exec"
    $log=Get-Content "$Output\$Arm-clean-verify.log" -Raw
    $pids=@([regex]::Matches($log,'Starting .*? with PID (\d+)')|ForEach-Object {$_.Groups[1].Value}|Sort-Object -Unique)
    $sessions=@(([xml](Get-Content "$Output\$Arm-coverage.xml" -Raw)).SelectNodes('/report/sessioninfo'))
    Require ($pids.Count-eq1-and$sessions.Count-eq1-and(Get-Item "$Output\$Arm-jacoco.exec").Length-gt0) 'Fresh single reported fork/session required'
    Require ([long]$sessions[0].start-ge$verify.startMs-and[long]$sessions[0].dump-le$verify.endMs-and[long]$sessions[0].dump-ge[long]$sessions[0].start) 'Coverage session outside actual verification'
    $proof=@{arm=$Arm;artifact=$artifact;tests=$ids;coverage=$coverage;reportedPid=$pids[0];session=@{id=$sessions[0].id;start=$sessions[0].start;dump=$sessions[0].dump};osArgvObserved=$false}
    $proof|ConvertTo-Json -Depth 35|Set-Content "$Output\$Arm-online-proof.json";return $proof
}
if($LibraryOnly){return}
Require ($IsWindows-and$ExecuteAuthorized-and$CandidateReviewed) 'Windows runtime and independently reviewed candidate must be explicitly authorized'
$candidateSpec=PilotCandidateRevision $CandidateRevision $CandidateWrapper
$CandidateWrapper=$candidateSpec.path
AssertBoundaryPaths $Project $Output $Cache $JavaHome
Require (-not(Test-Path $Output)) 'Fresh evidence required'
AssertPilotCandidateFile $candidateSpec
New-Item $Output -ItemType Directory|Out-Null
$names=@('JAVA_HOME','PATH','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME','MVNW_PREFER_PWSH')
$before=GetBoundaryEnvironmentSnapshot;$cwd=(Get-Location).Path;$original=$null;$installed=$false;$pushed=$false
$record=@{status='RUNNING';scope='Windows-only three-pair offline PACKAGE pilot; no official HOBL score/Mac parity/default adoption';phases=@();samples=@();failures=@();host=@{imageOS=$env:ImageOS;imageVersion=$env:ImageVersion;processArchitecture=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString();osArchitecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();logicalProcessors=[Environment]::ProcessorCount}}
try{
    PilotSource $false
    Require ((Test-Path "$Project\.git" -PathType Container)-and(BoundaryGit @('-C',$Project,'rev-parse','--git-common-dir'))-eq'.git'-and-not(Test-Path "$Project\.git\objects\info\alternates")) 'Unborrowed ordinary clone required'
    foreach($name in $names|Where-Object {$_-notin@('JAVA_HOME','PATH')}){Require (-not[Environment]::GetEnvironmentVariable($name)) "Review inherited option $name"}
    foreach($name in 'MVNW_REPOURL','MVNW_USERNAME','MVNW_PASSWORD','GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR','__MVNW_ARG0_NAME__'){Require (-not[Environment]::GetEnvironmentVariable($name)) "Review injected $name"}
    foreach($name in '.m2\settings.xml','.mavenrc','.mavenrc_pre.cmd','.mavenrc_pre.bat','mavenrc_pre.cmd','mavenrc_pre.bat','mavenrc_post.cmd','mavenrc_post.bat'){Require (-not(Test-Path (Join-Path $HOME $name))) 'Unreviewed user Maven rc/settings'}
    Require (-not@(Get-Process -Name java,javaw -ErrorAction SilentlyContinue).Count) 'Competing JVM present'
    $java="$JavaHome\bin\java.exe";Require ((Get-FileHash $java).Hash-eq'094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0') 'Pinned JDK25 bytes differ'
    $wrapper="$Project\mvnw.cmd";Require ((Get-FileHash $wrapper).Hash-eq'5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A') 'Original wrapper differs'
    $original=[IO.File]::ReadAllBytes($wrapper);[IO.File]::WriteAllBytes("$Output\original-mvnw.cmd",$original)
    $record.sourcePin='6feeae0f13e0e258eedc99832416b42bb13779b1'
    $record.sourceTree=BoundaryGit @('-C',$Project,'rev-parse','HEAD^{tree}')
    $record.candidateSha256=(Get-FileHash $CandidateWrapper).Hash
    $record.candidateRevision=$CandidateRevision
    $record.candidateProvenance=$candidateSpec
    if($CandidateRevision-eq'UpstreamF62f442'){$record.scope='EXACT current upstream f62f442 port, version-token-only3.3.5-SNAPSHOT render; Windows-only same-source classic/Core selector three-pair PACKAGE pilot; no Mac/default/HOBL-score claim'}
    elseif($CandidateRevision-eq'UpstreamF62f442HttpsLicense'){$record.scope='SEPARATELY NAMED upstream f62f442 HTTPS-license consumer-policy variant, NOT exact original port; Windows-only same-source classic/Core three-pair PACKAGE screen; benefit UNKNOWN; no prototype gain transfer/Mac/default/HOBL-score claim'}
    $record.originalWrapperSha256=(HashBytes $original)
    $record.javaSha256=(Get-FileHash $java).Hash
    [IO.File]::WriteAllBytes($wrapper,[IO.File]::ReadAllBytes($CandidateWrapper));$installed=$true;PilotSource $true
    $env:JAVA_HOME=$JavaHome;$env:PATH="$JavaHome\bin"+[IO.Path]::PathSeparator+$env:PATH
    Push-Location $Project;$pushed=$true
    foreach($name in 'pwsh.exe','powershell.exe'){
        Require (-not(Test-Path (Join-Path $Project $name))) 'Project shell shadow rejected'
        $paths=@(& "$env:SystemRoot\System32\where.exe" $name);Require ($LASTEXITCODE-eq0-and$paths.Count-gt0) 'Both classic and Core availability required; fallback is not a candidate result'
        $path=$paths[0];$bytes=[IO.File]::ReadAllBytes($path)
        Require ([BitConverter]::ToUInt16($bytes,([BitConverter]::ToInt32($bytes,60)+4))-eq0xAA64) 'Native ARM64 shell required'
        $record[$name]=@{candidatePaths=$paths;selectedPath=$path;sha256=(Get-FileHash $path).Hash;productVersion=(Get-Item $path).VersionInfo.ProductVersion;machine='AA64';provenance='WHERE/PATH plus file identity outside timers; not child PID/module observation'}
    }
    $base=@("-Dmaven.repo.local=$Cache",'-Dserver.address=127.0.0.1')
    SetPwshPilotArm baseline
    $version=PilotCall 'wrapper-version' ($base+@('--version'))
    Require ((Get-Content $version.log -Raw)-match'Apache Maven 3\.9\.11') 'Original Maven3.9.11 required'
    $a=PilotPreparation baseline;$b=PilotPreparation candidate
    Same $a.tests $b.tests 'Online test identities differ';Same $a.coverage $b.coverage 'Online full coverage differs'
    Require ($a.reportedPid-ne$b.reportedPid-and$a.session.id-ne$b.session.id) 'Online preparations did not produce fresh distinct forks/sessions'
    $record.onlineMetadataDifferences=@(ComparePilotPayload $b.artifact $a.artifact 'candidate-online' 'baseline-online')
    foreach($pair in 1..3){
        foreach($arm in $(if($pair-eq2){@('candidate','baseline')}else{@('baseline','candidate')})){
            SetPwshPilotArm baseline
            $null=PilotCall "pair-$pair-$arm-clean" ($base+@('clean'))
            PilotSource $true;SetPwshPilotArm $arm
            $phase=PilotCall "pair-$pair-$arm-package" (@('-o')+$base+@('-DskipTests','package')) $true
            $log=Get-Content $phase.log -Raw
            Require ($log-match'BUILD SUCCESS'-and$log-match'0 Checkstyle violations'-and$log-match'Tests are skipped'-and$log-match'Compiling 30 source files'-and$log-match'Compiling 17 source files'-and$log-match'Goal makeAggregateBom requires online mode.*skipping') 'Required fresh package/check/test-compilation work absent'
            $label="pair-$pair-$arm";$artifact=PilotArtifact $label $false
            $changes=@(ComparePilotPayload $artifact $a.artifact $label 'baseline-online')
            $sample=@{pair=$pair;arm=$arm;candidateRevision=$CandidateRevision;candidateSha256=$candidateSpec.expectedSha256;seconds=$phase.seconds;exitCode=$phase.exitCode;selectorPresent=(Test-Path Env:MVNW_PREFER_PWSH);selector=$env:MVNW_PREFER_PWSH;artifact=$artifact;metadataDifferences=$changes}
            $sample|ConvertTo-Json -Depth 20|Set-Content "$Output\$label-case.json";$record.samples+=,$sample;PilotSource $true
        }
    }
    $baseline=@($record.samples|Where-Object arm -eq baseline|ForEach-Object seconds);$candidate=@($record.samples|Where-Object arm -eq candidate|ForEach-Object seconds)
    $record.pairs=@(foreach($pair in 1..3){
        $left=@($record.samples|Where-Object {$_.pair-eq$pair-and$_.arm-eq'baseline'})[0].seconds
        $right=@($record.samples|Where-Object {$_.pair-eq$pair-and$_.arm-eq'candidate'})[0].seconds
        @{pair=$pair;baseline=$left;candidate=$right;differenceSeconds=($left-$right);differencePercent=(100*($left-$right)/$left)}
    })
    $record.summary=@{baselineMedian=(Median $baseline);candidateMedian=(Median $candidate);baselineMin=($baseline|Measure-Object -Minimum).Minimum;baselineMax=($baseline|Measure-Object -Maximum).Maximum;candidateMin=($candidate|Measure-Object -Minimum).Minimum;candidateMax=($candidate|Measure-Object -Maximum).Maximum}
    $record.status='PASS'
}catch{$record.status='FAIL';$record.failures+=@{phase='main';error=$_.ToString()}}
finally{
    try{if($installed){PilotSource $true;[IO.File]::WriteAllBytes($wrapper,$original);PilotSource $false;$record.sourceRestored=$true}}catch{$record.failures+=@{phase='source-restoration';error=$_.ToString()}}
    if($pushed){Pop-Location}
    $restore=RestoreBoundaryEnvironment $before $names;$restore.cwdEqual=((Get-Location).Path-eq$cwd);$restore|ConvertTo-Json -Depth 10|Set-Content "$Output\restoration.json"
    if(-not$restore.restored-or-not$restore.cwdEqual){$record.failures+=@{phase='environment';error='Managed presence/value/cwd restoration failed'}}
    $record.remainingJavaCandidates=@(Get-Process -Name java,javaw -ErrorAction SilentlyContinue).Count
    if($record.remainingJavaCandidates){$record.failures+=@{phase='cleanup';error='Java remains without proven owned identity; none killed'}}
    if($record.failures.Count){$record.status='FAIL'};$record|ConvertTo-Json -Depth 40|Set-Content "$Output\result.json"
}
Require ($record.status-eq'PASS') 'Pilot failed; no retry'
