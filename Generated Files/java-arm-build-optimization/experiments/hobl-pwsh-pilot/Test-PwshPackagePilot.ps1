#requires -Version 7.5
param([Parameter(Mandatory)][string]$FixtureRoot,[switch]$IntentionalFailure,[string]$ReferenceReport,[string]$ReferenceBom,[string]$ReferenceOnlineManifest,[string]$ReferenceOfflineManifest)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
if($IntentionalFailure){throw 'Intentional genuine Actions-shell failure fixture'}
. "$PSScriptRoot\Invoke-PwshPackagePilot.ps1" -Project 'owned-project' -Cache 'owned-cache' -JavaHome 'owned-jdk' -Output 'owned-output' -LibraryOnly
Require ($Project-ceq'owned-project'-and$JavaHome-ceq'owned-jdk'-and$Output-ceq'owned-output') 'Library parameter collision'
Require (-not(Test-Path $FixtureRoot)) 'Fresh fixture root required'
New-Item $FixtureRoot -ItemType Directory|Out-Null
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\Invoke-PwshPackagePilot.ps1",[ref]$tokens,[ref]$errors)
Require ($errors.Count-eq0) 'Runner parser errors'
Require ((Get-FileHash "$PSScriptRoot\candidate-mvnw.cmd").Hash-eq'655A91268C8DE0B8B233492F49014F9F3975BCABE7B0B8B2DC5C22A8E26EAEBA') 'Candidate source drift'
$checks=0
function Check([string]$Name,[scriptblock]$Body){& $Body;$script:checks++;Write-Output "PASS $Name"}
function Reject([scriptblock]$Body){$failed=$false;try{& $Body}catch{$failed=$true};Require $failed 'Negative fixture accepted'}
Check 'selector absent versus true and case-insensitive presence restoration' {
    $before=GetBoundaryEnvironmentSnapshot
    try{
        SetPwshPilotArm baseline;Require (-not(Test-Path Env:MVNW_PREFER_PWSH)) 'Baseline selector present'
        SetPwshPilotArm candidate;Require ($env:MVNW_PREFER_PWSH-ceq'true') 'Opt-in absent'
    }finally{$restore=RestoreBoundaryEnvironment $before @('MVNW_PREFER_PWSH');Require $restore.restored 'Selector restoration failed'}
    $mixed=[Collections.Hashtable]::new([StringComparer]::Ordinal);$mixed.Add('path','owned')
    Require ((GetBoundaryEnvironmentSnapshot $mixed).Contains('PATH')) 'OrdinalIgnoreCase snapshot lost PATH'
}
Check 'actual revision selection and source guard pin all three variants; no cross-variant or arbitrary hash' {
    $prototype=PilotCandidateRevision
    $upstream=PilotCandidateRevision UpstreamF62f442
    $https=PilotCandidateRevision UpstreamF62f442HttpsLicense
    Require ($prototype.revision-ceq'Prototype334'-and$prototype.expectedSha256-ceq'655A91268C8DE0B8B233492F49014F9F3975BCABE7B0B8B2DC5C22A8E26EAEBA') 'Default prototype changed'
    AssertPilotCandidateFile $prototype;AssertPilotCandidateFile $upstream;AssertPilotCandidateFile $https
    Reject {AssertPilotCandidateFile (PilotCandidateRevision UpstreamF62f442 $prototype.path)}
    Reject {AssertPilotCandidateFile (PilotCandidateRevision Prototype334 $upstream.path)}
    Reject {AssertPilotCandidateFile (PilotCandidateRevision UpstreamF62f442HttpsLicense $prototype.path)}
    Reject {AssertPilotCandidateFile (PilotCandidateRevision UpstreamF62f442HttpsLicense $upstream.path)}
    Reject {AssertPilotCandidateFile (PilotCandidateRevision Prototype334 $https.path)}
    Reject {AssertPilotCandidateFile (PilotCandidateRevision UpstreamF62f442 $https.path)}
    Reject {PilotCandidateRevision arbitrary}
    $bad=Join-Path $FixtureRoot 'wrong-bytes.cmd';[IO.File]::WriteAllText($bad,'fixture, never executed')
    Reject {AssertPilotCandidateFile (PilotCandidateRevision UpstreamF62f442 $bad)}
    Reject {AssertPilotCandidateFile (PilotCandidateRevision UpstreamF62f442HttpsLicense $bad)}
    $Project=Join-Path $FixtureRoot 'source-guard';New-Item $Project -ItemType Directory|Out-Null
    function BoundaryGit([string[]]$Arguments){
        if($Arguments[-1]-eq'HEAD'){return '6feeae0f13e0e258eedc99832416b42bb13779b1'}
        if($Arguments-contains'status'){return ' M mvnw.cmd'}
        if($Arguments[-1]-eq'origin'){return 'https://github.com/spring-projects/spring-petclinic.git'}
        throw 'Unexpected source query'
    }
    function Get-FileHash([string]$Path,[string]$LiteralPath,[string]$Algorithm='SHA256'){
        $selected=if($LiteralPath){$LiteralPath}else{$Path}
        if($selected.EndsWith('pom.xml')){return @{Hash='A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D'}}
        Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $selected -Algorithm $Algorithm
    }
    Copy-Item $upstream.path "$Project\mvnw.cmd"
    $candidateSpec=$upstream;PilotSource $true
    $candidateSpec=$prototype;Reject {PilotSource $true}
    $candidateSpec=$https;Reject {PilotSource $true}
    Copy-Item $prototype.path "$Project\mvnw.cmd" -Force
    $candidateSpec=$upstream;Reject {PilotSource $true}
    $candidateSpec=$https;Reject {PilotSource $true}
    $candidateSpec=$prototype;PilotSource $true
    Copy-Item $https.path "$Project\mvnw.cmd" -Force
    $candidateSpec=$https;PilotSource $true
    $candidateSpec=$prototype;Reject {PilotSource $true}
    $candidateSpec=$upstream;Reject {PilotSource $true}
    $workflow=Get-Content "$PSScriptRoot\pwsh-package.workflow.yml" -Raw
    $branch=[regex]::Match($workflow,'(?s)\$revisionArgs=@\{\}.*?(?=\s+& ''\./Generated)').Value
    Require ($branch.Length-gt0) 'Actual workflow selection block missing'
    $environmentBefore=GetBoundaryEnvironmentSnapshot
    try{
        $env:CANDIDATE_REVISION='Prototype334'
        $arguments=& ([scriptblock]::Create($branch+';return $revisionArgs'))
        Require ($arguments.Count-eq0) 'Default workflow must omit explicit revision override'
        $env:CANDIDATE_REVISION='UpstreamF62f442'
        $arguments=& ([scriptblock]::Create($branch+';return $revisionArgs'))
        Require ($arguments.CandidateRevision-ceq'UpstreamF62f442') 'Explicit upstream workflow override missing'
        $env:CANDIDATE_REVISION='UpstreamF62f442HttpsLicense'
        $arguments=& ([scriptblock]::Create($branch+';return $revisionArgs'))
        Require ($arguments.CandidateRevision-ceq'UpstreamF62f442HttpsLicense') 'Explicit separately named HTTPS workflow override missing'
        $env:CANDIDATE_REVISION='unknown';Reject {& ([scriptblock]::Create($branch))}
    }finally{$restore=RestoreBoundaryEnvironment $environmentBefore @('CANDIDATE_REVISION');Require $restore.restored 'Workflow-selector environment not restored'}
}
Check 'both upstream data variants survive Git cmd text/eol=crlf filter roundtrip' {
    $root=Join-Path $FixtureRoot 'git-roundtrip';New-Item $root -ItemType Directory|Out-Null
    [IO.File]::WriteAllText("$root\.gitattributes","*.cmd text eol=crlf`n")
    & git -C $root init --quiet;Require ($LASTEXITCODE-eq0) 'Fixture git init failed'
    foreach($revision in 'UpstreamF62f442','UpstreamF62f442HttpsLicense'){
        $spec=PilotCandidateRevision $revision;$copy=Join-Path $root $spec.file
        Copy-Item $spec.path $copy
        & git -C $root -c core.autocrlf=false add -- .gitattributes $spec.file
        Require ($LASTEXITCODE-eq0) 'Fixture Git filter add failed'
        Remove-Item $copy
        & git -C $root checkout-index --force -- $spec.file
        Require ($LASTEXITCODE-eq0-and(Get-FileHash $copy).Hash-eq$spec.expectedSha256) 'Rendered bytes changed on Git checkout'
    }
}
Check 'real required payload map rejects resource or code changes' {
    function PilotProperties {param($Label,$EntryName) @{fixed='same';'build.time'='same'}}
    function ComparePilotBom {param($Actual,$Expected,$ActualLabel,$ExpectedLabel)}
    function ComparePilotManifest {param($Actual,$Expected,$ActualLabel,$ExpectedLabel)}
    $expected=@{classes=@{C='1'};testClasses=@{T='1'};dependencies=@{D='1'};entries=@(@{name='BOOT-INF/classes/static/a.txt';sha='ABC'},@{name='META-INF/MANIFEST.MF';sha='DEF'},@{name='BOOT-INF/classes/git.properties';sha='mutable'})}
    $actual=@{classes=@{C='1'};testClasses=@{T='1'};dependencies=@{D='1'};entries=@(@{name='BOOT-INF/classes/static/a.txt';sha='ABC'},@{name='META-INF/MANIFEST.MF';sha='DEF'},@{name='BOOT-INF/classes/git.properties';sha='other'})}
    $expected.raw=@(@{name='BOOT-INF/classes/git.properties';sha='same'},@{name='META-INF/build-info.properties';sha='same'})
    $actual.raw=@(@{name='BOOT-INF/classes/git.properties';sha='same'},@{name='META-INF/build-info.properties';sha='same'})
    $null=ComparePilotPayload $actual $expected actual reference
    $actual.entries[0].sha='changed';Reject {ComparePilotPayload $actual $expected actual reference}
    $actual.entries[0].sha='ABC';$actual.classes.C='changed';Reject {ComparePilotPayload $actual $expected actual reference}
    $actual.classes.C='1';$actual.raw[0].sha='unclassified';Reject {ComparePilotPayload $actual $expected actual reference}
}
Check 'actual comparator preserves online BOM content and permits only classified serial/time or proven offline omission' {
    $Output=Join-Path $FixtureRoot 'bom-fixtures';New-Item $Output -ItemType Directory|Out-Null
    if($ReferenceBom){
        $bom=Get-Content $ReferenceBom -Raw|ConvertFrom-Json -AsHashtable -Depth 100 -DateKind String
    }else{
        $bom=@{bomFormat='CycloneDX';specVersion='1.6';serialNumber='urn:uuid:fixture';metadata=@{timestamp='2026-01-01T00:00:00Z';component=@{name='fixture';version='1'}};components=@(1..108|ForEach-Object {@{'bom-ref'="c$_";name="C$_";version='1'}});dependencies=@(0..108|ForEach-Object {@{ref="c$_";dependsOn=@('c1')}})}
    }
    Require ($bom.components.Count-eq108-and$bom.dependencies.Count-eq109) 'BOM fixture universe differs'
    function NewBomFixture([string]$Label,$Content,[bool]$Online,[bool]$Skip=$false){
        $manifest="Manifest-Version: 1.0`r`nMain-Class: fixture.Main`r`n"
        if($Online){$manifest+="Sbom-Location: META-INF/sbom/application.cdx.json`r`nSbom-Format: CycloneDX`r`n"}
        $metadata=[ordered]@{'META-INF/MANIFEST.MF'=($manifest+"`r`n");'BOOT-INF/classes/git.properties'="git.commit.id=fixture`ngit.dirty=true";'META-INF/build-info.properties'='build.version=fixture'}
        if($Online){$metadata['META-INF/sbom/application.cdx.json']=ConvertTo-Json -InputObject $Content -Depth 100}
        $zip=[IO.Compression.ZipFile]::Open("$Output\$Label.jar",[IO.Compression.ZipArchiveMode]::Create)
        $entries=@()
        try{foreach($key in $metadata.Keys){
            $bytes=[Text.Encoding]::UTF8.GetBytes($metadata[$key]);$s=$zip.CreateEntry($key).Open();try{$s.Write($bytes)}finally{$s.Dispose()}
            $entries+=@{name=$key;sha=(HashBytes $bytes)}
        }}finally{$zip.Dispose()}
        return @{online=$Online;offlineSbomSkipObserved=$Skip;classes=@{C='same'};testClasses=@{T='same'};dependencies=@{D='same'};entries=$entries;raw=$entries}
    }
    $baseline=NewBomFixture baseline $bom $true
    $same=NewBomFixture same $bom $true
    Require (@(ComparePilotPayload $same $baseline same baseline).Count-eq0) 'Identical BOM acquired differences'
    $changed=(ConvertTo-Json -InputObject $bom -Depth 100)|ConvertFrom-Json -AsHashtable -Depth 100 -DateKind String
    $changed.components[0]['version']='unexpected-version'
    $version=NewBomFixture version $changed $true
    Reject {ComparePilotPayload $version $baseline version baseline}
    $changed=(ConvertTo-Json -InputObject $bom -Depth 100)|ConvertFrom-Json -AsHashtable -Depth 100 -DateKind String
    $changed.dependencies[0]['dependsOn']=@('urn:unexpected:dependency')
    $edge=NewBomFixture edge $changed $true
    Reject {ComparePilotPayload $edge $baseline edge baseline}
    $changed=(ConvertTo-Json -InputObject $bom -Depth 100)|ConvertFrom-Json -AsHashtable -Depth 100 -DateKind String
    $changed['serialNumber']='urn:uuid:harmless-change';$changed['metadata']['timestamp']='2026-02-02T00:00:00Z'
    $harmless=NewBomFixture harmless $changed $true
    $differences=@(ComparePilotPayload $harmless $baseline harmless baseline)
    Same @($differences.path) @('serialNumber','metadata.timestamp') 'Allowed BOM differences not exactly classified'
    $offline=NewBomFixture offline $null $false $true
    $omission=@(ComparePilotPayload $offline $baseline offline baseline)
    Require (@($omission|Where-Object entry -eq 'META-INF/sbom/application.cdx.json').Count-eq1-and@($omission|Where-Object entry -eq 'META-INF/MANIFEST.MF').Count-eq2) 'Contract BOM/manifest omissions not exactly classified'
    $unproved=NewBomFixture unproved $null $false
    Reject {ComparePilotPayload $unproved $baseline unproved baseline}
    Reject {ComparePilotPayload $offline $unproved offline unproved}
    $wrongMode=NewBomFixture wrongmode $bom $true;$wrongMode.online=$false;$wrongMode.offlineSbomSkipObserved=$true
    Reject {ComparePilotPayload $wrongMode $baseline wrongmode baseline}
    $script:manifestFixtureBom=$bom
    @{referenceKind=$(if($ReferenceBom){'real retained108/109 BOM'}else{'self-contained synthetic108/109 BOM'});referenceSha256=$(if($ReferenceBom){(Get-FileHash $ReferenceBom).Hash}else{$null});changedVersionRejected=$true;changedEdgeRejected=$true;allowedMetadata=$differences;offlineOmission=$omission}|ConvertTo-Json -Depth 15|Set-Content "$FixtureRoot\bom-regressions.json"
}
Check 'actual manifest comparator permits exactly the retained SBOM boundary and rejects unrelated headers' {
    $Output=Join-Path $FixtureRoot 'manifest-fixtures';New-Item $Output -ItemType Directory|Out-Null
    $offlineText="Manifest-Version: 1.0`r`nMain-Class: org.springframework.boot.loader.launch.JarLauncher`r`nStart-Class: org.springframework.samples.petclinic.PetClinicApplication`r`n`r`n"
    $onlineText=$offlineText.Replace("`r`n`r`n","`r`nSbom-Location: META-INF/sbom/application.cdx.json`r`nSbom-Format: CycloneDX`r`n`r`n")
    $onlineBytes=if($ReferenceOnlineManifest){[IO.File]::ReadAllBytes($ReferenceOnlineManifest)}else{[Text.Encoding]::UTF8.GetBytes($onlineText)}
    $offlineBytes=if($ReferenceOfflineManifest){[IO.File]::ReadAllBytes($ReferenceOfflineManifest)}else{[Text.Encoding]::UTF8.GetBytes($offlineText)}
    function NewManifestFixture([string]$Label,[byte[]]$Manifest,[bool]$Online,[bool]$Skip=$false){
        $values=[ordered]@{'META-INF/MANIFEST.MF'=$Manifest;'BOOT-INF/classes/git.properties'=[Text.Encoding]::UTF8.GetBytes("git.commit.id=fixture`ngit.dirty=true");'META-INF/build-info.properties'=[Text.Encoding]::UTF8.GetBytes('build.version=fixture')}
        if($Online){$values['META-INF/sbom/application.cdx.json']=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $script:manifestFixtureBom -Depth 100))}
        $zip=[IO.Compression.ZipFile]::Open("$Output\$Label.jar",[IO.Compression.ZipArchiveMode]::Create);$entries=@()
        try{foreach($key in $values.Keys){$s=$zip.CreateEntry($key).Open();try{$s.Write($values[$key])}finally{$s.Dispose()};$entries+=@{name=$key;sha=(HashBytes $values[$key])}}}finally{$zip.Dispose()}
        return @{online=$Online;offlineSbomSkipObserved=$Skip;classes=@{C='same'};testClasses=@{T='same'};dependencies=@{D='same'};entries=$entries;raw=$entries}
    }
    $online=NewManifestFixture online $onlineBytes $true
    $offline=NewManifestFixture offline $offlineBytes $false $true
    $differences=@(ComparePilotPayload $offline $online offline online)
    Same @($differences|Where-Object entry -eq 'META-INF/MANIFEST.MF'|ForEach-Object attribute) @('Sbom-Location','Sbom-Format') 'Boundary attributes not exactly classified'
    Require (@(ComparePilotManifest $online $online online online).Count-eq0) 'Online same-mode semantics changed'
    Require (@(ComparePilotManifest $offline $offline offline offline).Count-eq0) 'Offline same-mode semantics changed'
    $text=[Text.Encoding]::UTF8.GetString($offlineBytes)
    $main=NewManifestFixture main ([Text.Encoding]::UTF8.GetBytes($text.Replace('org.springframework.boot.loader.launch.JarLauncher','unexpected.Main'))) $false $true
    Reject {ComparePilotPayload $main $online main online}
    $extra=NewManifestFixture extra ([Text.Encoding]::UTF8.GetBytes($text.Replace("`r`n`r`n","`r`nUnexpected-Header: forbidden`r`n`r`n"))) $false $true
    Reject {ComparePilotPayload $extra $online extra online}
    $location=NewManifestFixture location ([Text.Encoding]::UTF8.GetBytes(([Text.Encoding]::UTF8.GetString($onlineBytes)).Replace('Sbom-Location: META-INF/sbom/application.cdx.json','Sbom-Location: META-INF/unexpected.json'))) $true
    Reject {ComparePilotPayload $location $online location online}
    $wrong=NewManifestFixture wrong $onlineBytes $true;$wrong.online=$false;$wrong.offlineSbomSkipObserved=$true
    Reject {ComparePilotPayload $wrong $online wrong online}
    $missing=NewManifestFixture missing $offlineBytes $false
    Reject {ComparePilotPayload $missing $online missing online}
    @{retainedManifests=[bool]($ReferenceOnlineManifest-and$ReferenceOfflineManifest);onlineSha256=(HashBytes $onlineBytes);offlineSha256=(HashBytes $offlineBytes);classifications=$differences;mainClassRejected=$true;extraHeaderRejected=$true;locationRejected=$true;wrongModeRejected=$true;missingSkipRejected=$true}|ConvertTo-Json -Depth 15|Set-Content "$FixtureRoot\manifest-regressions.json"
}
Check 'actual six-case loop: uniform normal clean outside timer, only offline package timed' {
    $before=GetBoundaryEnvironmentSnapshot
    try{
        $record=@{samples=@()};$base=@('-Dmaven.repo.local=owned-cache','-Dserver.address=127.0.0.1');$calls=@()
        $a=@{artifact=@{}}
        $mockLog=Join-Path $FixtureRoot 'package.log'
        'BUILD SUCCESS; 0 Checkstyle violations; Tests are skipped; Compiling 30 source files; Compiling 17 source files; Goal makeAggregateBom requires online mode for execution but Maven is currently offline, skipping'|Set-Content $mockLog
        function PilotCall($Label,$Arguments,$Timed=$false){$script:observedCalls+=,@{name=$Label;arguments=$Arguments;timed=$Timed;selector=$env:MVNW_PREFER_PWSH};@{seconds=1;exitCode=0;log=$mockLog}}
        function PilotSource {}
        function PilotArtifact {param($Label,$Online) @{fixture=$true}}
        function ComparePilotPayload {}
        $script:observedCalls=@();$Output=$FixtureRoot
        $loop=$ast.Find({param($n)$n-is[Management.Automation.Language.ForEachStatementAst]-and$n.Extent.Text.StartsWith('foreach($pair in 1..3)')},$true)
        & ([scriptblock]::Create($loop.Extent.Text))
        Require ($record.samples.Count-eq6-and$script:observedCalls.Count-eq12) 'Wrong loop/sample count'
        Same @($record.samples.arm) @('baseline','candidate','candidate','baseline','baseline','candidate') 'Wrong alternation'
        foreach($call in $script:observedCalls){
            if($call.name.EndsWith('-clean')){Require (-not$call.timed-and$call.arguments[-1]-eq'clean'-and-not$call.selector) 'Clean is not uniform normal baseline'}
            else{Require ($call.timed-and$call.arguments[0]-eq'-o'-and$call.arguments[-2]-eq'-DskipTests'-and$call.arguments[-1]-eq'package') 'Timed command changed'}
        }
    }finally{$null=RestoreBoundaryEnvironment $before @('MVNW_PREFER_PWSH')}
}
Check 'actual call logs native failure without success fallback; tiny fixture only' {
    $cmd=Join-Path $FixtureRoot 'tiny.cmd'
    [IO.File]::WriteAllText($cmd,"@echo off`r`n@echo ARG=%~1`r`n@exit /b 37`r`n")
    $wrapper=$cmd;$Output=$FixtureRoot;$record=@{phases=@()}
    Reject {PilotCall tiny @('alpha beta') $true}
    Require ($record.phases.Count-eq1-and$record.phases[0].exitCode-eq37-and(Get-Content "$FixtureRoot\tiny.log" -Raw)-match'ARG=alpha beta') 'Native code/argv boundary lost'
}
Check 'no markers/tracing or implicit runtime from unauthorized entrypoint' {
    Require (-not$ast.Find({param($n)$n-is[Management.Automation.Language.CommandAst]-and$n.GetCommandName()-in@('AddBoundaryMarkers','Start-Sleep','Register-CimIndicationEvent')},$true)) 'Observer/marker in pilot'
    $call=$ast.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'PilotCall'},$true)
    Require ($call.Extent.Text.Contains('Measure-Command {& $wrapper @Arguments *> $log;$script:nativeCode=$LASTEXITCODE}')) 'Literal HOBL timer changed'
    Reject {& "$PSScriptRoot\Invoke-PwshPackagePilot.ps1" -Project fixture -Cache fixture -JavaHome fixture -Output "$FixtureRoot\must-not-exist"}
    Require (-not(Test-Path "$FixtureRoot\must-not-exist")) 'Unauthorized runtime wrote output'
}
if($ReferenceReport){$null=BoundaryCoverage ([xml](Get-Content $ReferenceReport -Raw))}
@{status='PASS';checks=$checks;javaOrMavenOrBootstrapInvoked=$false;candidateSha256=(Get-FileHash "$PSScriptRoot\candidate-mvnw.cmd").Hash}|ConvertTo-Json|Set-Content "$FixtureRoot\selftest.json"
# Actions' pwsh shell forwards LASTEXITCODE; expected tiny failures must not leak.
$global:LASTEXITCODE=0
Write-Output "PASS $checks pure/tiny checks; Actions-shell success code explicitly zero"
