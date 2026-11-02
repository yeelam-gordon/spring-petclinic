[CmdletBinding()]
param([string]$FixtureRoot)
$ErrorActionPreference='Stop'
if(-not$FixtureRoot){throw 'Explicit new owned fixture root required'}
if(Test-Path $FixtureRoot){throw 'Refuse existing fixture root'}
New-Item $FixtureRoot -ItemType Directory|Out-Null
$runner=Join-Path $PSScriptRoot 'Invoke-HoblContract.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
. $runner -LibraryOnly
$checks=0
function Check([string]$Name,[scriptblock]$Body){& $Body;$script:checks++;Write-Output "PASS $Name"}
function Reject([scriptblock]$Body){$failed=$false;try{& $Body}catch{$failed=$true};Require $failed 'Negative control unexpectedly accepted'}
Check 'original package arguments; no hidden batch/optimization flags' {
    Same (ContractArguments package 'owned cache' $false) @('-o','-Dmaven.repo.local=owned cache','-DskipTests','package') 'Package contract changed'
    Same (ContractArguments test cache $false) @('-o','-Dmaven.repo.local=cache','test') 'Test contract changed'
    Same (ContractArguments clean cache $false) @('-Dmaven.repo.local=cache','clean') 'Clean contract changed'
}
Check 'online prep and separately acknowledged loopback' {
    Same (ContractArguments go-offline cache $false) @('-Dmaven.repo.local=cache','-DskipTests','dependency:go-offline') 'Prep changed'
    Same (ContractArguments verify cache $false) @('-Dmaven.repo.local=cache','clean','verify') 'Verify changed'
    Require ((ContractArguments package cache)-contains'-Dserver.address=127.0.0.1') 'Loopback not explicit'
    Reject {ContractArguments unknown cache}
}
Check 'median comes from paired sums, never sum of medians' {
    $rows=@(@{buildSeconds=1;testSeconds=101},@{buildSeconds=100;testSeconds=100},@{buildSeconds=101;testSeconds=1})
    $summary=Summarize $rows
    Require ($summary.scenarioMedian-eq102 -and ($summary.buildMedian+$summary.testMedian)-eq200) 'Incorrect paired aggregation'
}
Check 'native Mac time locale, CPU fields, missing/duplicate rejection' {
    $time=ParseTime "real 12.34`nuser 8.90`nsys 1.20`n"
    Require ($time.real-eq12.34 -and $time.user-eq8.9 -and $time.sys-eq1.2) 'Time parse changed'
    Reject {ParseTime "real 1`nuser 1`n"}
    Reject {ParseTime "real 1`nreal 2`nuser 1`nsys 1`n"}
}
Check 'exact runtime rejects wrong vendor/arch/patch' {
    $runtime=" java.home = owned`n java.version = 25.0.5.0.2`n java.runtime.version = 25.0.5.0.2+1-LTS`n java.vendor = Microsoft`n os.arch = aarch64"
    $null=NativeRuntime $runtime
    foreach($bad in @($runtime.Replace('Microsoft','Other'),$runtime.Replace('aarch64','amd64'),$runtime.Replace('+1-LTS','+2-LTS'))){Reject {NativeRuntime $bad}}
}
Check 'recursive test identities do not count nested suite totals twice' {
    [xml]$xml='<testsuite tests="1"><testcase classname="A" name="outer"/><testsuite tests="1"><testcase classname="B" name="nested"><skipped/></testcase></testsuite></testsuite>'
    $tests=TestKeys @($xml)
    Require ($tests.Count-eq2 -and @($tests|Where-Object state -eq skipped).Count-eq1) 'Nested test counting broken'
}
Check 'full ancestor method descriptors distinguish coverage; duplicates reject' {
    [xml]$xml='<report name="r"><package name="p"><class name="C"><method name="f" desc="()V"><counter type="LINE" missed="0" covered="1"/></method><method name="f" desc="(I)V"><counter type="LINE" missed="1" covered="0"/></method></class></package></report>'
    Require ((CoverageKeys $xml).Count-eq2) 'Lost overload descriptor'
    [xml]$duplicate='<report name="r"><counter type="LINE" missed="0" covered="1"/><counter type="LINE" missed="0" covered="1"/></report>'
    Reject {CoverageKeys $duplicate}
    [xml]$one='<report name="r"><sessioninfo id="a"/><package name="p"><sourcefile name="C.java"><line nr="1" mi="0" ci="1"/></sourcefile></package></report>'
    [xml]$other=$one.OuterXml.Replace('id="a"','id="b"')
    Same (CoverageSemantics $one) (CoverageSemantics $other) 'Session-only difference should not alter coverage semantics'
    [xml]$changed=$one.OuterXml.Replace('nr="1"','nr="2"')
    Require ((CoverageSemantics $one)-cne(CoverageSemantics $changed)) 'Line identity lost'
}
Check 'ZIP exact binary bytes and empty required metadata rejection' {
    $path=Join-Path $FixtureRoot 'binary.zip';$zip=[IO.Compression.ZipFile]::Open($path,[IO.Compression.ZipArchiveMode]::Create)
    $bytes=[byte[]](0,255,13,10,65,10)
    try{$entry=$zip.CreateEntry('binary');$s=$entry.Open();$s.Write($bytes);$s.Dispose();$null=$zip.CreateEntry('empty')}finally{$zip.Dispose()}
    $zip=[IO.Compression.ZipFile]::OpenRead($path)
    try{Same (HashBytes (StreamBytes $zip.GetEntry('binary'))) (HashBytes $bytes) 'Binary bytes changed';Reject {StreamBytes $zip.GetEntry('empty')}}finally{$zip.Dispose()}
    Require ((HashBytes ([byte[]](65,13,10,66)))-ne(HashBytes ([byte[]](65,10,13,66)))) 'Same-length newline variants collapsed'
}
Check 'actual production phase propagates native failure after logging, no Java' {
    $definition=$ast.Find({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst] -and $node.Name-eq'Phase'},$true)
    Invoke-Expression $definition.Extent.Text
    function Save {}
    $result=@{phases=@()};$OutputDirectory=$FixtureRoot
    $script:wrapper={param([Parameter(ValueFromRemainingArguments)]$InputArgs) 'synthetic native failure';$global:LASTEXITCODE=7}
    Reject {Phase negative @('-o','test') (-not$IsMacOS)}
    Require ($result.phases.Count-eq1 -and $result.phases[0].exitCode-eq7 -and (Test-Path (Join-Path $FixtureRoot 'negative.log'))) 'Failure lost or success fallback'
}
Check 'actual production loop runs five clean/package/test/report sequences; audits stay untimed' {
    $result=@{phases=@();samples=@();snapshots=@()};$LocalCache='owned-cache'
    $mockLog=Join-Path $FixtureRoot 'mock-package.log'
    'Goal makeAggregateBom requires online mode for execution but Maven is currently offline, skipping'|Set-Content $mockLog
    function Phase([string]$Name,[string[]]$Arguments,[bool]$Timed=$false){
        $result.phases+=@{name=$Name;arguments=$Arguments;timed=$Timed}
        $seconds=if($Name.EndsWith('-package')){1}elseif($Name.EndsWith('-test')){2}else{100}
        return @{seconds=$seconds;log=$mockLog}
    }
    function Snapshot([string]$Name,[bool]$Online){$result.snapshots+=@{name=$Name;online=$Online}}
    function SourceGate {}
    function Save {}
    $loop=$ast.Find({param($node)$node-is[Management.Automation.Language.ForStatementAst]},$true)
    & ([scriptblock]::Create($loop.Extent.Text))
    Require ($result.samples.Count-eq5 -and $result.phases.Count-eq20 -and $result.snapshots.Count-eq5) 'Wrong loop count/command count'
    Require (@($result.phases|Where-Object timed).Count-eq10) 'Clean/report entered workload timers'
    foreach($row in $result.samples){Require ($row.scenarioRuntimeSeconds-eq3 -and $row.cleanSeconds-eq100) 'Clean/audit leaked into scenario sum'}
    foreach($phase in $result.phases){
        $offline=$phase.name-match'-(package|test|audit-report)$'
        Require (($phase.arguments-contains'-o')-eq$offline) 'Wrong offline boundary'
    }
}
Check 'actual production filters/count gate accept valid rows and reject wrong test states' {
    $commands=@($ast.FindAll({param($node)$node-is[Management.Automation.Language.CommandAst] -and $node.GetCommandName()-eq'Where-Object' -and $node.Extent.Text-match'^Where-Object (Name|state) '},$true))
    Require ($commands.Count-eq3) 'Expected actual Git/pass/skip filters'
    $rows=@([pscustomobject]@{Name='GIT_OWNED';state='passed'},[pscustomobject]@{Name='OTHER';state='skipped'})
    foreach($command in $commands){
        $selected=@($rows|& ([scriptblock]::Create('$input | '+$command.Extent.Text)))
        Require ($selected.Count-eq1) 'Production filter binding/selection failed'
    }
    $gate=$ast.Find({param($node)$node-is[Management.Automation.Language.CommandAst] -and $node.Extent.Text.StartsWith('Require ($tests.Count-eq56')},$true)
    $tests=@(foreach($i in 1..56){@{class='owned';name="case$i";state=$(if($i-le54){'passed'}else{'skipped'})}})
    & ([scriptblock]::Create($gate.Extent.Text))
    $tests[0].state='failure'
    Reject {& ([scriptblock]::Create($gate.Extent.Text))}
}
Check 'actual Surefire JDK-property block accepts observed home and rejects wrong/missing values' {
    $block=$ast.Find({param($node)$node-is[Management.Automation.Language.ForEachStatementAst] -and $node.Extent.Text.StartsWith('foreach($xml in $reports)')},$true)
    $JavaHome=$FixtureRoot;$escaped=[Security.SecurityElement]::Escape($JavaHome)
    $text="<testsuite><properties><property name='java.home' value='$escaped'/><property name='java.runtime.version' value='25.0.5.0.2+1-LTS'/><property name='java.vendor' value='Microsoft'/><property name='os.arch' value='aarch64'/></properties></testsuite>"
    $reports=@([xml]$text)
    & ([scriptblock]::Create($block.Extent.Text))
    foreach($bad in @($text.Replace($escaped,$escaped+'-wrong'),$text.Replace('Microsoft','Other'),$text.Replace('aarch64','amd64'),$text.Replace('+1-LTS','+2-LTS'),$text.Replace("name='java.home'","name='missing.home'"))){
        $reports=@([xml]$bad);Reject {& ([scriptblock]::Create($block.Extent.Text))}
    }
}
Check 'actual historical coverage guard rejects one reported class at matching counter/line totals' {
    $gate=$ast.Find({param($node)$node-is[Management.Automation.Language.CommandAst] -and $node.Extent.Text.StartsWith('Require ($counters.Count-eq726')},$true)
    $counters=[object[]]::new(726)
    $lines=(@(1..296|ForEach-Object {"<line nr='$_'/>"})-join'')
    [xml]$coverage="<report><package><class name='one'/><sourcefile>$lines</sourcefile></package></report>"
    Reject {& ([scriptblock]::Create($gate.Extent.Text))}
    $classes=(@(1..25|ForEach-Object {"<class name='C$_'/>"})-join'')
    [xml]$coverage="<report><package>$classes<sourcefile>$lines</sourcefile></package></report>"
    & ([scriptblock]::Create($gate.Extent.Text))
}
Check 'complete production Snapshot rejects synthetic one-class universe after metadata/test/runtime gates' {
    $definition=$ast.Find({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst] -and $node.Name-eq'Snapshot'},$true)
    Invoke-Expression $definition.Extent.Text
    function Save {}
    $ProjectFullClone=Join-Path $FixtureRoot 'synthetic-project';$OutputDirectory=Join-Path $FixtureRoot 'synthetic-evidence';$JavaHome=Join-Path $FixtureRoot 'synthetic-java'
    $target=Join-Path $ProjectFullClone 'target'
    foreach($path in $OutputDirectory,(Join-Path $target 'test-classes'),(Join-Path $target 'surefire-reports'),(Join-Path $target 'site/jacoco')){New-Item $path -ItemType Directory -Force|Out-Null}
    $zip=[IO.Compression.ZipFile]::Open((Join-Path $target 'application.jar'),[IO.Compression.ZipArchiveMode]::Create)
    try{
        $metadata=[ordered]@{
            'META-INF/MANIFEST.MF'='Manifest-Version: 1.0'
            'META-INF/build-info.properties'='build.version=synthetic'
            'BOOT-INF/classes/git.properties'="git.commit.id=6feeae0f13e0e258eedc99832416b42bb13779b1`ngit.dirty=false"
            'META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml'='<project/>'
            'META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties'='version=synthetic'
            'META-INF/sbom/application.cdx.json'='{"components":[{}],"dependencies":[{}]}'
        }
        foreach($name in $metadata.Keys){$entry=$zip.CreateEntry($name);$s=$entry.Open();try{$s.Write([Text.Encoding]::UTF8.GetBytes($metadata[$name]))}finally{$s.Dispose()}}
        foreach($i in 1..30){$null=$zip.CreateEntry("BOOT-INF/classes/Fake$i.class")}
        foreach($i in 1..98){$null=$zip.CreateEntry("BOOT-INF/lib/fake$i.jar")}
    }finally{$zip.Dispose()}
    foreach($i in 1..25){[IO.File]::WriteAllBytes((Join-Path $target "test-classes/Fake$i.class"),[byte[]](1))}
    $escaped=[Security.SecurityElement]::Escape($JavaHome)
    $properties="<properties><property name='java.home' value='$escaped'/><property name='java.runtime.version' value='25.0.5.0.2+1-LTS'/><property name='java.vendor' value='Microsoft'/><property name='os.arch' value='aarch64'/></properties>"
    $testcases=(@(foreach($i in 1..56){"<testcase classname='synthetic' name='fake$i'>$(if($i-ge55){'<skipped/>'})</testcase>"})-join'')
    [IO.File]::WriteAllText((Join-Path $target 'surefire-reports/TEST-synthetic.xml'),"<testsuite>$properties$testcases</testsuite>")
    $methods=(@(foreach($i in 1..121){
        "<method name='fake$i' desc='()V'>"+(@(foreach($type in 'INSTRUCTION','BRANCH','LINE','COMPLEXITY','METHOD','CLASS'){"<counter type='$type' missed='0' covered='1'/>"})-join'')+'</method>'
    })-join'')
    $lines=(@(foreach($i in 1..296){"<line nr='$i' mi='0' ci='1'/>"})-join'')
    [IO.File]::WriteAllText((Join-Path $target 'site/jacoco/jacoco.xml'),"<report name='synthetic'><package name='fake'><class name='OnlyOne'>$methods</class><sourcefile name='Fake.java'>$lines</sourcefile></package></report>")
    $result=@{snapshots=@()};$reason=$null
    try{Snapshot 'synthetic-negative' $true}catch{$reason=$_.ToString()}
    Require ($reason-eq'HOBL full coverage universe differs' -and $result.snapshots.Count-eq0) 'Synthetic malformed universe was accepted or failed before its intended guard'
    $script:snapshotLabelFixture=@{project=$ProjectFullClone;output=$OutputDirectory;java=$JavaHome;target=$target;metadata=$metadata;methods=$methods;lines=$lines}
}
Check 'complete production online/offline Snapshot preserves input labels and exact metadata mapping' {
    $definition=$ast.Find({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst] -and $node.Name-eq'Snapshot'},$true)
    Invoke-Expression $definition.Extent.Text
    function Save {}
    $fixture=$script:snapshotLabelFixture;$ProjectFullClone=$fixture.project;$OutputDirectory=$fixture.output;$JavaHome=$fixture.java
    $extraClasses=(@(2..25|ForEach-Object {"<class name='C$_'/>"})-join'')
    [IO.File]::WriteAllText((Join-Path $fixture.target 'site/jacoco/jacoco.xml'),"<report name='synthetic'><package name='fake'><class name='C1'>$($fixture.methods)</class>$extraClasses<sourcefile name='Fake.java'>$($fixture.lines)</sourcefile></package></report>")
    [IO.File]::WriteAllBytes((Join-Path $fixture.target 'jacoco.exec'),[byte[]](1,2,0,255))
    $result=@{snapshots=@()}
    foreach($online in @($true,$false)){
        $inputCase=if($online){'synthetic-online'}else{'synthetic-offline'}
        if(-not$online){
            $zip=[IO.Compression.ZipFile]::Open((Join-Path $fixture.target 'application.jar'),[IO.Compression.ZipArchiveMode]::Update)
            try{$zip.GetEntry('META-INF/sbom/application.cdx.json').Delete()}finally{$zip.Dispose()}
        }
        Snapshot $inputCase $online
        $snapshot=$result.snapshots[-1]
        Require ($snapshot.name-ceq$inputCase) 'Snapshot input case label overwritten'
        $expectedNames=@($fixture.metadata.Keys|Where-Object {$online -or $_-ne'META-INF/sbom/application.cdx.json'})
        Same @($snapshot.rawMetadata.entry) $expectedNames 'Raw metadata entry names/order changed'
        foreach($rawEntry in $snapshot.rawMetadata){
            Require ((Split-Path $rawEntry.path)-ceq(Join-Path $OutputDirectory $inputCase)) 'Metadata directory no longer maps to input case'
            $expectedBytes=[Text.Encoding]::UTF8.GetBytes($fixture.metadata[$rawEntry.entry])
            $actualBytes=[IO.File]::ReadAllBytes($rawEntry.path)
            Require ([Convert]::ToBase64String($actualBytes)-ceq[Convert]::ToBase64String($expectedBytes)) 'Raw metadata bytes changed'
            Require ($rawEntry.bytes-eq$expectedBytes.Length -and $rawEntry.sha256-eq(HashBytes $expectedBytes)) 'Raw metadata size/hash changed'
        }
    }
}
Check 'actual Git resolver preserves PATH order, spaces and duplicates; rejects absent/invalid applications' {
    foreach($case in @(
        @{paths=@('owned git')},
        @{paths=@('/opt/homebrew/bin/git','/usr/bin/git')},
        @{paths=@('C:\Program Files\Git\bin\git.exe','C:\Program Files\Git\cmd\git.exe','C:\Program Files\Git\clangarm64\bin\git.exe')},
        @{paths=@('duplicate git','duplicate git')}
    )){
        $paths=$case.paths
        $applications=@($paths|ForEach-Object {[pscustomobject]@{Source=$_;CommandType=[Management.Automation.CommandTypes]::Application}})
        $resolution=ResolveGitApplication $applications {param($Path) $true}
        Same $resolution.selectedPath $paths[0] 'First ordered Git path not selected'
        Same $resolution.candidatePaths $paths 'Candidate ordering/duplicates changed'
    }
    Reject {ResolveGitApplication @() {param($Path) $true}}
    Reject {ResolveGitApplication @([pscustomobject]@{Source='';CommandType='Application'}) {param($Path) $true}}
    Reject {ResolveGitApplication @([pscustomobject]@{Source=@('one','two');CommandType='Application'}) {param($Path) $true}}
    Reject {ResolveGitApplication @([pscustomobject]@{Source='owned';CommandType='Function'}) {param($Path) $true}}
    Reject {ResolveGitApplication @([pscustomobject]@{Source='missing';CommandType='Application'})}
    Reject {ResolveGitApplication @([pscustomobject]@{Source=$FixtureRoot;CommandType='Application'})}
}
Check 'actual GitText and SourceGate retain argv boundaries and native failure propagation' {
    foreach($functionName in 'GitText','SourceGate'){
        $definition=$ast.Find({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst] -and $node.Name-eq$functionName},$true)
        Invoke-Expression $definition.Extent.Text
    }
    $script:gitCalls=@();$script:gitMockExit=0
    $ProjectFullClone='owned project with spaces';$result=@{pin='6feeae0f13e0e258eedc99832416b42bb13779b1'}
    $script:gitExecutable={
        $script:gitCalls+=,@($args)
        $global:LASTEXITCODE=$script:gitMockExit
        if($args[-1]-eq'HEAD'){'6feeae0f13e0e258eedc99832416b42bb13779b1'}
    }
    SourceGate
    Same $script:gitCalls[0] @('-C','owned project with spaces','rev-parse','HEAD') 'Git arguments joined/split'
    Require ($script:gitCalls.Count-eq2) 'Actual SourceGate did not query head and status'
    $script:gitMockExit=19;$reason=$null
    try{SourceGate}catch{$reason=$_.ToString()}
    Require ($reason-eq'Git failed 19') 'Native Git failure was masked'
}
@{status='PASS';checks=$checks;javaInvoked=$false;runnerSha256=(Get-FileHash $runner).Hash}|ConvertTo-Json|Set-Content (Join-Path $FixtureRoot 'selftest.json')
Write-Output "PASS $checks offline checks; zero Java/Maven"
