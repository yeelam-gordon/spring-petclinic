param([string]$SetupTestRoot=$env:COMPARISON_SETUP_TEST_ROOT,[string]$CompleteArtifactReference,[string]$TestUnexpectedCheck)
$ErrorActionPreference='Stop'
$runner=Join-Path $PSScriptRoot 'Invoke-MatchedComparison.ps1'
. $runner -LibraryOnly
$passed=[Collections.Generic.List[string]]::new()
function Check([string]$Name,[scriptblock]$Body){
    $prior=PortableEnvironmentSnapshot
    try{& $Body;$passed.Add($Name)}
    finally{
        if($SetupTestRoot){New-Item $SetupTestRoot -ItemType Directory -Force|Out-Null;$after=PortableEnvironmentSnapshot;@{check=$Name;beforePresent=$prior.Contains('JAVA_HOME');afterPresent=$after.Contains('JAVA_HOME');equal=($prior.Contains('JAVA_HOME')-eq$after.Contains('JAVA_HOME')-and[string]::Equals($prior['JAVA_HOME'],$after['JAVA_HOME'],[StringComparison]::Ordinal))}|ConvertTo-Json -Compress|Add-Content (Join-Path $SetupTestRoot 'check-home-trace.jsonl')}
    }
}
function Rejects([scriptblock]$Body,[string]$ExpectedMessage=''){
    $threw=$false
    try{& $Body}catch{$threw=$true;if($ExpectedMessage){Require ($_.Exception.Message-like"*$ExpectedMessage*") "Wrong rejection: $($_.Exception.Message)"}}
    Require $threw 'Expected rejection'
}
function WithRawMetadataFixture([object[]]$Entries,[scriptblock]$Body){
    $root=if($SetupTestRoot){$SetupTestRoot}elseif($env:GITHUB_WORKSPACE){Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}else{throw 'Specify -SetupTestRoot outside public payload'}
    $directory=Join-Path $root ('raw-metadata-'+[guid]::NewGuid().ToString('N'))
    New-Item $directory -ItemType Directory -Force|Out-Null
    $memory=[IO.MemoryStream]::new()
    $writer=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Create,$true)
    try{foreach($item in $Entries){$stream=$writer.CreateEntry($item.name).Open();try{$stream.Write($item.bytes,0,$item.bytes.Length)}finally{$stream.Dispose()}}}finally{$writer.Dispose()}
    $memory.Position=0;$archive=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Read)
    try{& $Body $archive $directory}finally{$archive.Dispose();$memory.Dispose()}
}
Check 'JacocoScope opt-in plans both OSes, rejects other workload, preserves default labels' {
    foreach($os in 'Windows','MacOS'){
        $p=& $runner -PlanOnly -Platform $os -Comparison JacocoScope -Workload current17 -MvndHome fixture|ConvertFrom-Json
        Require ($p.comparison-eq'JacocoScope' -and -not$p.stock -and $p.arms[0]-eq'default' -and $p.pairs[1][0]-eq'candidate') 'Wrong candidate mode'
    }
    Rejects {& $runner -PlanOnly -Comparison JacocoScope -Workload normalizedHobl25 -Platform Windows -MvndHome fixture} 'current17'
    $p=& $runner -PlanOnly -Platform Windows -MvndHome fixture|ConvertFrom-Json
    Require ($p.stock -and -not$p.comparison -and $p.pairs[0][0]-eq'stock') 'Default plan relabeled'
}
Check 'JacocoScope summary uses actual arm medians and rejects mixed modes/full XML drift' {
    $correct=@{tests=@();coverage=@{};classes=@{};testClasses=@{};dependencies=@{};jarSha256='same';reportSemantics=@('full')}
    $w=@{status='PASS';plan=(ComparisonPlan Windows current17 fixture);javaIdentity='same';mavenCoreSha256='same';correctness=$correct;test=@{default=@(10,10,10);candidate=@(8,8,8)}}
    $m=@{status='PASS';plan=(ComparisonPlan MacOS current17 fixture);javaIdentity='same';mavenCoreSha256='same';correctness=$correct.Clone();test=@{default=@(8,8,8);candidate=@(7,7,7)}}
    $w.plan.samples=3;$m.plan.samples=3;$w.plan.comparison='JacocoScope';$m.plan.comparison='JacocoScope'
    $s=CompareEvidence $w $m
    Require ($s.windowsDefaultTest-eq10 -and $s.macCandidateTest-eq7 -and $s.defaultWindowsMinusMac-eq2 -and $s.candidateWindowsMinusMac-eq1) 'Wrong arm/gap arithmetic'
    $m.correctness.reportSemantics=@('changed line');Rejects {CompareEvidence $w $m} 'full reported coverage'
    $m.plan.comparison='MavenVsDaemon';Rejects {CompareEvidence $w $m} 'mode mismatch'
}
Check 'JacocoScope real orchestration calls two untimed verifies and six alternating test-only cases' {
    $module=New-Module -ArgumentList ${function:PrepareJacocoScope}.ToString(),${function:MeasureJacocoScope}.ToString() -ScriptBlock {
        param($prepare,$measure)
        $script:Samples=3;$script:plan=@{pairs=@(@('default','candidate'),@('candidate','default'),@('default','candidate'))};$script:calls=@()
        function RunJacocoScopeCase($name,$arm,$goals,$timed){$script:calls+=@{name=$name;arm=$arm;goals=$goals;timed=$timed}}
        . ([scriptblock]::Create("function PrepareJacocoScope { $prepare }; function MeasureJacocoScope { $measure }"))
        Export-ModuleMember -Function PrepareJacocoScope,MeasureJacocoScope
    }
    $calls=& $module {PrepareJacocoScope;MeasureJacocoScope;$script:calls}
    Require ($calls.Count-eq8 -and ($calls[0].goals-join' ')-eq'clean verify' -and -not$calls[0].timed -and -not$calls[1].timed) 'Prep sequence drift'
    Same @($calls|Select-Object -Skip 2|ForEach-Object arm) @('default','candidate','candidate','default','default','candidate') 'Alternation drift'
    foreach($call in $calls|Select-Object -Skip 2){Require ($call.timed -and $call.goals.Count-eq1 -and $call.goals[0]-eq'test') 'Package/stock added to test screen'}
}
Check 'JI-001 actual production mode branches preserve both default preps and distinct candidate screen' {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
    $main=@($ast.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.TryStatementAst]})[-1]
    $prep=@($main.Body.Statements|Where-Object {$_-is[Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('PrepareJacocoScope')})[0].Extent.Text
    $timing=@($main.Body.Statements|Where-Object {$_-is[Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('MeasureJacocoScope')})[0].Extent.Text
    $root=if($SetupTestRoot){$SetupTestRoot}else{Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}
    $original=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '..\..\..\..\pom.xml'))
    $savedOpts=[Environment]::GetEnvironmentVariable('MAVEN_OPTS','Process')
    try{foreach($mode in 'MavenVsDaemon','JacocoScope'){
        $fixture=Join-Path $root ('production-branches-'+[guid]::NewGuid().ToString('N'))
        $project=Join-Path $fixture 'project';$output=Join-Path $fixture 'evidence'
        foreach($p in @($output,(Join-Path $project 'target/site/jacoco'),(Join-Path $project 'target/surefire-reports'))){New-Item $p -ItemType Directory -Force|Out-Null}
        [IO.File]::WriteAllBytes((Join-Path $project 'pom.xml'),$original)
        $module=New-Module -ArgumentList $prep,$timing,$mode,$project,$output,${function:JacocoTrialPomBytes}.ToString(),${function:AssertJacocoSource}.ToString(),${function:PrepareJacocoScope}.ToString(),${function:MeasureJacocoScope}.ToString() -ScriptBlock {
            param($prep,$timing,$mode,$project,$output,$transform,$assert,$prepare,$measure)
            $script:Comparison=$mode;$script:ProjectFullClone=$project;$script:OutputDirectory=$output;$script:Samples=3;$script:events=@()
            $script:plan=@{sourcePin='500158f732419217507c7656904b8e6aa1bcc0d6';pairs=$(if($mode-eq'JacocoScope'){@(@('default','candidate'),@('candidate','default'),@('default','candidate'))}else{@(@('stock','daemon'),@('daemon','stock'),@('stock','daemon'))})}
            $script:result=@{selectedRuntime='fixture';package=@{stock=@();daemon=@()};test=@{stock=@();daemon=@()}}
            function Require($condition,$message){if(-not$condition){throw $message}}
            function Run($name,$engine,$goals,$timed){
                $script:events+=@{kind='run';name=$name;engine=$engine;goals=$goals;timed=$timed}
                if($script:failStockPrep -and $name-eq'stock-prep'){throw 'fixture-stock-prep-exit7'}
                if($goals-contains'test'){
                    [IO.File]::WriteAllBytes((Join-Path $script:ProjectFullClone 'target/jacoco.exec'),[byte[]]@(1))
                    'fixture'|Set-Content (Join-Path $script:ProjectFullClone 'target/site/jacoco/jacoco.xml')
                    'fixture'|Set-Content (Join-Path $script:ProjectFullClone 'target/surefire-reports/TEST-fixture.xml')
                }
                return @{seconds=1;exitCode=0}
            }
            function Snapshot($name,$tests){$script:events+=@{kind='snapshot';name=$name;tests=$tests}}
            function Get-Content {param($Path,[switch]$Raw) 'Maven 3.9.16'}
            function RuntimeProfile($text){'fixture'}
            function AssertRuntime($a,$b,$role){Require ($a-eq$b) 'Runtime changed'}
            function RunJacocoScopeCase($name,$arm,$goals,$timed){$script:events+=@{kind='scope';name=$name;arm=$arm;goals=$goals;timed=$timed}}
            . ([scriptblock]::Create("function JacocoTrialPomBytes { $transform }; function AssertJacocoSource { $assert }; function PrepareJacocoScope { $prepare }; function MeasureJacocoScope { $measure }"))
            & ([scriptblock]::Create($prep));& ([scriptblock]::Create($timing))
            Export-ModuleMember -Variable events
        }
        try{
            $events=& $module {$script:events}
            if($mode-eq'MavenVsDaemon'){
                Same @($events|Select-Object -First 6|ForEach-Object name) @('stock-version','stock-prep','stock-prep','daemon-version','daemon-prep','daemon-prep') 'Actual default prep/snapshot order changed'
                Same @($events|Where-Object {$_.kind-eq'run'-and$_.goals-contains'verify'}|ForEach-Object engine) @('stock','daemon') 'Default verify engines omitted'
                Require (@($events|Where-Object {$_.kind-eq'snapshot'-and$_.tests}).Count-eq8) 'Default full prep/test snapshots omitted'
                Require (@($events|Where-Object {$_.kind-eq'run'-and$_.timed-and$_.goals-contains'package'}).Count-eq6) 'Default packages omitted'
                Require (@($events|Where-Object {$_.kind-eq'run'-and$_.timed-and$_.goals-contains'test'}).Count-eq6) 'Default tests omitted'
                Rejects {& $module {$script:failStockPrep=$true;& ([scriptblock]::Create($prep))}} 'fixture-stock-prep-exit7'
            }else{
                $calls=@($events|Where-Object kind -eq scope)
                Same @($calls|Select-Object -First 2|ForEach-Object arm) @('default','candidate') 'Actual candidate branch prep coupling'
                Require ($calls.Count-eq8 -and @($events|Where-Object {$_.kind-eq'run'-and$_.engine-eq'stock'}).Count-eq0) 'Candidate branch added stock/omitted cases'
                Same @($calls|Select-Object -Skip 2|ForEach-Object arm) @('default','candidate','candidate','default','default','candidate') 'Candidate timed order changed'
                Require ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes((Join-Path $project 'pom.xml'))))-eq'A14A495B06D207043B9AE6B9CDE8B129357991AFD9DF0A68C94D93081E280B2F') 'Actual branch did not install common POM'
            }
        }finally{[IO.File]::WriteAllBytes((Join-Path $project 'pom.xml'),$original)}
    }}finally{[Environment]::SetEnvironmentVariable('MAVEN_OPTS',$savedOpts,'Process')}
}
Check 'JacocoScope actual case executes native fixture then untimed audits and propagates fidelity failure' {
    $root=if($SetupTestRoot){$SetupTestRoot}else{Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}
    $fixture=Join-Path $root ('integrated-case-'+[guid]::NewGuid().ToString('N'))
    $project=Join-Path $fixture 'project';$output=Join-Path $fixture 'evidence'
    foreach($path in @($output,(Join-Path $project 'target/site/jacoco'),(Join-Path $project 'target/surefire-reports'))){New-Item $path -ItemType Directory -Force|Out-Null}
    $module=New-Module -ArgumentList ${function:RunJacocoScopeCase}.ToString(),${function:JacocoScopeArguments}.ToString(),$project,$output -ScriptBlock {
        param($body,$scope,$project,$output)
        $script:ProjectFullClone=$project;$script:OutputDirectory=$output;$script:events=@();$script:failProof=$false
        $script:result=@{test=@{default=@();candidate=@()};snapshots=@(@{reportSemantics=@('baseline')});selectedRuntime=@{arch='aarch64'};jacoco=@{freshness=@()}}
        function Require($condition,$message){if(-not$condition){throw $message}}
        function ClearJacocoTestOutput($p){$script:events+='cleanup';return @{readySinceMs=1}}
        function Run($name,$engine,$goals,$timed){
            Require ($engine-eq'daemon' -and $goals[0]-ceq'-Djacoco.instrumentation.includes=*') 'Wrong native fixture arm/engine'
            $script:events+=if($timed){'native-test'}else{'native-report'}
            [IO.File]::WriteAllBytes((Join-Path $script:ProjectFullClone 'target/jacoco.exec'),[byte[]]@(1,2,3))
            '<report/>'|Set-Content (Join-Path $script:ProjectFullClone 'target/site/jacoco/jacoco.xml')
            '<testsuite><properties/></testsuite>'|Set-Content (Join-Path $script:ProjectFullClone 'target/surefire-reports/TEST-fixture.xml')
            'fixture-native-output'|Set-Content (Join-Path $script:OutputDirectory "$name.log")
            return @{seconds=2;exitCode=0}
        }
        function JacocoExecEvidence($data,$arm){$script:events+='audit-exec';Require ($data.Length-eq3 -and $arm-eq'default') 'Exec fixture not passed';return @{arm=$arm;session=@{id='new'}}}
        function JacocoPostExitEvidence($log,$report,$properties,$context,$exec){
            $script:events+='post-proof'
            Require ($context.caseStart-eq1 -and $context.caseEnd-gt1 -and $context.arm-eq'default' -and $context.referenceSemantics[0]-eq'baseline' -and $exec.arm-eq'default') 'Fresh/session/reference inputs not wired'
            if($script:failProof){throw 'fixture-full-XML-mismatch'}
            return @{reportedPid=42;session=@{id='new'};osArgvObserved=$false}
        }
        function SourceGate {$script:events+='source-gate'}
        function Snapshot($name,$tests){$script:events+='snapshot';Require $tests 'Full test audit skipped';$script:result.snapshots+=@{reportSemantics=@('baseline')}}
        function Save {$script:events+='save'}
        . ([scriptblock]::Create("function JacocoScopeArguments { $scope }; function RunJacocoScopeCase { $body }"))
        Export-ModuleMember -Function RunJacocoScopeCase
    }
    $events=& $module {RunJacocoScopeCase fixture default @('test') $true;$script:events}
    Same $events @('cleanup','native-test','audit-exec','native-report','post-proof','source-gate','snapshot','save') 'Native/audit ordering changed'
    Rejects {& $module {$script:failProof=$true;RunJacocoScopeCase rejected default @('test') $true}} 'fixture-full-XML-mismatch'
}
Check 'JacocoScope restore finally preserves original bytes and surfaces cleanup plus restore failures' {
    $root=if($SetupTestRoot){$SetupTestRoot}else{Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}
    $project=Join-Path $root ('integrated-restore-'+[guid]::NewGuid().ToString('N'));New-Item $project -ItemType Directory -Force|Out-Null
    $original=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '..\..\..\..\pom.xml'))
    $trial=JacocoTrialPomBytes $original;[IO.File]::WriteAllBytes((Join-Path $project 'pom.xml'),$trial)
    $module=New-Module -ArgumentList ${function:RestoreComparisonPom}.ToString(),${function:RestoreJacocoPom}.ToString(),${function:AssertJacocoSource}.ToString(),$project,$original -ScriptBlock {
        param($restore,$bytes,$assert,$project,$original)
        $script:ProjectFullClone=$project;$script:originalPomBytes=$original;$script:trialPomHash='trial';$script:result=@{status='FAIL';cleanupFailure='fixture-cleanup-failure'}
        function Require($condition,$message){if(-not$condition){throw $message}}
        function SourceGate {if([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $script:ProjectFullClone 'pom.xml')))-cne[Convert]::ToBase64String($script:originalPomBytes)){throw 'Not restored'}}
        . ([scriptblock]::Create("function AssertJacocoSource { $assert }; function RestoreJacocoPom { $bytes }; function RestoreComparisonPom { $restore }"))
        Export-ModuleMember -Function RestoreComparisonPom
    }
    $r=& $module {try{throw 'fixture-build-failure'}catch{}finally{RestoreComparisonPom};$script:result}
    Require ($r.sourceRestoration.restored -and $r.status-eq'FAIL' -and $r.cleanupFailure-eq'fixture-cleanup-failure') 'Failure restoration or cleanup error lost'
    Remove-Item (Join-Path $project 'pom.xml');New-Item (Join-Path $project 'pom.xml') -ItemType Directory|Out-Null
    $r=& $module {RestoreComparisonPom;$script:result}
    Require ($r.status-eq'FAIL' -and $r.restorationFailure -and $r.cleanupFailure-eq'fixture-cleanup-failure') 'Restore failure masked cleanup failure'
}
Check 'JacocoScope case audits are outside Run, full freshness helpers required, inactive workflow opt-in only' {
    $body=${function:RunJacocoScopeCase}.ToString()
    Require ($body.IndexOf('ClearJacocoTestOutput')-lt$body.IndexOf('$phase=Run') -and $body.IndexOf('JacocoExecEvidence')-gt$body.IndexOf('$completed=')) 'Freshness audit moved inside native timer'
    foreach($token in 'JacocoPostExitEvidence','Snapshot','Copy-Item','seenSessions','seenForks','referenceSemantics'){Require ($body.Contains($token)) "Case omits $token"}
    Require ($body-notmatch'Get-CimInstance|Start-Sleep|StartFlightRecording') 'Timed polling/profiler introduced'
    $yaml=Get-Content (Join-Path $PSScriptRoot 'matched-comparison.workflow.yml') -Raw
    Require ($yaml-match'options: \[MavenVsDaemon, JacocoScope\]' -and $yaml-match'-Comparison \$env:COMPARISON' -and $yaml-match'JacocoScope requires current17' -and $yaml-match'jacoco-scope') 'Workflow opt-in missing'
}
Check 'JaCoCo pure arm plan is current17 daemon only with fixed alternating order' {
    $plan=JacocoScopePlan current17 3
    Require ($plan.engine-eq'daemon' -and $plan.javaMajor-eq17 -and $plan.samples-eq3) 'Wrong JaCoCo engine/runtime'
    Require ((JacocoScopeArguments default)-ceq'-Djacoco.instrumentation.includes=*') 'Default instrumentation differs'
    Require ((JacocoScopeArguments candidate)-ceq'-Djacoco.instrumentation.includes=org.springframework.samples.petclinic.*') 'Candidate instrumentation differs'
    Rejects {JacocoScopePlan normalizedHobl25 3}
    Rejects {JacocoScopePlan current17 0}
    Rejects {JacocoScopePlan current17 4}
    Rejects {JacocoScopeArguments stock}
    $plan.pairs[1]=@('default','candidate')
    Rejects {AssertJacocoScopePlan $plan} 'arm order differs'
}
Check 'JaCoCo common POM transform matches audited bytes and leaves report configuration unchanged' {
    $original=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '..\..\..\..\pom.xml'))
    $trial=JacocoTrialPomBytes $original
    $lf=[Text.Encoding]::UTF8.GetBytes([Text.Encoding]::UTF8.GetString($original).Replace("`r`n","`n"))
    Require ([Convert]::ToBase64String((JacocoTrialPomBytes $lf))-ceq[Convert]::ToBase64String($trial)) 'Both checkout conventions must install the exact common audited POM'
    Require ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($trial))-eq'A14A495B06D207043B9AE6B9CDE8B129357991AFD9DF0A68C94D93081E280B2F') 'Not the reviewed shared POM'
    [xml]$before=[Text.Encoding]::UTF8.GetString($original);[xml]$after=[Text.Encoding]::UTF8.GetString($trial)
    $ns=[Xml.XmlNamespaceManager]::new($before.NameTable);$ns.AddNamespace('m','http://maven.apache.org/POM/4.0.0')
    $path="//m:plugin[m:artifactId='jacoco-maven-plugin']/m:executions/m:execution[m:id='report']"
    Require ($before.SelectSingleNode($path,$ns).OuterXml-ceq$after.SelectSingleNode($path,$ns).OuterXml) 'Report execution filtered/changed'
    Require ($after.SelectNodes("//m:plugin[m:artifactId='jacoco-maven-plugin']/m:executions/m:execution[m:goals/m:goal='prepare-agent']/m:configuration/m:includes/m:include",$ns).Count-eq1) 'Agent binding missing/duplicated'
    Rejects {JacocoTrialPomBytes ([Text.Encoding]::UTF8.GetBytes('unreviewed POM'))}
}
Check 'JaCoCo source fingerprint rejects unrelated edits and restores exact original bytes or throws' {
    $original=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '..\..\..\..\pom.xml'))
    $trial=JacocoTrialPomBytes $original;$head='500158f732419217507c7656904b8e6aa1bcc0d6'
    AssertJacocoSource $head @() $original -Original
    AssertJacocoSource $head @(' M pom.xml') $trial
    Rejects {AssertJacocoSource $head @(' M pom.xml',' M src/Other.java') $trial} 'Unrelated source edits'
    Rejects {AssertJacocoSource $head @(' M pom.xml') $original} 'fingerprint differs'
    Rejects {AssertJacocoSource 'wrong' @() $original -Original} 'Wrong JaCoCo source pin'
    $root=if($SetupTestRoot){$SetupTestRoot}elseif($env:GITHUB_WORKSPACE){Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}else{throw 'Specify -SetupTestRoot outside public payload'}
    $dir=Join-Path $root ('jacoco-source-'+[guid]::NewGuid().ToString('N'));New-Item $dir -ItemType Directory -Force|Out-Null
    $pom=Join-Path $dir 'pom.xml';[IO.File]::WriteAllBytes($pom,$trial)
    $restored=RestoreJacocoPom $pom $original
    Require ($restored.restored -and [Convert]::ToBase64String([IO.File]::ReadAllBytes($pom))-ceq[Convert]::ToBase64String($original)) 'Byte restoration failed'
    $lf=[Text.Encoding]::UTF8.GetBytes([Text.Encoding]::UTF8.GetString($original).Replace("`r`n","`n"))
    [IO.File]::WriteAllBytes($pom,$trial);$null=RestoreJacocoPom $pom $lf
    Require ([Convert]::ToBase64String([IO.File]::ReadAllBytes($pom))-ceq[Convert]::ToBase64String($lf)) 'LF checkout restoration changed bytes'
    $blocked=Join-Path $dir 'blocked-pom.xml';New-Item $blocked -ItemType Directory|Out-Null
    Rejects {RestoreJacocoPom $blocked $original}
}
Check 'JaCoCo semantic XML ignores only sessions and catches line or descriptor changes without counter-value changes' {
    [xml]$xml='<report name="r"><sessioninfo id="a" start="1" dump="2"/><package name="p"><class name="p/C"><method name="f" desc="()V"><counter type="LINE" missed="0" covered="1"/></method></class><sourcefile name="C.java"><line nr="1" mi="0" ci="1" mb="0" cb="0"/></sourcefile></package></report>'
    [xml]$session=$xml.OuterXml.Replace('id="a" start="1" dump="2"','id="b" start="3" dump="4"')
    Same (JacocoSemanticElements $session) (JacocoSemanticElements $xml) 'Session was not excluded'
    [xml]$line=$xml.OuterXml.Replace('ci="1"','ci="2"')
    Same (CompleteCounters $line) (CompleteCounters $xml) 'Fixture counter changed'
    Rejects {Same (JacocoSemanticElements $line) (JacocoSemanticElements $xml) 'Changed line'}
    [xml]$method=$xml.OuterXml.Replace('desc="()V"','desc="(I)V"')
    Require ($method.SelectSingleNode('//counter').OuterXml-ceq$xml.SelectSingleNode('//counter').OuterXml) 'Fixture counter value changed'
    Rejects {Same (JacocoSemanticElements $method) (JacocoSemanticElements $xml) 'Changed descriptor'}
    Rejects {JacocoSemanticElements $null} 'Missing JaCoCo report'
}
Check 'JaCoCo report universe requires all 25 classes 750 counters and 333 lines' {
    $types=@('INSTRUCTION','BRANCH','LINE','COMPLEXITY','METHOD','CLASS')
    $classes=for($c=0;$c-lt25;$c++){
        $methods=for($m=0;$m-lt5;$m++){$counters=$types|ForEach-Object{"<counter type=`"$_`" missed=`"0`" covered=`"1`"/>"};"<method name=`"f$m`" desc=`"()V`">$($counters-join'')</method>"}
        "<class name=`"p/C$c`">$($methods-join'')</class>"
    }
    $lines=1..333|ForEach-Object{"<line nr=`"$_`" mi=`"0`" ci=`"1`" mb=`"0`" cb=`"0`"/>"}
    [xml]$xml="<report name=`"fixture`"><package name=`"p`">$($classes-join'')<sourcefile name=`"F.java`">$($lines-join'')</sourcefile></package></report>"
    $proof=JacocoReportEvidence $xml
    Require ($proof.classes.Count-eq25 -and $proof.counters.Count-eq750 -and $proof.lineRecords-eq333) 'Full report universe lost'
    $null=$xml.SelectSingleNode('//line').ParentNode.RemoveChild($xml.SelectSingleNode('//line'))
    Rejects {JacocoReportEvidence $xml} 'universe differs'
}
function JacocoPostExitFixture([bool]$Windows){
    $pidValue=if($Windows){11080}else{5604}
    $stamp=if($Windows){'2026-11-01T16:33:46.640-08:00'}else{'2026-11-02T00:32:39.295Z'}
    $start=if($Windows){1793579622505L}else{1793579556988L}
    $dump=if($Windows){1793579646213L}else{1793579575430L}
    $jdkHome=if($Windows){'C:\hostedtoolcache\jdk17'}else{'/Users/runner/jdk17/Contents/Home'}
    $exec=if($Windows){'C:\owned\project\target\jacoco.exec'}else{'/owned/project/target/jacoco.exec'}
    $agent=if($Windows){'C:\cache\org.jacoco.agent-0.8.15-runtime.jar'}else{'/cache/org.jacoco.agent-0.8.15-runtime.jar'}
    $runtime=@{home=$jdkHome;version='17.0.21.0.2';runtime='17.0.21.0.2+1-LTS';vendor='Microsoft';arch='aarch64'}
    $properties="<properties><property name=`"java.home`" value=`"$jdkHome`"/><property name=`"java.version`" value=`"17.0.21.0.2`"/><property name=`"java.runtime.version`" value=`"17.0.21.0.2+1-LTS`"/><property name=`"java.vendor`" value=`"Microsoft`"/><property name=`"os.arch`" value=`"aarch64`"/></properties>"
    $log="[INFO] argLine set to -javaagent:${agent}=destfile=$exec`n"+((1..9|ForEach-Object{"[INFO] $stamp INFO : Starting Context$_ using Java 17 with PID $pidValue"})-join"`n")
    return @{log=$log;report=[xml]"<sessioninfo id=`"fixture-$pidValue`" start=`"$start`" dump=`"$dump`"/>";properties=[xml]$properties;
        context=@{caseStart=$start-100;caseEnd=$dump+100;runtime=$runtime;arm='default';execPath=$exec;seenSessions=@();seenForks=@()};pid=$pidValue;stamp=$stamp;start=$start;dump=$dump}
}
Check 'Post-exit Windows and Mac offset timestamps collapse nine contexts to one honest reported PID' {
    foreach($windows in $true,$false){
        $f=JacocoPostExitFixture $windows
        $proof=JacocoPostExitEvidence $f.log $f.report $f.properties $f.context
        Require ($proof.reportedPid-eq$f.pid -and $proof.startupRecords-eq9 -and -not$proof.osArgvObserved -and -not$proof.osProcessCreationObserved) 'Wrong fork/provenance'
        Require ($proof.preparedAgent.implicitAll -and -not$proof.executionData) 'Prepared defaults mislabeled observed scope'
        $reuse=$f.context.Clone();$reuse.seenForks=@(@{reportedPid=$f.pid;session=@{start=$f.start-1000;dump=$f.start-500}})
        $null=JacocoPostExitEvidence $f.log $f.report $f.properties $reuse
    }
}
Check 'Post-exit evidence rejects missing ambiguous stale out-of-window and replayed witnesses' {
    foreach($windows in $true,$false){
        $f=JacocoPostExitFixture $windows
        Rejects {JacocoPostExitEvidence ($f.log-split"`n")[0] $f.report $f.properties $f.context} 'reported test PID'
        Rejects {JacocoPostExitEvidence ($f.log+"`n$($f.stamp) Starting Other using Java 17 with PID $($f.pid+1)") $f.report $f.properties $f.context} 'reported test PID'
        Rejects {JacocoPostExitEvidence $f.log $null $f.properties $f.context} 'Missing report'
        Rejects {JacocoPostExitEvidence $f.log ([xml]'<report/>') $f.properties $f.context} 'Exactly one fresh report session'
        $stale=[xml]"<sessioninfo id=`"old`" start=`"$($f.start-2000)`" dump=`"$($f.start-1000)`"/>"
        Rejects {JacocoPostExitEvidence $f.log $stale $f.properties $f.context} 'fresh case bounds'
        $inside=[xml]"<sessioninfo id=`"inside`" start=`"$($f.start+5000)`" dump=`"$($f.dump)`"/>"
        Rejects {JacocoPostExitEvidence $f.log $inside $f.properties $f.context} 'Startup PID witness outside'
        $late=$f.context.Clone();$late.caseEnd=$f.dump-1
        Rejects {JacocoPostExitEvidence $f.log $f.report $f.properties $late} 'fresh case bounds'
        $seen=$f.context.Clone();$seen.seenSessions=@($f.report.DocumentElement.GetAttribute('id'))
        Rejects {JacocoPostExitEvidence $f.log $f.report $f.properties $seen} 'Previously seen'
        $collision=$f.context.Clone();$collision.seenForks=@(@{reportedPid=$f.pid;session=@{start=$f.start;dump=$f.dump}})
        Rejects {JacocoPostExitEvidence $f.log $f.report $f.properties $collision} 'collision'
        Rejects {JacocoPostExitEvidence ($f.log.Replace('destfile=','excludes=*,destfile=')) $f.report $f.properties $f.context} 'Unknown/duplicate'
        $missing=$f.context.Clone();$missing.Remove('caseStart')
        Rejects {JacocoPostExitEvidence $f.log $f.report $f.properties $missing} 'invalid case bounds'
        $candidate=$f.context.Clone();$candidate.arm='candidate'
        $scoped=$f.log.Replace("destfile=$($f.context.execPath)","destfile=$($f.context.execPath),includes=org.springframework.samples.petclinic.*")
        Rejects {JacocoPostExitEvidence $scoped $f.report $f.properties $candidate} 'observed exec scope required'
    }
}
function JacocoExecFixture([string[]]$Names){
    $stream=[IO.MemoryStream]::new()
    $header=[Convert]::FromHexString('01C0C010071000017300000000000000010000000000000002')
    $stream.Write($header,0,$header.Length);$id=0
    foreach($name in $Names){
        $stream.WriteByte(17);$bytes=[BitConverter]::GetBytes([long](++$id));[Array]::Reverse($bytes);$stream.Write($bytes,0,8)
        $text=[Text.Encoding]::UTF8.GetBytes($name);$stream.WriteByte([byte]($text.Length-shr8));$stream.WriteByte([byte]($text.Length-band255));$stream.Write($text,0,$text.Length)
        $stream.WriteByte(1);$stream.WriteByte(1)
    }
    try{return ,$stream.ToArray()}finally{$stream.Dispose()}
}
Check 'Observed exec scope uses records and session, rejects wrong arms/truncation without inventing OS argv' {
    $app='org/springframework/samples/petclinic/Fixture'
    $candidate=JacocoExecFixture @($app)
    $default=JacocoExecFixture @($app,'org/springframework/ThirdParty')
    $a=JacocoExecEvidence $candidate candidate;$b=JacocoExecEvidence $default default
    Require ($a.records-eq1 -and $a.externalRecords-eq0 -and $b.externalRecords-eq1 -and $a.session.id-ceq's' -and -not$b.universalClassCoverageProven) 'Observed exec evidence differs'
    Rejects {JacocoExecEvidence $default candidate} 'outside app prefix'
    Rejects {JacocoExecEvidence $candidate default} 'external execution records'
    Rejects {JacocoExecEvidence ([byte[]]$candidate[0..($candidate.Length-2)]) candidate} 'Truncated'
    $unknown=[byte[]]$candidate.Clone();$unknown[0]=255
    Rejects {JacocoExecEvidence $unknown candidate} 'header must be first'
    $headerLast=[byte[]](@($candidate[5..($candidate.Length-1)])+@($candidate[0..4]))
    Rejects {JacocoExecEvidence $headerLast candidate} 'header must be first'
    $laterHeader=[byte[]](@($candidate)+@($candidate[0..4]))
    Rejects {JacocoExecEvidence $laterHeader candidate} 'Unexpected later'
}
Check 'JH-002 real linked ancestor rejects before deleting its target sentinel' {
    $root=if($SetupTestRoot){$SetupTestRoot}elseif($env:GITHUB_WORKSPACE){Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}else{throw 'Specify -SetupTestRoot'}
    $directory=Join-Path $root ('ancestor-link-'+[guid]::NewGuid().ToString('N'))
    $real=Join-Path $directory 'real-parent';$alias=Join-Path $directory 'linked-parent'
    New-Item (Join-Path $real 'project/.git'),(Join-Path $real 'project/target') -ItemType Directory -Force|Out-Null
    $sentinel=Join-Path $real 'project/target/jacoco.exec';[IO.File]::WriteAllText($sentinel,'owned sentinel')
    New-Item $alias -ItemType $(if($IsWindows){'Junction'}else{'SymbolicLink'}) -Target $real|Out-Null
    try{
        Rejects {ClearJacocoTestOutput (Join-Path $alias 'project')} 'Linked project ancestry'
        Require ((Test-Path $sentinel) -and [IO.File]::ReadAllText($sentinel)-ceq'owned sentinel') 'Ancestor target was deleted/changed'
    }finally{[IO.Directory]::Delete($alias)}
}
Check 'Exact-owned test cleanup retains source/classes and exposes linked-path/delete failures' {
    $root=if($SetupTestRoot){$SetupTestRoot}elseif($env:GITHUB_WORKSPACE){Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}else{throw 'Specify -SetupTestRoot'}
    $project=Join-Path $root ('cleanup-'+[guid]::NewGuid().ToString('N'))
    foreach($path in '.git','target/site/jacoco','target/surefire-reports','target/surefire','target/test-classes'){New-Item (Join-Path $project $path) -ItemType Directory -Force|Out-Null}
    'source'|Set-Content (Join-Path $project 'pom.xml');'keep'|Set-Content (Join-Path $project 'target/test-classes/Keep.class')
    'old'|Set-Content (Join-Path $project 'target/jacoco.exec')
    $clean=ClearJacocoTestOutput $project
    Require ($clean.clean -and $clean.paths.Count-eq4 -and (Test-Path (Join-Path $project 'pom.xml')) -and (Test-Path (Join-Path $project 'target/test-classes/Keep.class'))) 'Cleanup escaped owned output set'
    'old'|Set-Content (Join-Path $project 'target/jacoco.exec')
    $module=New-Module -ArgumentList ${function:ClearJacocoTestOutput}.ToString() -ScriptBlock {
        param($body)
        function Require($condition,$message){if(-not$condition){throw $message}}
        function Remove-Item {throw 'fixture-delete-error'}
        . ([scriptblock]::Create("function ClearJacocoTestOutput { $body }"))
        Export-ModuleMember -Function ClearJacocoTestOutput
    }
    Rejects {& $module {param($p) ClearJacocoTestOutput $p} $project} 'fixture-delete-error'
    $linked=New-Module -ArgumentList ${function:ClearJacocoTestOutput}.ToString(),$project -ScriptBlock {
        param($body,$owned)
        $script:owned=$owned
        function Require($condition,$message){if(-not$condition){throw $message}}
        function Get-Item {param($LiteralPath,[switch]$Force,$ErrorAction)
            if($LiteralPath-eq(Join-Path $script:owned 'target')){return @{Attributes=[IO.FileAttributes]::ReparsePoint}}
            Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
        }
        function Remove-Item {throw 'Delete must not precede complete path validation'}
        . ([scriptblock]::Create("function ClearJacocoTestOutput { $body }"))
        Export-ModuleMember -Function ClearJacocoTestOutput
    }
    Rejects {& $linked {param($p) ClearJacocoTestOutput $p} $project} 'Linked test-output'
}
Check 'Raw Maven metadata preserves same-length CRLF/LF distinctions exactly' {
    $name='META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties'
    $a=[Text.Encoding]::UTF8.GetBytes("a=1`r`nb=2`n")
    $b=[Text.Encoding]::UTF8.GetBytes("a=1`nb=2`r`n")
    Require ($a.Length-eq$b.Length) 'Fixture lengths differ'
    $script:rawMetadataHashes=@()
    foreach($bytes in @($a,$b)){
        WithRawMetadataFixture @(@{name=$name;bytes=$bytes}) {
            param($archive,$directory)
            $manifest=RetainRawMetadata $archive @($name) $directory
            $record=$manifest.entries[0];$raw=Join-Path $directory $record.rawPath
            Require ($record.entry-ceq$name -and $record.bytes-eq$bytes.Length -and $record.status-eq'retained') 'Raw entry receipt mismatch'
            Require ([Convert]::ToBase64String([IO.File]::ReadAllBytes($raw))-ceq[Convert]::ToBase64String($bytes)) 'Raw entry bytes rewritten'
            Require ($record.sha256-eq(Get-FileHash $raw).Hash) 'Raw hash mismatch'
            $script:rawMetadataHashes+=,$record.sha256
        }
    }
    Require ($script:rawMetadataHashes.Count-eq2 -and $script:rawMetadataHashes[0]-ne$script:rawMetadataHashes[1]) 'Same length hid different metadata bytes'
}
Check 'Missing duplicate and empty required raw metadata fail with retained receipts' {
    $name='META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties'
    foreach($kind in 'absent','duplicate','empty'){
        $entries=switch($kind){
            'absent' {@(@{name='unrelated';bytes=[byte[]]@(1)})}
            'duplicate' {@(@{name=$name;bytes=[byte[]]@(1)},@{name=$name;bytes=[byte[]]@(2)})}
            'empty' {@(@{name=$name;bytes=[byte[]]@()})}
        }
        WithRawMetadataFixture $entries {
            param($archive,$directory)
            Rejects {RetainRawMetadata $archive @($name) $directory}
            $manifest=Get-Content (Join-Path $directory 'manifest.json') -Raw|ConvertFrom-Json
            Require ($manifest.status-eq'FAIL' -and $manifest.entries[0].status-eq$kind -and $manifest.entries[0].error) 'Required-entry failure not explicit'
            Require (@(Get-ChildItem $directory -Filter '*.raw' -File).Count-eq0) 'Invalid required entry was selected silently'
        }
    }
}
Check 'RAW-001 real malformed ZIP actual bytes must be nonempty and match declared length' {
    $name='META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties'
    # Exact independently failing stored-ZIP fixture: declared length 1, empty stream.
    $empty=[Convert]::FromBase64String('UEsDBBQAAAAAAOhQYl0AAAAAAAAAAAEAAABKAAAATUVUQS1JTkYvbWF2ZW4vb3JnLnNwcmluZ2ZyYW1ld29yay5zYW1wbGVzL3NwcmluZy1wZXRjbGluaWMvcG9tLnByb3BlcnRpZXNQSwECFAAUAAAAAADoUGJdAAAAAAAAAAABAAAASgAAAAAAAAAAAAAAAAAAAAAATUVUQS1JTkYvbWF2ZW4vb3JnLnNwcmluZ2ZyYW1ld29yay5zYW1wbGVzL3NwcmluZy1wZXRjbGluaWMvcG9tLnByb3BlcnRpZXNQSwUGAAAAAAEAAQB4AAAAaAAAAAAA')
    $memory=[IO.MemoryStream]::new()
    $writer=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Create,$true)
    try{
        $stream=$writer.CreateEntry($name,[IO.Compression.CompressionLevel]::NoCompression).Open()
        try{$stream.WriteByte(120)}finally{$stream.Dispose()}
    }finally{$writer.Dispose()}
    $short=$memory.ToArray();$memory.Dispose()
    $declared=[BitConverter]::GetBytes([uint32]2)
    [Array]::Copy($declared,0,$short,22,4)
    $central=-1
    for($i=0;$i-le$short.Length-4;$i++){
        if([BitConverter]::ToUInt32($short,$i)-eq0x02014b50){$central=$i;break}
    }
    Require ($central-ge0) 'Fixture central directory absent'
    [Array]::Copy($declared,0,$short,$central+24,4)
    foreach($case in @(@{bytes=$empty;declared=1;actual=0;message='Empty actual required'},@{bytes=$short;declared=2;actual=1;message='length mismatch'})){
        $root=if($SetupTestRoot){$SetupTestRoot}elseif($env:GITHUB_WORKSPACE){Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}else{throw 'Specify -SetupTestRoot outside public payload'}
        $directory=Join-Path $root ('malformed-metadata-'+[guid]::NewGuid().ToString('N'))
        New-Item $directory -ItemType Directory -Force|Out-Null
        [IO.File]::WriteAllBytes((Join-Path $directory 'input.zip'),$case.bytes)
        $memory=[IO.MemoryStream]::new([byte[]]$case.bytes)
        $archive=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Read)
        try{
            Require ($archive.GetEntry($name).Length-eq$case.declared) 'Malformed ZIP header fixture mismatch'
            $stream=$archive.GetEntry($name).Open();$actual=[IO.MemoryStream]::new()
            try{$stream.CopyTo($actual);Require ($actual.Length-eq$case.actual) 'Malformed ZIP stream fixture mismatch'}finally{$stream.Dispose();$actual.Dispose()}
            Rejects {RetainRawMetadata $archive @($name) $directory} $case.message
            $manifest=Get-Content (Join-Path $directory 'manifest.json') -Raw|ConvertFrom-Json
            $record=$manifest.entries[0]
            Require ($manifest.status-eq'FAIL'-and$record.status-eq'error'-and$record.bytes-eq$case.actual) 'Malformed required entry mislabeled retained'
            Require ($null-eq$record.rawPath-and$null-eq$record.sha256-and$record.error) 'Malformed bytes received a success artifact/hash'
            Require (@(Get-ChildItem $directory -Filter '*.raw' -File).Count-eq0) 'Malformed required bytes were written as retained'
        }finally{$archive.Dispose();$memory.Dispose()}
    }
}
Check 'Raw metadata write failure is explicit rather than a false retained record' {
    $name='META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties'
    WithRawMetadataFixture @(@{name=$name;bytes=[byte[]]@(239,187,191,97,61,255,0,13,10)}) {
        param($archive,$directory)
        New-Item (Join-Path $directory '01-pom.properties.raw') -ItemType Directory|Out-Null
        Rejects {RetainRawMetadata $archive @($name) $directory} 'Failed retaining packaged'
        $manifest=Get-Content (Join-Path $directory 'manifest.json') -Raw|ConvertFrom-Json
        Require ($manifest.status-eq'FAIL' -and $manifest.entries[0].status-eq'error') 'Write failure reported as retained'
    }
}
Check 'Raw metadata retention is in untimed Snapshot, not measured Run' {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
    $functions=$ast.FindAll({param($n) $n-is[Management.Automation.Language.FunctionDefinitionAst]},$true)
    $run=@($functions|Where-Object Name -eq Run)[0]
    $snapshot=@($functions|Where-Object Name -eq Snapshot)[0]
    Require ($run.Body.Extent.Text-notmatch'\bRetainRawMetadata\b') 'Retention entered measured command'
    Require ($snapshot.Body.Extent.Text-match'\bRetainRawMetadata\b' -and $snapshot.Body.Extent.Text.Contains('META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties')) 'Snapshot omits required root Maven bytes'
}
Check 'MAC-JNI-001 actual Mac mapped module wins over JVM option banner' {
    $owned='/Users/runner/work/spring-petclinic/spring-petclinic/comparison-owned/evidence/jvm-owned'
    $expected="$owned/mvndnative-unknown-7ec026a594b9b494-libmvndnative.jnilib"
    $banner="Picked up JAVA_TOOL_OPTIONS: `"-Djava.io.tmpdir=$owned`" `"-Dmvndnative.tmpdir=$owned`" --enable-native-access=ALL-UNNAMED"
    $fixture=$banner+"`n5324:`nDynamic libraries:`n0x00000001013f8000 `t"+$expected+"`n0x0000000101408000 `t$owned/jansi-2.4.3-6ad94ed535b831db-libjansi.jnilib"
    Require ((MacNativeLibraryPath $fixture)-ceq$expected) 'Mapped JNI path lost or JVM banner selected'
    Rejects {MacNativeLibraryPath $banner} 'Expected exactly one mapped JNI library record'
    Rejects {MacNativeLibraryPath 'Picked up JAVA_TOOL_OPTIONS: "-Dmvndnative.tmpdir=/owned/mvndnative.jnilib"'} 'Expected exactly one mapped JNI library record'
}
Check 'MAC-JNI-001 mapped path spaces, horizontal spacing, CRLF and Mac suffixes' {
    $path='/Users/runner/Work With Spaces/jvm-owned/mvndnative-unknown-libmvndnative.jnilib'
    Require ((MacNativeLibraryPath ("0x1234 `t"+$path+"`r`n"))-ceq$path) 'Spaces/CRLF damaged mapped path'
    Require ((MacNativeLibraryPath '0x1234 /owned/libmvndnative.dylib')-ceq'/owned/libmvndnative.dylib') 'Mapped dylib not parsed'
}
Check 'MAC-JNI-001 absent or ambiguous modules fail closed' {
    Rejects {MacNativeLibraryPath '0x1234 /owned/libjansi.jnilib'} 'Expected exactly one mapped JNI library record'
    Rejects {MacNativeLibraryPath "0x1234 /owned/libmvndnative.jnilib`n0x5678 /other/libmvndnative.jnilib"} 'Expected exactly one mapped JNI library record'
}
Check 'MAC-JNI-001 parsing preserves evidence for existing ownership rejection' {
    Require ((MacNativeLibraryPath '0x1234 /other/libmvndnative.jnilib')-ceq'/other/libmvndnative.jnilib') 'Parser rewrote unowned path'
}
Check 'PowerShell AST parses' {
    foreach($path in @($runner,$PSCommandPath)){
        $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
        Require ($errors.Count-eq0) "Parser error: $path"
    }
}
Check 'Windows current17 executable plan, no I/O' {
    $p=& $runner -PlanOnly -Platform Windows -MvndHome 'C:\fixture\mvnd' -Samples 3 -LoopbackTests|ConvertFrom-Json
    Require ($p.stock-eq'C:\fixture\mvnd\mvn\bin\mvn.cmd') 'Windows stock path'
    Require ($p.sourcePin-eq'500158f732419217507c7656904b8e6aa1bcc0d6' -and $p.javaMajor-eq17 -and $p.expectedTests-eq79) 'Current workload'
    Require ($p.pairs.Count-eq3 -and $p.pairs[1][0]-eq'daemon') 'Alternating order'
}
Check 'MacOS normalizedHobl25 executable plan, no I/O' {
    $p=& $runner -PlanOnly -Platform MacOS -Workload normalizedHobl25 -MvndHome '/fixture/mvnd' -Samples 3 -LoopbackTests|ConvertFrom-Json
    Require ($p.candidate-eq'/fixture/mvnd/bin/mvnd' -and $p.stock-eq'/fixture/mvnd/mvn/bin/mvn') 'Mac paths'
    Require ($p.javaMajor-eq25 -and $p.expectedTests-eq56 -and $p.scope-match'NOT original') 'Normalized HOBL label'
}
Check 'Median, including even-length and empty rejection' {
    Require ((Median @(3,1,2))-eq2 -and (Median @(1,4))-eq2.5) 'Median arithmetic'
    Rejects {Median @()}
}
Check 'Nonzero exit rejects, zero accepted' {NativeCode 0 'fixture';Rejects {NativeCode 7 'fixture'}}
Check 'All six coverage types, overloaded methods and sourcefile identities' {
    [xml]$x='<report name="r"><package name="p"><class name="c"><method name="f" desc="()V"><counter type="INSTRUCTION" missed="0" covered="1"/></method><method name="f" desc="(I)V"><counter type="METHOD" missed="0" covered="1"/></method><counter type="CLASS" missed="0" covered="1"/><counter type="BRANCH" missed="1" covered="1"/></class><sourcefile name="c.java"><counter type="LINE" missed="0" covered="1"/><counter type="COMPLEXITY" missed="0" covered="1"/></sourcefile></package></report>'
    $a=CompleteCounters $x;Require ($a.Count-eq6) 'Dropped semantic counter'
    [xml]$changed=$x.OuterXml.Replace('type="LINE" missed="0"','type="LINE" missed="1"')
    Rejects {Same (CompleteCounters $changed) $a 'Counter mismatch'}
    [xml]$identityChanged=$x.OuterXml.Replace('desc="(I)V"','desc="(J)V"')
    Rejects {Same (CompleteCounters $identityChanged) $a 'Method identity mismatch'}
}
Check 'Recursive nested testcase identity and skip status' {
    $ids=TestIdentities @([xml]'<testsuite tests="0"><testsuite><testcase classname="a" name="one"/><testcase classname="a" name="two"><skipped/></testcase></testsuite></testsuite>')
    Require ($ids.Count-eq2 -and $ids[1].state-eq'skipped') 'Nested testcase loss'
}
Check 'Both platforms and both supported workload plan combinations' {
    foreach($os in 'Windows','MacOS'){foreach($mode in 'current17','normalizedHobl25'){
        $p=& $runner -PlanOnly -Platform $os -Workload $mode -MvndHome 'fixture' -Samples 3 -LoopbackTests|ConvertFrom-Json
        Require ($p.platform-eq$os -and $p.workload-eq$mode -and $p.mavenCore-eq'3.9.16' -and $p.online -and $p.samples-eq3 -and $p.loopbackTests) 'Matched CI plan drift'
    }}
}
Check 'Cross-OS summary rejects changed JDK identity' {
    $correct=@{tests=@();coverage=@{};classes=@{};testClasses=@{};dependencies=@{};jarSha256='fixture'}
    $w=@{status='PASS';plan=(ComparisonPlan Windows current17 fixture);javaIdentity='same';mavenCoreSha256='same';correctness=$correct;package=@{stock=@(1,2,3);daemon=@(1,2,3)};test=@{stock=@(1,2,3);daemon=@(1,2,3)}}
    $m=@{status='PASS';plan=(ComparisonPlan MacOS current17 fixture);javaIdentity='same';mavenCoreSha256='same';correctness=$correct;package=$w.package;test=$w.test}
    $w.plan.samples=3;$m.plan.samples=3
    $summary=CompareEvidence $w $m;Require ($summary.stockPackageWindowsToMac-eq1) 'Pure fixture ratio'
    $m.javaIdentity='different';Rejects {CompareEvidence $w $m}
}
Check 'Explicit module and loopback arguments are shared, smoke plan is labeled' {
    $args=@(CommonMavenArguments 'cache' 'settings' 'module-pom' $true)
    Require ($args -contains '--file' -and $args -contains 'module-pom' -and $args -contains '-Dserver.address=127.0.0.1') 'Explicit common source/bind options missing'
    Require (@($args|Where-Object {$_ -like '-Dmanagement.server.address=*'}).Count-eq0) 'Shared-port management forbids a separate address'
    $p=& $runner -PlanOnly -Platform Windows -MvndHome 'fixture' -Samples 1 -LoopbackTests|ConvertFrom-Json
    Require ($p.samples-eq1 -and $p.loopbackTests) 'Smoke plan mismatch'
}
Check 'TV006 actual daemon and Surefire runtime mismatches reject' {
    $expected=@{home=(Join-Path $PSScriptRoot 'fixture17');version='17';runtime='17+1';vendor='Microsoft';arch='aarch64'}
    AssertRuntime $expected $expected 'matching fixture'
    $wrongHome=$expected.Clone();$wrongHome.home=Join-Path $PSScriptRoot 'other17'
    Rejects {AssertRuntime $wrongHome $expected 'daemon fixture'} 'daemon fixture actual home differs'
    $wrongRuntime=$expected.Clone();$wrongRuntime.runtime='17+2'
    Rejects {AssertRuntime $wrongRuntime $expected 'Surefire fixture'} 'Surefire fixture actual runtime differs'
    $decoded=RuntimeProfile 'java.home=C\:\\fixture\\jdk17' -EscapedProperties
    Require ($decoded.home-eq'C:\fixture\jdk17') 'jcmd Java-properties path was not decoded'
}
Check 'TV007 PID reuse immediately before forced termination never kills replacement' {
    $expected=@{pid=42;started='original';executable='java';command='java owned-registry -Dmvnd.id=fixture';registry='owned-registry';daemonId='fixture'}
    $script:fixtureReads=0;$script:fixtureKills=0
    $outcome=SafeOwnedStop $expected {
        param($id);$script:fixtureReads++
        if($script:fixtureReads-eq1){$expected}else{@{pid=42;started='replacement';executable='other';command='unrelated'}}
    } {param($id);throw [TimeoutException]::new('pure mocked wait timeout')} {param($id);$script:fixtureKills++}
    Require ($script:fixtureKills-eq0 -and $outcome.action-eq'reused-before-force; untouched') 'Replacement PID was killed'
    Rejects {SafeOwnedStop $expected {param($id);$expected} {param($id);throw [InvalidOperationException]::new('not a timeout')} {param($id);$script:fixtureKills++}}
    Require ($script:fixtureKills-eq0) 'Non-timeout error escalated to termination'
}
Check 'TV008 opposite loopback modes reject before ratios' {
    $w=@{status='PASS';plan=@{platform='Windows';samples=3;loopbackTests=$true};deviations=@('loopback')}
    $m=@{status='PASS';plan=@{platform='MacOS';samples=3;loopbackTests=$false};deviations=@()}
    Rejects {CompareEvidence $w $m} 'Cross-OS loopbackTests mismatch'
}
Check 'Manual workflow, exact two-label matrix, explicit acknowledgement, no retries/secrets' {
    $y=Get-Content (Join-Path $PSScriptRoot 'matched-comparison.workflow.yml') -Raw
    Require ($y-match'workflow_dispatch:' -and $y-notmatch'(?m)^  (push|pull_request|schedule):') 'Automatic trigger'
    Require ($y-match'runner: \[windows-11-arm, macos-15\]') 'Runner allocation changed'
    Require ($y-match'I_HAVE_APPROVAL_AND_BUDGET' -and $y-notmatch'secrets\.|continue-on-error|retry') 'Authorization/false-success scope'
    Require ($y-match'architecture: aarch64' -and $y-match'VC.Tools.ARM64') 'Native tool preflight missing'
    Require ($y-match'-Workload \$env:WORKLOAD -Samples 3 -LoopbackTests -ExclusiveSlotApproved') 'Both matrix jobs must explicitly use the validated common loopback policy'
}
$workflowRuns=@{}
Check 'Every embedded workflow PowerShell block parses without execution' {
    $lines=Get-Content (Join-Path $PSScriptRoot 'matched-comparison.workflow.yml')
    $blocks=0
    for($i=0;$i-lt$lines.Count;$i++){
        if($lines[$i]-match'^      - name: (.+)$'){$stepName=$Matches[1]}
        if($lines[$i]-match'^\s+run: \|$'){
            $body=@();$i++
            while($i-lt$lines.Count -and ($lines[$i]-match'^          ' -or -not$lines[$i].Trim())){
                $body+=if($lines[$i].Length-ge10){$lines[$i].Substring(10)}else{''};$i++
            }
            $i--;$errors=$null;$tokens=$null
            $null=[Management.Automation.Language.Parser]::ParseInput(($body -join "`n"),[ref]$tokens,[ref]$errors)
            Require ($errors.Count-eq0) 'Workflow PowerShell syntax';$blocks++
            $workflowRuns[$stepName]=$body -join "`n"
        }
    }
    Require ($blocks-eq6) 'Expected six embedded evidence/JDK/setup/run blocks'
}
Check 'Actual pinned JDK downloader covers four native builds and rejects wrong digests without resolver' {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($workflowRuns['Fetch checksum-pinned official Microsoft JDK without resolver catalog'],[ref]$tokens,[ref]$errors)
    $definitions=($ast.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.FunctionDefinitionAst]}|ForEach-Object {$_.Extent.Text})-join"`n"
    $saved=@{};foreach($n in 'GITHUB_WORKSPACE','GITHUB_OUTPUT','WORKLOAD'){$saved[$n]=[Environment]::GetEnvironmentVariable($n)}
    try {
        $root=if($SetupTestRoot){$SetupTestRoot}elseif($env:GITHUB_WORKSPACE){Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}else{throw 'Specify -SetupTestRoot outside public payload'}
        foreach($mode in 'current17','normalizedHobl25'){foreach($windows in $true,$false){
            $case=Join-Path $root ('jdk-'+[guid]::NewGuid().ToString('N'));New-Item $case -ItemType Directory -Force|Out-Null
            $env:GITHUB_WORKSPACE=$case;$env:GITHUB_OUTPUT=Join-Path $case 'outputs';$env:WORKLOAD=$mode
            $module=New-Module -ArgumentList $definitions -ScriptBlock {
                param($text)
                . ([scriptblock]::Create($text))
                function Invoke-WebRequest($Uri,$OutFile){'mock archive only'|Set-Content $OutFile}
                function Get-FileHash($Path,$Algorithm){@{Hash=$script:expectedHash}}
            }
            $pin=& $module {param($w) Get-PinnedMicrosoftJdk $env:WORKLOAD $w} $windows
            Require ($pin.name-match'aarch64' -and $pin.sha256.Length-eq64 -and $pin.url-like'https://aka.ms/download-jdk/*') 'Native publisher pin incomplete'
            & $module {param($w,$hash) $script:expectedHash=$hash;Invoke-PinnedMicrosoftJdk $w} $windows $pin.sha256
            $record=Get-Content (Join-Path $case 'comparison-owned/setup-evidence/jdk-archive.json') -Raw|ConvertFrom-Json
            Require ($record.status-eq'PASS' -and $record.pin.build-in@('17.0.21.0.2','25.0.5.0.2')) 'Verified local-file handoff failed'
            Remove-Item $env:GITHUB_OUTPUT
            Rejects {& $module {param($w) $script:expectedHash='wrong';Invoke-PinnedMicrosoftJdk $w} $windows} 'checksum mismatch'
            Require (-not(Test-Path $env:GITHUB_OUTPUT)) 'Unverified archive exported to setup-java'
            $record=Get-Content (Join-Path $case 'comparison-owned/setup-evidence/jdk-archive.json') -Raw|ConvertFrom-Json
            Require ($record.status-eq'FAIL' -and $record.scriptExitCode-eq1) 'JDK checksum failure evidence missing'
        }}
        $yaml=Get-Content (Join-Path $PSScriptRoot 'matched-comparison.workflow.yml') -Raw
        Require ($yaml-match'distribution: jdkfile' -and $yaml-match'jdkFile: \$\{\{ steps.jdk_archive.outputs.jdkFile \}\}') 'Catalog resolver unexpectedly restored'
    } finally {foreach($n in $saved.Keys){[Environment]::SetEnvironmentVariable($n,$saved[$n])}}
}
Check 'Actual hosted environment boundary preserves strict unknown guard and fresh output' {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($workflowRuns['Matched package and separate test screen'],[ref]$tokens,[ref]$errors)
    $definition=($ast.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.FunctionDefinitionAst]}|ForEach-Object {$_.Extent.Text})-join"`n"
    . ([scriptblock]::Create($definition))
    $runnerAst=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
    $optionGuard=($runnerAst.EndBlock.Statements|Where-Object {$_.Extent.Text.Contains('Review nonempty injected option')}).Extent.Text
    $freshGuard=(Get-Content $runner|Where-Object {$_-match'^Require ' -and $_.Contains("'Fresh output required'")})-join"`n"
    Require ($optionGuard -and $freshGuard) 'Actual pinned guards absent'
    $names=@('MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MVND_OPTS','MVND_CLIENT','GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR','GITHUB_WORKSPACE')
    $before=@{};foreach($n in $names){$before[$n]=[Environment]::GetEnvironmentVariable($n)}
    try {
        foreach($n in $names){if($n-ne'GITHUB_WORKSPACE'){Remove-Item "Env:$n" -ErrorAction SilentlyContinue}}
        $root=if($SetupTestRoot){$SetupTestRoot}else{Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}
        $env:GITHUB_WORKSPACE=Join-Path $root ('hosted-env-'+[guid]::NewGuid().ToString('N'))
        $OutputDirectory=Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/evidence'
        $env:MAVEN_OPTS='-Xms256m'
        Rejects {& ([scriptblock]::Create($optionGuard))} 'Review nonempty injected option MAVEN_OPTS first'
        $script:hostedCallbacks=0
        $callback={& ([scriptblock]::Create($optionGuard));& ([scriptblock]::Create($freshGuard));$script:hostedCallbacks++}
        Invoke-ReviewedHostedEnvironment $callback $true
        Require ($script:hostedCallbacks-eq1 -and $env:MAVEN_OPTS-ceq'-Xms256m' -and -not(Test-Path $OutputDirectory)) 'Reviewed default normalization/restoration/fresh guard failed'
        $env:MAVEN_OPTS='-Xmx9g'
        Rejects {Invoke-ReviewedHostedEnvironment $callback $true} 'Unknown injected MAVEN_OPTS'
        Require ($script:hostedCallbacks-eq1 -and $env:MAVEN_OPTS-ceq'-Xmx9g') 'Unknown option ran or mutated'
        $receipt=Get-Content (Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/hosted-environment.json') -Raw|ConvertFrom-Json
        Require ($receipt.originalValue-eq'[REDACTED_UNKNOWN_OPTION_VALUE]' -and $receipt.decision-eq'reject-unknown') 'Unknown option receipt leaked/misclassified'
        $env:MAVEN_OPTS='-Xms256m'
        Rejects {Invoke-ReviewedHostedEnvironment $callback $false} 'Unknown injected MAVEN_OPTS'
        $env:MAVEN_OPTS=$null
        Invoke-ReviewedHostedEnvironment $callback $false
        Require ($script:hostedCallbacks-eq2) 'Mac empty shared baseline rejected'
        $env:JAVA_TOOL_OPTIONS='-Xmx9g'
        Rejects {Invoke-ReviewedHostedEnvironment $callback $true} 'Review nonempty injected option JAVA_TOOL_OPTIONS first'
        Require ($script:hostedCallbacks-eq2) 'Other unknown injected option bypassed unchanged runner guard'
    } finally {foreach($n in $names){if($null-eq$before[$n]){Remove-Item "Env:$n" -ErrorAction SilentlyContinue}else{[Environment]::SetEnvironmentVariable($n,$before[$n])}}}
}
Check 'Actual workflow setup retains failed diagnostics and success leaves runner output fresh' {
    if(-not$SetupTestRoot){
        if(-not$env:GITHUB_WORKSPACE){throw 'Set -SetupTestRoot outside the publication payload for local mocked setup tests'}
        $SetupTestRoot=Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'
    }
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($workflowRuns['Explicit driver setup, checksum and Windows ARM64 compiler preflight'],[ref]$tokens,[ref]$errors)
    $functions=($ast.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.FunctionDefinitionAst]}|ForEach-Object {$_.Extent.Text})-join"`n"
    Require ($functions-match'function Invoke-ComparisonSetup') 'Actual workflow setup implementation absent'
    $setupNames=@('GITHUB_WORKSPACE','GITHUB_ENV','JAVA_HOME','WORKLOAD','ComSpec','ProgramFiles(x86)','CHECKOUT_OUTCOME','JAVA_OUTCOME','STATIC_OUTCOME','DRIVER_OUTCOME')
    $saved=PortableEnvironmentSnapshot
    try {
        foreach($scenario in 'checksum','missing-compiler','native-failure','success'){
            $caseRoot=Join-Path $SetupTestRoot ($scenario+'-'+[guid]::NewGuid().ToString('N'))
            New-Item $caseRoot -ItemType Directory -Force|Out-Null
            $env:GITHUB_WORKSPACE=$caseRoot;$env:GITHUB_ENV=Join-Path $caseRoot 'github-env';$env:JAVA_HOME=Join-Path $caseRoot 'mock-jdk';$env:WORKLOAD='current17'
            if($TestUnexpectedCheck-ceq'workflow-setup-seeded'){throw 'SYNTHETIC_FULL_SUITE_SETUP_FAILURE'}
            $env:ComSpec=Join-Path $caseRoot 'mock-cmd.exe';[Environment]::SetEnvironmentVariable('ProgramFiles(x86)',$caseRoot)
            $module=New-Module -ArgumentList $functions,$caseRoot,$scenario -ScriptBlock {
                param($definitions,$fixtureRoot,$fixtureCase)
                . ([scriptblock]::Create($definitions))
                function Invoke-WebRequest($Uri,$OutFile){'mock download'|Set-Content $OutFile}
                function Get-FileHash($Path,$Algorithm){
                    $value=switch -Regex ($Path){
                        'vendor\.zip$' {if($fixtureCase-eq'checksum'){'wrong'}else{'4DD97B1F26525055CEC960FB5B953B70D1E6606F96F5B096EFA932754FD3E9D0238E00CA97779368F29CB751F1776445C45DA618EA8D0D84692C3B936087309F'}}
                        '\.c$' {'31198B329118419DB30A8178FB438F44953B33F346C30E1BF313DF2F4E6A021E'}
                        '\.h$' {'E12BE1E39BB5FD0755B87D151D91712D9606D1118B1F6CCAB6BC2CB0857AA9DF'}
                    };@{Hash=$value}
                }
                function Expand-Archive($Path,$DestinationPath){
                    $d=Join-Path $DestinationPath 'maven-mvnd-1.0.6-windows-amd64'
                    foreach($relative in 'bin/mvnd.exe','mvn/lib/mvnd/mvnd-native-1.0.6.jar','mvn/lib/maven-core-3.9.16.jar'){
                        $file=Join-Path $d $relative;New-Item (Split-Path $file -Parent) -ItemType Directory -Force|Out-Null;'mock file'|Set-Content $file
                    }
                }
                function Binary-Setup($path){@{format='MOCK';machine='0xAA64';fileVersion='mock-only';path=$path}}
                function Add-SetupResource($jar,$dll){$script:mockResourceAdded=$true}
                function Start-SetupProcess($file,$arguments,$log){
                    if($file-match'java(?:\.exe)?$'){"java.runtime.version = 17.0.21.0.2+1-LTS`njava.vendor = Microsoft`nos.arch = aarch64"|Set-Content $log;return 0}
                    if($file-match'vswhere\.exe$'){
                        ''|Set-Content $log
                        if($fixtureCase-eq'native-failure'){return 23}
                        if($fixtureCase-ne'missing-compiler'){(Join-Path $fixtureRoot 'mock-vs')|Set-Content $log}
                        return 0
                    }
                    if($file-eq$env:ComSpec){
                        ((Join-Path $fixtureRoot 'cl.exe')+"`nMOCK compiler version; target ARM64")|Set-Content $log
                        'mock DLL'|Set-Content (Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/native/mvndnative.dll')
                        return 0
                    }
                    'mock process success'|Set-Content $log;return 0
                }
                $mockSetup=Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence'
                New-Item $mockSetup -ItemType Directory -Force|Out-Null
                @{pin=@{expectedRuntime='17.0.21.0.2+1-LTS'}}|ConvertTo-Json|Set-Content (Join-Path $mockSetup 'jdk-archive.json')
                $script:fixtureCaught=$null;try{Invoke-ComparisonSetup -Windows $true}catch{$script:fixtureCaught=$_.Exception.Message}
            }
            $actual=& $module { [pscustomobject]@{state=$script:state;setup=$script:setup} }
            $env:CHECKOUT_OUTCOME='success';$env:JAVA_OUTCOME='success';$env:STATIC_OUTCOME='success';$env:DRIVER_OUTCOME=if($scenario-eq'success'){'success'}else{'failure'}
            & ([scriptblock]::Create($workflowRuns['Finalize setup diagnostics even when an action failed']))
            $json=Join-Path $actual.setup 'setup.json'
            Require ((Test-Path $json) -and (Get-Item $json).Length-gt0) 'Failure artifact empty/missing'
            $record=Get-Content $json -Raw|ConvertFrom-Json
            if($scenario-eq'checksum'){Require ($record.status-eq'FAIL' -and $record.stage-eq'vendor-checksum' -and $null-eq$record.nativeExitCode -and $record.scriptExitCode-eq1) 'Checksum diagnostic gate'}
            elseif($scenario-eq'missing-compiler'){Require ($record.status-eq'FAIL' -and $record.stage-eq'compiler-discovery' -and $record.nativeExitCode-eq0 -and $record.error-match'component absent') 'Missing compiler must retain native 0 versus semantic failure'}
            elseif($scenario-eq'native-failure'){Require ($record.status-eq'FAIL' -and $record.nativeExitCode-eq23 -and $record.scriptExitCode-eq1) 'Native failure code lost'}
            else{Require ($record.status-eq'PASS' -and $record.scriptExitCode-eq0) 'Mock successful setup'}
            $OutputDirectory=Join-Path $caseRoot 'comparison-owned/evidence'
            Require (-not(Test-Path $OutputDirectory)) 'Setup precreated measured runner evidence'
            $guard=(Get-Content $runner|Where-Object {$_-match'^Require ' -and $_.Contains("'Fresh output required'")})-join"`n"
            Require ($guard-match'Fresh output required') 'Actual unchanged runner fresh-output guard not found'
            & ([scriptblock]::Create($guard))
            if($scenario-eq'success'){
                New-Item $OutputDirectory -ItemType Directory|Out-Null
                Rejects {& ([scriptblock]::Create($guard))} 'Fresh output required'
                Remove-Item $OutputDirectory
            }
        }
        $javaFailure=Join-Path $SetupTestRoot ('setup-java-'+[guid]::NewGuid().ToString('N'))
        $env:GITHUB_WORKSPACE=$javaFailure
        & ([scriptblock]::Create($workflowRuns['Initialize separate setup evidence before Java setup']))
        $env:JAVA_OUTCOME='failure';$env:STATIC_OUTCOME='skipped';$env:DRIVER_OUTCOME='skipped'
        & ([scriptblock]::Create($workflowRuns['Finalize setup diagnostics even when an action failed']))
        $record=Get-Content (Join-Path $javaFailure 'comparison-owned/setup-evidence/setup.json') -Raw|ConvertFrom-Json
        Require ($record.status-eq'FAIL' -and $record.stage-eq'java' -and $null-eq$record.nativeExitCode -and $record.jdk-eq'not-observed') 'setup-java action failure evidence lost or identity invented'
        Require (-not(Test-Path (Join-Path $javaFailure 'comparison-owned/evidence'))) 'Early setup action precreated runner output'
    } finally {$setupRestore=RestorePortableEnvironment $saved $setupNames;Require $setupRestore.restored 'Workflow setup fixture environment restoration failed'}
}
Check 'Opt-in complete portable artifact schema, real optional reference and explicit synthetic cross-host failures' {
    $base=if($SetupTestRoot){$SetupTestRoot}else{Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}
    $fixture=Join-Path $base ('complete-'+[guid]::NewGuid().ToString('N'))
    New-Item $fixture -ItemType Directory -Force|Out-Null
    function WriteCompleteZip($Path,$Rows){
        $archive=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
        try{foreach($row in $Rows){$stream=$archive.CreateEntry($row.name).Open();try{$stream.Write([byte[]]$row.raw,0,$row.raw.Length)}finally{$stream.Dispose()}}}finally{$archive.Dispose()}
    }
    $source=Join-Path $fixture 'synthetic-source';$main=Join-Path $source 'classes';$test=Join-Path $source 'test-classes'
    New-Item $main,$test -ItemType Directory -Force|Out-Null
    [byte[]]$class=@(0xCA,0xFE,0xBA,0xBE,0,0,0,61);$rows=@()
    foreach($i in 1..30){[IO.File]::WriteAllBytes((Join-Path $main "M$i.class"),$class);$rows+=@{name="BOOT-INF/classes/M$i.class";raw=$class}}
    foreach($i in 1..28){[IO.File]::WriteAllBytes((Join-Path $test "T$i.class"),$class)}
    foreach($i in 1..93){$rows+=@{name="BOOT-INF/lib/D$i.jar";raw=[byte[]]@(1)}}
    $components=@(1..106|ForEach-Object{@{'bom-ref'="C$_";name="synthetic$_";version='1'}})
    $dependencies=@(@{ref='root';dependsOn=@()})+@(1..106|ForEach-Object{@{ref="C$_";dependsOn=@()}})
    $bom=@{serialNumber='synthetic';metadata=@{component=@{'bom-ref'='root'}};components=$components;dependencies=$dependencies}
    $meta=@{'META-INF/MANIFEST.MF'='Manifest-Version: 1.0';'META-INF/build-info.properties'='build.time=synthetic';'BOOT-INF/classes/git.properties'="git.commit.id=500158f732419217507c7656904b8e6aa1bcc0d6`ngit.dirty=false";'META-INF/sbom/application.cdx.json'=($bom|ConvertTo-Json -Depth 20 -Compress);'META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties'='version=synthetic'}
    foreach($item in $meta.GetEnumerator()){$rows+=@{name=$item.Key;raw=[Text.Encoding]::UTF8.GetBytes($item.Value)}}
    $rows+=@{name='META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml';raw=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '..\..\..\..\pom.xml'))}
    foreach($i in 1..201){$rows+=@{name="resources/F$i";raw=[byte[]]@(2)}}
    $jar=Join-Path $source 'application.jar';WriteCompleteZip $jar $rows
    $a=Join-Path $fixture 'synthetic-a';$b=Join-Path $fixture 'synthetic-b'
    $null=ReadCompleteArtifact $jar $main $test $a;$null=ReadCompleteArtifact $jar $main $test $b
    Require ((CompareCompleteArtifacts $a $b).status-eq'PASS') 'Synthetic exact complete comparison failed'
    $manifestPath=Join-Path $b 'complete.json';$original=[IO.File]::ReadAllBytes($manifestPath)
    foreach($mutation in 'unknown','sha-coercion','missing-role','renamed','duplicate','digest','extra-inventory'){
        $value=[Text.Encoding]::UTF8.GetString($original)|ConvertFrom-Json -AsHashtable
        switch($mutation){
            'unknown'{$value.unknown='not-allowed'}
            'sha-coercion'{$value.entries[0].sha=$value.entries[0].sha256;$value.entries[0].Remove('sha256')}
            'missing-role'{$value.metadata=@($value.metadata|Select-Object -Skip 1)}
            'renamed'{$value.entries[0].name='renamed'}
            'duplicate'{$value.entries[1]=$value.entries[0]}
            'digest'{$value.entries[0].sha256='0'*64}
            'extra-inventory'{$value.entries+=,$value.entries[0]}
        }
        $value|ConvertTo-Json -Depth 40|Set-Content $manifestPath
        Rejects {CompareCompleteArtifacts $a $b}
    }
    [IO.File]::WriteAllBytes($manifestPath,$original)
    $changed=@($rows|ForEach-Object{@{name=$_.name;raw=$_.raw}})
    ($changed|Where-Object name -eq 'META-INF/build-info.properties').raw=[Text.Encoding]::UTF8.GetBytes('build.time=synthetic-other-host')
    $otherJar=Join-Path $source 'other.jar';WriteCompleteZip $otherJar $changed
    $cross=Join-Path $fixture 'synthetic-cross';$null=ReadCompleteArtifact $otherJar $main $test $cross
    Require ((CompareCompleteArtifacts $a $cross CrossHost).status-eq'UNKNOWN') 'Unreviewed cross-host metadata became success'
    Rejects {CompareCompleteArtifacts $a $cross SameHost}
    $containerJar=Join-Path $source 'container.jar';WriteCompleteZip $containerJar $rows
    $containerZip=[IO.Compression.ZipFile]::Open($containerJar,[IO.Compression.ZipArchiveMode]::Update)
    try{foreach($entry in $containerZip.Entries){$entry.LastWriteTime=[DateTimeOffset]::new(2001,1,1,0,0,0,[TimeSpan]::Zero)}}finally{$containerZip.Dispose()}
    $container=Join-Path $fixture 'synthetic-container';$null=ReadCompleteArtifact $containerJar $main $test $container
    Require ((CompareCompleteArtifacts $a $container CrossHost).status-eq'UNKNOWN') 'Unclassified ZIP bytes became success'
    $changedBom=$bom|ConvertTo-Json -Depth 20|ConvertFrom-Json -AsHashtable;$changedBom.components[0].version='changed'
    ($changed|Where-Object name -eq 'META-INF/sbom/application.cdx.json').raw=[Text.Encoding]::UTF8.GetBytes(($changedBom|ConvertTo-Json -Depth 20))
    $graphJar=Join-Path $source 'graph.jar';WriteCompleteZip $graphJar $changed
    $graph=Join-Path $fixture 'synthetic-graph';$null=ReadCompleteArtifact $graphJar $main $test $graph
    Rejects {CompareCompleteArtifacts $a $graph CrossHost} 'Meaningful complete SBOM graph differs'
    $duplicateJar=Join-Path $source 'duplicate.jar';WriteCompleteZip $duplicateJar ($rows+@($rows[0]))
    Rejects {ReadCompleteArtifact $duplicateJar $main $test} 'duplicate'
    $missingJar=Join-Path $source 'missing-role.jar';WriteCompleteZip $missingJar @($rows|Where-Object{$_.name-notlike'*/pom.properties'})
    Rejects {ReadCompleteArtifact $missingJar $main $test}
    $deepBom=$bom|ConvertTo-Json -Depth 20|ConvertFrom-Json -AsHashtable
    $deep=@{leaf='ORIGINAL'};foreach($i in 1..29){$deep=@{next=$deep}}
    $deepBom.components[0].deep=$deep
    $deepRows=@($rows|ForEach-Object{@{name=$_.name;raw=$_.raw}})
    ($deepRows|Where-Object name -eq 'META-INF/sbom/application.cdx.json').raw=[Text.Encoding]::UTF8.GetBytes(($deepBom|ConvertTo-Json -Depth 100 -WarningAction Stop))
    $deepJar=Join-Path $source 'deep.jar';WriteCompleteZip $deepJar $deepRows
    $deepA=Join-Path $fixture 'deep-a';$deepB=Join-Path $fixture 'deep-b'
    $null=ReadCompleteArtifact $deepJar $main $test $deepA;$null=ReadCompleteArtifact $deepJar $main $test $deepB
    Require ((CompareCompleteArtifacts $deepA $deepB).status-eq'PASS') 'Valid29-level complete graph rejected'
    $deepManifest=Join-Path $deepB 'complete.json';$deepSaved=Get-Content $deepManifest -Raw|ConvertFrom-Json -AsHashtable
    $node=($deepSaved.sbomGraph.components|Where-Object {$_['bom-ref']-ceq'C1'}).deep
    foreach($i in 1..29){$node=$node.next};$node.leaf='FORGED_MANIFEST_ONLY'
    $deepSaved|ConvertTo-Json -Depth 100 -WarningAction Stop|Set-Content $deepManifest
    Rejects {CompareCompleteArtifacts $deepA $deepB} 'Complete schema/digest/inventory binding mismatch'
    $over=@{leaf='OVER_BOUND'};foreach($i in 1..50){$over=@{next=$over}}
    ($deepSaved.sbomGraph.components|Where-Object {$_['bom-ref']-ceq'C1'}).deep=$over
    $deepSaved|ConvertTo-Json -Depth 100 -WarningAction Stop|Set-Content $deepManifest
    Rejects {CompareCompleteArtifacts $deepA $deepB}
    $deepBom.components[0].deep=$over
    ($deepRows|Where-Object name -eq 'META-INF/sbom/application.cdx.json').raw=[Text.Encoding]::UTF8.GetBytes(($deepBom|ConvertTo-Json -Depth 100 -WarningAction Stop))
    $overJar=Join-Path $source 'over-bound.jar';WriteCompleteZip $overJar $deepRows
    Rejects {ReadCompleteArtifact $overJar $main $test}
    if($CompleteArtifactReference){
        $real=Join-Path $fixture 'actual-current17-r4'
        $actual=ReadCompleteArtifact (Join-Path $CompleteArtifactReference 'application.jar') (Join-Path $CompleteArtifactReference 'classes') (Join-Path $CompleteArtifactReference 'test-classes') $real
        Require ($actual.jarSha256-eq'67C3ABD00F9FDC01CBA5C8258B0FB3139CF28E5CCE795945767E624A77D44202'-and(CompareCompleteArtifacts $real $real).status-eq'PASS') 'Actual accepted current17 r4 artifact failed'
    }
}
Check 'MixedClientPackage actual admissions and both OS production flow/cleanup with synthetic external boundaries' {
    $base=if($SetupTestRoot){$SetupTestRoot}else{Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'}
    & (Join-Path $PSScriptRoot 'Test-MixedClientPackage.ps1') -FixtureRoot (Join-Path $base ('mixed-'+[guid]::NewGuid().ToString('N')))
}
$yamlParser='unavailable';$actionsSchema='unavailable: actionlint not on PATH'
if(Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue){
    Check 'Existing YAML parser validates actual template syntax and job matrix' {
        $doc=Get-Content (Join-Path $PSScriptRoot 'matched-comparison.workflow.yml') -Raw|ConvertFrom-Yaml
        Require ($doc.jobs.Count-eq1 -and $doc.jobs.compare.strategy.matrix.runner.Count-eq2) 'Actual parsed two-job matrix'
        Require ($doc.jobs.compare.environment-eq'matched-comparison-approval') 'Approval environment'
        $measurement=@($doc.jobs.compare.steps|Where-Object name -eq 'Matched package and separate test screen')
        Require ($measurement.Count-eq1 -and $measurement[0].run-match'-Samples 3 -LoopbackTests -ExclusiveSlotApproved') 'Parsed shared matrix invocation does not match loopback plan'
    }
    $yamlParser='powershell-yaml: actual complete YAML parsed; not full Actions schema'
}
if(Get-Command actionlint -ErrorAction SilentlyContinue){
    & actionlint (Join-Path $PSScriptRoot 'matched-comparison.workflow.yml')
    NativeCode $LASTEXITCODE 'actionlint';$actionsSchema='actionlint PASS'
}
[ordered]@{verdict='PASS';checks=$passed.Count;names=@($passed);yamlSyntax=$yamlParser;actionsSchema=$actionsSchema;scope='Static and pure functions only; both OS plan branches executed on current Windows host. No Java, build, listener, CI, or Mac execution.'}|ConvertTo-Json -Depth 5
