$ErrorActionPreference='Stop'
$runner=Join-Path $PSScriptRoot 'Invoke-MatchedComparison.ps1'
. $runner -LibraryOnly
$passed=[Collections.Generic.List[string]]::new()
function Check([string]$Name,[scriptblock]$Body){& $Body;$passed.Add($Name)}
function Rejects([scriptblock]$Body,[string]$ExpectedMessage=''){
    $threw=$false
    try{& $Body}catch{$threw=$true;if($ExpectedMessage){Require ($_.Exception.Message-like"*$ExpectedMessage*") "Wrong rejection: $($_.Exception.Message)"}}
    Require $threw 'Expected rejection'
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
Check 'Every embedded workflow PowerShell block parses without execution' {
    $lines=Get-Content (Join-Path $PSScriptRoot 'matched-comparison.workflow.yml')
    $blocks=0
    for($i=0;$i-lt$lines.Count;$i++){
        if($lines[$i]-match'^\s+run: \|$'){
            $body=@();$i++
            while($i-lt$lines.Count -and ($lines[$i]-match'^          ' -or -not$lines[$i].Trim())){
                $body+=if($lines[$i].Length-ge10){$lines[$i].Substring(10)}else{''};$i++
            }
            $i--;$errors=$null;$tokens=$null
            $null=[Management.Automation.Language.Parser]::ParseInput(($body -join "`n"),[ref]$tokens,[ref]$errors)
            Require ($errors.Count-eq0) 'Workflow PowerShell syntax';$blocks++
        }
    }
    Require ($blocks-eq3) 'Expected three embedded executable setup/run blocks'
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
