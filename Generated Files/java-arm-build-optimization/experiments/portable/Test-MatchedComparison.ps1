param([string]$SetupTestRoot=$env:COMPARISON_SETUP_TEST_ROOT)
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
Check 'Actual workflow setup retains failed diagnostics and success leaves runner output fresh' {
    if(-not$SetupTestRoot){
        if(-not$env:GITHUB_WORKSPACE){throw 'Set -SetupTestRoot outside the publication payload for local mocked setup tests'}
        $SetupTestRoot=Join-Path $env:GITHUB_WORKSPACE 'comparison-owned/setup-evidence/mock-tests'
    }
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($workflowRuns['Explicit driver setup, checksum and Windows ARM64 compiler preflight'],[ref]$tokens,[ref]$errors)
    $functions=($ast.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.FunctionDefinitionAst]}|ForEach-Object {$_.Extent.Text})-join"`n"
    Require ($functions-match'function Invoke-ComparisonSetup') 'Actual workflow setup implementation absent'
    $saved=@{};foreach($n in 'GITHUB_WORKSPACE','GITHUB_ENV','JAVA_HOME','WORKLOAD','ComSpec','ProgramFiles(x86)','CHECKOUT_OUTCOME','JAVA_OUTCOME','STATIC_OUTCOME','DRIVER_OUTCOME'){$saved[$n]=[Environment]::GetEnvironmentVariable($n)}
    try {
        foreach($scenario in 'checksum','missing-compiler','native-failure','success'){
            $caseRoot=Join-Path $SetupTestRoot ($scenario+'-'+[guid]::NewGuid().ToString('N'))
            New-Item $caseRoot -ItemType Directory -Force|Out-Null
            $env:GITHUB_WORKSPACE=$caseRoot;$env:GITHUB_ENV=Join-Path $caseRoot 'github-env';$env:JAVA_HOME=Join-Path $caseRoot 'mock-jdk';$env:WORKLOAD='current17'
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
    } finally {foreach($n in $saved.Keys){[Environment]::SetEnvironmentVariable($n,$saved[$n])}}
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
