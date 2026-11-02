param([Parameter(Mandatory)][string]$FixtureRoot,[string]$ReferenceReport)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Invoke-WrapperBoundary.ps1" -Project 'fixture-project' -Cache 'fixture-cache' -JavaHome 'fixture-jdk' -Output 'fixture-output' -LibraryOnly
Require ($JavaHome-ceq'fixture-jdk'-and$Output-ceq'fixture-output'-and$LibraryOnly) 'Dot-source parameter collision'
Require (-not(Test-Path $FixtureRoot)) 'Fresh owned fixture directory required'
New-Item $FixtureRoot -ItemType Directory|Out-Null;$FixtureRoot=(Resolve-Path $FixtureRoot).Path
$source=@'
@echo off
@setlocal
@FOR /F "tokens=1* delims==" %%A IN ("MVN_CMD=fixture-value") DO @(
  set parsed=%%B
  call :seven
)
@SET PSModulePath=%__MVNW_PSMODULEP_SAVE%
@call :seven
@echo PARSED=%parsed%
@echo ARG1=%~1
@echo CODE=%ERRORLEVEL%
@exit /b %ERRORLEVEL%
:seven
@exit /b 7
'@
$source=$source.Replace("`r`n","`n").Replace("`n","`r`n")+"`r`n";$original=[Text.Encoding]::UTF8.GetBytes($source)
$marker="$FixtureRoot\markers.raw";$modified=AddBoundaryMarkers $original $marker
$text=[Text.Encoding]::UTF8.GetString($modified);$stripped=(@($text-split"(?<=`n)"|Where-Object{-not$_.StartsWith('@echo HOBL_BOUNDARY_')})-join'')
Require ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($stripped))-ceq[Convert]::ToBase64String($original)) 'Byte reconstruction failed'
[IO.File]::WriteAllBytes("$FixtureRoot\original.cmd",$original);[IO.File]::WriteAllBytes("$FixtureRoot\marked.cmd",$modified)
foreach($name in 'original','marked'){& "$FixtureRoot\$name.cmd" 'alpha beta' *> "$FixtureRoot\$name.log";Require ($LASTEXITCODE-eq7) 'Tiny fixture native exit differs'}
Require ((Get-Content "$FixtureRoot\original.log" -Raw)-ceq(Get-Content "$FixtureRoot\marked.log" -Raw)) 'Tiny stdout/argv/status differs'
$rows=@(Get-Content $marker);Require ($rows.Count-eq2-and$rows[0]-like'HOBL_BOUNDARY_BEFORE_FOR|*'-and$rows[1]-like'HOBL_BOUNDARY_AFTER_FOR|*') 'Marker order differs'
$case=@{before='2026-11-02T17:00:00.001+08:00';after='2026-11-02T17:00:02.011+08:00';seconds=2.01;markers=@('HOBL_BOUNDARY_BEFORE_FOR|Mon 11/02/2026|17:00:00.20','HOBL_BOUNDARY_AFTER_FOR|Mon 11/02/2026|17:00:01.20')}
$valid=BoundaryWindow ($case|ConvertTo-Json) "[INFO] Total time:  1.000 s";Require ($valid.status-eq'PARSED_COARSE_LOCAL_ONLY'-and$valid.forSeconds-eq1) 'Literal ISO clock parse failed'
$case.markers[1]='HOBL_BOUNDARY_AFTER_FOR|ambiguous|17:00:01.20';$bad=BoundaryWindow ($case|ConvertTo-Json) "[INFO] Total time:  1.000 s";Require ($bad.status-eq'UNKNOWN'-and-not$bad.ContainsKey('forSeconds')) 'Ambiguous date defaulted'
$case.markers[1]='HOBL_BOUNDARY_AFTER_FOR|Mon 11/02/2026|16:59:59.00';Require ((BoundaryWindow ($case|ConvertTo-Json) "[INFO] Total time:  1.000 s").status-eq'UNKNOWN') 'Reversed marker accepted'
$case.markers[1]='HOBL_BOUNDARY_AFTER_FOR|Mon 11/02/2026|17:00:01.20';$case.after='2026-11-03T17:00:02.011+08:00';Require ((BoundaryWindow ($case|ConvertTo-Json) "[INFO] Total time:  1.000 s").status-eq'UNKNOWN') 'Rollover accepted'
$case.after='2026-11-02T17:00:02.011+09:00';Require ((BoundaryWindow ($case|ConvertTo-Json) "[INFO] Total time:  1.000 s").status-eq'UNKNOWN') 'Offset change accepted'
$case.after='2026-11-02T17:00:02.011+08:00';Require ((BoundaryWindow ($case|ConvertTo-Json) 'no footer').status-eq'UNKNOWN') 'Missing footer accepted'
Require ((BoundaryWindow ($case|ConvertTo-Json) "[INFO] Total time:  3.000 s").status-eq'UNKNOWN') 'Negative remainder accepted'
$rejected=$false;try{$null=AddBoundaryMarkers $original "$FixtureRoot\unsafe%path"}catch{$rejected=$true};Require $rejected 'Unsafe marker destination accepted'
$rejected=$false;try{$null=AddBoundaryMarkers ([Text.Encoding]::UTF8.GetBytes($source+$source)) $marker}catch{$rejected=$true};Require $rejected 'Duplicate insertion anchors accepted'
$name='HOBL_BOUNDARY_ENV_'+[Guid]::NewGuid().ToString('N');$prior=[Environment]::GetEnvironmentVariables('Process')
try{[Environment]::SetEnvironmentVariable($name,'fixture','Process');$restored=RestoreBoundaryEnvironment $prior @($name);Require ($restored.restored-and-not(Test-Path ('Env:'+$name))) 'Absent restoration failed'}finally{if(Test-Path ('Env:'+$name)){Remove-Item ('Env:'+$name)}}
foreach($value in @('','normal-value')){
    try{[Environment]::SetEnvironmentVariable($name,$value,'Process');$state=[Environment]::GetEnvironmentVariables('Process');[Environment]::SetEnvironmentVariable($name,'changed','Process');$r=RestoreBoundaryEnvironment $state @($name);Require ($r.restored-and$r.keys[0].beforePresent-and$r.keys[0].afterPresent) 'Empty/normal presence restoration failed'}finally{if(Test-Path ('Env:'+$name)){Remove-Item ('Env:'+$name)}}
}
$failure=RestoreBoundaryEnvironment @{'INVALID=ENVIRONMENT'='fixture'} @('INVALID=ENVIRONMENT');Require (-not$failure.restored-and$failure.errors.Count-eq1) 'Restoration error hidden'
$realPath=[Environment]::GetEnvironmentVariable('PATH','Process')
$mixed='HoblCaseProbe_'+[Guid]::NewGuid().ToString('N');$upper=$mixed.ToUpperInvariant();$caseRows=@()
try{
    foreach($value in @('original-value','')){
        [Environment]::SetEnvironmentVariable($mixed,$value,'Process');$raw=[Environment]::GetEnvironmentVariables('Process')
        Require ($raw.Contains($mixed)-and-not$raw.Contains($upper)) 'Mixed-case fixture not actually case-sensitive in raw snapshot'
        [Environment]::SetEnvironmentVariable($upper,'changed','Process')
        $fixed=RestoreBoundaryEnvironment $raw @($upper)
        $actual=GetBoundaryEnvironmentSnapshot
        Require ($fixed.restored-and$fixed.keys[0].beforePresent-and$fixed.keys[0].afterPresent-and$actual.Contains($upper)-and[string]::Equals($actual[$upper],$value,[StringComparison]::Ordinal)) 'Mixed-case present/empty value lost or falsely restored'
        $caseRows+=@{case=$(if($value.Length){'mixed-present'}else{'mixed-empty'});restoration=$fixed;actualValueRestored=$true}
        Remove-Item ('Env:'+$mixed)
    }
    $absent=[Environment]::GetEnvironmentVariables('Process');[Environment]::SetEnvironmentVariable($mixed,'created','Process')
    $fixed=RestoreBoundaryEnvironment $absent @($upper);$actual=GetBoundaryEnvironmentSnapshot
    Require ($fixed.restored-and-not$actual.Contains($upper)-and-not$fixed.keys[0].beforePresent-and-not$fixed.keys[0].afterPresent) 'Mixed-case absent not restored'
    $caseRows+=@{case='mixed-absent';restoration=$fixed;actualAbsenceRestored=$true}
    [Environment]::SetEnvironmentVariable($mixed,'keep','Process')
    foreach($second in @('other','keep')){
        $ambiguous=[Collections.Hashtable]::new([StringComparer]::Ordinal);$ambiguous.Add($mixed,'keep');$ambiguous.Add($upper,$second)
        $rejected=$false;try{$null=GetBoundaryEnvironmentSnapshot $ambiguous}catch{$rejected=$_.Exception.Message-eq'Ambiguous case-insensitive environment keys'};Require $rejected 'Ambiguous before/after input silently picked'
        $rejected=$false;try{$null=RestoreBoundaryEnvironment $ambiguous @($upper)}catch{$rejected=$_.Exception.Message-eq'Ambiguous case-insensitive environment keys'}
        Require ($rejected-and[Environment]::GetEnvironmentVariable($mixed,'Process')-ceq'keep') 'Ambiguous restore mutated process before rejection'
    }
}finally{if(Test-Path ('Env:'+$mixed)){Remove-Item ('Env:'+$mixed)}}
Require ([string]::Equals($realPath,[Environment]::GetEnvironmentVariable('PATH','Process'),[StringComparison]::Ordinal)) 'Real PATH touched by disposable fixture'
$caseRows|ConvertTo-Json -Depth 10|Set-Content "$FixtureRoot\environment-case-regressions.json"
$tokens=$null;$errors=$null;$productionAst=[Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\Invoke-WrapperBoundary.ps1",[ref]$tokens,[ref]$errors);Require ($errors.Count-eq0) 'Runner syntax error'
$blocked=$false;try{& "$PSScriptRoot\Invoke-WrapperBoundary.ps1" -Project 'fixture-project' -Cache 'fixture-cache' -JavaHome 'fixture-jdk' -Output "$FixtureRoot\must-not-exist"}catch{$blocked=$_.Exception.Message-like'Explicit owner authorization*'}
Require ($blocked-and-not(Test-Path "$FixtureRoot\must-not-exist")) 'Authorization gate returned early or created runtime output'
$code=Get-Content "$PSScriptRoot\Invoke-WrapperBoundary.ps1" -Raw
Require ($code.IndexOf("'prep-go-offline'")-lt$code.IndexOf("'prep-verify'")-and$code.IndexOf("'prep-verify'")-lt$code.IndexOf("'prep-clean'")-and$code.IndexOf("'prep-clean'")-lt$code.IndexOf('$variant=AddBoundaryMarkers')) 'Original-wrapper prep order differs'
Require ($code.Contains('Measure-Command {& $wrapper @Arguments *> $log;$script:code=$LASTEXITCODE}')) 'Literal launch/timer differs'
Require ($code-notmatch'yeelam|evidence\\|ComSpec|Register-Cim|Invoke-WebRequest') 'Private path/alternate launch/download/tracing leaked'
$rejected=$false;try{$null=BoundaryCoverage ([xml]'<report><counter type="LINE" missed="0" covered="1"/></report>')}catch{$rejected=$true};Require $rejected 'Nonempty wrong coverage accepted'
$fake=[xml]'<report name="fixture"><package name="fixture"><sourcefile name="Fixture.java"/></package></report>'
$package=$fake.report.package;$classes=@(foreach($i in 0..24){$n=$fake.CreateElement('class');$n.SetAttribute('name',"fixture/C$i");[void]$package.AppendChild($n);$n})
foreach($i in 0..725){$method=$fake.CreateElement('method');$method.SetAttribute('name',"m$i");[void]$classes[$i%25].AppendChild($method);$counter=$fake.CreateElement('counter');foreach($a in @(@('type','LINE'),@('missed','0'),@('covered','1'))){$counter.SetAttribute($a[0],$a[1])};[void]$method.AppendChild($counter)}
foreach($i in 1..296){$line=$fake.CreateElement('line');$line.SetAttribute('nr',[string]$i);[void]$package.sourcefile.AppendChild($line)}
Require ($fake.SelectNodes('//counter').Count-eq726-and$fake.SelectNodes('/report/package/class').Count-eq25-and$fake.SelectNodes('/report/package/sourcefile/line').Count-eq296) 'Malformed-universe fixture shape differs'
$rejected=$false;try{$null=BoundaryCoverage $fake}catch{$rejected=$_.Exception.Message-like'Wrong pinned HOBL coverage identities*'};Require $rejected 'Right counts with wrong pinned identities accepted'
if($ReferenceReport){
    $real=[xml](Get-Content $ReferenceReport -Raw);$proof=BoundaryCoverage $real
    Require ($proof.counters.Count-eq726-and$proof.lineRecords-eq296-and$proof.classes.Count-eq25) 'Accepted retained universe rejected'
    $changed=$real.CloneNode($true);$node=$changed.SelectSingleNode('/report/package/class');$node.SetAttribute('name','wrong/SameCount')
    $rejected=$false;try{$null=BoundaryCoverage $changed}catch{$rejected=$true};Require $rejected 'Changed pinned class identity accepted'
    $changed=$real.CloneNode($true);$node=$changed.SelectSingleNode('/report/package/sourcefile/line');[void]$node.ParentNode.RemoveChild($node)
    $rejected=$false;try{$null=BoundaryCoverage $changed}catch{$rejected=$true};Require $rejected 'Missing source line accepted'
    $changed=$real.CloneNode($true);$changed.SelectSingleNode('//counter').SetAttribute('covered','malformed')
    $rejected=$false;try{$null=BoundaryCoverage $changed}catch{$rejected=$true};Require $rejected 'Malformed covered value accepted'
}
$paths=Join-Path $FixtureRoot 'path-fixtures';New-Item $paths -ItemType Directory|Out-Null
$source=Join-Path $paths 'project';$cache=Join-Path $paths 'cache';$jdk=Join-Path $paths 'jdk'
New-Item $source,$cache,$jdk -ItemType Directory|Out-Null
foreach($badCache in @($source,(Join-Path $source 'nested-cache'))){
    $output=Join-Path $paths ([Guid]::NewGuid().ToString('N'));$rejected=$false
    try{& "$PSScriptRoot\Invoke-WrapperBoundary.ps1" -Project $source -Cache $badCache -JavaHome $jdk -Output $output -ExecuteAuthorized}catch{$rejected=$_.Exception.Message-like'Cache/evidence/JDK must be outside source*'}
    Require ($rejected-and-not(Test-Path $output)) 'Equal/nested cache reached output or runtime'
}
$target=Join-Path $paths 'owned-target';New-Item $target -ItemType Directory|Out-Null
Set-Content (Join-Path $target 'sentinel.txt') 'owned fixture retained'
$link=Join-Path $paths 'owned-junction';New-Item $link -ItemType Junction -Target $target -ErrorAction Stop|Out-Null
foreach($role in @('project','cache','jdk','output')){
    $p=$source;$c=$cache;$j=$jdk;$o=Join-Path $paths ([Guid]::NewGuid().ToString('N'))
    switch($role){'project'{$p=Join-Path $link 'child'}'cache'{$c=Join-Path $link 'child'}'jdk'{$j=Join-Path $link 'child'}'output'{$o=Join-Path $link 'child'}}
    $rejected=$false;try{& "$PSScriptRoot\Invoke-WrapperBoundary.ps1" -Project $p -Cache $c -JavaHome $j -Output $o -ExecuteAuthorized}catch{$rejected=$_.Exception.Message-like'Linked input/output ancestry rejected*'}
    Require ($rejected-and-not(Test-Path $o)) 'Linked ancestry reached output or runtime'
}
Require ((Get-Content (Join-Path $target 'sentinel.txt') -Raw).Trim()-ceq'owned fixture retained') 'Junction target changed'
$workflow=Get-Content "$PSScriptRoot\boundary.workflow.yml" -Raw
$baselineWorkflow=Get-Content "$PSScriptRoot\..\hobl-contract\hobl-contract.workflow.yml" -Raw
$setupPattern='(?s)      - name: Pinned official native Microsoft JDK25 archive.*?(?=      - name: Offline protocol tests)'
$newSetup=[regex]::Match($workflow,$setupPattern);$oldSetup=[regex]::Match($baselineWorkflow,$setupPattern)
Require ($newSetup.Success-and$oldSetup.Success-and$newSetup.Value-ceq$oldSetup.Value) 'Archive/setup-java changed from baseline'
foreach($text in @("github.repository == 'yeelam-gordon/spring-petclinic'","inputs.acknowledgement == 'I_HAVE_APPROVAL_AND_BUDGET'",'environment: hobl-contract-approval','runs-on: windows-11-arm','actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02','RestoreBoundaryEnvironment $prior')){Require ($workflow.Contains($text)) 'Required workflow gate/setup/retention missing'}
Require ($workflow-notmatch'matrix:|vars\.HOBL_APPROVED|Preparation template only|Root integration boundary') 'Workflow placeholder or extra lane remains'
$jobs=$workflow.Substring($workflow.IndexOf('jobs:'));Require (([regex]::Matches($jobs,'(?m)^  [a-z]+:\s*$')).Count-eq1) 'Expected one job'
Require (([regex]::Matches($workflow,'if: always\(\)')).Count-ge2) 'Outcomes/artifacts not always retained'
$runBlocks=[regex]::Matches($workflow,'(?m)^        run: \|\r?\n(?<body>(?:          [^\r\n]*(?:\r?\n|$))+)')
Require ($runBlocks.Count-eq4) 'Workflow run-block extraction incomplete'
foreach($block in $runBlocks){$shell=[regex]::Replace($block.Groups['body'].Value,'(?m)^          ','');$e=$null;$t=$null;$null=[Management.Automation.Language.Parser]::ParseInput($shell,[ref]$t,[ref]$e);Require ($e.Count-eq0) 'Workflow inline PowerShell syntax error'}
$serializers=@($workflow-split'\r?\n'|Where-Object{$_.TrimStart().StartsWith('$receipt|ConvertTo-Json')})
Require ($serializers.Count-eq2-and$workflow.Contains('$prior=GetBoundaryEnvironmentSnapshot')) 'Workflow snapshot/depth integration missing'
& {
    foreach($line in $serializers){
        $receipt=@{restoration=$caseRows[0].restoration};$path=Join-Path $FixtureRoot ('workflow-env-'+[Guid]::NewGuid().ToString('N')+'.json')
        & ([scriptblock]::Create($line.Trim()))
        $roundtrip=Get-Content $path -Raw|ConvertFrom-Json -DateKind String
        Require ($roundtrip.restoration.keys[0].beforePresent-and$roundtrip.restoration.keys[0].afterPresent-and$roundtrip.restoration.keys[0].beforeType-eq'System.String') 'Workflow nested receipt collapsed/lost presence'
        Require ((Get-Content $path -Raw)-notmatch'System.Collections.Hashtable') 'Workflow serialized hashtable name instead of keys'
    }
}
& {
    $definition=$productionAst.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'BoundarySource'},$true)
    Invoke-Expression $definition.Extent.Text
    $Project='owned synthetic source with spaces';$seen=[Collections.Generic.List[object]]::new()
    function Get-FileHash { [pscustomobject]@{Hash='A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D'} }
    function git {
        $seen.Add(@($args));$global:LASTEXITCODE=0
        if($args-contains'rev-parse'){if($mode-eq'failed-head'){$global:LASTEXITCODE=23};'6feeae0f13e0e258eedc99832416b42bb13779b1'}
        elseif($args-contains'remote'){if($mode-eq'failed-origin'){$global:LASTEXITCODE=23};'https://github.com/spring-projects/spring-petclinic.git'}
        elseif($args-contains'diff'){if($mode-eq'failed-diff'){$global:LASTEXITCODE=23};'synthetic patch'}
        else{if($mode-like'failed-status*'){$global:LASTEXITCODE=23};if($mode-in@('wrapper','failed-status-with-text')){' M mvnw.cmd'}elseif($mode-eq'dirty'){' M pom.xml'}}
    }
    $rows=@()
    foreach($mode in @('clean','dirty','wrapper','failed-status','failed-status-with-text','failed-head')){
        $rejected=$false;$reason=$null
        try{BoundarySource ($mode-in@('wrapper','failed-status-with-text'))}catch{$rejected=$true;$reason=$_.Exception.Message}
        Require ($rejected-eq($mode-notin@('clean','wrapper'))) 'Actual source gate native failure/clean/dirty regression'
        if($mode-like'failed-*'){Require ($reason-like'Git query failed: exit 23*') 'Native failure interpreted before exit check'}
        $rows+=@{case=$mode;rejected=$rejected;reason=$reason}
    }
    $origin=$productionAst.Find({param($n)$n-is[Management.Automation.Language.CommandAst]-and$n.GetCommandName()-eq'Require'-and$n.Extent.Text.Contains("'remote','get-url','origin'")},$true)
    foreach($mode in @('clean','failed-origin')){$rejected=$false;try{& ([scriptblock]::Create($origin.Extent.Text))}catch{$rejected=$true};Require ($rejected-eq($mode-eq'failed-origin')) 'Actual origin gate failed exit handling';$rows+=@{case=$mode+'-origin';rejected=$rejected}}
    $Output=Join-Path $FixtureRoot 'git-diff';New-Item $Output -ItemType Directory|Out-Null
    $diffLine=@($code-split'\r?\n'|Where-Object{$_.TrimStart().StartsWith('git -C $Project diff -- mvnw.cmd')})
    Require ($diffLine.Count-eq1) 'Actual diff guard not found'
    foreach($mode in @('clean','failed-diff')){$rejected=$false;try{& ([scriptblock]::Create($diffLine[0]))}catch{$rejected=$true};Require ($rejected-eq($mode-eq'failed-diff')) 'Actual diff failed exit accepted';$rows+=@{case=$mode+'-diff';rejected=$rejected}}
    foreach($argv in $seen){Require ($argv[0]-ceq'-C'-and$argv[1]-ceq$Project) 'Git argv spacing/boundaries changed'}
    $rows|ConvertTo-Json -Depth 5|Set-Content "$FixtureRoot\git-query-regressions.json"
}
@{exit=0;fixture='builtins/pure XML/path/Git-provider tests only; no real wrapper bootstrap/Java';byteReconstruction=$true;nativeExits=@(7,7);literalIso=$true;presenceRestoration=@('absent','empty','normal','failure');windowsCaseRestoration=@('mixed-present','mixed-empty','mixed-absent','ambiguous-different-values-rejected','ambiguous-equal-values-rejected');realPathUntouched=$true;workflowNestedSerialization=$true;parameterScope=$true;originalPrepOrder=$true;coverageShapeAndIdentityNegatives=$true;acceptedCoverageChecked=[bool]$ReferenceReport;pathIsolation=@('equal-cache','nested-cache','project-junction-ancestor','cache-junction-ancestor','jdk-junction-ancestor','output-junction-ancestor');workflowSetupExact=$true;workflowGatesAndRetention=$true;productionGitExitCases=10;syntaxErrors=0}|ConvertTo-Json -Depth 5|Set-Content "$FixtureRoot\results.json"
