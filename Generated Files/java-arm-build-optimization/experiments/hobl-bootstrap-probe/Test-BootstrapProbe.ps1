param([Parameter(Mandatory)][string]$OriginalWrapper,[Parameter(Mandatory)][string]$FixtureRoot)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
. "$PSScriptRoot\Invoke-BootstrapProbe.ps1" -LibraryOnly
Require (-not(Test-Path $FixtureRoot)) 'Fresh fixture root required'
New-Item $FixtureRoot -ItemType Directory|Out-Null;$FixtureRoot=(Resolve-Path $FixtureRoot).Path
$original=[IO.File]::ReadAllBytes($OriginalWrapper)
Require ((HashBytes $original)-eq'5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A') 'Wrong original'
$variant=NewBootstrapVariant $original (Join-Path $FixtureRoot "clock O'Brien")
$text=[Text.Encoding]::UTF8.GetString($variant.bytes);$stock=[Text.Encoding]::UTF8.GetString($original)
Require ($variant.originalReconstructed-and($text-split'\r?\n'|Where-Object{$_-match'^@echo HOBL_BOUNDARY_'}).Count-eq2) 'Stage reconstruction/batch marks'
Require ($text.Contains('powershell -noprofile "& {'+$variant.entry+'$scriptDir=')) 'Not first inline expression/original flags'
Require ($text.Contains($variant.body+'$ErrorActionPreference = "Stop"')) 'Not first embedded statement'
Require ($variant.cached.IndexOf('$__hobl_cached_ticks')-lt$variant.cached.IndexOf('GetCurrentProcess')) 'Identity precedes cache clock'
Require ($variant.cached.IndexOf('$__hobl_diag_start_ticks')-lt$variant.cached.IndexOf('GetCurrentProcess')-and$variant.cached.IndexOf('ConvertTo-Json')-lt$variant.cached.IndexOf('$__hobl_diag_end_utc=')) 'Diagnostic work not bracketed'
Require ($variant.cached-notmatch'GetProcessById|Get-Process|Get-Cim|Start-Process|Invoke-WebRequest'-and$variant.cached.Contains('GetCurrentProcess')) 'Other-process access/extra process'
Require ($text.Contains('Write-Output "MVN_CMD=$MAVEN_HOME/bin/$MVN_CMD"')-and$text.Contains('exit $?')) 'Original stdout/exit removed'
foreach($snippet in @('& {'+$variant.entry+'$scriptDir=''fixture''; $script=''mvnw.cmd''}',$variant.body,$variant.cached)){
    $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($snippet,[ref]$tokens,[ref]$errors)
    Require ($errors.Count-eq0) 'Inserted PowerShell syntax invalid'
}
$ps=$text.Substring($text.IndexOf(': end batch / begin powershell #>')+': end batch / begin powershell #>'.Length)
$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($ps,[ref]$tokens,[ref]$errors);Require ($errors.Count-eq0) 'Complete embedded body invalid'
$scopeBody=$variant.body+'if($null -eq $__hobl_entry_utc -or $null -eq $__hobl_entry_ticks){throw ''Clock scope lost''}'
$scopeEntry=$variant.entry+'Invoke-Command -ScriptBlock ([Scriptblock]::Create($scopeBody)) -NoNewScope'
& ([Scriptblock]::Create($scopeEntry))
$duplicate=$stock.Replace('$ErrorActionPreference = "Stop"','$ErrorActionPreference = "Stop"'+"`r`n"+'$ErrorActionPreference = "Stop"')
$rejected=$false;try{$null=NewBootstrapVariant ([Text.Encoding]::UTF8.GetBytes($duplicate)) $FixtureRoot}catch{$rejected=$true};Require $rejected 'Duplicate anchor accepted'
$rejected=$false;try{$null=NewBootstrapVariant $original "$FixtureRoot\unsafe%"}catch{$rejected=$true};Require $rejected 'Unsafe path accepted'
$tiny=@'
@echo off
@setlocal
@FOR /F "tokens=1* delims==" %%A IN ("MVN_CMD=fixture-value") DO @(
  set parsed=%%B
)
@SET PSModulePath=%__MVNW_PSMODULEP_SAVE%
@echo PARSED=%parsed%
@echo ARG1=%~1
@exit /b 7
'@
$tiny=$tiny.Replace("`r`n","`n").Replace("`n","`r`n")+"`r`n"
$base=[Text.Encoding]::UTF8.GetBytes($tiny);$marked=AddBoundaryMarkers $base "$FixtureRoot\tiny-markers.raw"
[IO.File]::WriteAllBytes("$FixtureRoot\original.cmd",$base);[IO.File]::WriteAllBytes("$FixtureRoot\marked.cmd",$marked)
foreach($name in 'original','marked'){& "$FixtureRoot\$name.cmd" 'alpha beta' *> "$FixtureRoot\$name.log";Require ($LASTEXITCODE-eq7) 'Tiny fixture exit differs'}
Require ((Get-Content "$FixtureRoot\original.log" -Raw)-ceq(Get-Content "$FixtureRoot\marked.log" -Raw)) 'Tiny stdout/parser/argv changed'
$rows=@(Get-Content "$FixtureRoot\tiny-markers.raw");Require ($rows.Count-eq2-and$rows[0]-like'HOBL_BOUNDARY_BEFORE_FOR|*'-and$rows[1]-like'HOBL_BOUNDARY_AFTER_FOR|*') 'Tiny batch marker order'
Require (-not(Test-Path $variant.dataFile)-and-not(Test-Path $variant.endFile)) 'Child probe executed unexpectedly'
[IO.File]::WriteAllBytes("$FixtureRoot\instrumented-mvnw.cmd",$variant.bytes);[IO.File]::WriteAllBytes("$FixtureRoot\original-mvnw.cmd",$original)
$parent=@{before='2026-11-02T17:00:00.001+08:00';after='2026-11-02T17:00:05.001+08:00';seconds=5;markers=@('HOBL_BOUNDARY_BEFORE_FOR|Mon 11/02/2026|17:00:00.10','HOBL_BOUNDARY_AFTER_FOR|Mon 11/02/2026|17:00:04.90')}
$child=@{entryUtc='2026-11-02T09:00:01.100Z';bodyUtc='2026-11-02T09:00:02.100Z';cachedUtc='2026-11-02T09:00:03.100Z';diagnosticStartUtc='2026-11-02T09:00:03.200Z';entryTicks=100;bodyTicks=200;cachedTicks=300;diagnosticStartTicks=310;stopwatchFrequency=100;identity=@{status='OK';pid=123;psHome='fixture';psVersionTable=@{PSVersion='5.1-fixture'};ownExecutable='fixture.exe';ownPeMachine='0x8664'}}
$end='2026-11-02T09:00:04.200Z|410'
$valid=BootstrapWindows ($parent|ConvertTo-Json -Depth 8) ($child|ConvertTo-Json -Depth 8) $end
Require ($valid.status-eq'PARSED_DIAGNOSTIC_ONLY'-and$valid.sourceLoadEnvelopeSeconds-eq1-and$valid.cachedWorkSeconds-eq1-and$valid.addedMetadataSeconds-eq1) 'Same-child stage clocks invalid'
$missing=$child.Clone();$missing.Remove('entryTicks');$bad=BootstrapWindows ($parent|ConvertTo-Json -Depth 8) ($missing|ConvertTo-Json -Depth 8) $end
Require ($bad.status-eq'UNKNOWN'-and-not$bad.ContainsKey('sourceLoadEnvelopeSeconds')) 'Missing clock defaulted'
$reversed=$child.Clone();$reversed.cachedTicks=10;Require ((BootstrapWindows ($parent|ConvertTo-Json -Depth 8) ($reversed|ConvertTo-Json -Depth 8) $end).status-eq'UNKNOWN') 'Reversed ticks accepted'
$missing=$parent.Clone();$missing.markers=@($parent.markers[0]);Require ((BootstrapWindows ($missing|ConvertTo-Json -Depth 8) ($child|ConvertTo-Json -Depth 8) $end).status-eq'UNKNOWN') 'Missing batch stage accepted'
$reversedParent=$parent.Clone();$reversedParent.markers=@($parent.markers[1],$parent.markers[0]);Require ((BootstrapWindows ($reversedParent|ConvertTo-Json -Depth 8) ($child|ConvertTo-Json -Depth 8) $end).status-eq'UNKNOWN') 'Reversed batch stages accepted'
$errorData=$child.Clone();$errorData.identity=@{status='ERROR';errorType='FixtureError';ownPeMachine=$null}
$errorResult=BootstrapWindows ($parent|ConvertTo-Json -Depth 8) ($errorData|ConvertTo-Json -Depth 8) $end
Require ($errorResult.status-eq'UNKNOWN_METADATA'-and$errorResult.child.identity.errorType-eq'FixtureError'-and$null-eq$errorResult.child.identity.ownPeMachine) 'Metadata failure fabricated/defaulted'
Require ($variant.cached.Contains("catch { `$__hobl_identity['errorType']=")-and$variant.cached.Contains("status='ERROR'")) 'Production metadata error not recorded'
$version="Apache Maven 3.9.11 (fixture)`nJava version: 25.0.5.0.2, vendor: Microsoft, runtime: owned-jdk`nOS name: `"windows`", arch: `"aarch64`""
AssertProbeVersion $version 'owned-jdk';$rejected=$false;try{AssertProbeVersion ($version.Replace('3.9.11','3.9.12')) 'owned-jdk'}catch{$rejected=$true};Require $rejected 'Wrong Maven accepted'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\Invoke-BootstrapProbe.ps1",[ref]$tokens,[ref]$errors);Require ($errors.Count-eq0) 'Probe syntax'
$calls=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.CommandAst]-and$n.GetCommandName()-eq'ProbeCall'},$true));Require ($calls.Count-eq2-and$calls[0].Extent.Text-eq"ProbeCall 'warm-original'"-and$calls[1].Extent.Text-eq"ProbeCall 'cached-instrumented'") 'Not exactly2 version call sites'
$code=Get-Content "$PSScriptRoot\Invoke-BootstrapProbe.ps1" -Raw
Require ($code.Contains("`$arguments=@('--version')")-and$code-notmatch"ProbeCall.*(package|verify|clean|go-offline)") 'Non-version Maven work'
$workflow=Get-Content "$PSScriptRoot\bootstrap.workflow.yml" -Raw
Require ($workflow.Contains('environment: hobl-contract-approval')-and$workflow.Contains("github.repository == 'yeelam-gordon/spring-petclinic'")-and$workflow.Contains('runs-on: windows-11-arm')-and$workflow.Contains('I_HAVE_APPROVAL_AND_BUDGET')-and$workflow.Contains('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02')) 'Workflow ownership/setup/retention'
Require ($workflow-notmatch'Invoke-WrapperBoundary.ps1.*`|dependency:go-offline|matrix:') 'Package workflow route leaked'
$blocks=[regex]::Matches($workflow,'(?m)^        run: \|\r?\n(?<body>(?:          [^\r\n]*(?:\r?\n|$))+)');Require ($blocks.Count-eq4) 'Workflow blocks'
foreach($b in $blocks){$e=$null;$t=$null;$null=[Management.Automation.Language.Parser]::ParseInput(([regex]::Replace($b.Groups['body'].Value,'(?m)^          ','')),[ref]$t,[ref]$e);Require ($e.Count-eq0) 'Workflow PowerShell syntax'}
@{exit=0;originalReconstruction=$true;inlineFirst=$true;embeddedFirst=$true;cachedFirst=$true;identityDeferredAndBracketed=$true;selfMetadataOnly=$true;quotedPathSyntax=$true;fullEmbeddedSyntax=$true;negativeAnchorsPaths=$true;missingReversedClockUnknown=$true;metadataErrorNotDefault=$true;versionValidation=$true;exactly2VersionCallSites=$true;workflowSyntax=$true;tinyExits=@(7,7);realBootstrapOrJava=$false;childMetadataActuallyObserved=$false}|ConvertTo-Json|Set-Content "$FixtureRoot\results.json"
