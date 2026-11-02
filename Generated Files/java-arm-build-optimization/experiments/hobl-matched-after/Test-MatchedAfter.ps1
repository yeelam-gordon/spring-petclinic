param([Parameter(Mandatory)][string]$FixtureRoot,[string]$Baseline=(Join-Path $PSScriptRoot '..\hobl-contract'),[string]$OriginalWrapper)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
if(Test-Path $FixtureRoot){throw 'Fresh owned fixtures required'}
New-Item "$FixtureRoot\core" -ItemType Directory|Out-Null;$FixtureRoot=(Resolve-Path $FixtureRoot).Path
Get-ChildItem $Baseline -File|Copy-Item -Destination "$FixtureRoot\core"
$patch=(Resolve-Path "$PSScriptRoot\matched-after.patch").Path
git -C $FixtureRoot init --quiet;if($LASTEXITCODE){throw 'Owned fixture Git init failed'}
git -C $FixtureRoot apply --check --directory=core $patch;if($LASTEXITCODE){throw 'Patch check failed'}
git -C $FixtureRoot apply --directory=core $patch;if($LASTEXITCODE){throw 'Owned-copy patch failed'}
$runner="$FixtureRoot\core\Invoke-HoblContract.ps1"
. $runner -LibraryOnly
$sha='655A91268C8DE0B8B233492F49014F9F3975BCABE7B0B8B2DC5C22A8E26EAEBA'
$pom='A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D'
Require ((Get-FileHash "$PSScriptRoot\..\hobl-pwsh-pilot\candidate-mvnw.cmd").Hash-eq$sha) 'Public sibling qualification hash changed'
AssertHoblSourceMode $true $true ' M mvnw.cmd' $sha $pom
AssertHoblSourceMode $false $false '' '' ''
$rejects=@()
foreach($case in @(@{mode=$false;windows=$true;dirty=' M mvnw.cmd';hash=$sha;pom=$pom},@{mode=$true;windows=$false;dirty=' M mvnw.cmd';hash=$sha;pom=$pom},@{mode=$true;windows=$true;dirty=' M pom.xml';hash=$sha;pom=$pom},@{mode=$true;windows=$true;dirty=" M mvnw.cmd`n?? other";hash=$sha;pom=$pom},@{mode=$true;windows=$true;dirty=' M mvnw.cmd';hash='wrong';pom=$pom},@{mode=$true;windows=$true;dirty=' M mvnw.cmd';hash=$sha;pom='wrong'})){
    $rejected=$false;try{AssertHoblSourceMode $case.mode $case.windows $case.dirty $case.hash $case.pom}catch{$rejected=$true}
    Require $rejected 'Source mode negative accepted';$rejects+=@{input=$case;rejected=$true}
}
$tokens=$null;$errors=$null;$newAst=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors);Require ($errors.Count-eq0) 'Patched syntax invalid'
$oldAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Baseline 'Invoke-HoblContract.ps1'),[ref]$tokens,[ref]$errors)
foreach($name in 'Phase','ContractArguments'){
    $old=$oldAst.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true)
    $new=$newAst.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true)
    Require ($old.Extent.Text-ceq$new.Extent.Text) 'Native Mac timer/argv/phase changed'
}
$oldLoop=$oldAst.Find({param($n)$n-is[Management.Automation.Language.ForStatementAst]},$true)
$newLoop=$newAst.Find({param($n)$n-is[Management.Automation.Language.ForStatementAst]},$true)
Require ($oldLoop.Extent.Text-ceq$newLoop.Extent.Text) 'Five-loop scenarios changed'
& {
    foreach($name in 'GitText','SourceGate'){$f=$newAst.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true);Invoke-Expression $f.Extent.Text}
    $ProjectFullClone='owned fake project';$result=@{pin='6feeae0f13e0e258eedc99832416b42bb13779b1'}
    function Get-FileHash {param($Path) [pscustomobject]@{Hash=$(if($Path.EndsWith('pom.xml')){$pom}else{$sha})}}
    $script:gitExecutable={if($args[-1]-eq'HEAD'){'6feeae0f13e0e258eedc99832416b42bb13779b1'}else{if($script:preferActive){' M mvnw.cmd'}};$global:LASTEXITCODE=0}
    $prior=[Environment]::GetEnvironmentVariable('MVNW_PREFER_PWSH')
    try{
        $script:preferActive=$false;SourceGate
        $script:preferActive=$true;$env:MVNW_PREFER_PWSH='true'
        if($IsWindows){
            SourceGate
            $env:MVNW_PREFER_PWSH='false';$rejected=$false;try{SourceGate}catch{$rejected=$true};Require $rejected 'Selector loss accepted'
        }else{
            $rejected=$false;try{SourceGate}catch{$rejected=$_.Exception.Message-eq'Preferred pwsh mode is Windows-only'}
            Require $rejected 'Non-Windows preferred mode did not reject'
        }
    }
    finally{$script:preferActive=$false;if($null-eq$prior){Remove-Item Env:MVNW_PREFER_PWSH -ErrorAction SilentlyContinue}else{[Environment]::SetEnvironmentVariable('MVNW_PREFER_PWSH',$prior)}}
}
$core=Get-Content $runner -Raw
Require ($core.Contains("`$expectedDirty=if(`$script:preferActive){'true'}else{'false'}")) 'Git dirty metadata mode missing'
& {
    $assignment=$newAst.Find({param($n)$n-is[Management.Automation.Language.AssignmentStatementAst]-and$n.Extent.Text.StartsWith('$expectedDirty=if(')},$true)
    $gate=$newAst.Find({param($n)$n-is[Management.Automation.Language.CommandAst]-and$n.GetCommandName()-eq'Require'-and$n.Extent.Text.Contains('Wrong packaged Git provenance')},$true)
    foreach($mode in @($false,$true)){foreach($dirty in @('false','true')){
        $script:preferActive=$mode;$text="git.commit.id=6feeae0f13e0e258eedc99832416b42bb13779b1`ngit.dirty=$dirty"
        $rejected=$false;try{. ([scriptblock]::Create($assignment.Extent.Text+';'+$gate.Extent.Text))}catch{$rejected=$true}
        Require ($rejected-eq($dirty-ne$mode.ToString().ToLowerInvariant())) 'Actual metadata dirty-mode gate mismatch'
    }};$script:preferActive=$false
}
Require ($core.IndexOf('[IO.File]::WriteAllBytes($script:wrapper,[IO.File]::ReadAllBytes($candidate))')-lt$core.IndexOf("Phase 'prep-go-offline'")) 'Preference not applied before prep'
Require ($core-notmatch'^\s*\.\s+.*(diagnostic|pilot)' ) 'Circular baseline helper import'
if($OriginalWrapper){
    $originalBytes=[IO.File]::ReadAllBytes($OriginalWrapper);Require ((HashBytes $originalBytes)-eq'5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A') 'Wrong original fixture'
    $restoreNode=$newAst.Find({param($n)$n-is[Management.Automation.Language.TryStatementAst]-and$n.Extent.Text.StartsWith('try{if($preferOriginalBytes)')},$true)
    Require $restoreNode 'Production source-restore block missing'
    & {
        $script:wrapper=Join-Path $FixtureRoot 'restore-wrapper.cmd';$preferOriginalBytes=$originalBytes;$restoreErrors=@();$result=@{}
        Copy-Item "$PSScriptRoot\..\hobl-pwsh-pilot\candidate-mvnw.cmd" $script:wrapper
        $script:preferActive=$true;. ([scriptblock]::Create($restoreNode.Extent.Text))
        Require ($restoreErrors.Count-eq0-and-not$script:preferActive-and(Get-FileHash $script:wrapper).Hash-eq'5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A') 'Actual source restoration failed'
        [IO.File]::WriteAllText($script:wrapper,'unexpected owned fixture');$restoreErrors=@();$script:preferActive=$true
        . ([scriptblock]::Create($restoreNode.Extent.Text))
        Require ($restoreErrors.Count-eq1-and[IO.File]::ReadAllText($script:wrapper)-ceq'unexpected owned fixture') 'Unexpected source overwritten'
        $script:preferActive=$false
    }
}
$restoreEnv=$newAst.Find({param($n)$n-is[Management.Automation.Language.ForEachStatementAst]-and$n.Extent.Text.StartsWith('foreach($name in $saved.Keys)')},$true)
Require $restoreEnv 'Production environment-restore block missing'
$priorSelector=[Environment]::GetEnvironmentVariable('MVNW_PREFER_PWSH')
try{
    foreach($value in @($null,'','prior-value')){
        if($null-eq$value){Remove-Item Env:MVNW_PREFER_PWSH -ErrorAction SilentlyContinue}else{[Environment]::SetEnvironmentVariable('MVNW_PREFER_PWSH',$value)}
        $saved=@{MVNW_PREFER_PWSH=[Environment]::GetEnvironmentVariable('MVNW_PREFER_PWSH')};$restoreErrors=@();$env:MVNW_PREFER_PWSH='true'
        . ([scriptblock]::Create($restoreEnv.Extent.Text))
        Require ($restoreErrors.Count-eq0-and[string]::Equals($saved.MVNW_PREFER_PWSH,[Environment]::GetEnvironmentVariable('MVNW_PREFER_PWSH'),[StringComparison]::Ordinal)) 'Actual selector absence/empty/value restore failed'
    }
}finally{if($null-eq$priorSelector){Remove-Item Env:MVNW_PREFER_PWSH -ErrorAction SilentlyContinue}else{[Environment]::SetEnvironmentVariable('MVNW_PREFER_PWSH',$priorSelector)}}
& (Get-Command pwsh).Source -NoProfile -File "$FixtureRoot\core\Test-HoblContract.ps1" -FixtureRoot "$FixtureRoot\original17" *> "$FixtureRoot\original17.log"
Require ($LASTEXITCODE-eq0) 'Original17 static suite failed against patched copy'
$workflow=Get-Content "$PSScriptRoot\matched-after.workflow.yml" -Raw
Require ($workflow.Contains('runner: [windows-11-arm, macos-15]')-and$workflow.Contains('-WindowsPreferPwsh:$IsWindows')-and$workflow.Contains('inputs.windows_benefit_reviewed')-and$workflow.Contains('environment: hobl-contract-approval')) 'Matched manual platform gate missing'
@{exit=0;patchApply=$true;syntax=$true;positiveMode=$true;negativeCases=$rejects;actualSourceGateBothModes=$true;hostWindows=[bool]$IsWindows;preferredProductionExpectation=$(if($IsWindows){'success-and-selector-loss-rejection'}else{'Windows-only-rejection'});defaultProductionExpectation='success';macTimerArgvFiveLoopAstUnchanged=$true;original17Exit=0;javaMavenBootstrap=$false}|ConvertTo-Json -Depth 6|Set-Content "$FixtureRoot\results.json"
$global:LASTEXITCODE=0
