param([Parameter(Mandatory)][string]$FixtureRoot,[string]$Baseline=(Join-Path $PSScriptRoot '..\hobl-contract'),[string]$OriginalWrapper,[switch]$EnvironmentChild,[string]$PatchedDriver)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
function NativeMatchedScriptPath([string]$Path){
    $resolved=Resolve-Path -LiteralPath $Path -ErrorAction Stop
    if(@($resolved).Count-ne1-or$resolved.Provider.Name-ne'FileSystem'-or-not(Test-Path -LiteralPath $resolved.ProviderPath -PathType Leaf)){throw 'One actual filesystem script required'}
    return $resolved.ProviderPath
}
function ReadMatchedAdmission([string]$Workflow){
    $expression=[regex]::Match($Workflow,'(?m)^\s+if: ([^\r\n]+)').Groups[1].Value
    if(-not$expression){throw 'Production admission expression missing'}
    $expression=$expression.Replace('github.repository','$Repository').Replace('inputs.acknowledgement','$Acknowledgement').Replace('inputs.windows_benefit_reviewed','$Reviewed').Replace('inputs.platform_selection','$Selection').Replace('==','-eq').Replace('&&','-and').Replace('||','-or')
    return [scriptblock]::Create('param($Repository,$Acknowledgement,$Reviewed,$Selection) '+$expression)
}
function ReadMatchedRunners([string]$Workflow,[string]$Selection){
    $expression=[regex]::Match($Workflow,'runner: \$\{\{ fromJSON\((.*?)\) \}\}').Groups[1].Value
    if(-not$expression){throw 'Production matrix expression missing'}
    $branches=[regex]::Matches($expression,'inputs\.platform_selection == ''([^'']+)'' && ''([^'']+)''')
    foreach($branch in $branches){if($Selection-eq$branch.Groups[1].Value){return @($branch.Groups[2].Value|ConvertFrom-Json)}}
    $fallback=[regex]::Match($expression,'\|\| ''([^'']+)''$')
    if(-not$fallback.Success){throw 'Production matrix fallback missing'}
    return @($fallback.Groups[1].Value|ConvertFrom-Json)
}
if($EnvironmentChild){
    New-Item $FixtureRoot -ItemType Directory|Out-Null
    $PatchedDriver=NativeMatchedScriptPath $PatchedDriver
    . $PatchedDriver -LibraryOnly
    $tokens=$null;$errors=$null;$driverAst=[Management.Automation.Language.Parser]::ParseFile($PatchedDriver,[ref]$tokens,[ref]$errors)
    @{nativePath=$PatchedDriver;errors=@($errors|ForEach-Object {@{id=$_.ErrorId;message=$_.Message;file=$_.Extent.File;line=$_.Extent.StartLineNumber;column=$_.Extent.StartColumnNumber;text=$_.Extent.Text}})}|ConvertTo-Json -Depth 10|Set-Content "$FixtureRoot\parser-proof.json"
    Require ($errors.Count-eq0) 'Child driver syntax failed'
    $namesNode=$driverAst.Find({param($n)$n-is[Management.Automation.Language.AssignmentStatementAst]-and$n.Extent.Text.StartsWith('$managedEnvironmentNames=@(')},$true)
    . ([scriptblock]::Create($namesNode.Extent.Text))
    Require ($managedEnvironmentNames.Count-eq11) 'Production managed set is not eleven'
    $originalEnvironment=GetMatchedEnvironmentSnapshot
    try{
        [Environment]::SetEnvironmentVariable('MAVEN_ARGS','','Process')
        Remove-Item Env:MVNW_PREFER_PWSH -ErrorAction SilentlyContinue
        $before=GetMatchedEnvironmentSnapshot
        if($IsWindows){
            [Environment]::SetEnvironmentVariable('MAVEN_ARGS','old-scope-counterexample','Process')
            $old=RestoreBoundaryEnvironment $before @('MAVEN_OPTS')
            Require ($old.restored-and$env:MAVEN_ARGS-ceq'old-scope-counterexample') 'Original narrow counterexample not reproduced'
            $null=RestoreMatchedEnvironment $before $managedEnvironmentNames
        }
        foreach($name in $managedEnvironmentNames){[Environment]::SetEnvironmentVariable($name,"inner-mutated-$name",'Process')}
        if($IsWindows){[Environment]::SetEnvironmentVariable('pAtH','inner-mixed-case-path','Process')}
        $saved=$before;$result=@{}
        $restoreNode=$driverAst.Find({param($n)$n-is[Management.Automation.Language.AssignmentStatementAst]-and$n.Extent.Text.StartsWith('$result.environmentRestoration=RestoreMatchedEnvironment')},$true)
        . ([scriptblock]::Create($restoreNode.Extent.Text))
        Require ($result.environmentRestoration.restored-and$result.environmentRestoration.keys.Count-eq11-and@($result.environmentRestoration.keys|Where-Object {-not$_.equal}).Count-eq0) 'Actual inner production eleven-key restore failed'
        Require ((Test-Path Env:MAVEN_ARGS)-and$env:MAVEN_ARGS-ceq''-and-not(Test-Path Env:MVNW_PREFER_PWSH)) 'Empty/absent state lost'
        $workflow=Get-Content "$PSScriptRoot\matched-after.workflow.yml" -Raw
        $outerNames=[regex]::Match($workflow,'(?m)^\s*\$managedEnvironmentNames=@\([^\r\n]+').Value
        . ([scriptblock]::Create($outerNames))
        foreach($name in $managedEnvironmentNames){[Environment]::SetEnvironmentVariable($name,"outer-mutated-$name",'Process')}
        $prior=$before;$receipt=@{}
        $outerRestore=[regex]::Match($workflow,'(?m)^\s*\$receipt\.restoration=RestoreMatchedEnvironment[^\r\n]+').Value
        . ([scriptblock]::Create($outerRestore))
        Require ($receipt.restoration.restored-and$receipt.restoration.keys.Count-eq11-and@($receipt.restoration.keys|Where-Object {-not$_.equal}).Count-eq0) 'Actual outer production eleven-key restore failed'
        $proof=@{status='PASS';legacySubsetCounterexampleReproducedOnWindows=[bool]$IsWindows;actualInner=$result.environmentRestoration;actualOuter=$receipt.restoration;emptyMavenArgsPreserved=((Test-Path Env:MAVEN_ARGS)-and$env:MAVEN_ARGS-ceq'');absentPreferencePreserved=(-not(Test-Path Env:MVNW_PREFER_PWSH))}
        $serialized=$proof|ConvertTo-Json -Depth 10;$roundtrip=$serialized|ConvertFrom-Json
        Require ($roundtrip.actualInner.keys.Count-eq11-and$roundtrip.actualOuter.keys.Count-eq11-and$roundtrip.actualInner.keys[0].name) 'Depth10 nested serialized receipt lost concrete records'
        $serialized|Set-Content "$FixtureRoot\eleven-key-proof.json"
    }finally{
        $finalRestore=RestoreMatchedEnvironment $originalEnvironment $managedEnvironmentNames
        Require $finalRestore.restored 'Disposable child original environment not restored'
    }
    $global:LASTEXITCODE=0
    return
}
if(Test-Path $FixtureRoot){throw 'Fresh owned fixtures required'}
New-Item "$FixtureRoot\core" -ItemType Directory|Out-Null;$FixtureRoot=(Resolve-Path $FixtureRoot).Path
Get-ChildItem $Baseline -File|Copy-Item -Destination "$FixtureRoot\core"
New-Item "$FixtureRoot\hobl-wrapper-diagnostic" -ItemType Directory|Out-Null
Copy-Item "$PSScriptRoot\..\hobl-wrapper-diagnostic\Invoke-WrapperBoundary.ps1" "$FixtureRoot\hobl-wrapper-diagnostic"
$patch=(Resolve-Path "$PSScriptRoot\matched-after.patch").Path
git -C $FixtureRoot init --quiet;if($LASTEXITCODE){throw 'Owned fixture Git init failed'}
git -C $FixtureRoot apply --check --directory=core $patch;if($LASTEXITCODE){throw 'Patch check failed'}
git -C $FixtureRoot apply --directory=core $patch;if($LASTEXITCODE){throw 'Owned-copy patch failed'}
$runner=NativeMatchedScriptPath (Join-Path (Join-Path $FixtureRoot 'core') 'Invoke-HoblContract.ps1')
. $runner -LibraryOnly
$sha='655A91268C8DE0B8B233492F49014F9F3975BCABE7B0B8B2DC5C22A8E26EAEBA'
$pom='A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D'
Require ((Get-FileHash "$PSScriptRoot\..\hobl-pwsh-pilot\candidate-mvnw.cmd").Hash-eq$sha) 'Public sibling qualification hash changed'
AssertHoblSourceMode $true $true ' M mvnw.cmd' $sha $pom
AssertHoblSourceMode $false $false '' '' ''
$https='AAA4957C5AB29267A0D89C03D33621740A4233BF25AFEB480797023687CABB7D'
Require ((Get-FileHash "$PSScriptRoot\..\hobl-pwsh-pilot\upstream-f62f442-https-license-mvnw.cmd").Hash-eq$https) 'HTTPS data drift'
AssertHoblSourceMode $true $true ' M mvnw.cmd' $https $pom 'UpstreamF62f442HttpsLicense'
$rejected=$false;try{AssertHoblSourceMode $true $true ' M mvnw.cmd' $sha $pom 'UpstreamF62f442HttpsLicense'}catch{$rejected=$true};Require $rejected 'Old prototype accepted as HTTPS'
$rejected=$false;try{AssertHoblSourceMode $true $true ' M mvnw.cmd' $https $pom}catch{$rejected=$true};Require $rejected 'HTTPS accepted under old default'
& {
    function Get-Content {param($Path,[switch]$Raw) '<suppressions><suppress files="node_modules[\\/].*" checks=".*"/><suppress files="node[\\/].*" checks=".*"/><suppress files="build[\\/].*" checks=".*"/><suppress files="target[\\/].*" checks=".*"/><suppress files=".+\.(jar|git|ico|p12|gif|jks|jpg|svg|log)" checks="NoHttp"/></suppressions>'}
    AssertHoblNoHttpPath (Join-Path ([IO.Path]::GetPathRoot($FixtureRoot)) 'owned-worktrees/project') $true
    AssertHoblNoHttpPath (Join-Path ([IO.Path]::GetPathRoot($FixtureRoot)) 'owned-worktrees/project') $false
    foreach($segment in 'build','target','node','node_modules'){
        $blocked=$false;try{AssertHoblNoHttpPath (Join-Path ([IO.Path]::GetPathRoot($FixtureRoot)) "owned/$segment/project") $true}catch{$blocked=$true}
        Require $blocked 'Suppressing source ancestry accepted'
    }
}
$rejects=@()
foreach($case in @(@{mode=$false;windows=$true;dirty=' M mvnw.cmd';hash=$sha;pom=$pom},@{mode=$true;windows=$false;dirty=' M mvnw.cmd';hash=$sha;pom=$pom},@{mode=$true;windows=$true;dirty=' M pom.xml';hash=$sha;pom=$pom},@{mode=$true;windows=$true;dirty=" M mvnw.cmd`n?? other";hash=$sha;pom=$pom},@{mode=$true;windows=$true;dirty=' M mvnw.cmd';hash='wrong';pom=$pom},@{mode=$true;windows=$true;dirty=' M mvnw.cmd';hash=$sha;pom='wrong'})){
    $rejected=$false;try{AssertHoblSourceMode $case.mode $case.windows $case.dirty $case.hash $case.pom}catch{$rejected=$true}
    Require $rejected 'Source mode negative accepted';$rejects+=@{input=$case;rejected=$true}
}
$tokens=$null;$errors=$null;$newAst=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
@{nativePath=$runner;errors=@($errors|ForEach-Object {@{id=$_.ErrorId;message=$_.Message;file=$_.Extent.File;line=$_.Extent.StartLineNumber;column=$_.Extent.StartColumnNumber;text=$_.Extent.Text}})}|ConvertTo-Json -Depth 10|Set-Content "$FixtureRoot\parser-proof.json"
Require ($errors.Count-eq0) 'Patched syntax invalid'
$oldAst=[Management.Automation.Language.Parser]::ParseFile((NativeMatchedScriptPath (Join-Path $Baseline 'Invoke-HoblContract.ps1')),[ref]$tokens,[ref]$errors)
& {
    $drive='NativePath'+[Guid]::NewGuid().ToString('N')
    New-PSDrive -Name $drive -PSProvider FileSystem -Root "$FixtureRoot\core" -Scope Local|Out-Null
    try{
        $providerPath=$drive+':\Invoke-HoblContract.ps1'
        Require (Test-Path -LiteralPath $providerPath) 'Provider fixture not an existing file'
        $t=$null;$badErrors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($providerPath,[ref]$t,[ref]$badErrors)
        Require ($badErrors.Count-gt0-and$badErrors[0].ErrorId-eq'FileReadError') 'Old native/provider boundary did not fail as expected'
        $native=NativeMatchedScriptPath $providerPath
        $t=$null;$fixedErrors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($native,[ref]$t,[ref]$fixedErrors)
        Require ($fixedErrors.Count-eq0-and(Get-FileHash $native).Hash-eq(Get-FileHash $runner).Hash) 'Native-path fix changed bytes or still failed'
        $malformed=Join-Path $FixtureRoot 'malformed-script.ps1';[IO.File]::WriteAllText($malformed,'function Broken {')
        $t=$null;$syntaxErrors=$null;$null=[Management.Automation.Language.Parser]::ParseFile((NativeMatchedScriptPath $malformed),[ref]$t,[ref]$syntaxErrors)
        Require ($syntaxErrors.Count-gt0) 'Genuine syntax errors bypassed'
        @{oldErrorId=$badErrors[0].ErrorId;oldMessage=$badErrors[0].Message;oldLine=$badErrors[0].Extent.StartLineNumber;oldColumn=$badErrors[0].Extent.StartColumnNumber;oldSource=$badErrors[0].Extent.File;fixedNativePath=$native;fixedErrors=0;identicalBytes=$true;genuineSyntaxRejected=$true}|ConvertTo-Json -Depth 10|Set-Content "$FixtureRoot\native-path-regression.json"
    }finally{Remove-PSDrive $drive}
}
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
    function Get-FileHash {param($Path) [pscustomobject]@{Hash=$(if($Path.EndsWith('pom.xml')){$pom}else{$script:fixtureWrapperHash})}}
    $script:gitExecutable={if($args[-1]-eq'HEAD'){'6feeae0f13e0e258eedc99832416b42bb13779b1'}else{if($script:preferActive){' M mvnw.cmd'}};$global:LASTEXITCODE=0}
    $prior=[Environment]::GetEnvironmentVariable('MVNW_PREFER_PWSH')
    try{
        $script:fixtureWrapperHash=$sha;$script:preferRevision='Prototype334'
        $script:preferActive=$false;SourceGate
        $script:preferActive=$true;$env:MVNW_PREFER_PWSH='true'
        if($IsWindows){
            SourceGate
            $script:preferRevision='UpstreamF62f442HttpsLicense';$script:fixtureWrapperHash=$https;SourceGate
            $script:fixtureWrapperHash=$sha;$rejected=$false;try{SourceGate}catch{$rejected=$true};Require $rejected 'Actual HTTPS SourceGate accepted prototype bytes'
            $script:preferRevision='Prototype334';$script:fixtureWrapperHash=$sha
            $env:MVNW_PREFER_PWSH='false';$rejected=$false;try{SourceGate}catch{$rejected=$true};Require $rejected 'Selector loss accepted'
        }else{
            $rejected=$false;try{SourceGate}catch{$rejected=$_.Exception.Message-eq'Preferred pwsh mode is Windows-only'}
            Require $rejected 'Non-Windows preferred mode did not reject'
        }
    }
    finally{$script:preferActive=$false;$script:preferRevision='Prototype334';if($null-eq$prior){Remove-Item Env:MVNW_PREFER_PWSH -ErrorAction SilentlyContinue}else{[Environment]::SetEnvironmentVariable('MVNW_PREFER_PWSH',$prior)}}
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
        $script:preferRevision='Prototype334';$script:preferActive=$true;. ([scriptblock]::Create($restoreNode.Extent.Text))
        Require ($restoreErrors.Count-eq0-and-not$script:preferActive-and(Get-FileHash $script:wrapper).Hash-eq'5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A') 'Actual source restoration failed'
        Copy-Item "$PSScriptRoot\..\hobl-pwsh-pilot\upstream-f62f442-https-license-mvnw.cmd" $script:wrapper -Force
        $script:preferRevision='UpstreamF62f442HttpsLicense';$script:preferActive=$true;$restoreErrors=@()
        . ([scriptblock]::Create($restoreNode.Extent.Text))
        Require ($restoreErrors.Count-eq0-and-not$script:preferActive-and(Get-FileHash $script:wrapper).Hash-eq'5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A') 'HTTPS source restoration failed'
        [IO.File]::WriteAllText($script:wrapper,'unexpected owned fixture');$restoreErrors=@();$script:preferActive=$true
        . ([scriptblock]::Create($restoreNode.Extent.Text))
        Require ($restoreErrors.Count-eq1-and[IO.File]::ReadAllText($script:wrapper)-ceq'unexpected owned fixture') 'Unexpected source overwritten'
        $script:preferActive=$false;$script:preferRevision='Prototype334'
    }
}
& (Get-Process -Id $PID).Path -NoProfile -File $PSCommandPath -FixtureRoot "$FixtureRoot\environment-child" -EnvironmentChild -PatchedDriver $runner *> "$FixtureRoot\environment-child.log"
Require ($LASTEXITCODE-eq0) 'Isolated child actual eleven-key production restoration failed'
& (Get-Process -Id $PID).Path -NoProfile -File "$FixtureRoot\core\Test-HoblContract.ps1" -FixtureRoot "$FixtureRoot\original17" *> "$FixtureRoot\original17.log"
Require ($LASTEXITCODE-eq0) 'Original17 static suite failed against patched copy'
$workflow=Get-Content "$PSScriptRoot\matched-after.workflow.yml" -Raw
Require ($workflow.Contains('-WindowsPreferPwsh:$IsWindows')-and$workflow.Contains('inputs.windows_benefit_reviewed')-and$workflow.Contains('environment: hobl-contract-approval')) 'Matched manual platform gate missing'
Require ($workflow.Contains('default: Both')-and$workflow.Contains('options: [Both, MacOnly]')) 'Platform selection default changed'
$admission=ReadMatchedAdmission $workflow
$platformCases=@()
foreach($selection in @('Both','MacOnly','INVALID','',$null)){
    $admitted=[bool](& $admission 'yeelam-gordon/spring-petclinic' 'I_HAVE_APPROVAL_AND_BUDGET' $true $selection)
    $runners=@(ReadMatchedRunners $workflow $selection)
    $valid=$selection-in@('Both','MacOnly')
    Require ($admitted-eq$valid) 'Actual production admission accepted invalid/empty selector'
    if($selection-eq'Both'){Same $runners @('windows-11-arm','macos-15') 'Both default changed'}
    elseif($selection-eq'MacOnly'){Same $runners @('macos-15') 'MacOnly must create only Mac'}
    else{Require ($runners.Count-eq0) 'Invalid selector falls through to Windows/Both'}
    $platformCases+=@{selection=$selection;admitted=$admitted;runners=$runners}
}
foreach($selection in 'Both','MacOnly'){
    Require (-not(& $admission 'not-owner/repo' 'I_HAVE_APPROVAL_AND_BUDGET' $true $selection)) 'Platform OR bypasses owner guard'
    Require (-not(& $admission 'yeelam-gordon/spring-petclinic' 'wrong-ack' $true $selection)) 'Platform OR bypasses acknowledgement'
    Require (-not(& $admission 'yeelam-gordon/spring-petclinic' 'I_HAVE_APPROVAL_AND_BUDGET' $false $selection)) 'Platform OR bypasses benefit review'
}
$platformCases|ConvertTo-Json -Depth 10|Set-Content "$FixtureRoot\platform-admission.json"
Require ($workflow.Contains('default: Prototype334')-and$workflow.Contains('UpstreamF62f442HttpsLicense')-and$workflow.Contains('-WindowsCandidateRevision $env:WINDOWS_CANDIDATE_REVISION')) 'Explicit HTTPS paired-cohort input missing'
@{exit=0;patchApply=$true;syntax=$true;positiveMode=$true;httpsCandidateSha256=$https;httpsPositiveAndCrossVariantRejection=$true;noHttpAncestryPositiveNegative=$true;httpsOriginalWrapperRestoration=$true;elevenKeyActualInnerOuterChildExit=0;depth10ConcreteReceipts=$true;negativeCases=$rejects;actualSourceGateBothModes=$true;hostWindows=[bool]$IsWindows;preferredProductionExpectation=$(if($IsWindows){'success-and-selector-loss-rejection'}else{'Windows-only-rejection'});defaultProductionExpectation='success';macTimerArgvFiveLoopAstUnchanged=$true;original17Exit=0;javaMavenBootstrap=$false}|ConvertTo-Json -Depth 6|Set-Content "$FixtureRoot\results.json"
$global:LASTEXITCODE=0
