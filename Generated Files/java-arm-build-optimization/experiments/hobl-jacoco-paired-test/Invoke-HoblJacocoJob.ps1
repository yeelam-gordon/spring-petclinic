param([string]$ProjectFullClone,[string]$JavaHome,[string]$LocalCache,[string]$OutputDirectory,[string]$SetupDirectory,[string]$PythonExecutable,[switch]$ExecuteAuthorized,[switch]$CandidateReviewed,[switch]$LibraryOnly)
$ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$false
$codeRoot=$PSScriptRoot
$hashes=@{'Invoke-HoblJacocoTest.ps1'='DD91261D4A74F8AABBC985E4326F440056061D6BA5C6CE85069FF4F37E61BE31';'Test-HoblJacocoFlow.ps1'='AAEFF110BFD1270F7959DA1EC7CBE69284EE0B43D6E04322826C067ED443EDAD';'HoblJacocoContract.psm1'='3428BB2747D3EC16A5A62DCD443881886E94BA26BC642374836C89F0201A03EC';'Read-HoblExec.py'='4D25DB06B17285EDB7C9F5056DBAB67568D3C1D4992D2AE074A305A1C6B5C64A';'Test-HoblJacocoContract.ps1'='2FA14572AB97D5B4E82DA9CE59E7101CC7412ECA5B79D14A656EEB2AF675D606';'trial-pom.xml'='D7FF6C0FB845850374020A16A65F4B2B1F1BF8E3204C65AB56BDCA2137BDA818';'trial-pom.patch'='6AA4D014892B36CB3DB0D7558A218A1A514D14F8A3CBABC55D4A44CA4799685E'}
$payloadChecks=@()
$expectedBytes=@{'Invoke-HoblJacocoTest.ps1'=16743;'Test-HoblJacocoFlow.ps1'=11626;'HoblJacocoContract.psm1'=16814;'Read-HoblExec.py'=1987;'Test-HoblJacocoContract.ps1'=10335;'trial-pom.xml'=16489;'trial-pom.patch'=883}
foreach($name in $hashes.Keys){
    $resolved=Resolve-Path -LiteralPath (Join-Path $codeRoot $name);$bytes=[IO.File]::ReadAllBytes($resolved.ProviderPath)
    $actual=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
    $check=@{name=$name;expectedSha256=$hashes[$name];actualSha256=$actual;expectedBytes=$expectedBytes[$name];actualBytes=$bytes.Length};$payloadChecks+=,$check
    if($actual-cne$hashes[$name]-or$bytes.Length-ne$expectedBytes[$name]){
        $diagnostics=if($SetupDirectory){$SetupDirectory}elseif($env:GITHUB_WORKSPACE){Join-Path $env:GITHUB_WORKSPACE 'hobl-jacoco-owned/setup-evidence'}else{$null}
        if($diagnostics){
            New-Item $diagnostics -ItemType Directory -Force|Out-Null
            [IO.File]::WriteAllBytes((Join-Path $diagnostics "failed-$name.bytes"),$bytes)
            $policy=@();foreach($key in 'core.autocrlf','core.eol'){$value=@(& git -C $codeRoot config --get $key);$policy+=@{key=$key;values=$value;exitCode=$LASTEXITCODE}}
            $attributes=@(& git -C $codeRoot check-attr text eol -- $name)
            @{status='FAIL';error="Reviewed payload changed: $name";checks=$payloadChecks;effectiveSpecificGitPolicy=$policy;attributes=$attributes}|ConvertTo-Json -Depth 10|Set-Content (Join-Path $diagnostics 'payload-mismatch.json')
        }
        throw "Reviewed payload changed: $name"
    }
}
Import-Module (Join-Path $codeRoot 'HoblJacocoContract.psm1') -Force -DisableNameChecking
function RequireJob($Value,[string]$Message){if(-not$Value){throw $Message}}
function NativeJobLeaf([string]$Path){$p=Resolve-Path -LiteralPath $Path;RequireJob ($p.Provider.Name-eq'FileSystem'-and(Test-Path $p.ProviderPath -PathType Leaf)) 'Native filesystem leaf required';return $p.ProviderPath}
function GetHoblJacocoJobPlan([string]$Project,[string]$Jdk,[string]$Cache,[string]$Evidence,[string]$Python){
    return @{runner=(NativeJobLeaf (Join-Path $codeRoot 'Invoke-HoblJacocoTest.ps1'));parameters=@{ProjectFullClone=$Project;JavaHome=$Jdk;LocalCache=$Cache;OutputDirectory=$Evidence;PythonExecutable=(NativeJobLeaf $Python);ExecuteAuthorized=$true;CandidateReviewed=$true}}
}
function InvokeHoblJobRunner($Plan){$parameters=$Plan.parameters;$global:LASTEXITCODE=0;& $Plan.runner @parameters;$native=$LASTEXITCODE;RequireJob ($native-eq0) "Runner process exit=$native"}
function RestoreHoblJobOuter($Before){RestoreHoblContractEnvironment $Before}
function InvokeHoblJacocoJob([ValidateSet('Windows','MacOS')][string]$Platform,$Plan,[string]$Setup){
    New-Item $Setup -ItemType Directory -Force|Out-Null
    $before=GetHoblContractEnvironment;$original=[Environment]::GetEnvironmentVariable('MAVEN_OPTS')
    $empty=[string]::IsNullOrEmpty($original);$known=$Platform-eq'Windows'-and$original-ceq'-Xms256m'
    $receipt=@{status='RUNNING';scope='HOBLDerivedWarmTest_NOT5Loop_NOTBuild';platform=$Platform;runnerInvoked=$false;outerRestored=$false;payloadHashes=$hashes;payloadChecks=$payloadChecks;nativeRunner=$Plan.runner;parameters=$Plan.parameters;observedMavenOpts=$(if($empty-or$known){$original}else{'[REDACTED_UNKNOWN]'});originalMavenOptsSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes([string]$original)));normalization=$(if($empty){'accept empty/absent'}elseif($known){'exact reviewed Windows -Xms256m to common empty'}else{'reject unknown'});cleanupErrors=@()}
    $originalError=$null;$path=Join-Path $Setup 'job-environment.json'
    try{
        RequireJob ($empty-or$known) 'Unknown MAVEN_OPTS rejected before invocation'
        Remove-Item Env:MAVEN_OPTS -ErrorAction SilentlyContinue
        $receipt.runnerInvoked=$true
        InvokeHoblJobRunner $Plan
    }catch{$originalError=$_;$receipt.originalFailure=$_.ToString();$receipt.originalFailurePosition=$_.InvocationInfo.PositionMessage}
    finally{
        if($receipt.runnerInvoked){
            try{
                $innerPath=Join-Path $Plan.parameters.OutputDirectory 'result.json'
                RequireJob (Test-Path -LiteralPath $innerPath -PathType Leaf) 'Inner result/cleanup receipt missing'
                $inner=Get-Content -LiteralPath $innerPath -Raw|ConvertFrom-Json
                $receipt.inner=@{status=$inner.status;sourceRestored=$inner.sourceRestored;environmentRestoration=$inner.environmentRestoration;remainingJavaCandidates=$inner.remainingJavaCandidates;failure=$inner.failure;restorationFailures=$inner.restorationFailures}
                RequireJob ($inner.status-ceq'PASS'-and$inner.scope-ceq'HOBLDerivedWarmTest_NOT5Loop_NOTBuild'-and$inner.pin-ceq'6feeae0f13e0e258eedc99832416b42bb13779b1'-and$inner.trialPomSha256-ceq'D7FF6C0FB845850374020A16A65F4B2B1F1BF8E3204C65AB56BDCA2137BDA818'-and$inner.samples.Count-eq6-and$inner.snapshots.Count-eq8-and$inner.sourceRestored-and$inner.environmentRestoration.restored-and$inner.environmentRestoration.cwdEqual-and$inner.environmentRestoration.keys.Count-eq11-and@($inner.environmentRestoration.keys|Where-Object {-not$_.equal}).Count-eq0-and$inner.remainingJavaCandidates-eq0) 'Inner complete flow/source/eleven-key/cwd/Java proof failed'
            }catch{$receipt.cleanupErrors+=@{phase='inner-receipt';error=$_.ToString()}}
        }
        try{$receipt.outer=RestoreHoblJobOuter $before;$receipt.outerRestored=($receipt.outer.restored-and$receipt.outer.cwdEqual-and$receipt.outer.keys.Count-eq11);RequireJob $receipt.outerRestored 'Outer eleven-key/cwd restore failed'}catch{$receipt.cleanupErrors+=@{phase='outer-restoration';error=$_.ToString()}}
        $receipt.status=if(-not$originalError-and$receipt.cleanupErrors.Count-eq0){'PASS'}else{'FAIL'}
        $receipt|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $path
    }
    if($receipt.status-cne'PASS'){throw ((@($receipt.originalFailure)+@($receipt.cleanupErrors|ForEach-Object {"$($_.phase): $($_.error)"}))-join'; ')}
    return $receipt
}
if($LibraryOnly){return}
RequireJob ($ExecuteAuthorized-and$CandidateReviewed-and($IsWindows-or$IsMacOS)) 'Explicit native two-OS warm-test approval required'
$plan=GetHoblJacocoJobPlan $ProjectFullClone $JavaHome $LocalCache $OutputDirectory $PythonExecutable
$null=InvokeHoblJacocoJob $(if($IsWindows){'Windows'}else{'MacOS'}) $plan $SetupDirectory
$global:LASTEXITCODE=0
