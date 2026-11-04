function Assert-PScreen($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function Import-PScreen {
    $spec=@{
        'H3911.Source.psm1'=@('6AC4B84BEEDEED24E6330D556BFAA2954CA2D4771880F2A0C2602AEF5B91A1C0',@('Assert-H3911Source','Assert-H3911Inventory'))
        'H3911.Artifacts.psm1'=@('BD2B01750B3F6954425599F0E70F34F2A04B122E03724B1482704E76FC6B55F6',@('Read-H3911Artifact','Compare-H3911Artifacts'))
        'H3911.Offline.psm1'=@('99B6CA8A3025FBF5D55C7DE8E1871C8C0BEF47A69CA541D4C1472A73CC6BEF1D',@('Assert-H3911OfflineDelta'))
        'H3911.CallKernel.psm1'=@('14D87CEFF68D26689C4A05D56BF503C75F8C95942ED4685538738FAD8FB9FE9F',@('Assert-H3911KernelPOM','Invoke-H3911WindowsKernelProcess'))
        'H3911.GateOwner.psm1'=@('406C71D922394EAA666FE8759390C9114B1457461BA9E4F4C69859CE28A5C647',@('Assert-QualifierOwnerWitnessContent','Read-QualifierPrivateJava'))
        'H3911.StockMaven3911.psm1'=@('3D8DCF80AFF694FDC716122B2E76274BBB2D5FD7D882C7D04DC61DE5EF55911D',@('Assert-H3911StockMaven3911'))}
    $spec['H3911.Helpers.psm1']=@('1F1C0099CDC1A7DA6FE949BF973269418DCAAC0E1539A4598A6E5CCFE3720BAA',@('TestKeys','CoverageKeys','CoverageSemantics','JacocoExecEvidence'))
    $bound=@{}
    foreach($row in $spec.GetEnumerator()){
        $file=Join-Path $PSScriptRoot $row.Key;& ${function:Assert-PScreen} ((Microsoft.PowerShell.Utility\Get-FileHash $file).Hash-ceq$row.Value[0]) 'Sampling dependency differs'
        $m=Import-Module $file -Scope Local -PassThru -DisableNameChecking
        foreach($name in $row.Value[1]){$command=$m.ExportedCommands[$name];& ${function:Assert-PScreen} ($command-is[Management.Automation.FunctionInfo]-and$command.Module.Path-ceq$file) 'Sampling command object origin differs';$bound[$name]=$command}
    }
    $bound
}
function Get-H3911RetainedProtocol {
    param([ValidateSet('Qualify','PackageScreen',IgnoreCase=$false)][string]$Mode='Qualify',[ValidateSet('Windows','MacOS',IgnoreCase=$false)][string]$Platform='Windows')
    $calls=@();foreach($label in 'baseline-project','daemon-arch','daemon-home','daemon-project','baseline-maven-home','baseline-verify','candidate-verify'){$calls+=@{label=$label;kind='qualification';timed=$false}}
    if($Mode-ceq'PackageScreen'){
        $i=0
        foreach($route in 'A','B','A','B','B','A','A','B'){
            $i++;$prefix=if($i-le2){'warmup'}else{'sample'};$label="$prefix-$i-$route"
            $calls+=@{label=($label+'-clean');kind='clean';route=$route;timed=$false}
            $calls+=@{label=$label;kind='package';route=$route;timed=($i-gt2)}
        }
    }
    $calls+=@{label='normal-stop';kind='stop';timed=$false}
    @{mode=$Mode;platform=$Platform;calls=$calls;normalMaximum=$calls.Count;emergencyMaximum=($calls.Count+1);timedPackageOrder=$(if($Mode-ceq'PackageScreen'){'ABBAAB'}else{''});routeA=$(if($Platform-ceq'Windows'){'reviewed AAA/native Core/Maven3911'}else{'original Unix wrapper/Maven3911'});routeB=$(if($Platform-ceq'Windows'){'mvnd103 JVM/native25 daemon'}else{'official native Darwin103'});runtimeAllocated=$false}
}
function Get-PScreenFileBinding([string]$Path){
    & ${function:Assert-PScreen} ([IO.Path]::IsPathFullyQualified($Path)) 'Absolute retained evidence required'
    $file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop;$probe=$file
    & ${function:Assert-PScreen} ($file-is[IO.FileInfo]) 'Regular retained evidence required'
    while($probe){& ${function:Assert-PScreen} (-not($probe.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not$probe.LinkType) 'Linked retained evidence/ancestry';$probe=if($probe-is[IO.FileInfo]){$probe.Directory}else{$probe.Parent}}
    @{path=$file.FullName;bytes=$file.Length;sha256=(Microsoft.PowerShell.Utility\Get-FileHash $file.FullName).Hash}
}
function Assert-PScreenSeal($Evidence){
    foreach($sealed in $Evidence.receipt,$Evidence.stdout,$Evidence.stderr){$current=& ${function:Get-PScreenFileBinding} $sealed.path;& ${function:Assert-PScreen} ($current.sha256-ceq$sealed.sha256-and$current.bytes-eq$sealed.bytes) 'Retained process/output evidence changed after capture'}
}
function Assert-PScreenClock($Receipt,[DateTimeOffset]$NotBefore,[bool]$FixtureOnly,[string]$Exe,[string[]]$Tokens,[string]$WorkingDirectory,[string]$Log){
    & ${function:Assert-PScreen} ($Receipt-is[hashtable]-and$Receipt.validClock-is[bool]-and$Receipt.validClock-and($Receipt.exit-is[int]-or$Receipt.exit-is[long])-and$Receipt.exit-eq0-and$Receipt.stdoutComplete-is[bool]-and$Receipt.stdoutComplete-and$Receipt.stderrComplete-is[bool]-and$Receipt.stderrComplete-and$Receipt.timeout-is[bool]-and-not$Receipt.timeout) 'Native clock/exit/drain failure'
    & ${function:Assert-PScreen} (($Receipt.elapsedSeconds-is[double]-or$Receipt.elapsedSeconds-is[decimal]-or$Receipt.elapsedSeconds-is[int]-or$Receipt.elapsedSeconds-is[long])-and$Receipt.elapsedSeconds-gt0-and-not[double]::IsInfinity([double]$Receipt.elapsedSeconds)-and-not[double]::IsNaN([double]$Receipt.elapsedSeconds)) 'Finite positive process duration required'
    & ${function:Assert-PScreen} ($Receipt.clockBoundary-is[string]-and$Receipt.clockBoundary.StartsWith('immediately before Process.Start through normal WaitForExit',[StringComparison]::Ordinal)-and$Receipt.createdUtc-is[string]) 'Inner process clock boundary required'
    $created=[DateTimeOffset]::Parse($Receipt.createdUtc)
    & ${function:Assert-PScreen} ($created-ge$NotBefore-and$created-le[DateTimeOffset]::UtcNow-and-not$Receipt.observer-and$Receipt.observerGone-is[bool]-and$Receipt.observerGone) 'Stale process clock or live Core observer'
    if(-not$FixtureOnly){
        & ${function:Assert-PScreen} (($Receipt.pid-is[int]-or$Receipt.pid-is[long])-and$Receipt.pid-gt0-and$Receipt.pid-le[int]::MaxValue-and$Receipt.exe-is[string]-and[string]::Equals($Receipt.exe,$Exe,[StringComparison]::OrdinalIgnoreCase)-and$Receipt.arguments-is[array]-and($Receipt.arguments|ConvertTo-Json -Compress)-ceq($Tokens|ConvertTo-Json -Compress)-and$Receipt.workingDirectory-is[string]-and[string]::Equals($Receipt.workingDirectory,$WorkingDirectory,[StringComparison]::OrdinalIgnoreCase)) 'Native PID/logical batch/argv/cwd binding differs'
        & ${function:Assert-PScreen} ($Receipt.cmdGone-is[bool]-and$Receipt.cmdGone-and$Receipt.cmdKill-is[bool]-and-not$Receipt.cmdKill-and$Receipt.cleanupErrors-is[array]-and$Receipt.cleanupErrors.Count-eq0-and-not$Receipt.originalError-and$Receipt.clockBoundary-ceq'immediately before Process.Start through normal WaitForExit; drain/observer completion excluded') 'Owned native output/process finalization failed'
        $receiptBinding=& ${function:Get-PScreenFileBinding} ($Log+'.process.json')
        $disk=Get-Content $receiptBinding.path -Raw|ConvertFrom-Json -AsHashtable -DateKind String
        & ${function:Assert-PScreen} (($disk|ConvertTo-Json -Depth 12 -Compress)-ceq($Receipt|ConvertTo-Json -Depth 12 -Compress)) 'Retained process receipt differs from admitted facts'
        return @{receipt=$receiptBinding;stdout=(& ${function:Get-PScreenFileBinding} $Log);stderr=(& ${function:Get-PScreenFileBinding} ($Log+'.stderr'));pid=$Receipt.pid;createdUtc=$Receipt.createdUtc;logicalBatch=$Receipt.exe;arguments=$Receipt.arguments;workingDirectory=$Receipt.workingDirectory;exit=$Receipt.exit;seconds=$Receipt.elapsedSeconds;clockBoundary=$Receipt.clockBoundary;nativeImageObservation='14D records logical batch; native CMD image is source-selected, not separately observed';transportSourceSha256='14D87CEFF68D26689C4A05D56BF503C75F8C95942ED4685538738FAD8FB9FE9F'}
    }
    return @{fixtureOnly=$true;seconds=$Receipt.elapsedSeconds;clockBoundary=$Receipt.clockBoundary}
}
function Assert-PScreenTestFacts($Actual,$Expected){
    & ${function:Assert-PScreen} ($Actual-is[array]-and$Expected-is[array]-and$Actual.Count-eq$Expected.Count) 'Ordered test-fact arrays required'
    foreach($collection in @(@{rows=$Actual},@{rows=$Expected})){
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach($row in $collection.rows){
            & ${function:Assert-PScreen} ($row-is[Collections.IDictionary]-and$row.Count-eq3) 'Exact class/name/state facts required'
            foreach($key in $row.Keys){& ${function:Assert-PScreen} ($key-is[string]-and$key-cin@('class','name','state')) 'Unknown test-fact member'}
            & ${function:Assert-PScreen} ($row.class-is[string]-and$row.class.Length-gt0-and$row.name-is[string]-and$row.name.Length-gt0-and$row.state-is[string]-and$row.state-cin@('passed','skipped')) 'Typed test identity/state required'
            $identity=ConvertTo-Json -InputObject @($row.class,$row.name) -Compress
            & ${function:Assert-PScreen} ($seen.Add($identity)) 'Duplicate test identity'
        }
    }
    for($i=0;$i-lt$Actual.Count;$i++){foreach($key in 'class','name','state'){& ${function:Assert-PScreen} ([string]::Equals($Actual[$i][$key],$Expected[$i][$key],[StringComparison]::Ordinal)) 'Retained ordered test identity/state differs'}}
}
function Get-PScreenCoverageIdentity([string]$Key){
    $fact=ConvertFrom-Json -InputObject $Key -AsHashtable -DateKind String
    & ${function:Assert-PScreen} ($fact-is[Collections.IDictionary]-and$fact.Count-eq2-and$fact.type-is[string]-and$fact.type-cin@('INSTRUCTION','BRANCH','LINE','COMPLEXITY','METHOD','CLASS')-and$fact.ancestors-is[array]-and$fact.ancestors.Count-gt0) 'Exact coverage type/ancestry identity required'
    foreach($name in $fact.Keys){& ${function:Assert-PScreen} ($name-cin@('type','ancestors')) 'Unknown coverage identity field'}
    $ancestors=@()
    foreach($node in $fact.ancestors){
        & ${function:Assert-PScreen} ($node-is[Collections.IDictionary]-and$node.Count-eq2-and$node.element-is[string]-and$node.element.Length-gt0-and$node.attributes-is[Collections.IDictionary]) 'Typed coverage ancestor required'
        foreach($name in $node.Keys){& ${function:Assert-PScreen} ($name-cin@('element','attributes')) 'Unknown coverage ancestor field'}
        $attributes=[ordered]@{};[string[]]$names=@($node.attributes.Keys);[Array]::Sort($names,[StringComparer]::Ordinal)
        foreach($name in $names){& ${function:Assert-PScreen} ($name.Length-gt0-and$node.attributes[$name]-is[string]) 'Typed complete XML attribute map required';$attributes[$name]=$node.attributes[$name]}
        $ancestors+=,[ordered]@{element=$node.element;attributes=$attributes}
    }
    ConvertTo-Json -InputObject ([ordered]@{type=$fact.type;ancestors=$ancestors}) -Depth 40 -Compress
}
function Assert-PScreenCoverageFacts($Actual,$Expected){
    & ${function:Assert-PScreen} ($Actual-is[Collections.IDictionary]-and$Expected-is[Collections.IDictionary]-and$Actual.Count-eq$Expected.Count) 'Complete coverage identity maps required'
    $maps=@()
    foreach($inputMap in @(@{values=$Actual},@{values=$Expected})){
        $map=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
        foreach($key in $inputMap.values.Keys){
            & ${function:Assert-PScreen} ($key-is[string]-and$inputMap.values[$key]-is[string]-and$inputMap.values[$key]-cmatch'^\d+/\d+$') 'Typed exact missed/covered value required'
            $identity=& ${function:Get-PScreenCoverageIdentity} $key
            & ${function:Assert-PScreen} ($map.TryAdd($identity,$inputMap.values[$key])) 'Duplicate semantic coverage identity'
        }
        $maps+=,$map
    }
    foreach($key in $maps[0].Keys){& ${function:Assert-PScreen} ($maps[1].ContainsKey($key)-and[string]::Equals($maps[0][$key],$maps[1][$key],[StringComparison]::Ordinal)) 'Full coverage identity/value differs'}
}
function Assert-PScreenFullGate($C,$Commands,[string]$Label,$Gate){
    & ${function:Assert-PScreen} ($Gate-is[hashtable]-and$Gate.tests-is[array]-and$Gate.tests.Count-eq56-and$Gate.counters-is[Collections.IDictionary]-and$Gate.counters.Count-eq726-and$Gate.fork-is[string]-and-not[string]::IsNullOrWhiteSpace($Gate.fork)-and$Gate.session-is[string]-and-not[string]::IsNullOrWhiteSpace($Gate.session)-and$Gate.semantics-is[string]-and$Gate.semantics.Length-gt0) 'Typed full-gate collections/fork/session required'
    foreach($test in $Gate.tests){& ${function:Assert-PScreen} ($test-is[Collections.IDictionary]-and$test.class-is[string]-and$test.class.Length-gt0-and$test.name-is[string]-and$test.name.Length-gt0-and$test.state-is[string]-and$test.state-cin@('passed','skipped')) 'Actual test identity/state collection required'}
    & ${function:Assert-PScreen} (@($Gate.tests|Where-Object state -eq passed).Count-eq54-and@($Gate.tests|Where-Object state -eq skipped).Count-eq2) 'Full54pass/2skip required'
    foreach($key in $Gate.counters.Keys){& ${function:Assert-PScreen} ($key-is[string]-and$key.Length-gt0-and$Gate.counters[$key]-is[string]-and$Gate.counters[$key]-cmatch'^\d+/\d+$') 'Actual coverage counter map required'}
    $null=& ${function:Assert-PScreenTestFacts} $Gate.tests $Gate.tests
    if($C.FixtureOnly){return @{fixtureOnly=$true;label=$Label}}
    $dir=Join-Path $C.Output $Label;$bindings=@()
    $null=& ($Commands['Compare-H3911Artifacts']) $dir $dir -SourceProfile $C.SourceProfile
    $saved=Get-Content (Join-Path $dir 'artifact.json') -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    & ${function:Assert-PScreen} ($saved.jarSha256-ceq$Gate.artifact.jarSha256-and$saved.raw.Count-eq6) 'Full artifact return/capture binding differs'
    $reports=@();$reportFiles=@(Get-ChildItem (Join-Path $dir 'surefire') -Filter 'TEST-*.xml' -File)
    foreach($file in $reportFiles){$bindings+=& ${function:Get-PScreenFileBinding} $file.FullName;$reports+=,[xml](Get-Content $file.FullName -Raw)}
    $tests=& ($Commands['TestKeys']) $reports
    $null=& ${function:Assert-PScreenTestFacts} $tests $Gate.tests
    $xmlPath=Join-Path $dir 'jacoco/jacoco.xml';$xml=[xml](Get-Content $xmlPath -Raw);$counters=& ($Commands['CoverageKeys']) $xml
    & ${function:Assert-PScreen} ($counters.Count-eq726-and(& ($Commands['CoverageSemantics']) $xml)-ceq$Gate.semantics) 'Full retained coverage semantics differ'
    $null=& ${function:Assert-PScreenCoverageFacts} $counters $Gate.counters
    $execPath=Join-Path $dir 'jacoco.exec';$exec=& ($Commands['JacocoExecEvidence']) ([IO.File]::ReadAllBytes($execPath)) default
    & ${function:Assert-PScreen} ($exec.sha256-ceq$Gate.exec.sha256-and$exec.session.id-ceq$Gate.session) 'Full gate exec/session bytes differ'
    $call=@($C.Calls|Where-Object {$_.plan.label-ceq$Label})[0]
    & ${function:Assert-PScreen} (($call.start-is[int]-or$call.start-is[long])-and($call.end-is[int]-or$call.end-is[long])-and$call.end-ge$call.start) 'Actual full-gate time envelope required'
    $sessions=@($xml.SelectNodes('/report/sessioninfo'))
    & ${function:Assert-PScreen} ($sessions.Count-eq1-and$sessions[0].id-ceq$Gate.session-and[long]$sessions[0].start-eq$exec.session.start-and[long]$sessions[0].dump-eq$exec.session.dump-and[long]$sessions[0].start-ge$call.start-and[long]$sessions[0].dump-le$call.end) 'Fresh native report/exec session binding differs'
    $forks=@([regex]::Matches((Get-Content $call.log -Raw),'Starting .*? with PID (\d+)')|ForEach-Object {$_.Groups[1].Value}|Sort-Object -Unique)
    & ${function:Assert-PScreen} ($forks.Count-eq1-and$forks[0]-ceq$Gate.fork) 'Actual full-gate reported fork differs'
    foreach($report in $reports){foreach($expected in @(@('java.home',$C.Jdk),@('java.runtime.version','25.0.5.0.2+1-LTS'),@('java.vendor','Microsoft'),@('os.arch','aarch64'))){& ${function:Assert-PScreen} ($report.SelectSingleNode("//properties/property[@name='$($expected[0])']").value-ceq$expected[1]) 'Actual native25 full-gate profile differs'}}
    foreach($path in $call.log,($call.log+'.stderr'),($call.log+'.process.json')){$bindings+=& ${function:Get-PScreenFileBinding} $path}
    foreach($name in @('application.jar','artifact.json','jacoco.exec','jacoco/jacoco.xml')+@($saved.raw.file)){$bindings+=& ${function:Get-PScreenFileBinding} (Join-Path $dir $name)}
    @{label=$Label;files=$bindings;fixtureOnly=$false}
}
function Assert-PScreenBoundary($C,$Commands,$Hooks){
    & ${function:Assert-PScreen} ($C.WitnessGate.status-is[string]-and$C.WitnessGate.status-ceq'CONTENT_AND_CURRENT_IDENTITY_ADMITTED_PARENT_EXIT_STILL_REQUIRED'-and$C.Contexts.Count-eq5-and$C.Calls.Count-eq7) 'Witness-first/five contexts/seven full-gate calls required'
    $labels=@($C.Calls|ForEach-Object{$_.plan.label})
    & ${function:Assert-PScreen} (($labels-join',')-ceq'baseline-project,daemon-arch,daemon-home,daemon-project,baseline-maven-home,baseline-verify,candidate-verify') 'Only after both online gates and before stop'
    foreach($call in $C.Calls){& ${function:Assert-PScreen} (($call.exit-is[int]-or$call.exit-is[long])-and$call.exit-eq0) 'Qualification child failed'}
    $gateBindings=@();$gateBindings+=& ${function:Assert-PScreenFullGate} $C $Commands 'baseline-verify' $C.ScreenVerification.baseline
    $gateBindings+=& ${function:Assert-PScreenFullGate} $C $Commands 'candidate-verify' $C.ScreenVerification.candidate
    & ${function:Assert-PScreen} ($C.ScreenVerification.baseline.fork-ne$C.ScreenVerification.candidate.fork-and$C.ScreenVerification.baseline.session-ne$C.ScreenVerification.candidate.session) 'Distinct full-gate forks/sessions required'
    if($C.FixtureOnly){$proof=& $Hooks.Boundary $C}else{
        & ${function:Assert-PScreen} ([IO.Path]::IsPathFullyQualified($C.ScreenBoundaryFile)-and$C.ScreenBoundarySha256-is[string]-and$C.ScreenBoundarySha256-cmatch'^[A-F0-9]{64}$') 'Caller observer-completion handoff UNWIRED/missing'
        $file=Get-Item -LiteralPath $C.ScreenBoundaryFile -Force
        & ${function:Assert-PScreen} (-not$file.LinkType-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-and(Microsoft.PowerShell.Utility\Get-FileHash $file.FullName).Hash-ceq$C.ScreenBoundarySha256) 'Bound observer completion receipt differs'
        $proof=Get-Content $file.FullName -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    }
    & ${function:Assert-PScreen} ($proof.schema-is[string]-and$proof.schema-ceq'h3911-screen-boundary-v2'-and$proof.status-is[string]-and$proof.status-ceq'OBSERVERS_EXIT_CONFIRMED'-and$proof.observers-is[array]) 'Actual allocated observer completion required'
    $allocated=@();$allocationBindings=@()
    if($C.FixtureOnly){$allocated=@($proof.allocated)}
    else{
        foreach($call in $C.Calls){
            $binding=& ${function:Get-PScreenFileBinding} ($call.log+'.process.json');$process=Get-Content $binding.path -Raw|ConvertFrom-Json -AsHashtable -DateKind String
            if($process.observer){& ${function:Assert-PScreen} ($call.plan.observeCore-is[bool]-and$call.plan.observeCore-and$process.observerGone-is[bool]-and$process.observerGone) 'Allocated Core observer completion missing';$allocated+=@{allocationLabel=$call.plan.label;pid=$process.observer.pid;created=$process.observer.createdUtc;executable=$process.observer.executable;prefix=$process.observer.prefix;gone=$process.observerGone};$allocationBindings+=,$binding}
            elseif($call.plan.observeCore){throw 'HOLD: allocated baseline Core identity missing'}
        }
        $parentBinding=& ${function:Get-PScreenFileBinding} $C.ScreenParentObserverReceipt
        & ${function:Assert-PScreen} ($parentBinding.sha256-ceq$C.ScreenParentObserverReceiptSha256) 'Parent allocation/completion handoff UNWIRED or changed'
        $parent=Get-Content $parentBinding.path -Raw|ConvertFrom-Json -AsHashtable -DateKind String
        & ${function:Assert-PScreen} ($parent.fixtureOnly-is[bool]-and-not$parent.fixtureOnly-and$parent.observerScript-is[Collections.IDictionary]-and$parent.observerScript.sha256-ceq'A451B495298D977F0331543F359A606B62ED5B0CEDEE8E93358F0D120DF4A032') 'Native parent provenance and fixed observer script required'
        $nativeObserverSource=& ${function:Get-PScreenFileBinding} $parent.observerScript.path
        & ${function:Assert-PScreen} ($nativeObserverSource.sha256-ceq'A451B495298D977F0331543F359A606B62ED5B0CEDEE8E93358F0D120DF4A032'-and$nativeObserverSource.bytes-eq$parent.observerScript.bytes) 'Actual native observer script binding differs'
        & ${function:Assert-PScreen} ($parent.allocationLabel-is[string]-and-not[string]::IsNullOrWhiteSpace($parent.allocationLabel)-and$parent.capabilities-is[array]-and($parent.capabilities-join',')-ceq'owner,telemetry'-and$parent.gone-is[bool]-and$parent.gone) 'One actual combined owner/telemetry process required'
        $allocated+=,$parent;$allocationBindings+=,$parentBinding
        foreach($evidence in $proof.witnessBinding,$proof.telemetryBinding){$actual=& ${function:Get-PScreenFileBinding} $evidence.path;& ${function:Assert-PScreen} ($actual.sha256-ceq$evidence.sha256) 'Witness/telemetry completion bytes differ';$allocationBindings+=,$actual}
    }
    & ${function:Assert-PScreen} ($proof.observers.Count-eq$allocated.Count-and@($proof.observers.pid|Sort-Object -Unique).Count-eq$allocated.Count) 'Actual allocated observer set differs'
    foreach($observer in $proof.observers){
        & ${function:Assert-PScreen} ($observer.allocationLabel-is[string]-and$observer.allocationLabel.Length-gt0-and($observer.pid-is[int]-or$observer.pid-is[long])-and$observer.pid-gt0-and$observer.created-is[string]-and$observer.created.Length-gt0-and$observer.executable-is[string]-and$observer.executable.Length-gt0-and$observer.prefix-is[string]-and$observer.prefix.Length-gt0-and$observer.gone-is[bool]-and$observer.gone) 'Actual observer PID/birth/exe/allocation/prefix/gone required'
        $stamp=[DateTimeOffset]::MinValue;& ${function:Assert-PScreen} ([DateTimeOffset]::TryParse($observer.created,[ref]$stamp)) 'Parseable observer birth required'
        $match=@($allocated|Where-Object {$_.pid-eq$observer.pid-and$_.allocationLabel-ceq$observer.allocationLabel})
        & ${function:Assert-PScreen} ($match.Count-eq1) 'Unallocated or duplicate observer'
        foreach($key in 'created','executable','prefix','gone'){& ${function:Assert-PScreen} ($observer[$key]-ceq$match[0][$key]) 'Observer completion differs from allocation receipt'}
        if(-not$C.FixtureOnly){try{$p=[Diagnostics.Process]::GetProcessById([int]$observer.pid);$p.Dispose();throw 'HOLD: observer PID still exists/reused'}catch [ArgumentException]{}}
    }
    if(-not$C.FixtureOnly){$null=& ($Commands['Assert-QualifierOwnerWitnessContent']) $C $proof.ownerWitness $C.ScreenWitnessNotBefore}
    $proof.gateBindings=$gateBindings;$proof.allocationBindings=$allocationBindings
    $proof
}
function Assert-PScreenAdmission($C,$Commands,$Hooks,$Boundary){
    if($C.FixtureOnly){$owner=& $Hooks.Admit $C}else{
        $null=& ($Commands['Assert-H3911Source']) $C;$null=& ($Commands['Assert-H3911Inventory']) $C.Home
        & ${function:Assert-PScreen} ((Microsoft.PowerShell.Utility\Get-FileHash (Join-Path $C.Jdk 'bin/java.exe')).Hash-ceq'094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0'-and$env:PATH-ceq$C.BoundPath-and$env:MVNW_PREFER_PWSH-ceq'true'-and$env:MVND_CLIENT-ceq'jvm'-and(Get-Command pwsh.exe -CommandType Application).Source-ceq$C.CoreExe-and(Microsoft.PowerShell.Utility\Get-FileHash $C.CoreExe).Hash-ceq$C.CoreHash) 'Native25/AAA/Core/JVM route changed'
        $null=& ($Commands['Assert-H3911StockMaven3911']) -MavenHome $C.Contexts['baseline-maven-home'].value -PrivateWrapperCache $C.PrivateWrapperCache -Profile WindowsCore -Format Zip
        $owner=& ($Commands['Read-QualifierPrivateJava']) $C $Boundary.ownerWitness
        & ${function:Assert-PScreen} ($owner.status-ceq'owned'-and$owner.complete-is[bool]-and$owner.complete) 'Current private native owner HOLD'
    }
    foreach($key in 'pid','created','id','executable','jniSha256'){& ${function:Assert-PScreen} ($owner[$key]-ceq$C.ScreenOwner[$key]) 'Sampling owner changed'}
}
function Get-H3911PackageDecision($Samples,[switch]$FixtureOnly){
    & ${function:Assert-PScreen} ($Samples-is[array]-and$Samples.Count-eq6-and(@($Samples.route)-join'')-ceq'ABBAAB') 'Exactly six retained ABBAAB samples required'
    foreach($sample in $Samples){& ${function:Assert-PScreen} ($sample.route-is[string]-and$sample.timed-is[bool]-and$sample.timed-and($sample.seconds-is[double]-or$sample.seconds-is[decimal]-or$sample.seconds-is[int]-or$sample.seconds-is[long])-and$sample.seconds-gt0-and-not[double]::IsNaN([double]$sample.seconds)-and-not[double]::IsInfinity([double]$sample.seconds)) 'Typed finite timed package values required'}
    $a=@($Samples|Where-Object route -ceq A|ForEach-Object seconds);$b=@($Samples|Where-Object route -ceq B|ForEach-Object seconds)
    $am=@($a|Sort-Object)[1];$bm=@($b|Sort-Object)[1];$all=$true
    for($i=0;$i-lt3;$i++){$pair=$Samples[($i*2)..($i*2+1)];if(@($pair|Where-Object route -ceq B)[0].seconds-ge@($pair|Where-Object route -ceq A)[0].seconds){$all=$false}}
    @{samples=$Samples;baselineMedian=$am;candidateMedian=$bm;medianLowerPercent=100*($am-$bm)/$am;allPairsFavorable=$all;criteriaSatisfied=($all-and$bm-le.95*$am);disposition=$(if($FixtureOnly){'FIXTURE_ONLY_NOT_PERFORMANCE'}elseif($all-and$bm-le.95*$am){'PENDING_CALLER_NORMAL_CLEANUP_AND_AUDIT'}else{'NOADVANCE_NO_RETRY'});matchedHostFollowup='Ratio must improve AND Mac regression<5%; actual ratio<=1 remains goal, not assumed';scope='HOBL_DERIVED_PACKAGE_SCREEN_NOT_ORIGINAL_5_LOOP_OR_CURRENT17_OR_WHOLE_CI';requiresCallerFinalization=$true}
}
function Invoke-H3911PackageSamplingOperator {
    param([hashtable]$Context,[switch]$RuntimeApproved,[switch]$FixtureOnly,[hashtable]$FixtureHooks)
    & ${function:Assert-PScreen} ($RuntimeApproved-xor$FixtureOnly) 'Explicit sampling mode required'
    & ${function:Assert-PScreen} (-not$RuntimeApproved-or(-not$FixtureHooks-and$IsWindows-and$Context.Platform-ceq'Windows'-and-not$Context.FixtureOnly)) 'Real Windows only; fixture callbacks prohibited; Mac caller UNWIRED'
    if($RuntimeApproved){
        & ${function:Assert-PScreen} ($Context.SourceProfile-ceq'ReviewedHttpsCoreWrapper') 'Windows AAA profile required'
        foreach($key in 'ProcessInvoker','OwnerReader','PackageReader','SourceCheck','Timer','FixtureDispatch'){& ${function:Assert-PScreen} (-not$Context[$key]) 'No runtime-injected operation allowed'}
        foreach($key in 'Output','Home','Registry','Temp','Cache','Jdk','Settings','Project','CoreExe'){
            $path=$Context[$key];& ${function:Assert-PScreen} ([IO.Path]::IsPathFullyQualified($path)) 'Absolute native sampling inputs required'
            $item=Get-Item -LiteralPath $path -Force;$probe=$item
            while($probe){& ${function:Assert-PScreen} (-not($probe.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not$probe.LinkType) 'Linked sampling input/ancestry';$probe=if($probe-is[IO.FileInfo]){$probe.Directory}else{$probe.Parent}}
            if($key-cne'Project'){$a=[IO.Path]::GetFullPath($Context.Project).TrimEnd('\');$b=[IO.Path]::GetFullPath($path).TrimEnd('\');& ${function:Assert-PScreen} (-not([string]::Equals($a,$b,[StringComparison]::OrdinalIgnoreCase)-or$a.StartsWith($b+'\',[StringComparison]::OrdinalIgnoreCase)-or$b.StartsWith($a+'\',[StringComparison]::OrdinalIgnoreCase))) 'Sampling execution/immutable paths must be disjoint from project'}
        }
    }
    if($FixtureOnly){foreach($name in 'Boundary','Admit','Process','Capture'){& ${function:Assert-PScreen} ($FixtureHooks[$name]-is[scriptblock]) 'Complete explicit sampling models required'}}
    $C=$Context;$C.FixtureOnly=[bool]$FixtureOnly
    $commands=& ${function:Import-PScreen};$boundary=& ${function:Assert-PScreenBoundary} $C $commands $FixtureHooks
    $onlineDir=Join-Path $C.Output 'baseline-verify';$candidateDir=Join-Path $C.Output 'candidate-verify'
    $null=& ($commands['Compare-H3911Artifacts']) $onlineDir $candidateDir -SourceProfile $C.SourceProfile
    $online=& ($commands['Read-H3911Artifact']) (Join-Path $onlineDir 'application.jar') (Join-Path $onlineDir 'classes') (Join-Path $onlineDir 'test-classes') -SourceProfile $C.SourceProfile
    $out=Join-Path $C.Output 'package-screen';& ${function:Assert-PScreen} (-not(Test-Path $out)) 'Fresh package sampling namespace required'
    New-Item $out -ItemType Directory -ErrorAction Stop|Out-Null
    $before=[Environment]::GetEnvironmentVariables('Process');$cwd=(Get-Location).Path;$native=[Environment]::CurrentDirectory;$samples=@();$captures=@();$reference=$null;$errorRecord=$null;$result=@{status='FAIL';fixtureOnly=[bool]$FixtureOnly;noFreshSkipTestsCoverageClaim=$true;boundary=$boundary}
    try{
        $plan=& ${function:Get-H3911RetainedProtocol} -Mode PackageScreen -Platform $C.Platform
        foreach($step in @($plan.calls|Where-Object {$_.kind-in@('clean','package')})){
            $null=& ${function:Assert-PScreenAdmission} $C $commands $FixtureHooks $boundary
            $tokens=@('--batch-mode','--no-transfer-progress','-Dserver.address=127.0.0.1',"-Dmaven.repo.local=$($C.Cache)",'--settings',$C.Settings,'--global-settings',$C.Settings,'--file',(Join-Path $C.Project 'pom.xml'),'-o')
            if($step.route-ceq'B'){$tokens+=@('--serial',"-Djava.home=$($C.Jdk)","-Dmvnd.daemonStorage=$($C.Registry)")}
            $tokens+=if($step.kind-ceq'clean'){@('clean')}else{@('-DskipTests','package')}
            if(-not$FixtureOnly){$null=& ($commands['Assert-H3911KernelPOM']) $C $tokens $C.Project}
            $exe=if($step.route-ceq'A'){Join-Path $C.Project $(if($C.Platform-ceq'Windows'){'mvnw.cmd'}else{'mvnw'})}else{Join-Path $C.Home $(if($C.Platform-ceq'Windows'){'bin/mvnd.cmd'}else{'bin/mvnd'})}
            $log=Join-Path $out ($step.label+'.log')
            $launcher=if(-not$FixtureOnly){@{path=(Resolve-Path -LiteralPath $env:ComSpec).ProviderPath;sha256=(Microsoft.PowerShell.Utility\Get-FileHash $env:ComSpec).Hash;kind='source-selected CMD launcher, not native-image trace'}}else{$null}
            $notBefore=[DateTimeOffset]::UtcNow
            if($FixtureOnly){$process=& $FixtureHooks.Process $C $step $tokens $log}
            else{$exit=& ($commands['Invoke-H3911WindowsKernelProcess']) -Exe $exe -Tokens $tokens -Log $log -Context $C;$process=Get-Content ($log+'.process.json') -Raw|ConvertFrom-Json -AsHashtable -DateKind String;& ${function:Assert-PScreen} ($exit-is[int]-and$exit-eq0) 'Package native child nonzero'}
            $call=@{label=$step.label;route=$step.route;timed=$step.timed;seconds=$null;exit=$process.exit;log=$log};$C.Calls+=,$call
            $call.processEvidence=& ${function:Assert-PScreenClock} $process $notBefore ([bool]$FixtureOnly) $exe $tokens $C.Project $log
            $call.processEvidence.launcherAdmission=$launcher;$call.seconds=$call.processEvidence.seconds
            $null=& ${function:Assert-PScreenAdmission} $C $commands $FixtureHooks $boundary
            if($step.kind-ceq'package'){
                & ${function:Assert-PScreen} ((Get-Content $log -Raw)-match'Goal makeAggregateBom requires online mode.*skipping') 'Offline SBOM-only omission not evidenced'
                $project=if($FixtureOnly){& $FixtureHooks.Capture $C $step}else{$C.Project}
                $jar=@(Get-ChildItem (Join-Path $project 'target') -Filter '*.jar');& ${function:Assert-PScreen} ($jar.Count-eq1) 'One offline application JAR required'
                $dir=Join-Path $out $step.label;$offline=& ($commands['Read-H3911Artifact']) $jar[0].FullName (Join-Path $project 'target/classes') (Join-Path $project 'target/test-classes') $dir -SourceProfile $C.SourceProfile -Offline
                $null=& ($commands['Assert-H3911OfflineDelta']) $online $onlineDir $offline $dir
                if($reference){$null=& ($commands['Compare-H3911Artifacts']) $reference $dir -SourceProfile $C.SourceProfile -Offline}else{$reference=$dir}
                $captures+=@{label=$step.label;jarSha256=$offline.jarSha256;entries=$offline.entries.Count;regular=@($offline.entries|Where-Object {-not$_.directory}).Count;raw=$offline.raw.Count}
                if($step.timed){$samples+=,$call}
            }
        }
        if(-not$FixtureOnly){
            foreach($call in @($C.Calls|Where-Object {$_.processEvidence-and-not$_.processEvidence.fixtureOnly})){
                $null=& ${function:Assert-PScreenSeal} $call.processEvidence
            }
            foreach($gate in $boundary.gateBindings){foreach($sealed in $gate.files){$current=& ${function:Get-PScreenFileBinding} $sealed.path;& ${function:Assert-PScreen} ($current.sha256-ceq$sealed.sha256-and$current.bytes-eq$sealed.bytes) 'Frozen full-gate evidence changed during sampling'}}
        }
        $result.screen=& ${function:Get-H3911PackageDecision} $samples -FixtureOnly:$FixtureOnly;$result.status='OPERATOR_COMPLETE_CALLER_STOP_STILL_REQUIRED'
    }catch{$errorRecord=$_;$result.failure=$_.ToString();$result.status='FAIL';$result.screen=$null}
    finally{
        $after=[Environment]::GetEnvironmentVariables('Process');$same=$before.Count-eq$after.Count;foreach($key in $before.Keys){if(-not$after.Contains($key)-or$before[$key]-cne$after[$key]){$same=$false}}
        $result.callerStateEqual=$same-and(Get-Location).Path-ceq$cwd-and[Environment]::CurrentDirectory-ceq$native
        $result.offlineCaptures=$captures;$result.samples=$samples;$result.requiresCallerPrivateCleanup=$true
        if(-not$result.callerStateEqual){$result.status='FAIL';$result.screen=$null}
        $result|ConvertTo-Json -Depth 40 -WarningAction Stop|Set-Content (Join-Path $out 'operator.json')
    }
    if($errorRecord){$errorRecord.Exception.Data['RequiresCallerPrivateCleanup']=$true;throw $errorRecord}
    & ${function:Assert-PScreen} ($result.status-ne'FAIL') 'Sampling caller state failed'
    $result
}
Export-ModuleMember -Function Get-H3911RetainedProtocol,Get-H3911PackageDecision,Invoke-H3911PackageSamplingOperator
