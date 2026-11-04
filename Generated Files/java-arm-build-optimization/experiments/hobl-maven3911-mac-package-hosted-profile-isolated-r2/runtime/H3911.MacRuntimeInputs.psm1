function Assert-MacRuntimeInput($Value,[string]$Message){if(-not$Value){throw "HOLD: $Message"}}
function Import-H3911MacRuntimeInputs {
    & ${function:Assert-MacRuntimeInput} ((Microsoft.PowerShell.Utility\Get-FileHash (Join-Path $PSScriptRoot 'mac-jdk25-identity.json')).Hash-ceq'B4C08E1980A986419E9B402E9DF2B8DBA2C800E62E20995B1C9420EBE031678E') 'Trusted Mac JDK manifest differs'
    $spec=@{
        'H3911.Source.psm1'=@('6AC4B84BEEDEED24E6330D556BFAA2954CA2D4771880F2A0C2602AEF5B91A1C0',@('Assert-H3911Source','Assert-H3911PhysicalInputs'))
        'H3911.Helpers.psm1'=@('1F1C0099CDC1A7DA6FE949BF973269418DCAAC0E1539A4598A6E5CCFE3720BAA',@('PortableEnvironmentSnapshot','RestorePortableEnvironment'))
        'H3911.CallKernel.psm1'=@('14D87CEFF68D26689C4A05D56BF503C75F8C95942ED4685538738FAD8FB9FE9F',@('Assert-H3911KernelPOM'))
        'H3911.Artifacts.psm1'=@('BD2B01750B3F6954425599F0E70F34F2A04B122E03724B1482704E76FC6B55F6',@('Save-H3911Verify','Compare-H3911Artifacts'))
        'H3911.NativeProcess.psm1'=@('6CF9CB37879428520B87738FE8A0CDECEA8E0B6AA6577C068FDABB44F038E5A3',@('Invoke-H3911DirectNative'))
        'H3911.DistributionSetup.psm1'=@('7943C480E2E73F68554BBE46A30811F54A299EBDBA5FDF7F0A430314EEF12D57',@('Expand-H3911OwnedDistribution'))
        'H3911.Darwin103.psm1'=@('05F80C9435B3E6012FAE8874A887A7F96AF8B44311EC1D4A06265ED254E7A264',@('Assert-H3911Darwin103Distribution'))
        'H3911.StockMaven3911.psm1'=@('3D8DCF80AFF694FDC716122B2E76274BBB2D5FD7D882C7D04DC61DE5EF55911D',@('Assert-H3911StockMaven3911'))
        'H3911.EffectiveOwner.psm1'=@('4979E2E0160A6DCF9C7B13E279DA712F047634AABB7F3CB021C2A25578CF7B95',@('Read-H3911DarwinEffectiveOwner'))
        'H3911.DarwinLifecycle.psm1'=@('8DFD433F1ED138464CAE9FE19B28DDE0B7A91DD37451733D331C813847B8A9FF',@('New-H3911DarwinPrivateStopPlan','Confirm-H3911DarwinCliStop','Read-H3911DarwinScopedCensus'))}
    $bound=@{}
    foreach($row in $spec.GetEnumerator()){
        $path=Join-Path $PSScriptRoot $row.Key
        & ${function:Assert-MacRuntimeInput} ((Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $path).Hash-ceq$row.Value[0]) 'Mac dependency pin differs'
        $m=Import-Module $path -Scope Local -PassThru -DisableNameChecking
        foreach($name in $row.Value[1]){$command=$m.ExportedCommands[$name];& ${function:Assert-MacRuntimeInput} ($command-is[Management.Automation.FunctionInfo]-and$command.Module.Path-ceq$path-and$command.Name-ceq$name) 'Mac command object origin differs';$bound[$name]=$command}
        if($row.Key-ceq'H3911.DarwinLifecycle.psm1'){$same=& $m {Get-Command Test-LifeSame -CommandType Function};& ${function:Assert-MacRuntimeInput} ($same-is[Management.Automation.FunctionInfo]-and$same.Module.Path-ceq$path-and$same.Name-ceq'Test-LifeSame') 'Lifecycle identity comparison origin differs';$bound['Test-LifeSame']=$same}
        if($row.Key-ceq'H3911.DarwinLifecycle.psm1'){$proof=& $m {Get-Command Assert-LifeUidCensus -CommandType Function};& ${function:Assert-MacRuntimeInput} ($proof-is[Management.Automation.FunctionInfo]-and$proof.Module.Path-ceq$path) 'UID census predicate origin differs';$bound['Assert-LifeUidCensus']=$proof}
    }
    $bound
}
function Resolve-H3911MacInputPath([string]$Path,[switch]$Missing){
    & ${function:Assert-MacRuntimeInput} ([IO.Path]::IsPathFullyQualified($Path)) 'Absolute native Mac qualifier path required'
    $full=[IO.Path]::GetFullPath($Path).TrimEnd([char[]]'\/');$probe=$full
    & ${function:Assert-MacRuntimeInput} ($Missing-or(Test-Path -LiteralPath $full)) 'Existing physical input required'
    while($probe){
        if(Test-Path -LiteralPath $probe){$i=Get-Item -LiteralPath $probe -Force;& ${function:Assert-MacRuntimeInput} ($i.PSProvider.Name-ceq'FileSystem'-and-not($i.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not$i.LinkType-and($probe-ceq$full-or$i-is[IO.DirectoryInfo])) 'Linked/nonphysical Mac namespace'}
        $parent=[IO.Directory]::GetParent($probe);$probe=if($parent){$parent.FullName}else{$null}
    }
    $full
}
function Assert-H3911MacInputDisjoint([string]$A,[string]$B){
    $comparison=if($IsWindows){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
    & ${function:Assert-MacRuntimeInput} (-not([string]::Equals($A,$B,$comparison)-or$A.StartsWith($B+[IO.Path]::DirectorySeparatorChar,$comparison)-or$B.StartsWith($A+[IO.Path]::DirectorySeparatorChar,$comparison))) 'Mac project/owned/immutable trees must be disjoint'
}
function Assert-H3911MacSdk($C,[string]$Archive){
    & ${function:Assert-MacRuntimeInput} ((Microsoft.PowerShell.Utility\Get-FileHash (Join-Path $PSScriptRoot 'mac-jdk25-identity.json')).Hash-ceq'B4C08E1980A986419E9B402E9DF2B8DBA2C800E62E20995B1C9420EBE031678E') 'Trusted Mac JDK manifest differs'
    & ${function:Assert-MacRuntimeInput} ((Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Archive).Hash-ceq'C9CF199844411C8BAFD05722D2547538300523A63FF6207A440C71B175FF7873') 'Trusted Mac SDK archive differs'
    $identity=Get-Content (Join-Path $PSScriptRoot 'mac-jdk25-identity.json') -Raw|ConvertFrom-Json
    foreach($row in $identity.files){
        $path=& ${function:Resolve-H3911MacInputPath} (Join-Path $C.Jdk $row.path);$file=Get-Item -LiteralPath $path -Force
        & ${function:Assert-MacRuntimeInput} ($file.Length-eq$row.bytes-and(Microsoft.PowerShell.Utility\Get-FileHash $path).Hash-ceq$row.sha256-and[int][IO.File]::GetUnixFileMode($path)-eq$row.tarMode) 'Native Mac SDK selected bytes/mode differ'
    }
    & ${function:Assert-MacRuntimeInput} ([int][IO.File]::GetUnixFileMode((Join-Path $C.Project 'mvnw'))-eq493) 'Original Unix wrapper actual executable mode differs'
}
Export-ModuleMember -Function Import-H3911MacRuntimeInputs,Assert-H3911MacSdk,Resolve-H3911MacInputPath,Assert-H3911MacInputDisjoint
