function Assert-Darwin103($Value,[string]$Message){if(-not$Value){throw $Message}}
function Assert-H3911Darwin103Distribution {
    param([Parameter(Mandatory)][string]$Root,[string]$Inventory=(Join-Path $PSScriptRoot 'Darwin103.inventory.json'),[switch]$RequireNativeModes)
    Assert-Darwin103 ((Get-FileHash -LiteralPath $Inventory).Hash-ceq'45D9AA3DD7923358A576647F07AAC8D39617A9C9AEA4FBC33C1BA9664E42BCA3') 'Pinned Darwin103 inventory differs'
    $m=Get-Content -LiteralPath $Inventory -Raw|ConvertFrom-Json -AsHashtable
    Assert-Darwin103 ($m.schema-ceq'official-mvnd103-darwin-arm64-static-v1'-and$m.files.Count-eq121-and$m.directories.Count-eq17-and$m.source.sha256-ceq'B5528C92D5B0E14A8A47DDFF138C19D93AC01F6CB8A28514F8FA40F2CEB65194') 'Malformed Darwin103 inventory'
    $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($row in @($m.files)+@($m.directories)){
        Assert-Darwin103 ($row.path-is[string]-and$row.path-notmatch'(^[/\\]|\\|:|//|/$|(^|/)\.)'-and$names.Add($row.path)-and$row.tarMode-is[long]-and$row.tarMode-ge0-and$row.tarMode-le511) 'Unsafe/duplicate Darwin103 manifest path/mode'
    }
    foreach($row in $m.files){Assert-Darwin103 ($row.bytes-is[long]-and$row.bytes-ge0-and$row.sha256-cmatch'^[A-F0-9]{64}$') 'Malformed Darwin103 file binding'}
    Assert-Darwin103 ([IO.Path]::IsPathFullyQualified($Root)) 'Absolute native distribution root required'
    $resolved=Resolve-Path -LiteralPath $Root -ErrorAction Stop
    Assert-Darwin103 ($resolved.Provider.Name-ceq'FileSystem') 'Native filesystem distribution required'
    $rootItem=Get-Item -LiteralPath $resolved.ProviderPath -Force
    Assert-Darwin103 ($rootItem-is[IO.DirectoryInfo]) 'Distribution directory required'
    $ancestor=$rootItem;while($ancestor){Assert-Darwin103 (-not((Get-Item -LiteralPath $ancestor.FullName -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked Darwin103 ancestry';$ancestor=$ancestor.Parent}
    $Root=$resolved.ProviderPath;$all=@(Get-ChildItem -LiteralPath $Root -Recurse -Force)
    Assert-Darwin103 (-not@($all|Where-Object{($_.Attributes-band[IO.FileAttributes]::ReparsePoint)-or(-not$_.PSIsContainer-and$_.LinkType)-or($_.Attributes-band[IO.FileAttributes]::Hidden)-or$_.Name.StartsWith('.',[StringComparison]::Ordinal)}).Count) 'Linked/hidden Darwin103 member'
    $actual=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($item in $all){$relative=[IO.Path]::GetRelativePath($Root,$item.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47);Assert-Darwin103 ($actual.Add($relative)) 'Duplicate physical Darwin103 member'}
    Assert-Darwin103 ($actual.SetEquals($names)) 'Exact Darwin103 physical inventory differs'
    if($RequireNativeModes){Assert-Darwin103 $IsMacOS 'Native Mac mode admission unavailable on this host'}
    foreach($row in @($m.files)+@($m.directories)){
        $nativeRelative=$row.path.Replace([char]47,[IO.Path]::DirectorySeparatorChar);$path=Join-Path $Root $nativeRelative;$item=Get-Item -LiteralPath $path -Force
        if($row.Contains('sha256')){Assert-Darwin103 ($item-is[IO.FileInfo]-and$item.Length-eq$row.bytes-and(Get-FileHash -LiteralPath $path).Hash-ceq$row.sha256) 'Darwin103 file/type/bytes/hash differs'}
        else{Assert-Darwin103 ($item-is[IO.DirectoryInfo]) 'Darwin103 directory type differs'}
        if($IsMacOS){Assert-Darwin103 ([int][IO.File]::GetUnixFileMode($path)-eq$row.tarMode) 'Native Mac mode differs from pinned archive'}
    }
    $front=[IO.File]::ReadAllBytes((Join-Path $Root 'bin'|Join-Path -ChildPath 'mvnd'))
    Assert-Darwin103 ([BitConverter]::ToUInt32($front,0)-eq4277009103-and[BitConverter]::ToUInt32($front,4)-eq0x0100000C-and[BitConverter]::ToUInt32($front,12)-eq2) 'Frontend is not thin ARM64 Mach-O executable'
    $jarPath=Join-Path $Root ($m.jni.jarPath.Replace([char]47,[IO.Path]::DirectorySeparatorChar))
    $zip=[IO.Compression.ZipFile]::OpenRead($jarPath)
    try{
        $entry=$zip.GetEntry($m.jni.entry);Assert-Darwin103 $entry 'Exact Darwin ARM JNI resource absent'
        $stream=$entry.Open();$buffer=[IO.MemoryStream]::new()
        try{$stream.CopyTo($buffer);[byte[]]$jni=$buffer.ToArray()}finally{$stream.Dispose();$buffer.Dispose()}
        Assert-Darwin103 ($jni.Length-eq$m.jni.bytes-and[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($jni))-ceq$m.jni.sha256-and[BitConverter]::ToUInt32($jni,0)-eq4277009103-and[BitConverter]::ToUInt32($jni,4)-eq0x0100000C-and[BitConverter]::ToUInt32($jni,12)-eq6) 'Darwin JNI resource/hash/ARM dylib differs'
    }finally{$zip.Dispose()}
    @{status='EXACT_OFFICIAL_DARWIN103_STATIC_ADMISSION';files=121;directories=17;manifestSha256='45D9AA3DD7923358A576647F07AAC8D39617A9C9AEA4FBC33C1BA9664E42BCA3';archiveSha256=$m.source.sha256;frontend=$m.frontend;core=$m.core;jni=$m.jni;nativeMacModesChecked=[bool]$IsMacOS;tarModesProven=$true;nativeMacRuntimeQualified=$false;daemonOwnershipOrRegistryQualified=$false}
}
Export-ModuleMember -Function Assert-H3911Darwin103Distribution
