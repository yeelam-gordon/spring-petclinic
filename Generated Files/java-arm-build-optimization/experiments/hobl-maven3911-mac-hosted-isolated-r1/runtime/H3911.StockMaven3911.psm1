function Assert-Stock3911($Value,[string]$Message){if(-not$Value){throw $Message}}
function Resolve-Stock3911Path([string]$Path,[switch]$Directory){
    Assert-Stock3911 ([IO.Path]::IsPathFullyQualified($Path)) 'Absolute native stock/cache path required'
    $r=Resolve-Path -LiteralPath $Path -ErrorAction Stop;$item=Get-Item -LiteralPath $r.ProviderPath -Force
    $type=if($Directory){$item-is[IO.DirectoryInfo]}else{$item-is[IO.FileInfo]}
    Assert-Stock3911 ($r.Provider.Name-ceq'FileSystem'-and$type-and-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-and($Directory-or-not$item.LinkType)) 'Ordinary nonlinked stock/cache item required'
    $parent=if($Directory){$item}else{$item.Directory}
    while($parent){Assert-Stock3911 (-not((Get-Item -LiteralPath $parent.FullName -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked stock/cache ancestry';$parent=$parent.Parent}
    $r.ProviderPath
}
function Assert-H3911StockMaven3911 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$MavenHome,[Parameter(Mandatory)][string]$PrivateWrapperCache,[Parameter(Mandatory)][ValidateSet('WindowsCore','MacOriginal',IgnoreCase=$false)][string]$Profile,[ValidateSet('Zip','Tar',IgnoreCase=$false)][string]$Format='Zip')
    $inventory=Join-Path $PSScriptRoot 'StockMaven3911.inventory.json'
    Assert-Stock3911 ((Get-FileHash -LiteralPath $inventory).Hash-ceq'63382624DFFEF090C2B47C476767D9BE9F0620296193B650AE419ABE34FC4D0F') 'Trusted stock3911 inventory differs; caller manifests forbidden'
    $m=Get-Content -LiteralPath $inventory -Raw|ConvertFrom-Json -AsHashtable
    Assert-Stock3911 ($Profile-cne'WindowsCore'-or$Format-ceq'Zip') 'Windows wrapper uses ZIP only'
    $MavenHome=Resolve-Stock3911Path $MavenHome -Directory;$PrivateWrapperCache=Resolve-Stock3911Path $PrivateWrapperCache -Directory
    $key=if($Profile-ceq'WindowsCore'){$m.source.windowsCacheKey}else{$m.source.macCacheKey}
    $expected=Join-Path (Join-Path $PrivateWrapperCache $m.root) $key
    $comparison=if($Profile-ceq'WindowsCore'){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
    Assert-Stock3911 ([string]::Equals($MavenHome,$expected,$comparison)) 'Actual Maven home outside exact admitted private wrapper cache layout'
    $f=$m.formats[$Format];$files=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($row in $f.files){$files.Add($row.path,$row)}
    $dirs=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);foreach($name in $f.physicalDirectories){$null=$dirs.Add($name)}
    $actualFiles=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$actualDirs=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($item in Get-ChildItem -LiteralPath $MavenHome -Recurse -Force){
        Assert-Stock3911 (-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not(-not$item.PSIsContainer-and$item.LinkType)-and-not($item.Attributes-band[IO.FileAttributes]::Hidden)-and-not$item.Name.StartsWith('.')) 'Linked/hidden stock member'
        $relative=[IO.Path]::GetRelativePath($MavenHome,$item.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47)
        if($item.PSIsContainer){$null=$actualDirs.Add($relative);continue}
        $null=$actualFiles.Add($relative)
        if($relative-ceq'mvnw.url'){
            Assert-Stock3911 ($Profile-ceq'MacOriginal') 'Windows cache has no source-defined marker'
            [byte[]]$bytes=[IO.File]::ReadAllBytes($item.FullName);$expectedBytes=[Text.Encoding]::UTF8.GetBytes($f.url+"`n")
            Assert-Stock3911 ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))-ceq[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($expectedBytes))) 'Mac wrapper marker URL/bytes differ'
            continue
        }
        Assert-Stock3911 ($files.ContainsKey($relative)) 'Extra stock Maven file'
        $row=$files[$relative]
        Assert-Stock3911 ($item.Length-eq$row.bytes-and(Get-FileHash -LiteralPath $item.FullName).Hash-ceq$row.sha256) 'Stock Maven full file bytes/hash differ'
        if($IsMacOS-and$Profile-ceq'MacOriginal'){Assert-Stock3911 ([int][IO.File]::GetUnixFileMode($item.FullName)-eq$row.mode) 'Native Mac stock file mode differs'}
    }
    $expectedFiles=[Collections.Generic.HashSet[string]]::new($files.Keys,[StringComparer]::Ordinal)
    if($Profile-ceq'MacOriginal'){$null=$expectedFiles.Add('mvnw.url')}
    Assert-Stock3911 ($actualFiles.SetEquals($expectedFiles)-and$actualDirs.SetEquals($dirs)) 'Stock Maven complete file/directory universe differs'
    if($IsMacOS-and$Profile-ceq'MacOriginal'){foreach($row in $f.directories){$path=Join-Path $MavenHome ($row.path.Replace([char]47,[IO.Path]::DirectorySeparatorChar));Assert-Stock3911 ([int][IO.File]::GetUnixFileMode($path)-eq$row.mode) 'Native Mac explicit-directory mode differs'}}
    @{status='FULL_TRUSTED_STOCK_MAVEN3911_ADMITTED';home=$MavenHome;privateWrapperCache=$PrivateWrapperCache;profile=$Profile;archiveFormat=$Format;archiveSha256=$f.sha256;inventorySha256='63382624DFFEF090C2B47C476767D9BE9F0620296193B650AE419ABE34FC4D0F';archiveFiles=$f.files.Count;physicalFiles=$actualFiles.Count;directories=$actualDirs.Count;coreSha256=$m.core.sha256;nativeMacModesChecked=($IsMacOS-and$Profile-ceq'MacOriginal');runtimeQualified=$false;manifestAuthority='fixed module-owned inventory, not caller data'}
}
Export-ModuleMember -Function Assert-H3911StockMaven3911
