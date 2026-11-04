function Assert-DistributionSetup($Value,[string]$Message){if(-not$Value){throw $Message}}
function Resolve-SetupItem([string]$Path,[switch]$Directory){
    Assert-DistributionSetup ([IO.Path]::IsPathFullyQualified($Path)) 'Absolute native filesystem path required'
    $r=Resolve-Path -LiteralPath $Path -ErrorAction Stop;$i=Get-Item -LiteralPath $r.ProviderPath -Force
    $rightType=if($Directory.IsPresent){$i-is[IO.DirectoryInfo]}else{$i-is[IO.FileInfo]}
    Assert-DistributionSetup ($r.Provider.Name-ceq'FileSystem'-and$rightType-and-not($i.Attributes-band[IO.FileAttributes]::ReparsePoint)-and($Directory.IsPresent-or-not$i.LinkType)) 'Regular nonlinked setup input required'
    $parent=if($Directory){$i}else{$i.Directory};while($parent){Assert-DistributionSetup (-not((Get-Item -LiteralPath $parent.FullName -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked setup ancestry';$parent=$parent.Parent}
    $r.ProviderPath
}
function Get-SetupRelative([string]$Name,[string]$RootName,[bool]$Directory){
    Assert-DistributionSetup ($Name-and$Name-notmatch'[\x00-\x1f\\:]|^/|//' ) 'Unsafe archive member'
    $nameWithoutSlash=if($Directory){$Name.TrimEnd('/')}else{$Name}
    if([string]::Equals($nameWithoutSlash,$RootName,[StringComparison]::Ordinal)){Assert-DistributionSetup $Directory 'Archive root must be a directory';return ''}
    Assert-DistributionSetup ($nameWithoutSlash.StartsWith($RootName+'/',[StringComparison]::Ordinal)) 'Unexpected archive root'
    $relative=$nameWithoutSlash.Substring($RootName.Length+1)
    Assert-DistributionSetup ($relative-and$relative-notmatch'(^|/)\.|/$') 'Unsafe/hidden relative archive path'
    $relative
}
function Get-SetupAdmission([ValidateSet('Windows','Darwin',IgnoreCase=$false)][string]$Platform){
    $file=if($Platform-ceq'Windows'){'H3911.Source.psm1'}else{'H3911.Darwin103.psm1'}
    $hash=if($Platform-ceq'Windows'){'6AC4B84BEEDEED24E6330D556BFAA2954CA2D4771880F2A0C2602AEF5B91A1C0'}else{'05F80C9435B3E6012FAE8874A887A7F96AF8B44311EC1D4A06265ED254E7A264'}
    if($Platform-ceq'Windows'){Assert-DistributionSetup ((Get-FileHash (Join-Path $PSScriptRoot 'H3911.Helpers.psm1')).Hash-ceq'1F1C0099CDC1A7DA6FE949BF973269418DCAAC0E1539A4598A6E5CCFE3720BAA') 'Pinned Source helper closure differs'}
    $path=Join-Path $PSScriptRoot $file;Assert-DistributionSetup ((Get-FileHash $path).Hash-ceq$hash) 'Pinned distribution admission differs'
    $module=Import-Module $path -Scope Local -PassThru -DisableNameChecking
    $name=if($Platform-ceq'Windows'){'Assert-H3911Inventory'}else{'Assert-H3911Darwin103Distribution'}
    $command=$module.ExportedCommands[$name]
    Assert-DistributionSetup ($command-is[Management.Automation.FunctionInfo]-and[string]::Equals($command.Module.Path,$path,[StringComparison]::Ordinal)) 'Distribution command object origin differs'
    $command
}
function Get-SetupWindowsInputs([string]$Root){
    $Root=Resolve-SetupItem $Root -Directory;$metadata=Join-Path $Root 'provenance.json'
    $null=Resolve-SetupItem $metadata
    Assert-DistributionSetup ((Get-FileHash $metadata).Hash-ceq'A314822B548A08EBC3426E878A3FAB38BB45F81E153FBCAA1F067B7C29AB515F') 'Pinned Windows provenance differs'
    $p=Get-Content -LiteralPath $metadata -Raw|ConvertFrom-Json -AsHashtable
    Assert-DistributionSetup ($p.schema-ceq'hobl3911-local-jni-transport-v1'-and$p.files.Count-eq7) 'Windows provenance schema differs'
    $expected=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $null=$expected.Add('provenance.json');$snapshots=@{};$total=0
    foreach($row in $p.files){
        Assert-DistributionSetup ($row.file-is[string]-and$row.file-notmatch'[/\\:]|^\.'-and$expected.Add($row.file)) 'Unsafe staged transport name'
        $path=Resolve-SetupItem (Join-Path $Root $row.file)
        [byte[]]$bytes=[IO.File]::ReadAllBytes($path)
        Assert-DistributionSetup ($bytes.Length-eq$row.bytes-and[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))-ceq$row.sha256) 'Staged transport bytes/hash differ'
        $snapshots[$row.file]=$bytes;$total+=$bytes.Length
    }
    $actual=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($item in Get-ChildItem -LiteralPath $Root -Recurse -Force){Assert-DistributionSetup ($item-is[IO.FileInfo]-and-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not$item.LinkType-and-not($item.Attributes-band[IO.FileAttributes]::Hidden)) 'Staged hidden/link/directory member';$null=$actual.Add($item.Name)}
    Assert-DistributionSetup ($actual.SetEquals($expected)-and$total-eq158361) 'Exact seven transport files plus metadata required'
    $snapshots
}
function Expand-H3911OwnedDistribution {
    param([Parameter(Mandatory)][ValidateSet('Windows','Darwin',IgnoreCase=$false)][string]$Platform,[Parameter(Mandatory)][string]$Archive,[Parameter(Mandatory)][string]$Destination,[string]$WindowsInputs)
    $Archive=Resolve-SetupItem $Archive
    Assert-DistributionSetup ([IO.Path]::IsPathFullyQualified($Destination)-and-not(Test-Path -LiteralPath $Destination)) 'Fresh absolute destination required'
    $parent=Resolve-SetupItem (Split-Path -Parent $Destination) -Directory;$leaf=Split-Path -Leaf $Destination
    Assert-DistributionSetup ($leaf-and$leaf-notin@('.','..')-and$leaf-notmatch'[/\\:]') 'Unsafe destination leaf'
    $Destination=Join-Path $parent $leaf
    [byte[]]$archiveBytes=[IO.File]::ReadAllBytes($Archive)
    $archiveHash=if($Platform-ceq'Windows'){'EFE788E475F8433E855AC05F92E129DC3790517B58002620BA4DD8D264DCD511'}else{'B5528C92D5B0E14A8A47DDFF138C19D93AC01F6CB8A28514F8FA40F2CEB65194'}
    Assert-DistributionSetup ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($archiveBytes))-ceq$archiveHash) 'Official archive SHA256 differs'
    $inputs=if($Platform-ceq'Windows'){Get-SetupWindowsInputs $WindowsInputs}else{$null}
    $admission=Get-SetupAdmission $Platform
    $rootName=if($Platform-ceq'Windows'){'maven-mvnd-1.0.3-windows-amd64'}else{'maven-mvnd-1.0.3-darwin-aarch64'}
    $members=@();$seen=[Collections.Generic.HashSet[string]]::new($(if($Platform-ceq'Windows'){[StringComparer]::OrdinalIgnoreCase}else{[StringComparer]::Ordinal}))
    $memory=[IO.MemoryStream]::new($archiveBytes,$false);$zip=$null;$gzip=$null;$tar=$null;$owned=$false
    try{
        if($Platform-ceq'Windows'){
            $zip=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Read)
            foreach($entry in $zip.Entries){
                $directory=$entry.FullName.EndsWith('/');$kind=($entry.ExternalAttributes-shr16)-band61440
                Assert-DistributionSetup ($kind-in@(0,16384,32768)) 'Linked/unsupported ZIP entry'
                $relative=Get-SetupRelative $entry.FullName $rootName $directory
                if($relative){Assert-DistributionSetup ($seen.Add($relative)) 'Duplicate archive member';$members+=,@{path=$relative;directory=$directory;entry=$entry}}
            }
        }else{
            $gzip=[IO.Compression.GZipStream]::new($memory,[IO.Compression.CompressionMode]::Decompress)
            $tar=[System.Formats.Tar.TarReader]::new($gzip,$true)
            while($entry=$tar.GetNextEntry($true)){
                $directory=$entry.EntryType.ToString()-ceq'Directory'
                Assert-DistributionSetup ($directory-or$entry.EntryType.ToString()-in@('RegularFile','V7RegularFile')) 'Linked/unsupported TAR entry'
                $relative=Get-SetupRelative $entry.Name $rootName $directory
                if($relative){Assert-DistributionSetup ($seen.Add($relative)) 'Duplicate archive member';$members+=,@{path=$relative;directory=$directory;entry=$entry;mode=[int]$entry.Mode}}
            }
        }
        New-Item -ItemType Directory -Path $Destination -ErrorAction Stop|Out-Null;$owned=$true
        foreach($row in $members){
            $target=Join-Path $Destination ($row.path.Replace([char]47,[IO.Path]::DirectorySeparatorChar))
            if($row.directory){[IO.Directory]::CreateDirectory($target)|Out-Null;continue}
            [IO.Directory]::CreateDirectory((Split-Path -Parent $target))|Out-Null
            $output=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $input=if($Platform-ceq'Windows'){$row.entry.Open()}else{$row.entry.DataStream}
            try{$input.CopyTo($output)}finally{$output.Dispose();if($Platform-ceq'Windows'){$input.Dispose()}}
            if($Platform-ceq'Darwin'-and$IsMacOS){[IO.File]::SetUnixFileMode($target,[IO.UnixFileMode]$row.mode)}
        }
        if($Platform-ceq'Darwin'-and$IsMacOS){foreach($row in $members|Where-Object directory){[IO.File]::SetUnixFileMode((Join-Path $Destination ($row.path.Replace([char]47,[IO.Path]::DirectorySeparatorChar))),[IO.UnixFileMode]$row.mode)}}
        if($Platform-ceq'Windows'){
            $nativeJar=Join-Path $Destination 'mvn'|Join-Path -ChildPath 'lib'|Join-Path -ChildPath 'mvnd'|Join-Path -ChildPath 'mvnd-native-1.0.3.jar'
            Assert-DistributionSetup ((Get-FileHash $nativeJar).Hash-ceq'08470605F0840F30970D0B0DBAF788A48326DD94AA9FECEDCD21D704B27C6B0C') 'Original official native JAR differs'
            [IO.File]::WriteAllBytes($nativeJar,$inputs['mvnd-native-1.0.3.jar'])
            foreach($file in 'LOCAL-UNRELEASED-ARM64-JVM-SUPPLEMENT.txt','SHA256SUMS.json'){[IO.File]::WriteAllBytes((Join-Path $Destination $file),$inputs[$file])}
            $null=& $admission $Destination
        }else{$null=& $admission $Destination -RequireNativeModes:$IsMacOS}
        $inventory=@(Get-ChildItem -LiteralPath $Destination -Recurse -File -Force|Sort-Object FullName|ForEach-Object{@{path=[IO.Path]::GetRelativePath($Destination,$_.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]47);bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
        @{status='EXACT_OFFLINE_OWNED_DISTRIBUTION_SETUP';platform=$Platform;destination=$Destination;createdOwned=$owned;archiveSha256=$archiveHash;files=$inventory;fileCount=$inventory.Count;nativeMacModesChecked=($Platform-ceq'Darwin'-and$IsMacOS);runtimeQualified=$false;nativeCalls=0;windowsProvenanceFilesRetainedOutsideSdk=($Platform-ceq'Windows')}
    }catch{if($owned){$_.Exception.Data['OwnedPartialDestination']=$Destination};throw}
    finally{if($tar){$tar.Dispose()};if($gzip){$gzip.Dispose()};if($zip){$zip.Dispose()};$memory.Dispose()}
}
Export-ModuleMember -Function Expand-H3911OwnedDistribution
