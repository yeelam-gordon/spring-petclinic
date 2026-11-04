Import-Module (Join-Path $PSScriptRoot 'H3911.Helpers.psm1') -Scope Local -DisableNameChecking
function Assert-H3911PhysicalInputs($C){
    Assert-H3911 (-not$C.SourceProfile-or$C.SourceProfile-cin@('Original5DD','ReviewedHttpsCoreWrapper','MacOriginalWrapper')) 'Noncanonical source profile'
    $mac=$C.SourceProfile-ceq'MacOriginalWrapper'
    $names=if($mac){@('pom.xml','.mvn/jvm.config','mvnw.cmd','mvnw','.gitattributes','.mvn/wrapper/maven-wrapper.properties')}else{@('pom.xml','.mvn/jvm.config','mvnw.cmd')}
    $comparison=if($mac){[StringComparison]::Ordinal}else{[StringComparison]::OrdinalIgnoreCase}
    foreach($name in $names){
        $path=[IO.Path]::GetFullPath((Join-Path $C.Project $name));$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        $resolved=Resolve-Path -LiteralPath $path -ErrorAction Stop
        Assert-H3911 ($resolved.Provider.Name-ceq'FileSystem'-and$item-is[IO.FileInfo]-and-not$item.PSIsContainer-and-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-and[string]::Equals($item.FullName,$resolved.ProviderPath,$comparison)) 'Linked/non-file admitted input'
        $parent=$item.Directory;while($parent){$directory=Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop;Assert-H3911 ($directory-is[IO.DirectoryInfo]-and-not($directory.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked admitted input ancestry';$parent=$parent.Parent}
    }
}
function Assert-H3911MacOriginalSource($C){
    Assert-H3911PhysicalInputs $C
    Assert-H3911 (-not@([IO.Path]::GetFullPath($C.Project).Split([char[]]'\/')|Where-Object{$_-ceq'build'}).Count) 'Mac source inside suppressed build ancestry'
    foreach($name in 'GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR','GIT_INDEX_FILE'){Assert-H3911 (-not[Environment]::GetEnvironmentVariable($name)) "Mac Git override rejected: $name"}
    $git=(Get-Command git -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
    $head=& $git -C $C.Project rev-parse HEAD;Assert-H3911 ($LASTEXITCODE-eq0-and$head-ceq'6feeae0f13e0e258eedc99832416b42bb13779b1') 'Wrong HOBL HEAD'
    $policy=& $git -C $C.Project config --get core.autocrlf;Assert-H3911 ($LASTEXITCODE-eq0-and$policy-ceq'false') 'Mac source requires explicit autocrlf=false'
    $origin=& $git -C $C.Project remote get-url origin;Assert-H3911 ($LASTEXITCODE-eq0-and$origin-ceq'https://github.com/spring-projects/spring-petclinic.git') 'Mac canonical source origin differs'
    $common=& $git -C $C.Project rev-parse --git-common-dir
    $gitDir=Get-Item -LiteralPath (Join-Path $C.Project '.git') -Force
    Assert-H3911 ($LASTEXITCODE-eq0-and$common-ceq'.git'-and$gitDir-is[IO.DirectoryInfo]-and-not($gitDir.Attributes-band[IO.FileAttributes]::ReparsePoint)-and-not(Test-Path (Join-Path $C.Project '.git/objects/info/alternates'))) 'Mac ordinary full clone required'
    $shallow=& $git -C $C.Project rev-parse --is-shallow-repository;Assert-H3911 ($LASTEXITCODE-eq0-and$shallow-ceq'false') 'Mac shallow source rejected'
    $mode=& $git -C $C.Project ls-tree HEAD -- mvnw
    Assert-H3911 ($LASTEXITCODE-eq0-and$mode-cmatch'^100755 blob 885f47143484ae8989456039a2c3c134fb87c4ce\tmvnw$') 'Mac committed Unix wrapper mode/blob differs'
    $index=@(& $git -C $C.Project ls-files --stage -- mvnw)
    Assert-H3911 ($LASTEXITCODE-eq0-and$index.Count-eq1-and$index[0]-cmatch'^100755 885f47143484ae8989456039a2c3c134fb87c4ce 0\tmvnw$') 'Mac Unix wrapper index mode/blob differs'
    $pins=@(
        @('pom.xml','A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D'),
        @('.mvn/jvm.config','0E8B638C4F6EB6B951AB213FB1AF5BED05FBCAF80FFEB3ABA3B39EAE12235E3D'),
        @('mvnw','4B9C75F9D4829F2368319B767B119D4CB17F84974A149CE703B28FB637241791'),
        @('mvnw.cmd','5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A'),
        @('.gitattributes','BF25544E3FCCF82FE3CF2CAFBD744FF2302619C24001FDF566BA813392618EE8'),
        @('.mvn/wrapper/maven-wrapper.properties','8F2A4438810348270D9D98F8D6D530541DDB7271E373DB207E8AC381E0E35B62'))
    foreach($pin in $pins){Assert-H3911 ((Get-FileHash -LiteralPath (Join-Path $C.Project $pin[0])).Hash-ceq$pin[1]) "Mac source input bytes differ: $($pin[0])"}
    $bootstrap=Join-Path $C.Project '.mvn/wrapper';$members=@(Get-ChildItem -LiteralPath $bootstrap -Force -Recurse)
    Assert-H3911 ($members.Count-eq1-and$members[0]-is[IO.FileInfo]-and$members[0].Name-ceq'maven-wrapper.properties') 'Mac only-script bootstrap file universe differs'
    $status=@(& $git -C $C.Project status --porcelain --untracked-files=all)
    Assert-H3911 ($LASTEXITCODE-eq0-and$status.Count-eq0) 'Mac original wrapper source must be clean'
}
function Assert-H3911Source($C){
    if($C.SourceProfile-ceq'MacOriginalWrapper'){Assert-H3911MacOriginalSource $C;return}
    $reviewed=$C.SourceProfile-ceq'ReviewedHttpsCoreWrapper';Assert-H3911 (-not$C.SourceProfile-or$C.SourceProfile-cin@('Original5DD','ReviewedHttpsCoreWrapper')) 'Noncanonical source profile'
    Assert-H3911PhysicalInputs $C
    Assert-H3911 (-not@([IO.Path]::GetFullPath($C.Project).Split([char[]]'\/')|Where-Object{$_-ieq'build'}).Count-and(& git.exe -C $C.Project config --get core.autocrlf)-ceq'false'-and(& git.exe -C $C.Project remote get-url origin)-ceq'https://github.com/spring-projects/spring-petclinic.git') 'Canonical false-policy source outside build ancestry required'
    Assert-H3911 ((& git.exe -C $C.Project rev-parse HEAD)-ceq'6feeae0f13e0e258eedc99832416b42bb13779b1'-and$LASTEXITCODE-eq0) 'Wrong HOBL HEAD'
    $status=@(& git.exe -C $C.Project status --porcelain --untracked-files=all)
    Assert-H3911 ($LASTEXITCODE-eq0-and$(if($reviewed){$status.Count-eq1-and$status[0]-ceq' M mvnw.cmd'}else{$status.Count-eq0})) 'Source profile dirty set differs'
    Assert-H3911 ((& git.exe -C $C.Project rev-parse --git-common-dir)-ceq'.git'-and-not(Test-Path (Join-Path $C.Project '.git/objects/info/alternates'))) 'Ordinary full clone required'
    $wrapper=if($reviewed){'AAA4957C5AB29267A0D89C03D33621740A4233BF25AFEB480797023687CABB7D'}else{'5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A'}
    foreach($row in @(@('pom.xml','A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D'),@('.mvn/jvm.config','0E8B638C4F6EB6B951AB213FB1AF5BED05FBCAF80FFEB3ABA3B39EAE12235E3D'),@('mvnw.cmd',$wrapper))){Assert-H3911 ((Get-FileHash (Join-Path $C.Project $row[0])).Hash-ceq$row[1]) 'Original HOBL input bytes differ'}
}
function Assert-H3911Inventory([string]$Root){
    Assert-H3911 ((Get-FileHash (Join-Path $Root 'SHA256SUMS.json')).Hash-ceq'0D79A9F4F4656A33AC63DD2D44EAC0AD3F9B19FA0AD9F0810973D32F82B8BAAD') 'Approved distribution manifest differs'
    $ancestor=[IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Root));while($ancestor){Assert-H3911 (-not((Get-Item $ancestor.FullName -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked distribution ancestry';$ancestor=$ancestor.Parent}
    $m=@(Get-Content (Join-Path $Root 'SHA256SUMS.json') -Raw|ConvertFrom-Json);$all=@(Get-ChildItem $Root -Recurse -Force)
    Assert-H3911 (-not@($all|Where-Object{$_.Attributes-band[IO.FileAttributes]::ReparsePoint}).Count) 'Linked distribution member'
    $actual=@($all|Where-Object{-not$_.PSIsContainer}|ForEach-Object{[IO.Path]::GetRelativePath($Root,$_.FullName).Replace('\','/')}|Sort-Object -CaseSensitive)
    $expected=@(@($m.path)+@('SHA256SUMS.json')|Sort-Object -CaseSensitive)
    Assert-H3911 ((ConvertTo-H3911Json $actual)-ceq(ConvertTo-H3911Json $expected)) 'Exact distribution inventory differs'
    foreach($r in $m){Assert-H3911 ($r.path-notmatch'(^[/\\]|\\|:|(^|/)\.\.?(/|$))'-and(Get-Item (Join-Path $Root $r.path) -Force).Length-eq$r.bytes-and(Get-FileHash (Join-Path $Root $r.path)).Hash-ceq$r.sha256) 'Distribution path/bytes/hash differ'}
}
Export-ModuleMember -Function Assert-H3911PhysicalInputs,Assert-H3911Source,Assert-H3911Inventory
