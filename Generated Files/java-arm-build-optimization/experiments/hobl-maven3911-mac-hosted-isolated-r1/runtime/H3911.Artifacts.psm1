Import-Module (Join-Path $PSScriptRoot 'H3911.Helpers.psm1') -Scope Local -DisableNameChecking
function ConvertTo-H3911ArtifactJson($Value){ConvertTo-H3911Json $Value}
function Read-H3911Artifact($Jar,$Main,$Tests,[string]$Destination,[switch]$RequireClean,[ValidateSet('Original5DD','ReviewedHttpsCoreWrapper','MacOriginalWrapper')][string]$SourceProfile='Original5DD',[switch]$Offline){
    Require ($SourceProfile-cin@('Original5DD','ReviewedHttpsCoreWrapper','MacOriginalWrapper')) 'Noncanonical source profile'
    $roles=@('META-INF/MANIFEST.MF','META-INF/build-info.properties','BOOT-INF/classes/git.properties','META-INF/sbom/application.cdx.json','META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml','META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties')
    if($Offline){Require ($SourceProfile-in@('ReviewedHttpsCoreWrapper','MacOriginalWrapper')) 'Offline facade requires reviewed profile';$roles=@($roles|Where-Object{$_-cne'META-INF/sbom/application.cdx.json'})}
    if($Destination){Require (-not(Test-Path $Destination)) 'Fresh capture required';New-Item $Destination -ItemType Directory|Out-Null}
    [byte[]]$jarBytes=[IO.File]::ReadAllBytes($Jar);$memory=[IO.MemoryStream]::new($jarBytes,$false);$zip=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Read)
    $entries=@();$raw=@();$loose=@();$map=[Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
    try{
        foreach($entry in $zip.Entries){Require (-not$map.ContainsKey($entry.FullName)-and$entry.FullName-notmatch'(^/|\\|(^|/)\.\.?(/|$))') 'Duplicate/unsafe physical entry';$bytes=StreamBytes $entry $true;$map.Add($entry.FullName,$bytes);$entries+=,[ordered]@{name=$entry.FullName;bytes=$bytes.Length;sha256=(HashBytes $bytes);directory=$entry.FullName.EndsWith('/')}}
        Require ($entries.Count-eq$(if($Offline){333}else{335})-and@($entries|Where-Object{-not$_.directory}).Count-eq$(if($Offline){284}else{285})-and@($entries|Where-Object{$_.name-like'BOOT-INF/classes/*.class'}).Count-eq30-and@($entries|Where-Object{$_.name-like'BOOT-INF/lib/*.jar'}).Count-eq98) 'Original A41 physical/class/dependency universe'
        foreach($role in $roles){Require ($map.ContainsKey($role)-and$map[$role].Length-gt0) 'Missing/empty raw role';$name=('{0:D2}.raw'-f($raw.Count+1));$raw+=,[ordered]@{entry=$role;file=$name;bytes=$map[$role].Length;sha256=(HashBytes $map[$role])};if($Destination){[IO.File]::WriteAllBytes((Join-Path $Destination $name),$map[$role])}}
        Require ((HashBytes $map['META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml'])-ceq'A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D') 'Not original A41 POM'
        $git=[Text.Encoding]::UTF8.GetString($map[$roles[2]]);Require ($git-match'(?m)^git.commit.id=6feeae0f13e0e258eedc99832416b42bb13779b1\r?$') 'Wrong artifact version/source'
        if($RequireClean){Require ($git-match'(?m)^git.dirty=false\r?$') 'Clean original source artifact required'}
        if($SourceProfile-ceq'MacOriginalWrapper'){$dirty=[regex]::Matches($git,'(?m)^git\.dirty=([^\r\n]+)\r?$');Require ($dirty.Count-eq1-and$dirty[0].Groups[1].Value-ceq'false') 'Mac original artifact must have explicit clean provenance'}
        if($SourceProfile-ceq'ReviewedHttpsCoreWrapper'){Require (-not$RequireClean-and$git-match'(?m)^git.dirty=true\r?$') 'Reviewed wrapper must have explicit dirty provenance'}
        $bom=$null
        if(-not$Offline){
        $bom=[Text.Encoding]::UTF8.GetString($map[$roles[3]])|ConvertFrom-Json -AsHashtable
        $refs=@($bom.components|ForEach-Object{$_['bom-ref']})+@($bom.metadata.component['bom-ref'])
        Require ($bom.components.Count-eq108-and$bom.dependencies.Count-eq109-and@($refs|Sort-Object -Unique).Count-eq109-and@($bom.dependencies.ref|Sort-Object -Unique).Count-eq109) 'Original A41 full BOM universe'
        foreach($node in $bom.dependencies){Require ($node.ref-cin$refs) 'Unknown BOM node';foreach($edge in $node.dependsOn){Require ($edge-cin$refs) 'Dangling BOM edge'}}
        }else{Require (-not$map.ContainsKey('META-INF/sbom/application.cdx.json')-and-not$map.ContainsKey('META-INF/sbom/')) 'Unexpected offline SBOM entry'}
        foreach($scope in 'classes','test-classes'){
            $folder=if($scope-eq'classes'){$Main}else{$Tests};$items=@(Get-ChildItem $folder -Recurse -Force)
            Require (-not@($items|Where-Object{$_.Attributes-band[IO.FileAttributes]::ReparsePoint}).Count) 'Linked loose artifact'
            $files=@($items|Where-Object{-not$_.PSIsContainer}|Sort-Object FullName)
            Require (@($files|Where-Object Extension -eq '.class').Count-eq$(if($scope-eq'classes'){30}else{25})) 'Expected55 original compiled binaries'
            foreach($file in $files){$name=[IO.Path]::GetRelativePath($folder,$file.FullName).Replace('\','/');$bytes=[IO.File]::ReadAllBytes($file.FullName);$hash=HashBytes $bytes;if($file.Extension-eq'.class'){Require ($bytes.Length-ge8-and$bytes[6]-eq0-and$bytes[7]-eq61) 'Wrong class target'};if($scope-eq'classes'){$binding=if($map.ContainsKey("BOOT-INF/classes/$name")){"BOOT-INF/classes/$name"}else{$name};Require ($map.ContainsKey($binding)-and(HashBytes $map[$binding])-ceq$hash) 'Loose resource binding differs'};$loose+=,[ordered]@{scope=$scope;name=$name;bytes=$bytes.Length;sha256=$hash};if($Destination){$to=Join-Path $Destination "$scope/$name";New-Item (Split-Path $to) -ItemType Directory -Force|Out-Null;[IO.File]::WriteAllBytes($to,$bytes)}}
        }
        $record=[ordered]@{schema=$(if($SourceProfile-ceq'MacOriginalWrapper'){if($Offline){'mac-original-A41-offline-v1'}else{'mac-original-A41-online-v1'}}elseif($Offline){'reviewed-A41-offline-v1'}elseif($SourceProfile-ceq'ReviewedHttpsCoreWrapper'){'reviewed-A41-online-v1'}else{'original-A41-sha256-v1'});jarSha256=(HashBytes $jarBytes);entries=$entries;raw=$raw;loose=$loose;git=$git;bom=$bom}
        $json=ConvertTo-H3911ArtifactJson $record
        if($Destination){[IO.File]::WriteAllBytes((Join-Path $Destination 'application.jar'),$jarBytes);$json|Set-Content (Join-Path $Destination 'artifact.json')}
        return $record
    }finally{$zip.Dispose();$memory.Dispose()}
}
function Compare-H3911Artifacts([string]$Left,[string]$Right,[ValidateSet('Original5DD','ReviewedHttpsCoreWrapper','MacOriginalWrapper')][string]$SourceProfile='Original5DD',[switch]$Offline){
    Require ($SourceProfile-cin@('Original5DD','ReviewedHttpsCoreWrapper','MacOriginalWrapper')) 'Noncanonical source profile'
    $seen=@()
    foreach($dir in $Left,$Right){
        $actual=Read-H3911Artifact (Join-Path $dir 'application.jar') (Join-Path $dir 'classes') (Join-Path $dir 'test-classes') -RequireClean:($SourceProfile-in@('Original5DD','MacOriginalWrapper')) -SourceProfile $SourceProfile -Offline:$Offline
        $saved=Get-Content (Join-Path $dir 'artifact.json') -Raw|ConvertFrom-Json -AsHashtable
        if(-not[string]::Equals((ConvertTo-H3911ArtifactJson $saved),(ConvertTo-H3911ArtifactJson $actual),[StringComparison]::Ordinal)){throw 'Artifact schema/digest binding differs'}
        foreach($role in $actual.raw){$bytes=[IO.File]::ReadAllBytes((Join-Path $dir $role.file));if($bytes.Length-ne$role.bytes-or[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))-cne$role.sha256){throw 'Retained raw role differs'}}
        $seen+=,$actual
    }
    if(-not[string]::Equals((ConvertTo-H3911ArtifactJson $seen[0]),(ConvertTo-H3911ArtifactJson $seen[1]),[StringComparison]::Ordinal)){throw 'PENDING unknown same-host JAR/raw/resource/BOM difference; no normalization'}
    return @{status='PASS';ignored=@()}
}
function Save-H3911Verify($C,[string]$Label,$Call){
    $profile=if($C.SourceProfile){$C.SourceProfile}else{'Original5DD'}
    Require ($profile-cin@('Original5DD','ReviewedHttpsCoreWrapper','MacOriginalWrapper')) 'Noncanonical source profile'
    $dir=Join-Path $C.Output $Label;$jar=@(Get-ChildItem (Join-Path $C.Project 'target') -Filter '*.jar');Require ($jar.Count-eq1) 'One original executable JAR required'
    $artifact=Read-H3911Artifact $jar[0].FullName (Join-Path $C.Project 'target/classes') (Join-Path $C.Project 'target/test-classes') $dir -RequireClean:($profile-in@('Original5DD','MacOriginalWrapper')) -SourceProfile $profile
    Copy-Item (Join-Path $C.Project 'target/surefire-reports') (Join-Path $dir 'surefire') -Recurse;Copy-Item (Join-Path $C.Project 'target/site/jacoco') (Join-Path $dir 'jacoco') -Recurse;Copy-Item (Join-Path $C.Project 'target/jacoco.exec') (Join-Path $dir 'jacoco.exec')
    $reports=@(Get-ChildItem (Join-Path $dir 'surefire') -Filter 'TEST-*.xml'|ForEach-Object{[xml](Get-Content $_.FullName -Raw)});$tests=TestKeys $reports
    Require ($tests.Count-eq56-and@($tests|Where-Object state -eq passed).Count-eq54-and@($tests|Where-Object state -eq skipped).Count-eq2) 'Original56/54/2 states differ'
    foreach($report in $reports){foreach($expected in @(@('java.home',$C.Jdk),@('java.runtime.version','25.0.5.0.2+1-LTS'),@('java.vendor','Microsoft'),@('os.arch','aarch64'))){Require ($report.SelectSingleNode("//properties/property[@name='$($expected[0])']").value-ceq$expected[1]) 'Actual native25 fork profile differs'}}
    $xml=[xml](Get-Content (Join-Path $dir 'jacoco/jacoco.xml') -Raw);$counters=CoverageKeys $xml;$session=@($xml.SelectNodes('/report/sessioninfo'));Require ($counters.Count-eq726-and$xml.SelectNodes('/report/package/sourcefile/line').Count-eq296-and$xml.SelectNodes('/report/package/class').Count-eq25-and$session.Count-eq1-and[long]$session[0].start-ge$Call.start-and[long]$session[0].dump-le$Call.end) 'Original coverage universe/session freshness differs'
    $fork=@([regex]::Matches((Get-Content $Call.log -Raw),'Starting .*? with PID (\d+)')|ForEach-Object{$_.Groups[1].Value}|Sort-Object -Unique);Require ($fork.Count-eq1-and(Get-Item (Join-Path $dir 'jacoco.exec')).Length-gt0) 'Fresh reported fork/exec absent'
    $exec=JacocoExecEvidence ([IO.File]::ReadAllBytes((Join-Path $dir 'jacoco.exec'))) default
    Require ($exec.session.id-ceq$session[0].id-and$exec.session.start-eq[long]$session[0].start-and$exec.session.dump-eq[long]$session[0].dump) 'Exec/report session mismatch'
    return @{tests=$tests;counters=$counters;semantics=(CoverageSemantics $xml);session=$session[0].id;fork=$fork[0];artifact=$artifact;exec=$exec}
}
Export-ModuleMember -Function ConvertTo-H3911ArtifactJson,Read-H3911Artifact,Compare-H3911Artifacts,Save-H3911Verify
