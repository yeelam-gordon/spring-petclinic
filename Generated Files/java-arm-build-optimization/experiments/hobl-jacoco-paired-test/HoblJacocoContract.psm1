$base=Join-Path $PSScriptRoot '..\hobl-contract\Invoke-HoblContract.ps1'
if((Get-FileHash $base).Hash-ne'42431D527726E18D52091A00FF4DAE38CE28110F8F43CC1E89A58E05F49A3CB2'){throw 'Pinned HOBL pure helper drift'}
if((Get-FileHash (Join-Path $PSScriptRoot '..\hobl-wrapper-diagnostic\Invoke-WrapperBoundary.ps1')).Hash-ne'873BF3338C7AA42FAB92C986CA40F66C6D81C75B31A6312EC97CFFEF844F6E17'){throw 'Pinned environment helper drift'}
. $base -LibraryOnly
function InitializeMatchedWindowsEnvironmentHelpers{
    $tokens=$null;$errors=$null
    $path=Join-Path $PSScriptRoot '..\hobl-wrapper-diagnostic\Invoke-WrapperBoundary.ps1'
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Require ($errors.Count-eq0) 'Reviewed environment helper parse failed'
    foreach($name in 'GetBoundaryEnvironmentSnapshot','RestoreBoundaryEnvironment'){
        $definition=$ast.Find({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-eq$name},$true)
        Require $definition 'Reviewed environment helper export missing'
        . ([scriptblock]::Create($definition.Extent.Text.Replace("function $name","function script:$name")))
    }
}
function GetMatchedEnvironmentSnapshot{
    if($IsWindows){InitializeMatchedWindowsEnvironmentHelpers;return (GetBoundaryEnvironmentSnapshot)}
    $snapshot=[Collections.Hashtable]::new([StringComparer]::Ordinal)
    $values=[Environment]::GetEnvironmentVariables('Process')
    foreach($key in $values.Keys){$snapshot.Add([string]$key,$values[$key])};return $snapshot
}
function RestoreMatchedEnvironment($Before,[string[]]$Names){
    if($IsWindows){return (RestoreBoundaryEnvironment $Before $Names)}
    $errors=@()
    foreach($name in $Names){
        try{if($Before.Contains($name)){[Environment]::SetEnvironmentVariable($name,$Before[$name],'Process')}elseif(Test-Path ('Env:'+$name)){Remove-Item ('Env:'+$name) -ErrorAction Stop}}
        catch{$errors+=@{name=$name;error=$_.ToString()}}
    }
    $after=GetMatchedEnvironmentSnapshot
    $keys=@(foreach($name in $Names){
        $a=$Before.Contains($name);$b=$after.Contains($name)
        @{name=$name;beforePresent=$a;afterPresent=$b;equal=($a-eq$b-and[string]::Equals($Before[$name],$after[$name],[StringComparison]::Ordinal));beforeLength=$(if($a){$Before[$name].Length}else{$null});afterLength=$(if($b){$after[$name].Length}else{$null});beforeSha=$(if($a){HashBytes ([Text.Encoding]::UTF8.GetBytes($Before[$name]))}else{$null});afterSha=$(if($b){HashBytes ([Text.Encoding]::UTF8.GetBytes($after[$name]))}else{$null})}
    })
    return @{restored=($errors.Count-eq0-and@($keys|Where-Object {-not$_.equal}).Count-eq0);keys=$keys;errors=$errors;comparer='Ordinal Unix environment names'}
}
$originalPom='A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D'
$trialPom='D7FF6C0FB845850374020A16A65F4B2B1F1BF8E3204C65AB56BDCA2137BDA818'
$originalCmd='5DDDBC06B22E26410B82AA17181510058D58319DED13E1822D6D784196582F1A'
$aaa='AAA4957C5AB29267A0D89C03D33621740A4233BF25AFEB480797023687CABB7D'
function AssertHoblTrialPom([byte[]]$Original,[byte[]]$Trial){
    Require ((HashBytes $Original)-ceq$originalPom-and(HashBytes $Trial)-ceq$trialPom) 'Exact original/trial POM required'
    [xml]$a=[Text.Encoding]::UTF8.GetString($Original);[xml]$b=[Text.Encoding]::UTF8.GetString($Trial)
    $ns=[Xml.XmlNamespaceManager]::new($b.NameTable);$ns.AddNamespace('m',$b.DocumentElement.NamespaceURI)
    $property=$b.SelectSingleNode('/m:project/m:properties/m:jacoco.instrumentation.includes',$ns)
    $config=$b.SelectNodes('//m:plugin[m:artifactId="jacoco-maven-plugin"]/m:executions/m:execution[m:goals/m:goal="prepare-agent"]/m:configuration',$ns)
    Require ($property.InnerText-ceq'*'-and$config.Count-eq1-and$config[0].ChildNodes.Count-eq1-and$config[0].SelectSingleNode('m:includes/m:include',$ns).InnerText-ceq'${jacoco.instrumentation.includes}') 'Prepare-agent-only/default-all binding required'
    $null=$property.ParentNode.RemoveChild($property);$null=$config[0].ParentNode.RemoveChild($config[0])
    Require ($a.OuterXml-ceq$b.OuterXml) 'POM change beyond property/prepare-agent'
}
function AssertHoblTrialSource($Context,[ValidateSet('Windows','MacOS')][string]$Platform,[switch]$Original){
    Require ($Context.head-ceq'6feeae0f13e0e258eedc99832416b42bb13779b1'-and$Context.origin-cin@('https://github.com/spring-projects/spring-petclinic.git','https://github.com/spring-projects/spring-petclinic')-and$Context.commonDir-ceq'.git'-and-not$Context.borrowed) 'Pinned canonical unborrowed full clone required'
    Require ($Context.javaSha256-cmatch'^[0-9A-F]{64}$'-and$Context.javaSha256-ceq$Context.beforeJavaSha256-and$Context.jvmConfigSha256-cmatch'^[0-9A-F]{64}$'-and$Context.jvmConfigSha256-ceq$Context.beforeJvmConfigSha256) 'Java/JVM config changed'
    Require ($Context.mavenVersion-ceq'3.9.11'-and$Context.javaRuntime-ceq'25.0.5.0.2+1-LTS'-and$Context.arch-ceq'aarch64') 'Pinned native HOBL tools required'
    if($Platform-eq'Windows'){Require ($Context.javaSha256-ceq'094E0F67B96E6351F831C686A9B0C450DB55639639CFDD7F9E77597C83B928B0') 'Pinned native Windows JDK25 bytes'}
    $expected=if($Original){@()}elseif($Platform-eq'Windows'){@(' M mvnw.cmd',' M pom.xml')}else{@(' M pom.xml')}
    Require ((Json @($Context.dirty|Sort-Object -CaseSensitive))-ceq(Json @($expected|Sort-Object -CaseSensitive))) 'Only declared trial paths allowed'
    Require ($Context.pomSha256-ceq$(if($Original){$originalPom}else{$trialPom})) 'Wrong declared POM'
    Require ($Context.cmdSha256-ceq$(if(-not$Original-and$Platform-eq'Windows'){$aaa}else{$originalCmd})) 'Wrong CMD bytes'
    Require ($Context.shellSha256-ceq'4B9C75F9D4829F2368319B767B119D4CB17F84974A149CE703B28FB637241791') 'Original bash changed'
    if(-not$Original-and$Platform-eq'Windows'){Require ($Context.corePreference-ceq'true') 'Windows trial requires same AAA/Core'}
    Require ($Context.suppressions.Count-gt0-and$(if($Platform-eq'Windows'){$Context.absoluteWrapper-match'^[A-Za-z]:[\\/]'}else{$Context.absoluteWrapper.StartsWith('/')})) 'Actual absolute wrapper/policy required'
    foreach($rule in $Context.suppressions){Require ($rule.files-and$rule.checks) 'Unsupported suppression';Require (-not([regex]::IsMatch('io.spring.nohttp.checkstyle.check.NoHttpCheck',$rule.checks)-and[regex]::IsMatch($Context.absoluteWrapper,$rule.files))) 'Actual full wrapper path suppressed'}
}
function ReadHoblTrialContext([string]$Project,[string]$JavaExecutable,$Before,[ValidateSet('Windows','MacOS')][string]$Platform){
    foreach($name in 'GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR','GIT_INDEX_FILE','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES'){Require (-not[Environment]::GetEnvironmentVariable($name)) 'Injected Git context rejected'}
    Require (Test-Path (Join-Path $Project '.git') -PathType Container) 'Full clone directory required'
    $ancestor=[IO.Path]::GetFullPath($Project);while($ancestor){Require (-not((Get-Item -LiteralPath $ancestor -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Linked source ancestry';$parent=[IO.Directory]::GetParent($ancestor);$ancestor=if($parent){$parent.FullName}else{$null}}
    function Query([string[]]$Arguments){$text=@(& git -C $Project @Arguments);Require ($LASTEXITCODE-eq0) 'Source Git query failed';return @($text)}
    [xml]$policy=Get-Content (Join-Path $Project 'src/checkstyle/nohttp-checkstyle-suppressions.xml') -Raw
    $props=Get-Content (Join-Path $Project '.mvn/wrapper/maven-wrapper.properties') -Raw;Require ($props-match'/3\.9\.11/apache-maven-3\.9\.11-bin\.zip') 'Original Maven distribution required'
    return @{head=((Query @('rev-parse','HEAD'))-join'');origin=((Query @('remote','get-url','origin'))-join'');commonDir=((Query @('rev-parse','--git-common-dir'))-join'');borrowed=(Test-Path (Join-Path $Project '.git/objects/info/alternates'));dirty=@(Query @('status','--porcelain=v1','--untracked-files=all'));pomSha256=(Get-FileHash (Join-Path $Project 'pom.xml')).Hash;cmdSha256=(Get-FileHash (Join-Path $Project 'mvnw.cmd')).Hash;shellSha256=(Get-FileHash (Join-Path $Project 'mvnw')).Hash;javaSha256=(Get-FileHash $JavaExecutable).Hash;beforeJavaSha256=$Before.javaSha256;jvmConfigSha256=(Get-FileHash (Join-Path $Project '.mvn/jvm.config')).Hash;beforeJvmConfigSha256=$Before.jvmConfigSha256;mavenVersion='3.9.11';javaRuntime=$Before.javaRuntime;arch=$Before.arch;corePreference=$env:MVNW_PREFER_PWSH;absoluteWrapper=[IO.Path]::GetFullPath((Join-Path $Project $(if($Platform-eq'Windows'){'mvnw.cmd'}else{'mvnw'})));suppressions=@($policy.SelectNodes('/suppressions/suppress')|ForEach-Object {@{files=$_.files;checks=$_.checks}})}
}
function RestoreHoblTrialFiles([string]$Project,[byte[]]$Pom,[byte[]]$Cmd){
    Require ((HashBytes $Pom)-ceq$originalPom-and(HashBytes $Cmd)-ceq$originalCmd) 'Pinned restoration bytes required'
    Require ((Get-FileHash (Join-Path $Project 'pom.xml')).Hash-in@($originalPom,$trialPom)-and(Get-FileHash (Join-Path $Project 'mvnw.cmd')).Hash-in@($originalCmd,$aaa)) 'Unknown source bytes; refuse overwrite'
    [IO.File]::WriteAllBytes((Join-Path $Project 'pom.xml'),$Pom);[IO.File]::WriteAllBytes((Join-Path $Project 'mvnw.cmd'),$Cmd)
    Require ((Get-FileHash (Join-Path $Project 'pom.xml')).Hash-ceq$originalPom-and(Get-FileHash (Join-Path $Project 'mvnw.cmd')).Hash-ceq$originalCmd) 'Exact restore failed'
}
function GetHoblContractEnvironment { @{values=(GetMatchedEnvironmentSnapshot);cwd=(Get-Location).Path} }
function RestoreHoblContractEnvironment($Before){
    $r=RestoreMatchedEnvironment $Before.values @('JAVA_HOME','PATH','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME','MVNW_PREFER_PWSH')
    Set-Location -LiteralPath $Before.cwd;$r.cwdEqual=(Get-Location).Path-ceq$Before.cwd;Require ($r.restored-and$r.cwdEqual-and$r.keys.Count-eq11) 'Eleven-key/cwd restore failed';return $r
}
function AssertHoblRawMetadata($Snapshot){
    $required=@('META-INF/MANIFEST.MF','META-INF/build-info.properties','BOOT-INF/classes/git.properties','META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml','META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties','META-INF/sbom/application.cdx.json')
    Require ($Snapshot.rawMetadata.Count-eq$required.Count) 'Exactly six mandatory raw metadata roles required'
    $roles=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($raw in $Snapshot.rawMetadata){
        Require ($raw.entry-is[string]-and-not[string]::IsNullOrWhiteSpace($raw.entry)-and$roles.Add($raw.entry)) 'Duplicate/invalid raw metadata role'
        Require ($raw.sha256-cmatch'^[0-9A-F]{64}$'-and$raw.bytes-gt0) 'Nonempty SHA256 metadata required before role lookup'
    }
    Require ($roles.SetEquals([string[]]$required)) 'Missing/unknown/mutated raw metadata role'
    foreach($raw in $Snapshot.rawMetadata){
        $entries=@($Snapshot.entries|Where-Object {$_.name-ceq$raw.entry})
        Require ($entries.Count-eq1-and$entries[0].bytes-eq$raw.bytes-and$entries[0].sha256-ceq$raw.sha256) 'Raw role does not bind exact complete-JAR entry'
    }
    $pom=@($Snapshot.rawMetadata|Where-Object entry -eq 'META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml');Require ($pom[0].sha256-ceq$trialPom) 'Packaged exact D7 trial POM required'
    foreach($raw in $Snapshot.rawMetadata){$bytes=[IO.File]::ReadAllBytes($raw.path);Require ($bytes.Length-eq$raw.bytes-and(HashBytes $bytes)-ceq$raw.sha256) 'Raw metadata bytes/fingerprint differ';if($raw.entry-eq'META-INF/sbom/application.cdx.json'){$bom=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json;Require ($bom.components.Count-eq108-and$bom.dependencies.Count-eq109) 'Pinned online SBOM universe'};if($raw.entry-eq'BOOT-INF/classes/git.properties'){$git=[Text.Encoding]::UTF8.GetString($bytes);Require ($git-match'(?m)^git\.commit\.id=6feeae0f13e0e258eedc99832416b42bb13779b1\r?$'-and$git-match'(?m)^git\.dirty=true\r?$') 'Honest common trial Git metadata required'}}
}
function AssertHoblSnapshot($Snapshot,$Reference){
    AssertHoblRawMetadata $Snapshot
    if($Reference){AssertHoblRawMetadata $Reference}
    Require ($Snapshot.classes.Count-eq30-and$Snapshot.testClasses.Count-eq25-and$Snapshot.dependencies.Count-eq98-and$Snapshot.counters.Count-eq726-and$Snapshot.jarSha256-cmatch'^[0-9A-F]{64}$') 'HOBL sha256 Snapshot universe required'
    Require ($Snapshot.tests.Count-eq56-and@($Snapshot.tests|Where-Object state -eq passed).Count-eq54-and@($Snapshot.tests|Where-Object state -eq skipped).Count-eq2-and$Snapshot.coverageSemantics) 'Full HOBL tests/semantic report required'
    [xml]$xml=$Snapshot.coverageSemantics;Require ($xml.SelectNodes('/report/package/class').Count-eq25-and$xml.SelectNodes('/report/package/sourcefile/line').Count-eq296) 'HOBL class/line universe'
    Same (CoverageKeys $xml) $Snapshot.counters 'Complete ancestor counter identity/values differ from actual semantic XML'
    foreach($map in @($Snapshot.classes,$Snapshot.testClasses,$Snapshot.dependencies)){Require (@($map.Values|Where-Object {$_-cnotmatch'^[0-9A-F]{64}$'}).Count-eq0) 'Invalid code/dependency SHA256'}
    Require ($Snapshot.entries.Count-gt0-and@($Snapshot.entries|Where-Object {$_.sha256-cnotmatch'^[0-9A-F]{64}$'-or$_.bytes-lt0}).Count-eq0-and@($Snapshot.rawMetadata|Where-Object {$_.sha256-cnotmatch'^[0-9A-F]{64}$'}).Count-eq0) 'Portable SHA256 entry schema required'
    if($Reference){foreach($key in 'classes','testClasses','dependencies','entries','tests','counters','coverageSemantics','jarSha256'){Same $Snapshot[$key] $Reference[$key] "Frozen complete HOBL evidence changed: $key"}}
}
function AssertHoblTestExecution([string]$Log,[xml]$Report,[xml]$Properties,$Exec,$Context,[ValidateSet('default','candidate')][string]$Arm){
    $scope=if($Arm-eq'candidate'){'org.springframework.samples.petclinic.*'}else{'*'}
    $agent=[regex]::Matches($Log,'(?m)^.*?argLine set to ([^\r\n]+)')
    Require ($agent.Count-eq1-and$agent[0].Value-match'org\.jacoco\.agent-0\.8\.13-runtime\.jar='-and$agent[0].Value.Contains("includes=$scope")-and$agent[0].Value-notmatch'excludes=|exec=false|StartFlightRecording|TieredStopAtLevel') 'Wrong prepared0.8.13 agent/scope; not OS argv'
    $binding=[regex]::Match($agent[0].Groups[1].Value.Trim().Trim('"'),'^-javaagent:.+org\.jacoco\.agent-0\.8\.13-runtime\.jar=(.+)$');Require $binding.Success 'One complete agent declaration'
    Require (([regex]::Matches($agent[0].Groups[1].Value,'-javaagent:')).Count-eq1) 'Exactly one prepared agent required'
    $opts=@{};foreach($option in $binding.Groups[1].Value.Split(',')){$p=$option.Split('=',2);Require ($p.Count-eq2-and$p[0]-cin@('destfile','includes')-and-not$opts.ContainsKey($p[0])) 'Unknown/duplicate agent option';$opts[$p[0]]=$p[1]}
    Require ($opts.Count-eq2-and$opts.includes-ceq$scope-and$opts.destfile.Replace('\\','\').Replace('\','/')-ceq$Context.execPath.Replace('\','/')) 'Exact destination and includes required'
    Require ($Exec.sha256-cmatch'^[0-9A-F]{64}$'-and$Exec.records-gt$Exec.externalRecords-and$(if($Arm-eq'candidate'){$Exec.externalRecords-eq0}else{$Exec.externalRecords-gt0})) 'Observed app/exec scope required'
    $sessions=@($Report.SelectNodes('/report/sessioninfo'));Require ($sessions.Count-eq1) 'One report session'
    $s=$sessions[0];Require ($s.id-ceq$Exec.session[0]-and[long]$s.start-eq$Exec.session[1]-and[long]$s.dump-eq$Exec.session[2]-and[long]$s.start-ge$Context.startMs-and[long]$s.dump-le$Context.endMs-and[long]$s.dump-ge[long]$s.start-and$s.id-cnotin$Context.seenSessions) 'Fresh exec/report bounds required'
    $witness=@([regex]::Matches($Log,'Starting .*? with PID (\d+)')|ForEach-Object {$_.Groups[1].Value}|Sort-Object -Unique)
    Require ($witness.Count-eq1-and$witness[0]-match'^[1-9][0-9]*$'-and$witness[0]-notin$Context.seenPids) 'One fresh reported PID required'
    foreach($pair in @(@('java.home',$Context.javaHome),@('java.vendor','Microsoft'),@('java.runtime.version','25.0.5.0.2+1-LTS'),@('os.arch','aarch64'))){$values=@($Properties.SelectNodes("//property[@name='$($pair[0])']")|ForEach-Object {$_.value}|Sort-Object -Unique);Require ($values.Count-eq1-and$values[0]-ceq$pair[1]) 'Actual native test runtime differs'}
    return @{reportedPid=$witness[0];session=@{id=$s.id;start=[long]$s.start;dump=[long]$s.dump};preparedAgent=$agent[0].Groups[1].Value;osArgvObserved=$false}
}
Export-ModuleMember -Function AssertHoblTrialPom,ReadHoblTrialContext,AssertHoblTrialSource,RestoreHoblTrialFiles,GetHoblContractEnvironment,RestoreHoblContractEnvironment,AssertHoblSnapshot,AssertHoblTestExecution
