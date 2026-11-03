[CmdletBinding()]
param([ValidateSet('Jdk','Execute')][string]$Stage='Execute',[ValidateSet('Windows','MacOS')][string]$Platform,
    [string]$OwnedDirectory,[string]$JdkPath=$env:JAVA_HOME,[switch]$PlanOnly,[switch]$LibraryOnly)
$ErrorActionPreference='Stop'
$controllerRoot=$PSScriptRoot
$requested=@{Stage=$Stage;Platform=$Platform;OwnedDirectory=$OwnedDirectory;JdkPath=$JdkPath;PlanOnly=[bool]$PlanOnly;LibraryOnly=[bool]$LibraryOnly}
. (Join-Path $controllerRoot 'Invoke-MatchedComparison.ps1') -LibraryOnly
foreach($item in $requested.GetEnumerator()){Set-Variable $item.Key $item.Value}
function MixedHostedPins([string]$Os) {
    $windows=$Os-ceq'Windows'
    @{jdk="microsoft-jdk-17.0.21.0.2-$(if($windows){'windows-aarch64.zip'}else{'macos-aarch64.tar.gz'})";jdkHash=$(if($windows){'2C0E7679022F1666DA64B586F9941E86481C6F369212E918BE3E505581085336'}else{'6BC0241428F9485A3AA8FCF606C8395C24A5FF0F6D5E9DAE2C70EAE410A3F5F3'});flavor=$(if($windows){'windows-amd64'}else{'darwin-aarch64'});vendorHash=$(if($windows){'4DD97B1F26525055CEC960FB5B953B70D1E6606F96F5B096EFA932754FD3E9D0238E00CA97779368F29CB751F1776445C45DA618EA8D0D84692C3B936087309F'}else{'CC2887379788BFB54067DEE4F1E9E570624BE0BE6A73025CC59E24D3EE2525CC23D27FC33A58838A0F1A24CB75600FB0CD0AF3F730E70C2DA3660A9F6BF7DF3E'})}
}
function MixedHostedDownload($Url,$Path) {Invoke-WebRequest $Url -OutFile $Path}
function MixedHostedNative($File,$Arguments,$Log) {InvokePortableProcess $File $Arguments $Log}
function MixedHostedHash($Path,$Algorithm='SHA256') {(Get-FileHash $Path -Algorithm $Algorithm).Hash}
function MixedHostedUnzip($Path,$Destination) {Expand-Archive $Path $Destination}
function MixedHostedHost {
    $record=@{platform=$(if($IsWindows){'Windows'}elseif($IsMacOS){'MacOS'}else{'unsupported'});os=[Runtime.InteropServices.RuntimeInformation]::OSDescription;osArchitecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();processArchitecture=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString();logicalProcessors=[Environment]::ProcessorCount;imageOS=$env:ImageOS;imageVersion=$env:ImageVersion;cpu='UNKNOWN';memory='UNKNOWN';filesystem='UNKNOWN'}
    try{if($IsWindows){$record.cpu=@(Get-CimInstance Win32_Processor|Select-Object Name,NumberOfCores,NumberOfLogicalProcessors);$record.memory=(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory}else{$record.cpu=(& sysctl -n machdep.cpu.brand_string);if($LASTEXITCODE){$record.cpu='UNKNOWN'};$record.memory=(& sysctl -n hw.memsize);if($LASTEXITCODE){$record.memory='UNKNOWN'}}}catch{$record.hardwareError=$_.ToString()}
    try{$record.filesystem=[IO.DriveInfo]::new([IO.Path]::GetPathRoot((Get-Location).Path)).DriveFormat}catch{$record.filesystem='UNKNOWN'}
    if($null-eq$record.memory){$record.memory='UNKNOWN'};if(-not$record.cpu){$record.cpu='UNKNOWN'}
    $record.powershell=$PSVersionTable.PSVersion.ToString();$record.dotnet=[Environment]::Version.ToString()
    return $record
}
function AssertMixedHostedHash($Path,$Expected,$Setup,$Algorithm='SHA256') {
    $actual=MixedHostedHash $Path $Algorithm
    @{path=$Path;expected=$Expected;actual=$actual;algorithm=$Algorithm}|ConvertTo-Json|Set-Content (Join-Path $Setup ((Split-Path $Path -Leaf)+".$Algorithm.hash.json"))
    if($actual-cne$Expected){$bad=Join-Path $Setup 'mismatched-bytes';New-Item $bad -ItemType Directory -Force|Out-Null;Copy-Item $Path (Join-Path $bad (Split-Path $Path -Leaf));throw 'Hosted checksum mismatch; actual bytes retained'}
}
function AssertMixedHostedPayload($Root,$Setup) {
    Copy-Item (Join-Path $Root 'mixed-payload-sha256.json') (Join-Path $Setup 'payload-manifest-actual.json')
    $manifest=Get-Content (Join-Path $Root 'mixed-payload-sha256.json') -Raw|ConvertFrom-Json
    Same @($manifest.file|Sort-Object) @(@('Invoke-MatchedComparison.ps1','Test-MatchedComparison.ps1','Test-MixedClientPackage.ps1','Fixture-MixedProcess.ps1','Invoke-MixedHosted.ps1','Test-MixedHosted.ps1','mixed-client-package.workflow.yml','.gitattributes')|Sort-Object) 'Payload allowlist differs'
    foreach($row in $manifest){
        Same @($row.PSObject.Properties.Name|Sort-Object) @('file','sha256') 'Payload manifest fields differ'
        Require (($row.file-ceq'.gitattributes'-or$row.file-cmatch'^[A-Za-z0-9][A-Za-z0-9.-]+$')-and$row.file-notin@('.','..')) 'Unsafe payload manifest path'
        $path=Join-Path $Root $row.file;$actual=Join-Path $Setup 'payload-actual';New-Item $actual -ItemType Directory -Force|Out-Null
        Copy-Item $path (Join-Path $actual $row.file)
        AssertMixedHostedHash $path $row.sha256 $Setup
    }
}
function InvokeMixedHosted([string]$Stage,[string]$Os,[string]$Owned,[string]$Jdk,[switch]$OnlyPlan) {
    $windows=$Os-ceq'Windows';$names=@('JAVA_HOME','PATH','MAVEN_OPTS','MAVEN_ARGS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','MAVEN_SKIP_RC','JAVACMD','MAVEN_USER_HOME','MVNW_PREFER_PWSH','MVND_CLIENT','MVND_HOME','MVND_DAEMON_STORAGE','MVND_OPTS','MVND_JVM_ARGS','TMP','TEMP')
    $before=PortableEnvironmentSnapshot;$cwd=(Get-Location).Path
    $setup=Join-Path $Owned 'setup-evidence';New-Item $setup -ItemType Directory -Force|Out-Null
    $record=@{status='RUNNING';stage=$Stage;platform=$Os;payloadCommit=$env:GITHUB_SHA;repository=$env:GITHUB_REPOSITORY;ref=$env:GITHUB_REF;attempt=$env:GITHUB_RUN_ATTEMPT;run=$env:GITHUB_RUN_ID;nativeCalls=@()}
    try{
        AssertMixedHostedPayload $controllerRoot $setup
        $record.host=MixedHostedHost
        Require ($record.host.platform-ceq$Os-and$record.host.osArchitecture-ceq'Arm64') 'Hosted platform/ARM64 admission failed'
        $pins=MixedHostedPins $Os
        if($Stage-eq'Jdk'){
            $archive=Join-Path $Owned $pins.jdk;MixedHostedDownload "https://aka.ms/download-jdk/$($pins.jdk)" $archive
            AssertMixedHostedHash $archive $pins.jdkHash $setup
            "jdkFile=$archive"|Add-Content $env:GITHUB_OUTPUT;'javaVersion=17.0.21'|Add-Content $env:GITHUB_OUTPUT
        }else{
            $original=[Environment]::GetEnvironmentVariable('MAVEN_OPTS','Process')
            Require ([string]::IsNullOrEmpty($original)-or($windows-and$original-ceq'-Xms256m')) 'Unknown hosted MAVEN_OPTS'
            Remove-Item Env:MAVEN_OPTS -ErrorAction SilentlyContinue
            $record.hostedMavenOpts=@{originalLength=([string]$original).Length;recognizedWindowsDefault=($original-ceq'-Xms256m')}
            Require (Test-Path $Jdk -PathType Container) 'Selected JDK missing'
            $project=Join-Path $Owned 'project';$driver=Join-Path $Owned 'driver';$output=Join-Path $Owned 'evidence';$cache=Join-Path $Owned 'm2'
            foreach($fresh in $project,$driver,$output,$cache){Require (-not(Test-Path $fresh)) 'Fresh hosted experiment paths required'}
            $archive=Join-Path $Owned 'vendor.zip';MixedHostedDownload "https://archive.apache.org/dist/maven/mvnd/1.0.6/maven-mvnd-1.0.6-$($pins.flavor).zip" $archive
            AssertMixedHostedHash $archive $pins.vendorHash $setup SHA512;MixedHostedUnzip $archive $driver
            if($windows){AssertMixedHostedHash $archive 'CABA9E00736B8C0C62B9238EE75BC64294A0DF42E45ECD513FEE1914DA3FD6CF' $setup}
            $driverHome=Join-Path $driver "maven-mvnd-1.0.6-$($pins.flavor)"
            if($windows){
                AssertMixedHostedHash (Join-Path $driverHome 'bin/mvnd.exe') '386B03C8DF458D8573B9241259EEBFABA894B32DDF8D0767C8CAE6168F81FAD4' $setup
                Require ((MixedBinaryIdentity (Join-Path $driverHome 'bin/mvnd.exe')).machine-eq0x8664) 'Hosted frontend not PE8664'
                $vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
                $vslog=Join-Path $setup 'compiler-discovery.log';NativeCode (MixedHostedNative $vswhere @('-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.ARM64','-property','installationPath') $vslog) 'ARM compiler discovery'
                $vs=(Get-Content $vslog -Raw).Trim();Require $vs 'ARM compiler unavailable; no install fallback'
                $native=Join-Path $Owned 'native';New-Item $native -ItemType Directory|Out-Null
                $hashes=@{c='31198B329118419DB30A8178FB438F44953B33F346C30E1BF313DF2F4E6A021E';h='E12BE1E39BB5FD0755B87D151D91712D9606D1118B1F6CCAB6BC2CB0857AA9DF'}
                foreach($ext in 'c','h'){$path=Join-Path $native "mvndnative.$ext";MixedHostedDownload "https://raw.githubusercontent.com/apache/maven-mvnd/e0df65807439de579e16632881cf4be14b5a3cca/native/src/main/native/mvndnative.$ext" $path;AssertMixedHostedHash $path $hashes[$ext] $setup;Copy-Item $path $setup}
                $dll=Join-Path $native 'mvndnative.dll'
                $command="call `"$vs\VC\Auxiliary\Build\vcvarsall.bat`" arm64 >nul && where cl && cl /Bv /nologo /LD /O2 /MD /I`"$Jdk\include`" /I`"$Jdk\include\win32`" /Fo`"$native\mvndnative.obj`" `"$native\mvndnative.c`" /link /MACHINE:ARM64 /OUT:`"$dll`" /IMPLIB:`"$native\mvndnative.lib`""
                NativeCode (MixedHostedNative $env:ComSpec @('/d','/c',$command) (Join-Path $setup 'native-compile.log')) 'ARM JNI compile'
                Require ((MixedBinaryIdentity $dll).machine-eq0xAA64) 'Compiled hosted JNI not ARM64'
                $record.compiledJni=@{path=$dll;sha256=(MixedHostedHash $dll)}
                $jar=[IO.Compression.ZipFile]::Open((Join-Path $driverHome 'mvn/lib/mvnd/mvnd-native-1.0.6.jar'),[IO.Compression.ZipArchiveMode]::Update)
                try{$resource='org/mvndaemon/mvnd/nativ/Windows/arm64/mvndnative.dll';Require (-not$jar.GetEntry($resource)) 'Unexpected existing ARM JNI resource';[IO.Compression.ZipFileExtensions]::CreateEntryFromFile($jar,$dll,$resource)|Out-Null}finally{$jar.Dispose()}
            }else{
                NativeCode (MixedHostedNative 'chmod' @('+x',(Join-Path $driverHome 'bin/mvnd'),(Join-Path $driverHome 'mvn/bin/mvn')) (Join-Path $setup 'permissions.log')) 'Mac driver permissions'
            }
            NativeCode (MixedHostedNative 'git' @('-c','core.autocrlf=false','clone','https://github.com/spring-projects/spring-petclinic.git',$project) (Join-Path $setup 'clone.log')) 'Fresh full project clone'
            NativeCode (MixedHostedNative 'git' @('-C',$project,'-c','core.autocrlf=false','checkout','--detach','500158f732419217507c7656904b8e6aa1bcc0d6') (Join-Path $setup 'checkout.log')) 'Pinned project checkout'
            $arguments=@{ProjectFullClone=$project;JavaHome=$Jdk;MvndHome=$driverHome;LocalCache=$cache;OutputDirectory=$output;Comparison='MixedClientPackage';Workload='current17';Platform=$Os;Samples=3;LoopbackTests=$true;ExclusiveSlotApproved=$true}
            if($OnlyPlan){$arguments.PlanOnly=$true}
            $record.collectorArguments=$arguments
            & (Join-Path $controllerRoot 'Invoke-MatchedComparison.ps1') @arguments|Set-Content (Join-Path $setup 'collector-entrypoint-output.log')
            if(-not$OnlyPlan){
                $actual=Get-Content (Join-Path $output 'result.json') -Raw|ConvertFrom-Json
                Require ($actual.status-ceq'PASS') 'Collector did not settle PASS'
                if($windows){Require ($actual.loadedNative.sha256-ceq$record.compiledJni.sha256) 'Loaded ARM JNI differs from freshly compiled hosted DLL'}
            }
        }
        $record.status='PASS'
    }catch{$record.status='FAIL';$record.error=$_.ToString();throw}
    finally{
        Set-Location $cwd;$record.restoration=RestorePortableEnvironment $before $names;$record.restoration.cwdEqual=(Get-Location).Path-eq$cwd
        if(-not$record.restoration.restored-or-not$record.restoration.cwdEqual){$record.status='FAIL'}
        $record|ConvertTo-Json -Depth 20|Set-Content (Join-Path $setup "$Stage-result.json") -Encoding utf8
        Require ($record.restoration.restored-and$record.restoration.cwdEqual) 'Hosted18-state/cwd restoration failed'
    }
}
if($LibraryOnly){return}
InvokeMixedHosted $Stage $Platform $OwnedDirectory $JdkPath -OnlyPlan:$PlanOnly
