if($env:MIXED_DIRECT_RECORD){
    $tokens=@(for($i=1;$i-le[int]$env:DIRECT_TOKEN_COUNT;$i++){[Environment]::GetEnvironmentVariable("DIRECT_TOKEN_$i",'Process')})
    ConvertTo-Json -InputObject $tokens -Compress|Set-Content $env:MIXED_DIRECT_RECORD
    exit ([int]$env:MIXED_DIRECT_EXIT)
}
$case=$env:MIXED_CASE;$tokens=$env:MIXED_TOKENS|ConvertFrom-Json
$alive=Join-Path $env:MIXED_FIXTURE 'alive';$owner=Join-Path $env:MIXED_FIXTURE 'owner-created';$registryFile=Join-Path $env:MIXED_REGISTRY 'registry.bin'
@{arguments=$tokens;mode=$env:MVND_CLIENT}|ConvertTo-Json -Compress|Add-Content (Join-Path $env:MIXED_FIXTURE 'argv.jsonl')
if($case-eq'process-fail'-and'clean'-cin$tokens){exit 1}
if('--stop'-cin$tokens){if($case-eq'stop-fail'-and$env:MVND_CLIENT-eq'native'){exit 1};Remove-Item $alive -ErrorAction SilentlyContinue;[IO.File]::WriteAllBytes($registryFile,[byte[]]@(0,0,0,0));exit 0}
[IO.File]::WriteAllText($alive,'synthetic')
[IO.File]::WriteAllText($owner,'synthetic')
$stream=[IO.MemoryStream]::new()
$writer=[IO.BinaryWriter]::new($stream)
$writer.Write([byte[]]@(0,0,0,1))
foreach($value in @('abcdef12',$env:JAVA_HOME,$env:MVND_HOME)){$bytes=[Text.Encoding]::UTF8.GetBytes($value);$writer.Write([byte[]]@([byte]($bytes.Length-shr8),[byte]($bytes.Length-band255)));$writer.Write($bytes)}
$writer.Write([byte[]]@(0,0,48,57));$writer.Flush();[IO.File]::WriteAllBytes($registryFile,$stream.ToArray());$writer.Dispose()
$output=@($tokens|Where-Object{$_-like'-Doutput=*'})
if($output.Count){
    $path=$output[0].Substring(9);$value=if('-Dexpression=os.arch'-cin$tokens){'aarch64'}else{$env:JAVA_HOME}
    if($case-eq'wrong-context'){$value='wrong'}
    if($case-eq'empty-context'){$value=''}
    [IO.File]::WriteAllText($path,$value)
}
if('verify'-cin$tokens){
    $number=[int]$env:MIXED_VERIFY;$now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $directory=Join-Path $env:MIXED_PROJECT 'site';$reports=Join-Path $env:MIXED_PROJECT 'target/surefire-reports';$coverage=Join-Path $env:MIXED_PROJECT 'target/site/jacoco'
    New-Item $directory,$reports,$coverage -ItemType Directory -Force|Out-Null
    [IO.File]::WriteAllText((Join-Path $directory 'coverage.xml'),"<report><sessioninfo id='session$number' start='$now' dump='$now'/></report>")
    [IO.File]::WriteAllText((Join-Path $reports 'TEST-synthetic.xml'),'<testsuite/>')
    Copy-Item (Join-Path $directory 'coverage.xml') (Join-Path $coverage 'jacoco.xml')
    [IO.File]::WriteAllBytes((Join-Path $env:MIXED_PROJECT 'target/jacoco.exec'),[byte[]]@(1))
    Write-Output "Starting SYNTHETIC with PID $number"
}
exit 0
