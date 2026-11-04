function New-SyntheticMacTargets([string]$RepositorySource,[string]$OutputRoot){
    if(-not[IO.Path]::IsPathFullyQualified($RepositorySource)-or-not[IO.Path]::IsPathFullyQualified($OutputRoot)-or(Test-Path $OutputRoot)){throw 'Absolute repository/fresh fixture root required'}
    $git=(Get-Command git -CommandType Application|Select-Object -First 1).Source
    & python (Join-Path $PSScriptRoot 'Make-SyntheticFixtures.py') --git $git --repository $RepositorySource --output $OutputRoot
    if($LASTEXITCODE){throw 'Existing hermetic generator failed'}
    $target=Join-Path $OutputRoot 'clean\target';$path=Join-Path $target 'surefire-reports\TEST-synthetic.xml'
    $xml=[xml](Get-Content $path -Raw);$xml.testsuite.SetAttribute('name','ModelTest0')
    foreach($test in $xml.SelectNodes('/testsuite/testcase')){$test.SetAttribute('classname','ModelTest0')}
    $to=Join-Path $target 'surefire-reports\TEST-ModelTest0.xml';$xml.Save($to);Remove-Item $path
    [IO.File]::WriteAllText((Join-Path $target 'surefire-reports\ModelTest0.txt'),'SYNTHETIC_TEST_DATA_NOT_NATIVE')
    [IO.File]::WriteAllText((Join-Path $target 'site\jacoco\index.html'),'<html>SYNTHETIC_TEST_DATA_NOT_NATIVE</html>')
    New-Item (Join-Path $OutputRoot 'offline-projects') -ItemType Directory|Out-Null;$offline=@{};$i=0
    foreach($route in 'A','B','A','B','B','A','A','B'){$i++;$label=if($i-le2){"warmup-$i-$route"}else{"sample-$i-$route"};$dest=Join-Path $OutputRoot ('offline-projects\'+$label);Copy-Item (Join-Path $OutputRoot 'clean-offline') $dest -Recurse -Force;$offline[$label]=$dest}
    @{marker='SYNTHETIC_TEST_DATA_NOT_NATIVE';generator='Make-SyntheticFixtures.py';origin='Generated parser-contract bytes, never recovered Mac XML/classes/dependencies; clean Git property is an explicit synthetic model';javaExecuted=$false;compiledJava=$false;nativeAuthority=$false;online='clean';offlineLabels=@($offline.Keys)}|ConvertTo-Json|Set-Content (Join-Path $OutputRoot 'SYNTHETIC_TEST_DATA_NOT_NATIVE.json')
    @{root=$OutputRoot;onlineProject=(Join-Path $OutputRoot 'clean');offlineProjects=$offline}
}
function Write-SyntheticProcessReceipt([string]$Log,[string]$Exe,[string[]]$Tokens,[string]$WorkingDirectory,[int]$Identity,[double]$Seconds=1.0,[string]$Text='SYNTHETIC_TEST_DATA_NOT_NATIVE'){
    New-Item (Split-Path $Log) -ItemType Directory -Force|Out-Null
    [IO.File]::WriteAllText($Log,$Text);[IO.File]::WriteAllText(($Log+'.stderr'),'')
    @{platform='Posix';validClock=$true;exitConfirmed=$true;exit=0;stdoutComplete=$true;stderrComplete=$true;timeout=$false;killRequested=$false;failure=$null;terminationError=$null;pid=$Identity;createdUtc=[DateTimeOffset]::UtcNow.ToString('o');exe=$Exe;arguments=$Tokens;workingDirectory=$WorkingDirectory;elapsedSeconds=$Seconds;clockBoundary='immediately before Process.Start through normal WaitForExit';transport='direct executable / ArgumentList / no shell';stdoutBytes=(Get-Item $Log).Length;stderrBytes=0;stdoutSha256=(Get-FileHash $Log).Hash;stderrSha256=(Get-FileHash ($Log+'.stderr')).Hash;fixtureOnly=$true;provenance='SYNTHETIC_TEST_DATA_NOT_NATIVE'}|ConvertTo-Json -Depth 8|Set-Content ($Log+'.process.json')
}
function Save-SyntheticFullCapture($Commands,[string]$RuntimeRoot,[string]$TargetProject,$Context,[string]$Phase,$Call){
    $target=Join-Path $TargetProject 'target';$report=Join-Path $target 'surefire-reports\TEST-ModelTest0.xml';$xml=[xml](Get-Content $report -Raw)
    $xml.SelectSingleNode("//property[@name='java.home']").SetAttribute('value',$Context.Jdk);$xml.Save($report)
    $id=if($Phase-ceq'baseline-verify'){'A'}else{'B'}
    $coveragePath=Join-Path $target 'site\jacoco\jacoco.xml';$coverage=[xml](Get-Content $coveragePath -Raw);$session=$coverage.SelectSingleNode('/report/sessioninfo')
    $session.SetAttribute('id',$id);$session.SetAttribute('start',[string]$Call.start);$session.SetAttribute('dump',[string]$Call.end);$coverage.Save($coveragePath)
    $execPath=Join-Path $target 'jacoco.exec';$bytes=[IO.File]::ReadAllBytes($execPath);$bytes[8]=[byte][char]$id
    foreach($pair in @(@(9,[long]$Call.start),@(17,[long]$Call.end))){$value=[BitConverter]::GetBytes([long]$pair[1]);if([BitConverter]::IsLittleEndian){[Array]::Reverse($value)};[Array]::Copy($value,0,$bytes,[int]$pair[0],8)}
    [IO.File]::WriteAllBytes($execPath,$bytes)
    $captureContext=@{Project=$TargetProject;Output=$Context.Output;SourceProfile='MacOriginalWrapper';Jdk=$Context.Jdk}
    $saved=& $Commands['Save-H3911Verify'] $captureContext $Phase $Call
    $mq=Import-Module (Join-Path $RuntimeRoot 'H3911.MacQualifier.psm1') -PassThru -DisableNameChecking
    $witness=& $mq {Get-Command New-MQReportByteWitness -CommandType Function}
    $saved.reportBytes=& $witness (Join-Path $Context.Output $Phase) $Phase
    $saved
}
