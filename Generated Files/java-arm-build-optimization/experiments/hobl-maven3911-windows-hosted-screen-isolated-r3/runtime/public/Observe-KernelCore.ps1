param([string]$Prefix,[string]$Expected,[string]$Project)
$ErrorActionPreference='Stop'
[IO.File]::WriteAllText($Prefix+'.observer-ready','ready')
$watch=[Diagnostics.Stopwatch]::StartNew();$seen=$null
while($watch.Elapsed.TotalSeconds-lt180){
    if(Test-Path ($Prefix+'.observer-parent')){
        $parentId=[int][IO.File]::ReadAllText($Prefix+'.observer-parent')
        $rows=@(Get-CimInstance Win32_Process -Filter "Name='pwsh.exe' OR Name='powershell.exe'")
        foreach($row in $rows){
            if($row.ProcessId-eq$PID-or-not$row.CommandLine-or-not$row.CommandLine.Contains($Project)){continue}
            $ancestor=$row.ParentProcessId;$belongs=$false
            for($i=0;$i-lt4-and$ancestor;$i++){if($ancestor-eq$parentId){$belongs=$true;break};$p=Get-CimInstance Win32_Process -Filter "ProcessId=$ancestor";$ancestor=$p.ParentProcessId}
            if($belongs){$seen=@{observed=$true;pid=$row.ProcessId;parentPid=$parentId;created=$row.CreationDate.ToString('o');executable=$row.ExecutablePath;matchesExpected=[string]::Equals($row.ExecutablePath,$Expected,[StringComparison]::OrdinalIgnoreCase)};break}
        }
    }
    if($seen-or(Test-Path ($Prefix+'.observer-done'))){break}
    Start-Sleep -Milliseconds 10
}
if(-not$seen){$seen=@{observed=$false;matchesExpected=$false;reason='Missed ordinary owned-child observation; HOLD'}}
$seen|ConvertTo-Json|Set-Content ($Prefix+'.core-witness.json')
