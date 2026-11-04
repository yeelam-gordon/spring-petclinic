function New-H3911SyntheticFixtures([string]$RepositorySource,[string]$OutputDirectory){
    $git=(Get-Command git -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
    $names=if($IsWindows){@('python','python3')}else{@('python3','python')}
    $python=@($names|ForEach-Object{Get-Command $_ -CommandType Application -ErrorAction SilentlyContinue}|Where-Object Source -NotLike '*WindowsApps*'|Select-Object -First 1).Source
    if(-not$python){throw 'Existing Python3 application required; no install performed'}
    & $python (Join-Path $PSScriptRoot 'Make-SyntheticFixtures.py') --git $git --repository $RepositorySource --output $OutputDirectory
    if($LASTEXITCODE-ne0){throw 'Synthetic fixture factory failed'}
    Get-Content (Join-Path $OutputDirectory 'fixture-inputs.json') -Raw|ConvertFrom-Json
}
Export-ModuleMember -Function New-H3911SyntheticFixtures
