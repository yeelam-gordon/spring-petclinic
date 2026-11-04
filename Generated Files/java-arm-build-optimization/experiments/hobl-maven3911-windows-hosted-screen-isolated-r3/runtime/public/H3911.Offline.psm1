Import-Module (Join-Path $PSScriptRoot 'H3911.Helpers.psm1') -Scope Local -DisableNameChecking
function Assert-H3911OfflineDelta($Online,[string]$OnlineDirectory,$Offline,[string]$OfflineDirectory){
    $reviewed=$Online.schema-ceq'reviewed-A41-online-v1'-and$Offline.schema-ceq'reviewed-A41-offline-v1'
    $mac=$Online.schema-ceq'mac-original-A41-online-v1'-and$Offline.schema-ceq'mac-original-A41-offline-v1'
    Assert-H3911 ($reviewed-or$mac) 'Typed online/offline contract required'
    $drop=@('META-INF/sbom/','META-INF/sbom/application.cdx.json')
    $expected=@($Online.entries|Where-Object{$_.name-cnotin$drop-and$_.name-cne'META-INF/MANIFEST.MF'})
    $actual=@($Offline.entries|Where-Object{$_.name-cne'META-INF/MANIFEST.MF'})
    $onlineLoose=@($Online.loose|Where-Object{-not($_.scope-ceq'classes'-and$_.name-ceq'META-INF/sbom/application.cdx.json')})
    Assert-H3911 ([string]::Equals((ConvertTo-H3911Json $expected),(ConvertTo-H3911Json $actual),[StringComparison]::Ordinal)-and[string]::Equals((ConvertTo-H3911Json $onlineLoose),(ConvertTo-H3911Json $Offline.loose),[StringComparison]::Ordinal)) 'Unexpected offline payload/resource/inventory delta'
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $on=$utf8.GetString([IO.File]::ReadAllBytes((Join-Path $OnlineDirectory '01.raw')));$off=$utf8.GetString([IO.File]::ReadAllBytes((Join-Path $OfflineDirectory '01.raw')))
    foreach($line in 'Sbom-Location: META-INF/sbom/application.cdx.json','Sbom-Format: CycloneDX'){
        $pattern='(?m)^'+[regex]::Escape($line)+'\r?\n';Assert-H3911 ([regex]::Matches($on,$pattern).Count-eq1) 'Exact online SBOM header required';$on=[regex]::Replace($on,$pattern,'')
    }
    Assert-H3911 ([string]::Equals($on,$off,[StringComparison]::Ordinal)-and$off-notmatch'(?m)^Sbom-') 'Unexpected offline manifest delta'
    foreach($role in $Offline.raw|Where-Object entry -cne 'META-INF/MANIFEST.MF'){$reference=@($Online.raw|Where-Object entry -ceq $role.entry);Assert-H3911 ($reference.Count-eq1-and$reference[0].sha256-ceq$role.sha256-and$reference[0].bytes-eq$role.bytes) 'Unexpected offline raw metadata delta'}
}
Export-ModuleMember -Function Assert-H3911OfflineDelta
