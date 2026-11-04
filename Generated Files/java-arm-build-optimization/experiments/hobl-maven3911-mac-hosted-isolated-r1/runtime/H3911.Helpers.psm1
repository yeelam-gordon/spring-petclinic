function Assert-H3911($Value,[string]$Message){if(-not$Value){throw $Message}}
function ConvertTo-H3911Json($Value){ConvertTo-Json -InputObject $Value -Depth 40 -Compress -WarningAction Stop}
function Require($Condition,[string]$Message){Assert-H3911 $Condition $Message}
function Json($Value){ConvertTo-H3911Json $Value}
function HashBytes([byte[]]$Bytes){[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))}
function StreamBytes($Entry,[bool]$AllowEmpty=$false){
    $stream=$Entry.Open();$memory=[IO.MemoryStream]::new()
    try{$stream.CopyTo($memory);$bytes=$memory.ToArray()}finally{$stream.Dispose();$memory.Dispose()}
    Require (($AllowEmpty -or $bytes.Length-gt0) -and $bytes.Length-eq$Entry.Length) 'Empty/truncated required ZIP entry'
    return ,$bytes
}
function CoverageKeys([xml]$Xml){
    $map=[ordered]@{}
    foreach($counter in $Xml.SelectNodes('//counter')){
        $parts=@();$node=$counter.ParentNode
        while($node -and $node.NodeType-eq[Xml.XmlNodeType]::Element){
            $attributes=[ordered]@{};foreach($a in @($node.Attributes|Sort-Object Name)){$attributes[$a.Name]=$a.Value}
            $parts=@(@{element=$node.LocalName;attributes=$attributes})+$parts;$node=$node.ParentNode
        }
        $key=Json @{ancestors=$parts;type=$counter.GetAttribute('type')}
        Require (-not$map.Contains($key)) 'Duplicate complete coverage identity'
        $map[$key]="$($counter.GetAttribute('missed'))/$($counter.GetAttribute('covered'))"
    }
    return $map
}
function CoverageSemantics([xml]$Xml){
    $copy=$Xml.CloneNode($true)
    foreach($session in @($copy.SelectNodes('/report/sessioninfo'))){$null=$session.ParentNode.RemoveChild($session)}
    return $copy.OuterXml
}
function TestKeys([xml[]]$Reports){
    $rows=@(foreach($xml in $Reports){foreach($test in $xml.SelectNodes('//testcase')){
        $state=if($test.SelectSingleNode('failure')){'failure'}elseif($test.SelectSingleNode('error')){'error'}elseif($test.SelectSingleNode('skipped')){'skipped'}else{'passed'}
        @{class=$test.GetAttribute('classname');name=$test.GetAttribute('name');state=$state}
    }})
    $identities=@($rows|ForEach-Object {Json @($_.class,$_.name)})
    Require (@($identities|Group-Object|Where-Object Count -gt 1).Count-eq0) 'Duplicate recursive test identity'
    return @($rows|Sort-Object class,name,state)
}
function JacocoScopeArguments([string]$Arm) {
    $scope=switch($Arm){'default'{'*'}'candidate'{'org.springframework.samples.petclinic.*'}default{throw 'Unsupported JaCoCo arm'}}
    return "-Djacoco.instrumentation.includes=$scope"
}
function JacocoExecEvidence([byte[]]$Data,[string]$Arm) {
    $null=JacocoScopeArguments $Arm
    $memory=[IO.MemoryStream]::new($Data);$reader=[IO.BinaryReader]::new($memory)
    function Take([int]$Count){$bytes=$reader.ReadBytes($Count);Require ($bytes.Length-eq$Count) 'Truncated JaCoCo exec';return ,$bytes}
    function Utf(){ $n=([int]$reader.ReadByte()-shl8)-bor[int]$reader.ReadByte();return [Text.UTF8Encoding]::new($false,$true).GetString((Take $n)) }
    function Long(){ $bytes=Take 8;[Array]::Reverse($bytes);return [BitConverter]::ToInt64($bytes,0) }
    $headers=0;$sessions=@();$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    try{
        Require ($memory.Length-ge5) 'Truncated JaCoCo exec header'
        Require ($reader.ReadByte()-eq1) 'JaCoCo exec header must be first'
        Require ([Convert]::ToHexString((Take 4))-ceq'C0C01007') 'Unsupported JaCoCo exec header'
        $headers=1
        while($memory.Position-lt$memory.Length){
            switch($reader.ReadByte()){
                1 {throw 'Unexpected later JaCoCo exec header'}
                16 {$sessions+=@{id=(Utf);start=(Long);dump=(Long)}}
                17 {
                    $null=Take 8;$name=Utf;Require ($names.Add($name)) 'Duplicate JaCoCo execution class'
                    $length=0;$shift=0
                    do{$value=$reader.ReadByte();Require ($shift-le28) 'Invalid JaCoCo probe count';$length=$length-bor(($value-band127)-shl$shift);$shift+=7}while($value-band128)
                    Require ($length-ge0) 'Invalid JaCoCo probe count';$null=Take ([int][math]::Ceiling($length/8.0))
                }
                default {throw 'Unknown JaCoCo exec block'}
            }
        }
        Require ($headers-eq1 -and $sessions.Count-eq1 -and $names.Count-gt0) 'One populated JaCoCo execution session required'
        $outside=@($names|Where-Object {-not$_.StartsWith('org/springframework/samples/petclinic/',[StringComparison]::Ordinal)}).Count
        Require ($names.Count-gt$outside) 'No application execution records'
        if($Arm-eq'candidate'){Require ($outside-eq0) 'Candidate execution records outside app prefix'}
        else{Require ($outside-gt0) 'Default external execution records not observed'}
        return @{arm=$Arm;session=$sessions[0];records=$names.Count;externalRecords=$outside;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Data));observedScope=$true;universalClassCoverageProven=$false;provenance='Observed names/session in retained exec format 0x1007; strict UTF8 names, unsupported encoding rejects'}
    }finally{$reader.Dispose();$memory.Dispose()}
}
function PortableEnvironmentSnapshot([Collections.IDictionary]$Values,[bool]$Windows=$IsWindows) {
    if($null-eq$Values){$Values=[Environment]::GetEnvironmentVariables('Process')}
    $map=[Collections.Hashtable]::new($(if($Windows){[StringComparer]::OrdinalIgnoreCase}else{[StringComparer]::Ordinal}))
    foreach($key in $Values.Keys){Require (-not$map.Contains([string]$key)) 'Ambiguous environment keys';$map.Add([string]$key,$Values[$key])}
    return $map
}
function RestorePortableEnvironment($Before,[string[]]$Names,[bool]$Windows=$IsWindows) {
    $Before=PortableEnvironmentSnapshot $Before $Windows;$null=PortableEnvironmentSnapshot $null $Windows
    $errors=@();foreach($name in $Names){try{if($Before.Contains($name)){[Environment]::SetEnvironmentVariable($name,$Before[$name],'Process')}elseif(Test-Path ('Env:'+$name)){Remove-Item ('Env:'+$name) -ErrorAction Stop}}catch{$errors+=,$name}}
    $after=PortableEnvironmentSnapshot $null $Windows
    $keys=@(foreach($name in $Names){@{name=$name;beforePresent=$Before.Contains($name);afterPresent=$after.Contains($name);beforeLength=$(if($Before.Contains($name)){$Before[$name].Length}else{$null});afterLength=$(if($after.Contains($name)){$after[$name].Length}else{$null});equal=($Before.Contains($name)-eq$after.Contains($name)-and[string]::Equals($Before[$name],$after[$name],[StringComparison]::Ordinal))}})
    return @{keys=$keys;errors=$errors;restored=($errors.Count-eq0-and-not@($keys|Where-Object{-not$_.equal}).Count)}
}
Export-ModuleMember -Function Assert-H3911,ConvertTo-H3911Json,Require,Json,HashBytes,StreamBytes,CoverageKeys,CoverageSemantics,TestKeys,JacocoScopeArguments,JacocoExecEvidence,PortableEnvironmentSnapshot,RestorePortableEnvironment
