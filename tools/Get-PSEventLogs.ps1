

$outdir = Resolve-Path $args[0]

$scripts = @{}

Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object {$_.Id -eq 4104} | ForEach-Object {
    $scriptid = $_.Properties[3].value
    if ($scripts.ContainsKey($scriptid)){
        $scripts[$scriptid] += , $_.Properties
    } else {
        $scripts[$scriptid] = @() + , $_.Properties
    }
}

$scriptstream = [System.IO.MemoryStream]::new()
$scriptwriter = [System.IO.StreamWriter]::new($scriptstream)

$scripts.Values | ForEach-Object {
    $scriptstream.Position = 0
    $scriptstream.SetLength(0)
    $i = 0
    $_ | Sort-Object {$_[0].value} | ForEach-Object{
        $i += 1
        $nblock = $_[0].value
        $block = $_[2].value
        $scriptid = $_[3].value
        $scriptwriter.Write($block)
        if ($nblock -ne $i){
            Write-Warning("$scriptid is missing block $i - $($nblock-1)")
            $i = $nblock
        }
    }
    $scriptwriter.Flush()
    $scriptstream.Position = 0
    $filehash = $(Get-FileHash -InputStream $scriptstream -Algorithm SHA256 | Select-Object -Expand Hash)
    Write-Host "$scriptid - $filehash"
    $filehash = Join-Path $outdir $filehash
    $scriptstream.Position = 0
    if (-Not (Test-Path $filehash)){
        Write-Host "writing to $filehash"
        $fstream = [System.IO.File]::Create($filehash)
        $scriptstream.WriteTo($fstream)
        $fstream.dispose()
    }
}
