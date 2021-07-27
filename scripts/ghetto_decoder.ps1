ghetto_decoder.ps1

$base64data = "SywoKK7MS9ZNLMgEAA=="
$data = [System.Convert]::FromBase64String($base64data)
$ms = New-Object System.IO.MemoryStream
$ms.Write($data, 0, $data.Length)
$ms.Seek(0,0) | Out-Null

$sr = New-Object System.IO.StreamReader(New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress))

while ($line = $sr.ReadLine()) {  
	$line
}
