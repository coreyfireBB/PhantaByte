$ascii = @"
                             ....::-===++++++++===--::..............................................
                       ....-=+#%@@@@@@@@@@@@@@@@@@%%%%%%%#+=-:......................................
                    ..:-*%@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%@@%%%#+-:.................................
                 ..-*%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%#=...............................
              ...+%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%#=.............................
             ..-#%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%#-............................
            ..=%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%*:............................
            .=%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%#=.............................
           .:%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%*:.............................
           .*%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%#=..............................
           .%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%#...............................
          .-%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%##+.   ...........................
          .=%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%##:.   ...........................
           +%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%+..   ...........................
           +%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%#:..   ...........................
          .=%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%=.     ...........................
          .-%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#..     ...........................
           .%#%%%%%%%%%%@@@@%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:.      ...........................
           .###%%%%%%%@@@@@@@@@%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@%-..      ...........................
           .+##%%%%%%%%%@@@@@@@@@@@@@%%%@@@@@@@@@@@@@@@@@@@@@%#:...      ...........................
           .-##%%%%%%%%@@@@@@@@@@@@@@@@@@%%%%%@@@@@@@@@@@%%%%+.....      ...........................
           ..*#%%%%%%%%@@%%%%%###%%%%%@@@@%%%%%%@@@@@@@%%%%#-.......................................
           ..=#%%%%%%%%%#:............:+%%%%%%%%%@@@@@#*#%#:. ......................................
           ..:##%%%%%%%%............... ..+%%%%%%@@@@#=*##:.  ......................................
           ..:*#%%%%%%%%...................:%%%%%%@@@+=##+.   ......................................
           ...+#%%%%%%%%-...................%%%%%%@@@++##:.   ......................................
           ...+#%%%%%%%%%+--:::::::........=%%%%%%@@@+*##..   ......................................
           ...+#%%%%%%%%%%%@@@@@@@@@@@@@@@@@%%@%%%@@@+*#*-.   ......................................
           ...*#%%%%%%%%%%@@@@@@@@@@@@@@@@@@%@@@%%@@%++#*=..........................................
           ...+%%%%%%%%%%@@@@@@@@@@@@@@@@@@@%@@@%%@@%++#*+..........................................
           ...+%%%%%%%%%@@@@@@@@@@@@@@@@@@@@%@@@%%@@%++#**:.........................................
           ...=%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@%%@@@@*+##*=.........................................
           ...-%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@%%@@@@*+###*-........................................
           ...:#%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@%%%@@@@*=*###*:.......................................
           ....+%%%%%@@%@@@@@@@@@@@@@@@@@@@@@@%%@@@@@*-=#%%#*:......................................
           ....:*%%%%%%%@@@@@@@@@@@@@@@@@@@@@%%%@@@@@#==*#%%%+......................................
           .....=#%%%%%%%@@@@@@@@@@@@@@@@@@%%%%%@@@@@#######%%=.....................................
           ......+%%%%%%%@@@@@@@@@@@@@%%@%%%%%%%%@@@@@@%%%%%%%*:....................................
           .......=%%%%%%%@@@@@@@@@@@@%%%%%%%####%%#####*#%%%%+:. ..................................
           ........=#%%%%%%@@@@@@@@@@@@%%%%%@%##%%%%%%%**#%%%*:.. ..................................
           .........=#%%%%%@@@@@@@@%%%%%%%%@@@@@@@@@@@@@@@%#=.......................................
           ..........-#%%%%%@@@%%%%%%%%%%@@@@@@%#*+==---::..........................................
           ...........-#%%%%%%%%%%%%%@%%%%*-:.......................................................
           ............:#%%%%%%%%%%%%@%*-...         ...............................................
           .............-#%%%%%@@@@@@#-..            ...............................................
           ..............-*%%%%@@@@@*..              ...............................................
           ...............:*%%%@@@@*...              ...............................................
           ................:+%@@@@#.................................................................
           ..................+%@@@:.................................................................
           ...................-#@#..................................................................
           .....................+#..................................................................
           ......................::.................................................................
           .........................................................................................

██████  ██   ██  █████  ███    ██ ████████  █████  ██████  ██    ██ ████████ ███████ 
██   ██ ██   ██ ██   ██ ████   ██    ██    ██   ██ ██   ██  ██  ██     ██    ██      
██████  ███████ ███████ ██ ██  ██    ██    ███████ ██████    ████      ██    █████   
██      ██   ██ ██   ██ ██  ██ ██    ██    ██   ██ ██   ██    ██       ██    ██      
██      ██   ██ ██   ██ ██   ████    ██    ██   ██ ██████     ██       ██    ███████ 
                                                                                     
                                                                                    

"@
Write-Host $ascii

# Import the required module for GPO manipulation
Import-Module GroupPolicy

function Get-UserChoice {
    param (
        [string]$Prompt,
        [array]$Options
    )

    # Display the options
    for ($i = 0; $i -lt $Options.Length; $i++) {
        Write-Host ("{0}: {1}" -f $i, $Options[$i])
    }

    do {
        # Read the user's choice
        $choiceIndex = Read-Host $Prompt

        # Attempt to parse the input as an integer
        [int]$choiceIndexParsed = 0
        $isParsed = [int]::TryParse($choiceIndex, [ref]$choiceIndexParsed)

        # Validate the input
        $isValid = $isParsed -and $choiceIndexParsed -ge 0 -and $choiceIndexParsed -lt $Options.Length
        if (-not $isValid) {
            Write-Host "Invalid choice. Please enter a number between 0 and $($Options.Length - 1)."
        }
    } while (-not $isValid)

    return $Options[$choiceIndexParsed]
}

function Get-MultipleUserChoices {
    param (
        [string]$Prompt,
        [array]$Options
    )

    # Display the options
    for ($i = 0; $i -lt $Options.Length; $i++) {
        Write-Host ("{0}: {1}" -f $i, $Options[$i])
    }

    do {
        # Read the user's choices
        $choiceIndices = Read-Host $Prompt

        # Split the input into an array of indices
        $indices = $choiceIndices -split ',' | ForEach-Object { $_.Trim() }

        # Validate the indices
        $valid = $indices -and ($indices | ForEach-Object { $_ -match '^\d+$' -and [int]$_ -ge 0 -and [int]$_ -lt $Options.Length })

        if (-not $valid) {
            Write-Host "Invalid choices. Please enter valid numbers separated by commas."
        }
    } while (-not $valid)

    return $indices | ForEach-Object { $Options[$_] }
}

# This section allows you to create a new GPO, or allows you to modify an existing GPO. 
function New-Or-Modify-GPO {
    $action = Get-UserChoice -Prompt "Would you like to create a new GPO or modify an existing one? Enter the number corresponding to your choice:" -Options @('Create', 'Modify')
    
    if ($action -eq 'Create') {
        $gpoName = Read-Host "Enter the name for the new GPO"
        $gpo = New-GPO -Name $gpoName
        Write-Host "Created new GPO: $gpoName"
    } else {
        $gpoName = Read-Host "Enter the name of the existing GPO to modify"
        $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
        Write-Host "Modifying existing GPO: $gpoName"
    }

    return $gpo
}

# This is still in test flight. This is an option to push a logon script for GPO's that require a logon script. 
function Upload-ScriptToSysvol {
    param (
        [string]$LocalScriptPath,
        [string]$ScriptName
    )

    $FULLDOMAIN = (Get-ADDomain).Forest
    $DOMAIN = (Get-ADDomain).Name

    $sysvolPath = "\\\\$DOMAIN\\sysvol\\$FULLDOMAIN\\scripts\\$ScriptName"
    if (Test-Path $LocalScriptPath) {
        Copy-Item -Path $LocalScriptPath -Destination $sysvolPath -Force
        Write-Host "Uploaded script to SYSVOL location: $sysvolPath"
    } else {
        Write-Host "The specified local script path does not exist: $LocalScriptPath"
        exit
    }
    return $sysvolPath
}

# Function to link a script to the GPO as a logon script
function Link-ScriptToGPO {
    param (
        [Microsoft.GroupPolicy.Gpo]$Gpo,
        [string]$ScriptPath,
        [string]$ScriptName
    )
    # Define the script parameters
    $scriptParams = @{
        DisplayName = $Gpo.DisplayName
        ScriptName = $ScriptName
        ScriptParameters = ''
        ScriptOrder = 1
    }

    # Add the logon script to the GPO
    New-GPRegistryValue @scriptParams -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Scripts\Logon" -ValueName "0" -Type String -Value $ScriptPath
    Write-Host "Linked script to GPO as a logon script: $ScriptPath"
}


function Apply-HardeningTechniques {
    param (
        [Microsoft.GroupPolicy.Gpo]$Gpo,
        [string]$Action
    )

    $techniques = @(
        'Disable LLMNR',
        'Disable mDNS',
        'Disable NetBios Name Solution (NBNS) {Not fully working}',
        'Enable SMB Signing Workstations',
        'Enable SMB Signing Servers',
        'Disable WPAD',
        'Force NTLMv2 or higher',
        'Restrict Null Sessions',
        'Disable WDigest',
        'Restrict AT.exe',
        'Prefer IPv4 over IPv6',
        'Enable Windows Firewall Logging',
        'Disable PowerShell V2',
        'Enable PowerShell Script Block Logging',
        'Enable PowerShell Constrained Language Mode (CLM)',
        'Remove SeDebug Privilege from Users in the Linked OU {testing}',
        'Enable Restricted Admin Mode',
        'Enable LSA Protection',
        'Disable Credential Caching (Set to 0 Cached Credentials)',
        'Disable Internet Explorer',
        'Enable SEHOP (Structured Exception Handler Overwrite Protection)',
        'Disable Reversible Password Encryption',
        'Enable Client-Side LDAP Signing',
        'Disable Insecure Logons to an SMB Server',
        'Restrict Anonymous Access to Named Pipes and Shares',
        'Add LSASS Injection Mitigation ASR Rule'
    )

    Write-Host "Select hardening techniques to apply (separate multiple selections with commas):"
    $selectedTechniques = Get-MultipleUserChoices -Prompt "Select hardening techniques by entering their corresponding numbers:" -Options $techniques

    foreach ($technique in $selectedTechniques) {
        switch ($technique) {
            'Disable LLMNR' {
                <#
                0: Disable Multicast Name Resolution. (Secure)
                    This setting disables multicast name resolution. When set to 0, the system will not use multicast to resolve DNS queries, which can enhance security by preventing unwanted network traffic related to multicast DNS (mDNS).
                1: Enable Multicast Name Resolution. (Default)
                    This setting enables multicast name resolution. When set to 1, the system will use multicast to resolve DNS queries if needed. This is useful in environments where multicast DNS is required for local network discovery and name resolution.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Value 0 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Value 1 -Type DWord
                }
            }
            'Disable mDNS' {
                <#
                0: mDNS is disabled. (Secure)
                    This setting disables Multicast DNS (mDNS), which is used for local network name resolution. Disabling mDNS enhances security by preventing potential information leakage and reducing the attack surface on the network.
                1: mDNS is enabled. (Default)
                    This setting enables Multicast DNS (mDNS). While useful for local network discovery, it can introduce security risks by exposing network information to potential attackers.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Value 0 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Value 1 -Type DWord
                }
            }
            'Disable NetBios Name Solution (NBNS) {Not fully working}' {
                <#
                0x1 (1): Broadcast (B-node)
                    NetBIOS names are resolved by broadcasting. The machine sends a broadcast to the network, and the first machine that responds is assumed to be the owner of the name.
                0x2 (2): Peer-to-Peer (P-node)
                    NetBIOS names are resolved using a WINS server (Windows Internet Name Service). Broadcasts are not used; the machine queries the WINS server to resolve names.
                0x4 (4): Mixed (M-node)
                    This is a combination of B-node and P-node. The machine first attempts to resolve NetBIOS names using broadcasts (B-node). If that fails, it then queries a WINS server (P-node).
                0x8 (8): Hybrid (H-node) -- Default Windows setting
                    This is a combination of P-node and B-node. The machine first queries a WINS server (P-node) to resolve NetBIOS names. If that fails, it then falls back to broadcasting (B-node).
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NodeType" -Value 2 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NodeType" -Value 8 -Type DWord
                }
            }
            'Enable SMB Signing Workstations' {
                <#
                1: Enable workstation-side SMB signing. (Secure)
                    This setting ensures that SMB communications initiated from the workstation are digitally signed to prevent man-in-the-middle attacks. Enabling SMB signing enhances security by ensuring the integrity and authenticity of SMB communications on the network.
                0: Disable workstation-side SMB signing. (Less Secure)
                    This setting disables SMB signing for workstation-side communications, which may improve performance but increases the risk of man-in-the-middle attacks where SMB communications can be intercepted and altered.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "EnableSecuritySignature" -Value 1 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "EnableSecuritySignature" -Value 0 -Type DWord
                }
            }
            'Enable SMB Signing Servers' {
                <#
                1: Enable server-side SMB signing. (Secure)
                    This setting ensures that SMB communications are digitally signed to prevent man-in-the-middle attacks. Enabling SMB signing enhances security by ensuring the integrity and authenticity of SMB communications on the network.
                0: Disable server-side SMB signing. (Default)
                    This setting disables SMB signing for server-side communications, which may improve performance but increases the risk of man-in-the-middle attacks where SMB communications can be intercepted and altered.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -Value 1 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -Value 0 -Type DWord
                }
            }
            
            'Disable WPAD' {
                
                <#
                0: Automatic proxy detection is disabled. (Secure)
                    Windows will not attempt to automatically detect proxy settings using the Web Proxy Auto-Discovery Protocol (WPAD).
                1: Automatic proxy detection is enabled. (Windows Default Setting)
                    Windows will attempt to automatically detect proxy settings using WPAD. This involves sending a DNS query for wpad.<domain> to find a WPAD server that can provide the proxy configuration.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\WinHttp" -ValueName "EnableAutoDetect" -Value 0 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\WinHttp" -ValueName "EnableAutoDetect" -Value 1 -Type DWord
                }
            }
            'Force NTLMv2 or higher' {
                <#
                0: Send LM and NTLM responses; never use NTLMv2 session security. (Old Default for 2003 or older OS's )
                    This setting sends both LM and NTLM response messages and never uses NTLMv2 session security.
                1: Send LM and NTLM responses; use NTLMv2 session security if negotiated.
                    This setting sends both LM and NTLM response messages and uses NTLMv2 session security if it is negotiated.
                2: Send NTLM response only.
                    This setting sends only NTLM response messages, and LM response messages are not sent. NTLMv2 session security is not used.
                3: Send NTLMv2 response only. (Default for modern OS's such as Win 10+, server 2012+, this is preferred over option 0, but 5 is most secure)
                    This setting sends only NTLMv2 response messages. LM and NTLM responses are not sent.
                4: Send NTLMv2 response only; refuse LM.
                    This setting sends only NTLMv2 response messages and refuses LM responses. NTLM responses are also accepted.
                5: Send NTLMv2 response only; refuse LM and NTLM. (Most secure option)
                    This setting sends only NTLMv2 response messages and refuses both LM and NTLM responses.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Value 5 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Value 3 -Type DWord
                }
            }
            'Restrict Null Sessions' {
                <#
                0: Null session access is not restricted.(Default)
                    This setting allows null sessions to access certain named pipes and shared resources. This can be useful for compatibility with older systems or applications that rely on null sessions, but it poses a security risk because it allows unauthenticated access.
                1: Null session access is restricted.(Secure)
                    This setting restricts null session access, preventing unauthenticated users from accessing named pipes and shared resources. This is the more secure option and is recommended for most environments.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RestrictNullSessAccess" -Value 1 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RestrictNullSessAccess" -Value 0 -Type DWord
                }
            }
            'Disable WDigest' {
                <#
                0: WDigest does not use logon credentials.(Secure)
                    This setting disables the use of logon credentials for WDigest authentication, meaning that the plain-text credentials are not stored in memory. This enhances security by preventing potential credential theft through memory attacks.
                1: WDigest uses logon credentials.(Default)
                    This setting allows WDigest to use logon credentials, which may be necessary for compatibility with some older systems or applications that require WDigest authentication. However, this setting stores the credentials in memory, which can be a security risk if an attacker gains access to the system's memory.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ValueName "UseLogonCredential" -Value 0 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ValueName "UseLogonCredential" -Value 1 -Type DWord
                }
            }
            'Restrict AT.exe' {
                <#
                0: The AT command is enabled.(Default)
                    This setting allows the use of the AT command to schedule tasks. Users can use the AT command to schedule tasks to run at specific times.
                1: The AT command is disabled. (Secure)
                    This setting disables the use of the AT command. Users will not be able to use the AT command to schedule tasks. This is typically done for security reasons, as the AT command is considered outdated and less secure compared to newer task scheduling methods like schtasks.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows NT\Schedule" -ValueName "DisableAt" -Value 1 -Type DWord
                } else {
                    Remove-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows NT\Schedule" -ValueName "DisableAt"
                }
            }
            'Prefer IPv4 over IPv6' {
                <#
                0x00 (0): Enable all IPv6 components (Default).
                    This is the default value. IPv6 is fully enabled, and all IPv6 interfaces, components, and capabilities are active.
                0x01 (1): Disable only the tunneling over IPv4 (6to4, ISATAP, and Teredo).
                    This setting disables all IPv6 tunneling over IPv4. Native IPv6 interfaces remain active.
                0x10 (16): Disable all 6to4 tunneling.
                    This setting disables only the 6to4 tunneling mechanism used to encapsulate IPv6 traffic over IPv4 networks.
                0x11 (17): Disable both 6to4 and ISATAP tunneling.
                    This setting disables both the 6to4 and ISATAP tunneling mechanisms.
                0x20 (32): Disable Teredo tunneling. (Secured Selection)
                    This setting disables the Teredo tunneling protocol, which is another mechanism used to encapsulate IPv6 traffic over IPv4.
                0xFF (255): Disable all IPv6 components.
                    This setting disables all IPv6 interfaces, components, and capabilities on the machine. IPv6 is effectively disabled.
                0x01 (Bit 0): Disable the preferred state of IPv6 on all interfaces (sets all IPv6 interfaces to 'unpreferred').
                    IPv6 remains enabled, but all interfaces are set to unpreferred, meaning they will not be used by default.
                0x02 (Bit 1): Disable all IPv6 interfaces except for the loopback.
                    Only the loopback interface (::1) remains active, while all other IPv6 interfaces are disabled.
                0x08 (Bit 3): Disable IPv6 over native interfaces.
                    Native IPv6 interfaces are disabled, but tunneling over IPv4 is still allowed.
                0x20 (Bit 5): Disable Teredo.
                    Disables the Teredo protocol, which is used to allow IPv6 communication through NAT devices.
                0x40 (Bit 6): Disable all IPv6 interfaces except the loopback and link-local.
                    Only the loopback and link-local interfaces are enabled.
                0x80 (Bit 7): Prefer IPv4 over IPv6.
                    IPv4 is preferred over IPv6 when both are available.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -ValueName "DisabledComponents" -Value 32 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -ValueName "DisabledComponents" -Value 0 -Type DWord
                }
            }
            'Disable PowerShell V2' {
                <#
                The best way to remove PS v2 is: Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart
                - This can be done via a Logon script as well in the future. 
                0: PowerShell V2 is enabled. (Default)
                    This setting allows PowerShell Version 2 to be available on the system. PowerShell V2 lacks many of the security features present in later versions, making it less secure.
                1: PowerShell V2 is disabled. (Secure)
                    This setting disables PowerShell Version 2, preventing it from being used on the system. This enhances security by ensuring that only more secure versions of PowerShell are available.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" -ValueName "PowerShellVersion" -Value 1 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" -ValueName "PowerShellVersion" -Value 0 -Type DWord
                }
            }
            'Enable PowerShell Script Block Logging' {
                <#
                1: PowerShell Script Block Logging is enabled. (Secure)
                    This setting enables logging of all PowerShell script blocks, which includes any code that is executed, even if it is obfuscated or encoded. This provides detailed visibility into PowerShell activities and helps in detecting malicious scripts.
                0: PowerShell Script Block Logging is disabled. (Default)
                    This setting disables logging of PowerShell script blocks. Without this logging, it becomes more difficult to detect and investigate malicious PowerShell activity.
                #>
                # Define the registry key and value name
                if ($Action -eq 'Remediate') {
                    $RegistryKeyPath = "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
                    $ValueName = "EnableScriptBlockLogging"
            
                    # Enable Script Block Logging by setting the value to 1
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 1
                    
                    Write-Host "PowerShell Script Block Logging has been enabled."
                } else {
                    # Disable Script Block Logging by setting the value to 0
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 0
                    
                    Write-Host "PowerShell Script Block Logging has been disabled."
                }
            }
            'Enable PowerShell Constrained Language Mode (CLM)' {
                if ($Action -eq 'Remediate') {
                    <#
                    1: Constrained Language Mode is enabled. (Secure)
                        This setting enforces Constrained Language Mode in PowerShell, which restricts the language to limit the execution of potentially harmful scripts. CLM is useful for mitigating the risk of attack when running PowerShell in environments where untrusted code might be executed.
                    0: Constrained Language Mode is disabled. (Default)
                        This setting disables Constrained Language Mode, allowing PowerShell to run with full language capabilities. While this provides more flexibility, it also increases the risk of running malicious scripts.
                    #>
            
                    # Define the registry key and value name
                    $RegistryKeyPath = "HKLM\Software\Policies\Microsoft\Windows\PowerShell"
                    $ValueName = "EnableConstrainedLanguage"
            
                    # Enable Constrained Language Mode by setting the value to 1
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 1
                    
                    Write-Host "PowerShell Constrained Language Mode (CLM) has been enabled."
                } else {
                    # Disable Constrained Language Mode by setting the value to 0
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 0
                    
                    Write-Host "PowerShell Constrained Language Mode (CLM) has been disabled."
                }
            }
            'Remove SeDebug Privilege from Users in the Linked OU {testing}' {
                <#
                SeDebugPrivilege allows users to debug and adjust the memory of processes owned by other users. 
                    This privilege is typically only required by system administrators or specific service accounts.    
                    Remediation:
                        This script will remove SeDebugPrivilege from all users in the Organizational Unit (OU) where this Group Policy Object (GPO) is applied. 
                        Make sure no SQL admins, or developers that require this priv, are in the OU
                    Note: Ensure that the application of this GPO is appropriate, as removing this privilege can affect legitimate administrative tasks.
                    #>
                    
                    # Define the registry key and value name
                if ($Action -eq 'Remediate') {
                    $RegistryKeyPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
                    $ValueName = "SeDebugPrivilege"
            
                    # Remove the SeDebugPrivilege for all users in the OU
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type MultiString -Value ""
                    Write-Host "SeDebugPrivilege has been removed from all users in the linked OU."
                } else {
                    $RegistryKeyPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
                    $ValueName = "SeDebugPrivilege"

                    # Add SEDebug back to all users in the OU
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type MultiString -Value ""
                    Write-Host "SeDebugPrivilege has been given back to all users in the linked OU."
                }
            }            
            'Enable Restricted Admin Mode' {
                <#
                1: Restricted Admin Mode is enabled. (Secure)
                    This setting enables Restricted Admin Mode for Remote Desktop connections. When enabled, it prevents the transmission of reusable credentials to the remote system, reducing the risk of credential theft.
                0: Restricted Admin Mode is disabled. (Less Secure)
                    This setting allows Remote Desktop connections without Restricted Admin Mode, which could expose reusable credentials to the remote system, increasing the risk of credential theft.
                #>
                if ($Action -eq 'Remediate') {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DisableRestrictedAdmin" -Value 0 -Type DWord
                } else {
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DisableRestrictedAdmin" -Value 1 -Type DWord
                }
            } 
            'Enable LSA Protection' {
                <#
                1: LSA Protection is enabled. (Secure)
                    This setting enables LSA Protection, which runs the Local Security Authority (LSA) process in a secure mode to prevent code injection by non-protected processes. Enabling this setting helps protect against credential theft attacks, such as those that target the LSA process to extract credentials from memory.
                0: LSA Protection is disabled. (Default)
                    This setting disables LSA Protection, allowing the LSA process to run without the additional security measures, which can increase the risk of credential theft attacks.
                #>
                # Define the registry key and value name
                if ($Action -eq 'Remediate') {
                    $RegistryKeyPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
                    $ValueName = "RunAsPPL"

                    # Enable LSA Protection by setting the value to 1
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 1
                    
                    Write-Host "LSA Protection has been enabled."
                } else {
                    $RegistryKeyPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
                    $ValueName = "RunAsPPL"
                    # Disable LSA Protection by setting the value to 0
                    Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 0
                    
                    Write-Host "LSA Protection has been disabled."
                }
            } 
                'Disable Credential Caching (Set to 0 Cached Credentials)' {
                     <#
                    0: Disable credential caching. (Secure)
                        This setting configures the system to not cache any credentials locally. Disabling credential caching reduces the risk of credential theft from cached credentials, which can be a target for attackers with physical or local access to a machine.
                    1 or higher: Cache a certain number of credentials. (Default)
                        This setting allows a specified number of user credentials to be cached locally. While it may improve user experience by allowing login without network connectivity, it increases the risk of credential theft.
                    #>
                    if ($Action -eq 'Remediate') {
                        # Define the registry key and value name
                        $RegistryKeyPath = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                        $ValueName = "CachedLogonsCount"

                        # Set the number of cached credentials to 0
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type String -Value "0"
                        
                        Write-Host "Credential caching has been disabled (0 cached credentials)."
                    } else {
                        $RegistryKeyPath = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                        $ValueName = "CachedLogonsCount"
                        # Set the number of cached credentials to a default value (adjust as needed)
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type String -Value "10"
                        
                        Write-Host "Credential caching has been set to 10 cached credentials (or default)."
                    }
                }
                'Disable Internet Explorer' {
                     <#
                    1: Disable Internet Explorer. (Secure)
                        This setting disables Internet Explorer, preventing users from accessing it. Disabling IE enhances security by reducing the attack surface associated with outdated and vulnerable browser technology.
                    0: Enable Internet Explorer. (Default)
                        This setting allows Internet Explorer to be accessed by users. While necessary for legacy applications, it increases the security risk due to IE's outdated security posture.
                    #>
                    if ($Action -eq 'Remediate') {
                        # Define the registry key and value name
                        $RegistryKeyPath = "HKLM\Software\Policies\Microsoft\Internet Explorer\Main"
                        $ValueName = "DisableIE"

                        # Disable Internet Explorer by setting the value to 1
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 1
                        
                        Write-Host "Internet Explorer has been disabled."
                    } else {
                        $RegistryKeyPath = "HKLM\Software\Policies\Microsoft\Internet Explorer\Main"
                        $ValueName = "DisableIE"
                        # Enable Internet Explorer by setting the value to 0
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 0
                        
                        Write-Host "Internet Explorer has been enabled."
                    }
                }
                'Enable SEHOP (Structured Exception Handler Overwrite Protection)' {
                    if ($Action -eq 'Remediate') {
                        <#
                        1: Enable SEHOP. (Secure)
                            This setting enables SEHOP, which provides protection against a certain class of buffer overflow attacks by ensuring that the structured exception handler (SEH) chain is not overwritten. Enabling SEHOP helps to mitigate potential exploits that rely on this type of attack.
                        0: Disable SEHOP. (Less Secure)
                            This setting disables SEHOP, leaving the system vulnerable to exploits that attempt to overwrite the SEH chain. While necessary for compatibility with certain legacy applications, disabling SEHOP increases the risk of successful attacks.
                        #>

                        # Define the registry key and value name
                        $RegistryKeyPath = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
                        $ValueName = "DisableExceptionChainValidation"

                        # Enable SEHOP by setting the value to 0
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 0
                        
                        Write-Host "SEHOP has been enabled."
                    } else {
                        $RegistryKeyPath = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
                        $ValueName = "DisableExceptionChainValidation"
                        # Disable SEHOP by setting the value to 1
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 1
                        
                        Write-Host "SEHOP has been disabled."
                    }
                }
                'Disable Reversible Password Encryption' {
                    if ($Action -eq 'Remediate') {
                        <#
                        0: Disable reversible password encryption. (Secure)
                            This setting ensures that passwords are not stored using reversible encryption. Disabling reversible encryption enhances security by preventing the storage of passwords in a form that can be easily decrypted. This is the recommended setting for most environments.
                        1: Enable reversible password encryption. (Less Secure)
                            This setting allows passwords to be stored using reversible encryption, which is equivalent to storing passwords in plain text. This setting is only necessary for certain applications that require knowledge of the user's password in plain text.
                        #>

                        # Define the registry key and value name
                        $RegistryKeyPath = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                        $ValueName = "ClearTextPassword"

                        # Disable reversible password encryption by setting the value to 0
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 0
                        
                        Write-Host "Reversible password encryption has been disabled."
                    } else {
                        $RegistryKeyPath = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                        $ValueName = "ClearTextPassword"
                        # Enable reversible password encryption by setting the value to 1
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 1
                        
                        Write-Host "Reversible password encryption has been enabled."
                    }
                }
                'Enable Client-Side LDAP Signing' {
                    <#
                    1: Enable client-side LDAP signing. (Secure)
                        This setting ensures that LDAP communications from the client are digitally signed to prevent man-in-the-middle attacks. Enabling LDAP signing enhances security by ensuring the integrity and authenticity of LDAP communications between clients and servers.
                     0: Disable client-side LDAP signing. (Less Secure)
                        This setting disables LDAP signing for client-side communications, which may improve compatibility with older systems but increases the risk of man-in-the-middle attacks where LDAP communications can be intercepted and altered.
                    #>
                    if ($Action -eq 'Remediate') {
                        # Define the registry key and value name
                        $RegistryKeyPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\LDAP"
                        $ValueName = "LDAPClientIntegrity"

                        # Enable client-side LDAP signing by setting the value to 1
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 1
                        
                        Write-Host "Client-side LDAP signing has been enabled."
                    } else {
                        $RegistryKeyPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\LDAP"
                        $ValueName = "LDAPClientIntegrity"
                        # Disable client-side LDAP signing by setting the value to 0
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 0
                        
                        Write-Host "Client-side LDAP signing has been disabled."
                    }
                }
                'Disable Insecure Logons to an SMB Server' {
                    <#
                    1: Disable insecure logons to an SMB server. (Secure)
                        This setting enforces secure logons by disallowing insecure guest logons or unauthenticated access to SMB servers. Disabling insecure logons enhances security by ensuring that only authenticated users can access SMB shares.
                    0: Allow insecure logons to an SMB server. (Less Secure)
                        This setting allows insecure guest logons or unauthenticated access to SMB servers, which can pose a significant security risk by exposing shared resources to unauthorized users.
                    #>
                    if ($Action -eq 'Remediate') {
                        # Define the registry key and value name
                        $RegistryKeyPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
                        $ValueName = "EnableSecuritySignature"

                        # Disable insecure logons to an SMB server by setting the value to 1
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 1
                        
                        Write-Host "Insecure logons to an SMB server have been disabled."
                    } else {
                        $RegistryKeyPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
                        $ValueName = "EnableSecuritySignature"
                        # Allow insecure logons to an SMB server by setting the value to 0
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 0
                        
                        Write-Host "Insecure logons to an SMB server have been allowed."
                    }
                }
                'Restrict Anonymous Access to Named Pipes and Shares' {
                    <#
                    1: Restrict anonymous access to named pipes and shares. (Secure)
                        This setting restricts anonymous access, ensuring that only authenticated users can access named pipes and shares. Enabling this restriction enhances security by preventing unauthorized access to network resources.
                    0: Allow anonymous access to named pipes and shares. (Less Secure)
                        This setting allows anonymous users to access named pipes and shares, which can pose a significant security risk by exposing network resources to unauthorized access.
                    #>
                    if ($Action -eq 'Remediate') {
                        # Define the registry key and value name
                        $RegistryKeyPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                        $ValueName = "RestrictNullSessAccess"

                        # Restrict anonymous access to named pipes and shares by setting the value to 1
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 1
                        
                        Write-Host "Anonymous access to named pipes and shares has been restricted."
                    } else {
                        $RegistryKeyPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                        $ValueName = "RestrictNullSessAccess"
                        # Allow anonymous access to named pipes and shares by setting the value to 0
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key $RegistryKeyPath -ValueName $ValueName -Type DWord -Value 0
                        
                        Write-Host "Anonymous access to named pipes and shares has been allowed."
                    }
                }
                'Add LSASS Injection Mitigation ASR Rule' {
                    <#
                    1: Enable LSASS Injection Mitigation ASR Rule (Secure)
                        This setting enables the ASR rule that mitigates LSASS injection, enhancing security by preventing certain attack vectors that target LSASS.
                    0: Disable LSASS Injection Mitigation ASR Rule (Less Secure)
                        This setting disables the ASR rule, which may be necessary for compatibility with certain legacy systems or applications, but it reduces security.
                    #>
                    if ($Action -eq 'Remediate') {
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -Value 1 -Type DWord
                    } else {
                        Set-GPRegistryValue -Name $Gpo.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -Value 0 -Type DWord
                    }
                }

        }
        Write-Host "$technique $Action completed."
    }
}


# Link, unlink, or skip Linking to an OU. You must present the Distinguished Name. 
function Link-Or-Unlink-OU {
    param (
        [Microsoft.GroupPolicy.Gpo]$Gpo
    )

    $linkAction = Get-UserChoice -Prompt "Would you like to link or unlink the GPO to/from an OU? Enter the number corresponding to your choice:" -Options @('Link', 'Unlink', 'Skip')

    switch ($linkAction) {
        'Link' {
            $ou = Read-Host "Enter the distinguished name of the OU to link the GPO to"
            New-GPLink -Name $Gpo.DisplayName -Target $ou
            Write-Host "Linked GPO to OU: $ou"
        }
        'Unlink' {
            $ou = Read-Host "Enter the distinguished name of the OU to unlink the GPO from"
            Remove-GPLink -Name $Gpo.DisplayName -Target $ou
            Write-Host "Unlinked GPO from OU: $ou"
        }
        'Skip' {
            Write-Host "Skipping the link/unlink operation."
        }
    }
}

try {
    $remediateOrReverse = Get-UserChoice -Prompt "Would you like to remediate or reverse remediation efforts? Enter the number corresponding to your choice:" -Options @('Remediate', 'Reverse')
    $gpo = New-Or-Modify-GPO
    Link-Or-Unlink-OU -Gpo $gpo
    Apply-HardeningTechniques -Gpo $gpo -Action $remediateOrReverse
    Write-Host "GPO $remediateOrReverse completed successfully."
} catch {
    Write-Host "An error occurred: $_"
}
