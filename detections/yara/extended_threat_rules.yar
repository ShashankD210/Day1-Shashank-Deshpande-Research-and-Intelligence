rule Volt_Typhoon_LotL_Ntdsutil
{
    meta:
        author = "GreySentinel CTI Team"
        description = "Detects Volt Typhoon Living-off-the-Land credential dumping via ntdsutil.exe"
        reference = "https://github.com/GreySentinel/cti-threat-intelligence-portfolio"
        date = "2026-01-20"
        tlp = "CLEAR"

    strings:
        $ntdsutil = "ntdsutil.exe" nocase
        $ifm = "ifm" nocase
        $create_full = "create full" nocase
        $ds_rm = "ds rm" nocase
        $authoritative = "authoritative restore" nocase
        $vssadmin = "vssadmin.exe" nocase
        $shadow_copy = "shadow copy" nocase

    condition:
        ($ntdsutil or $vssadmin) and
        2 of ($ifm, $create_full, $ds_rm, $authoritative, $shadow_copy)
}

rule Volt_Typhoon_SOHO_Router_C2
{
    meta:
        author = "GreySentinel CTI Team"
        description = "Detects Volt Typhoon C2 relaying through compromised SOHO routers"
        reference = "https://github.com/GreySentinel/cti-threat-intelligence-portfolio"
        date = "2026-01-20"
        tlp = "CLEAR"

    strings:
        $router_relay_1 = "SOHO_router" nocase
        $router_relay_2 = "port_forward" nocase
        $router_relay_3 = "upnp" nocase
        $router_relay_4 = "nat_traversal" nocase
        $c2_beacon = "beacon" nocase
        $heartbeat = "heartbeat" nocase

    condition:
        2 of ($router_relay_*) and
        1 of ($c2_beacon, $heartbeat)
}

rule Lazarus_Group_CrossPlatform_Implant
{
    meta:
        author = "GreySentinel CTI Team"
        description = "Detects Lazarus Group cross-platform implant artifacts"
        reference = "https://github.com/GreySentinel/cti-threat-intelligence-portfolio"
        date = "2026-01-20"
        tlp = "CLEAR"

    strings:
        $implant_1 = "Beacon" nocase
        $implant_2 = "C2_Callback" nocase
        $implant_3 = "payload_stage2" nocase
        $implant_4 = "XOR_decrypt" nocase
        $implant_5 = "AES_decrypt" nocase
        $implant_6 = "reverse_shell" nocase
        $implant_7 = "bind_shell" nocase

    condition:
        3 of ($implant_*)
}

rule Lazarus_Group_Malicious_NPM_Package
{
    meta:
        author = "GreySentinel CTI Team"
        description = "Detects Lazarus Group malicious npm package indicators"
        reference = "https://github.com/GreySentinel/cti-threat-intelligence-portfolio"
        date = "2026-01-20"
        tlp = "CLEAR"

    strings:
        $npm_1 = "postinstall" nocase
        $npm_2 = "preinstall" nocase
        $npm_3 = "child_process" nocase
        $npm_4 = "execSync" nocase
        $npm_5 = "spawn" nocase
        $npm_6 = "Buffer.from" nocase
        $npm_7 = "require('child_process')" nocase

    condition:
        3 of ($npm_*)
}

rule Lazarus_Group_Malicious_PyPI_Package
{
    meta:
        author = "GreySentinel CTI Team"
        description = "Detects Lazarus Group malicious PyPI package indicators"
        reference = "https://github.com/GreySentinel/cti-threat-intelligence-portfolio"
        date = "2026-01-20"
        tlp = "CLEAR"

    strings:
        $pypi_1 = "setup.py" nocase
        $pypi_2 = "os.system" nocase
        $pypi_3 = "subprocess" nocase
        $pypi_4 = "urllib.request" nocase
        $pypi_5 = "base64.b64decode" nocase
        $pypi_6 = "exec(" nocase
        $pypi_7 = "eval(" nocase

    condition:
        3 of ($pypi_*)
}

rule APT29_Memory_Resident_Loader
{
    meta:
        author = "GreySentinel CTI Team"
        description = "Detects APT29 memory-resident loader patterns"
        reference = "https://github.com/GreySentinel/cti-threat-intelligence-portfolio"
        date = "2026-01-20"
        tlp = "CLEAR"

    strings:
        $loader_1 = "ReflectiveLoader" nocase
        $loader_2 = "DllMain" nocase
        $loader_3 = "VirtualAlloc" nocase
        $loader_4 = "CreateRemoteThread" nocase
        $loader_5 = "NtUnmapViewOfSection" nocase
        $loader_6 = "SetWindowsHookEx" nocase
        $loader_7 = "RtlCreateUserThread" nocase
        $loader_8 = "NtCreateThreadEx" nocase

    condition:
        3 of ($loader_*)
}

rule APT29_Cloud_API_Abuse
{
    meta:
        author = "GreySentinel CTI Team"
        description = "Detects APT29 abuse of legitimate cloud APIs for C2 and exfiltration"
        reference = "https://github.com/GreySentinel/cti-threat-intelligence-portfolio"
        date = "2026-01-20"
        tlp = "CLEAR"

    strings:
        $cloud_1 = "graph.microsoft.com" nocase
        $cloud_2 = "login.microsoftonline.com" nocase
        $cloud_3 = "oauth2/v2.0/token" nocase
        $cloud_4 = "devicecode" nocase
        $cloud_5 = "device_code" nocase
        $cloud_6 = "authorization_code" nocase

    condition:
        2 of ($cloud_*) and
        1 of ($cloud_1, $cloud_2)
}
