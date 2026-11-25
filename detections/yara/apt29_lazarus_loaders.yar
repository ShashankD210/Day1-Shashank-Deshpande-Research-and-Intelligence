rule APT29_MemoryLoader_CrossPlatformDropper
{
    meta:
        author = "GreySentinel CTI Team"
        description = "Detects structural patterns associated with APT29 and Lazarus Group memory-resident loaders and cross-platform droppers"
        reference = "https://github.com/GreySentinel/cti-threat-intelligence-portfolio"
        date = "2026-01-15"
        tlp = "CLEAR"

    strings:
        // APT29 memory loader indicators
        $apt29_loader_1 = "ReflectiveLoader" nocase
        $apt29_loader_2 = "DllMain" nocase
        $apt29_loader_3 = "VirtualAlloc" nocase
        $apt29_loader_4 = "CreateRemoteThread" nocase
        $apt29_loader_5 = "NtUnmapViewOfSection" nocase
        $apt29_loader_6 = "SetWindowsHookEx" nocase

        // Lazarus cross-platform dropper indicators
        $lazarus_dropper_1 = "dropped_payload" nocase
        $lazarus_dropper_2 = "stage2.bin" nocase
        $lazarus_dropper_3 = "config.json" nocase
        $lazarus_dropper_4 = "beacon" nocase
        $lazarus_dropper_5 = "c2_callback" nocase
        $lazarus_dropper_6 = "XOR_decrypt" nocase

        // Shared memory loader patterns
        $mem_exec_1 = "RtlCreateUserThread" nocase
        $mem_exec_2 = "NtCreateThreadEx" nocase
        $mem_exec_3 = "HeapCreate" nocase
        $mem_exec_4 = "WriteProcessMemory" nocase

    condition:
        // APT29 memory loader pattern
        (2 of ($apt29_loader_*) and 1 of ($mem_exec_*)) or
        // Lazarus cross-platform dropper pattern
        (2 of ($lazarus_dropper_*) and 1 of ($mem_exec_*)) or
        // Generic memory-resident loader
        (3 of ($mem_exec_*))
}

rule APT29_OAuth_CloudAPI_Abuse
{
    meta:
        author = "GreySentinel CTI Team"
        description = "Detects patterns associated with APT29 OAuth device code phishing and cloud API abuse"
        reference = "https://github.com/GreySentinel/cti-threat-intelligence-portfolio"
        date = "2026-01-15"
        tlp = "CLEAR"

    strings:
        $oauth_device = "device_code" nocase
        $oauth_grant = "authorization_code" nocase
        $ms_graph = "graph.microsoft.com" nocase
        $azure_ad = "login.microsoftonline.com" nocase
        $token_endpoint = "/oauth2/v2.0/token" nocase
        $device_auth = "/devicecode" nocase

    condition:
        2 of ($oauth_device, $oauth_grant, $device_auth, $token_endpoint) and
        1 of ($ms_graph, $azure_ad)
}

rule Lazarus_SupplyChain_MaliciousPackage
{
    meta:
        author = "GreySentinel CTI Team"
        description = "Detects patterns associated with Lazarus Group supply chain attacks via malicious npm/PyPI packages"
        reference = "https://github.com/GreySentinel/cti-threat-intelligence-portfolio"
        date = "2026-01-15"
        tlp = "CLEAR"

    strings:
        $npm_postinstall = "postinstall" nocase
        $pip_setup = "setup.py" nocase
        $child_process = "child_process" nocase
        $exec_sync = "execSync" nocase
        $spawn = "spawn" nocase
        $base64_decode = "Buffer.from" nocase
        $os_system = "os.system" nocase
        $subprocess = "subprocess" nocase
        $urllib = "urllib.request" nocase

    condition:
        (2 of ($npm_postinstall, $child_process, $exec_sync, $spawn, $base64_decode)) or
        (2 of ($pip_setup, $os_system, $subprocess, $urllib))
}
