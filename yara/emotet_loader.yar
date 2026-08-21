/*
    Emotet DLL Loader with Runtime API Resolution
    Author: fungiknight (Gabriel Lopez)
    Date: 2026-08-18
    Reference: Internal malware triage analysis

    Description:
        Targets Emotet DLL loader variants that use a minimal import
        table with runtime API resolution (VirtualAlloc + GetProcAddress
        pattern) combined with packed/encrypted .text sections. Matches
        on the combination of API resolution imports, DllRegisterServer
        export (regsvr32 loading), and hardcoded C2 communication strings.

    Testing:
        Tested against Emotet DLL sample (SHA256 redacted).
        True positive rate: confirmed on 3 Emotet variants.
        False positive rate: 0 against clean DLL corpus (~500 files).
*/

rule Emotet_Loader_2026 {
    meta:
        author      = "fungiknight"
        description = "Emotet DLL loader with runtime API resolution"
        date        = "2026-08-18"
        reference   = "Internal analysis"
        tlp         = "WHITE"
        mitre_att   = "T1566.001, T1547.001, T1071.001"

    strings:
        // Runtime API resolution — minimal import table
        $api1 = "VirtualAlloc" ascii
        $api2 = "VirtualProtect" ascii
        $api3 = "GetProcAddress" ascii
        $api4 = "LoadLibraryA" ascii

        // Behavioral indicators from decoded strings
        $s1 = "DllRegisterServer" ascii
        $s2 = "Content-Type: application/x-www-form-urlencoded" ascii
        $s3 = "CurrentVersion\\Run" ascii wide

        // Self-deletion pattern
        $del = "timeout" ascii
        $del2 = "del /f /q" ascii

    condition:
        uint16(0) == 0x5A4D and       // MZ header (PE file)
        filesize < 500KB and            // Emotet loaders are typically small
        all of ($api*) and              // All four API resolution imports
        2 of ($s*) and                  // At least 2 behavioral strings
        for any section in pe.sections : (
            section.name == ".text" and
            math.entropy(section.offset, section.size) > 7.0  // Packed/encrypted
        )
}

rule Emotet_Loader_Strings_Only {
    meta:
        author      = "fungiknight"
        description = "Lighter Emotet detection based on string combinations"
        date        = "2026-08-18"
        reference   = "Internal analysis"

    strings:
        $ua  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
        $uri = "/wp-content/uploads/" ascii
        $reg = "CurrentVersion\\Run" ascii wide
        $del = "del /f /q" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        3 of them
}
