/*
 * Credential-access and intrusion tooling markers. Strings are drawn from
 * public tool documentation; combinations (not single tokens) are required
 * to keep false positives on security-admin workstations low.
 */

rule Generic_Mimikatz_Credential_Dumper
{
    meta:
        description = "Mimikatz module/command surface"
        severity = 9
        family = "mimikatz"
    strings:
        $mod1 = "sekurlsa::logonpasswords" ascii nocase
        $mod2 = "lsadump::sam" ascii nocase
        $mod3 = "lsadump::dcsync" ascii nocase
        $mod4 = "sekurlsa::pth" ascii nocase
        $mod5 = "crypto::capi" ascii nocase
        $mod6 = "mimilib" ascii nocase
        $banner = /mimikatz\s+#\s+\d+\.\d+/ ascii nocase
    condition:
        filesize < 8MB and (2 of ($mod*) or $banner)
}

rule Suspicious_Lsass_Dump_Tooling
{
    meta:
        description = "PE referencing LSASS together with minidump APIs"
        severity = 7
        family = "generic"
    strings:
        $lsass = "lsass" ascii nocase
        $dump1 = "MiniDumpWriteDump" ascii
        $dump2 = "comsvcs MiniDump" ascii nocase
        $dump3 = "rundll32.exe comsvcs.dll" ascii nocase
    condition:
        filesize < 4MB and uint16(0) == 0x5A4D and $lsass and 1 of ($dump*)
}

rule Suspicious_Process_Injection_API_Trio
{
    meta:
        description = "PE importing the classic allocate-write-execute injection trio"
        severity = 7
        family = "generic"
    strings:
        $alloc = "VirtualAlloc" ascii
        $write = "WriteProcessMemory" ascii
        $exec1 = "CreateRemoteThread" ascii
        $exec2 = "NtCreateThreadEx" ascii
    condition:
        filesize < 20MB and uint16(0) == 0x5A4D and all of ($alloc, $write) and 1 of ($exec*)
}
