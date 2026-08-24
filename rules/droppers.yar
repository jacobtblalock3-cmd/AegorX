/*
 * Script-dropper obfuscation and packer markers. Packed-PE is informational
 * only (severity 4, below the suspicious threshold) because packers have
 * abundant legitimate use; it exists to enrich analyst output.
 */

rule Suspicious_VBS_JS_Obfuscated_Dropper
{
    meta:
        description = "Windows-script dropper combining eval, encoded I/O stream, and char-code deobfuscation"
        severity = 7
        family = "generic"
    strings:
        $wsh = "WScript.Shell" ascii nocase
        $ado = "ADODB.Stream" ascii nocase
        $exec = /\b(execute|eval)\s*\(/ ascii nocase
        $chrchain = /(chr\s*\(\s*\d+\s*\)\s*&\s*){5,}/ ascii nocase
    condition:
        filesize < 1MB and 1 of ($wsh, $ado) and $exec and (1 of ($wsh, $ado, $chrchain))
}

rule Info_PE_UPX_Packed
{
    meta:
        description = "PE packed with UPX (informational; common in both tooling and malware)"
        severity = 4
        family = "packer"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and $upx0 and #upx1 > 2
}
