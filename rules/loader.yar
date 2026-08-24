/*
 * LOLBin/loader cradles: patterns where stock OS binaries are abused to
 * fetch-and-run payloads. Compound regexes require the download AND the
 * execution half of the chain so ordinary admin scripts do not trip them.
 */

rule Suspicious_PowerShell_Cradle
{
    meta:
        description = "PowerShell downloads-and-executes pattern (classic dropper cradle)"
        severity = 8
        family = "generic"
    strings:
        $cradle_webclient = /(iex|invoke-expression)[^;]{0,80}\(?\s*new-object\s+net\.webclient\)?\s*\.\s*download(string|file)/ ascii nocase
        $cradle_wget = /(iex|invoke-expression)\s*\(\s*\(?['\"]?[a-z]:\\?[^;]{0,40}(iwr|iwr\b.*\.content|invoke-webrequest)/ ascii nocase
        $cradle_enc = /powershell(\.exe)?[^;\n]{0,60}\s-(enc|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}/ ascii nocase
        $cradle_hidden_dl = /-nop(rowfile)?\s+-w(indowstyle)?\s+hidden[^;\n]{0,60}(downloadstring|downloadfile|invoke-expression|iex\b)/ ascii nocase
    condition:
        filesize < 512KB and any of them
}

rule Suspicious_Certutil_Download
{
    meta:
        description = "certutil used as a URL fetcher (urlcache/verifyctl against http)"
        severity = 7
        family = "generic"
    strings:
        $certutil = "certutil" ascii nocase
        $fetch = /(-urlcache|-verifyctl)/ ascii nocase
        $url = /https?:\/\// ascii nocase
    condition:
        filesize < 256KB and all of them
}

rule Suspicious_Mshta_Remote
{
    meta:
        description = "mshta executing a remote or UNC-hosted HTA"
        severity = 7
        family = "generic"
    strings:
        $mshta = /mshta(\.exe)?\s+("|')?(https?:\/\/|\\\\)/ ascii nocase
    condition:
        filesize < 64KB and any of them
}

rule Suspicious_Regsvr32_Remote
{
    meta:
        description = "regsvr32 /i:http squiblydoo-style scriptlet load"
        severity = 7
        family = "generic"
    strings:
        $squibly = /regsvr32(\.exe)?[^\n]{0,80}\/i[":]?https?:\/\// ascii nocase
    condition:
        filesize < 64KB and any of them
}
