/*
 * Ransomware surface: extortion-note language and the shadow-copy/backup
 * sabotage command pairs publicized across incident-response reporting.
 * Combinations required; single generic words never trigger.
 */

rule Ransom_Extortion_Note_Language
{
    meta:
        description = "Extortion-note phrasing with payment instruction"
        severity = 8
        family = "ransomware"
    strings:
        $note1 = "your files have been encrypted" ascii nocase
        $note2 = "your files are encrypted" ascii nocase
        $note3 = "restore your files" ascii nocase
        $note4 = "recover your files" ascii nocase
        $pay1 = /send\s+\d+(\.\d+)?\s+(btc|bitcoin)/ ascii nocase
        $pay2 = /(bitcoin|btc)\s+(wallet|address)/ ascii nocase
        $pay3 = "do not rename encrypted files" ascii nocase
    condition:
        filesize < 1MB and 1 of ($note*) and 1 of ($pay*)
}

rule Ransom_Shadow_Copy_Sabotage
{
    meta:
        description = "Volume-shadow/backup destruction command pair used to block recovery"
        severity = 9
        family = "ransomware"
    strings:
        $vss = /vssadmin(\.exe)?\s+delete\s+shadows/ ascii nocase
        $wbadmin = /wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)/ ascii nocase
        $recovery = /bcdedit(\.exe)?.{0,40}recoveryenabled\s+no/ ascii nocase
        $firewall = /wmic(\.exe)?.{0,30}shadowcopy\s+delete/ ascii nocase
    condition:
        filesize < 4MB and 2 of them
}
