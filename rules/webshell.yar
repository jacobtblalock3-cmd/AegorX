/*
 * Webshell one-liners for the three common server stacks. Each rule pairs
 * a language-context marker with an eval-from-request idiom so ordinary
 * application code that happens to use eval() is not flagged.
 */

rule PHP_Webshell_Request_Eval
{
    meta:
        description = "PHP evaluating attacker-controlled request parameters"
        severity = 9
        family = "webshell"
    strings:
        $php_open = "<?php" ascii
        $eval1 = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ ascii nocase
        $eval2 = /assert\s*\(\s*\$_(POST|GET|REQUEST)\s*\[/ ascii nocase
        $eval3 = /(system|shell_exec|passthru|popen)\s*\(\s*\$_(POST|GET|REQUEST)\s*\[/ ascii nocase
    condition:
        filesize < 2MB and $php_open and 1 of ($eval*)
}

rule ASPX_Webshell_Request_Eval
{
    meta:
        description = "ASP.NET page evaluating request parameters"
        severity = 8
        family = "webshell"
    strings:
        $asp_directive = "<%@" ascii
        $page_marker = /<%@?\s*Page\b/ ascii nocase
        $eval = /eval\s*\(\s*request\s*[\.\[]/ ascii nocase
        $exec = /process\.start\s*\(\s*request\s*[\.\[]/ ascii nocase
    condition:
        filesize < 2MB and ($asp_directive or $page_marker) and 1 of ($eval, $exec)
}

rule JSP_Webshell_Runtime_Exec
{
    meta:
        description = "JSP shelling out via Runtime.exec on request input"
        severity = 8
        family = "webshell"
    strings:
        $jsp = "request.getParameter" ascii nocase
        $exec = "Runtime.getRuntime().exec" ascii nocase
    condition:
        filesize < 2MB and all of them
}
