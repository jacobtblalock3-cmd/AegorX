rule EICAR_Test_File
{
    meta:
        description = "EICAR standard antivirus test file (tolerates trailing-byte variants)"
        author = "Defentra Project"
        severity = 8
        reference = "https://www.eicar.org"
    strings:
        // The first 62 bytes are the invariant core defined by the EICAR spec;
        // generators may vary the final characters ('H*' / 'X*'), so matching
        // only the stable prefix catches tail-mutated samples too.
        $eicar_core = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" ascii
    condition:
        $eicar_core
}
