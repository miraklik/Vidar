rule Vidar_Go_Avalanche_Sample
{
    meta:
        description = "Detects specific Vidar Go sample with Avalanche strings"
        author = "miraklik"
        date = "2026-09-06"
        hash = "d08b7a755e3606050156cd2834e588c02f1c945b6ee3ee7b567f70dd24b10c92"
        reference = "https://github.com/miraklik/Vidar"

    strings:
        $s1 = "Avalanche Risk Analysis System" ascii wide
        $s2 = "avalanche.example.com" ascii wide
        $s3 = "Hex encoded 'avalanche'" ascii wide
        $s4 = "passwordSet" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        2 of them
}