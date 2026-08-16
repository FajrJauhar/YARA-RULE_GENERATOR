rule Dynamic_Yara_Rule_GEN
 {
	meta:
	    description = "Dynamic Rule"
	    generated_by = "Python Dynamic Generator"
	strings:
         $string_0 = "!This program cannot be run in DOS mode.
$"
        $string_1 = "SYNTHETIC_STATIC_ANALYSIS_SAMPLE"
        $string_2 = "SYNTHETIC_MALWARE_SAMPLE"
        $string_3 = "MALWARE_FAMILY_ALPHA"
        $dll_4 = "KERNEL32.dll"
        $string_5 = ".text"
        $string_6 = "`.rdata"
        $string_7 = "@.data"
        $string_8 = "KERNEL32.dll"

	condition:
	    any of them
}