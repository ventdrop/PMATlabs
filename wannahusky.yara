rule wannaHusky {
    
    meta: 
        last_updated = "2022-01-26"
        author = "@ventdrop"
        description = "A rule for locating wannaHusky ransomware"

    strings:
        $magic_byte = { 4D 5A } // MZ byte
        $a = {40 77 61 6e 6e 61 48 75 73 6b 79} // @wannaHusky function in hex
        $b = "@Desktop\\WANNAHUSKY.png" ascii
    condition:
        ($magic_byte at 0x00) and ($a and $b)
}
