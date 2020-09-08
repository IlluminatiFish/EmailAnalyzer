rule SpamBot_1
{
    meta:
        description = "Identifies an email spam bot"
        author = "IlluminatiFish"
        date = "08/09/2020 @ 18:40"
    strings:
        #$origin_email = /From: .{0,7}.{0,7}.{0,7}@..com
		$header_str_1 = "X-WCRX: 6055" fullword      
		$header_str_2 = "X-WCMS: 46734" fullword   
		$header_str_3 = "Organization: Google_Corporation" fullword   
    condition:
        any of ($header_str_*)
}


rule SpamBot_2
{
    meta:
        description = "Identifies an email spam bot"
        author = "IlluminatiFish"
        date = "08/09/2020 @ 18:40"
    strings:
		$header_str_1 = "X-Mailer: Alfie12" fullword      
		$header_str_2 = "To: <-----@---->" fullword   
		$header_str_3 = "CC: <-----@---->" fullword

    condition:
        any of ($header_str_*)
}
