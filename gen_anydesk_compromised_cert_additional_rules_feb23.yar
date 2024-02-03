/*

Original Ruleset by Florian Roth: https://github.com/Neo23x0/signature-base/blob/master/yara/gen_anydesk_compromised_cert_feb23.yar

His ruleset covered 396 out of 421 malicious files with the AnyDesk certificate, missing 25 malicious files. The ruleset generated 0 false positives on the 560 legitimate AnyDesk files that we know.

I created two new rules based on the ones by Florian Roth to get broader coverage of already known malware that is appending the AnyDesk certificate by two different approaches:

1. Legitimate AnyDesk executables that we are aware of all have the Major Linker Version of 10
2. Legitimate AnyDesk executables that we are aware of all include the string "C:\Buildbot\ad-windows-32\build\release\app-32\win_loader\AnyDesk.pdb"

So we created two rules that will cover all files that include the leaked certificate but do not have Major Linker version of 10 or do not include the string.

The first rule would cover 24 of the 25 previously undetected malicious files. No false positives on the 560 legitimate AnyDesk files that we know have been generated.

The second rule would cover 22 of the 25 previously undetected malicious files. No false positives on the 560 legitimate AnyDesk files that we know have been generated.

*/

import "pe"

rule SUSP_AnyDesk_Compromised_Certificate_Jan24_Linker_Version {
   meta:
      description = "Detects binaries signed with a potentially compromised signing certificate of AnyDesk and binaries where that certificate was appended. Files with Major Linker version 10 will not be detected (the Linker Version used by legitimate AnyDesk files)"
      date = "2024-02-03"
      author = "Maik Morgenstern"
      reference = "https://download.anydesk.com/changelog.txt"
      score = 75
   condition:
      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         pe.signatures[i].serial == "0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8"    
      ) and not
      pe.linker_version.major == 10     
}

rule SUSP_AnyDesk_Compromised_Certificate_Jan24_Build_String {
   meta:
      description = "Detects binaries signed with a potentially compromised signing certificate of AnyDesk and binaries where that certificate was appended. Files that include the String Buildbot\\ad-windows-32 will not be detected (the string is included in legitimate AnyDesk files)"
      date = "2024-02-03"
      author = "Maik Morgenstern"
      reference = "https://download.anydesk.com/changelog.txt"
      score = 75
   strings:
    $a1 = "Buildbot\\ad-windows-32"
   condition:
      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         pe.signatures[i].serial == "0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8"    
      ) and not $a1    
}
