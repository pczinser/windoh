# windoh

This is a PoC dropper for a payload obfuscation technique whereby the payload is stored in DNS A records. This program uses Win32 functions to make DNS-Over-HTTPS to a self hosted BIND9 server that has your payload staged as A records for the specified domain.

I have a BIND9 server hardcoded into the project currently with a msfvenom calc.exe payload staged as the A records for exmaple.com. You can build this solution in releasee mode. Go through the prompts and a calc.exe window will pop up without any alerts on Windows Defender.
