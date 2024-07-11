# windoh

This is a PoC dropper for a payload obfuscation technique whereby the payload is stored in DNS A records. This program uses Win32 functions to make DNS-Over-HTTPS to a self hosted BIND9 server that has your payload staged as A records for the specified domain.
