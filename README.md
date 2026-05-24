# BaseREPR-Desktop

**The gold standard** <sub>(not really)</sub> in encryption solutions! The .exe file found in `./x64/Release/BaseREPR-Desktop.exe` works on all 64 bit Windows machines.

Capable of encrypting/decrypting a string containing following characters:
``0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._+!'(%,$/:=*;)?<>@&^%|[]{} `#\\~\t\n``

Note: There are some rare decryption artifacts, probably due to the limited size of unsigned 64-bit integers in C++.
