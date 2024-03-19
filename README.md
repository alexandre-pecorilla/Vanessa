# Vanessa
![ledoc](https://www.gala.fr/imgre/fit/http.3A.2F.2Fprd2-bone-image.2Es3-website-eu-west-1.2Eamazonaws.2Ecom.2Fgal.2F2019.2F09.2F04.2F0194b49f-b003-40e3-9c99-6bce0d17dfaa.2Ejpeg/220x146/quality/80/video-doc-gyneco-s-explique-apres-son-clash-avec-eric-naulleau-la-tension-monte.jpg)

Windows Shellcode Toolset that grows as I learn...

## Overview
```
Vanessa 1.0 Usage Guide
       Basic Commands:
           Encrypt with XOR: Vanessa.exe ex input.bin key
           Encrypt with RC4: Vanessa.exe er input.bin key
           Decrypt with XOR: Vanessa.exe dx input.bin key
           Decrypt with RC4: Vanessa.exe dr input.bin key
       Output Formats:
           Add 'b' for binary output (e.g., Vanessa.exe exb input.bin key)
           Add 'c' for C array output (e.g., Vanessa.exe exc input.bin key)
       Notes:
           'input.bin' must be a file containing binary data, e.g., generated with msfvenom -f raw.
           'key' should be a string used as the password for encryption/decryption, not a file.
```
⚠️ **Watch out:** Make sure `LaBouletteCestDansLaChaussette.dll` is in the same directory than `Vanessa.exe`.

## Releases
Download latest releases [here](https://github.com/alexandre-pecorilla/Vanessa/releases/tag/v1.0.0).

## Features
For now the tool can encrypt/decrypt shellcodes using XOR or RC4 and save the output in a binary file or as a C/C++ byte array.
