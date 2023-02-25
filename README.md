# aes_dinvoke
a repository that contains the program.cs source file for the youtube video https://www.youtube.com.

The program.cs file contains the implementation of the AES encrypter program used in lab 4 of the workshop: https://github.com/mvelazc0/defcon27_csharp_workshop
The program.cs file further implements Dynamic Invoke AKA D/Invoke to replace the usage of P/Invoke for the AES shellcode laucher program.

The combination of both AES shellcode encryption and D/Invoke was able to bypass the latest updated Windows Defender on a Windows 11 machine (25/02/2023)

Please refer to the video below for the full details including proof of concept demonstration, setup, and usage guide:
