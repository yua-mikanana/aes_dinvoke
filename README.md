# aes_dinvoke
C# Shellcode Launcher - Undetected by Windows Defender 

The program.cs file contains the implementation of the AES encrypter program used in lab 4 of the workshop: https://github.com/mvelazc0/defcon27_csharp_workshop

The program.cs file uses AES encryption and contains a decrypter function that will perform AES decryption on the shellcode during the program execution. The program also uses the typical VirtualAlloc, Marshal.Copy, CreateThread, and WaitForSingleObject combination to allocate memory, write the shellcode into the memory address, and perform execution of the shellcode with CreateThread/WaitForSingle Object.

The program.cs file further implements Dynamic Invoke A.K.A D/Invoke to replace the usage of P/Invoke for the AES shellcode laucher program.

The combination of both AES shellcode encryption and D/Invoke was able to bypass the latest updated Windows Defender on a Windows 11 machine (25/02/2023)

Please refer to the video below for the full details including proof of concept demonstration, setup, and usage guide:
https://www.youtube.com/watch?v=UaOW_OHvvt8

