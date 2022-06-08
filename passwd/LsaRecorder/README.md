
# LsaRecorder
```Hook LsaApLogonUserEx2 to recording winlogon password.```

### History
Many years ago, I focus in LSA research and reverse winlogon authentification.

This tool record password winlogon and store file or other network location.

### Usage
```
Usage:
        LsaRecorder.exe [-r location] [-ar location] [-ur]
Options:
        -r  LOCATION : Record Logon Password to Disk.Namepipe.Mailslot
        -ar LOCATION : Record Logon Password Whether logon success or not.
        -ur          : Uninstall Record Logon Password
```

### Requirements
- Works on WinXP/7/10/11 (x86/x64)
- Build with Visual Studio 2010+
- According target OS archtecture, build x86/x64 binary respectively.
- UAC elevated required.

### Reference
- https://bbs.pediy.com/thread-251888.htm