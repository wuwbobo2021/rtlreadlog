# rtlreadlog
Alternative for RTL8762A, RTL8762C, RTL8763B and RTL8761ATT Log Debug Analyzer on Linux.

I wrote this program because the vendor's DebugAnalyzer doesn't work on Mono or Wine with .NET installed.

## Compile
Install `libserialport0`, `libserialport-dev`, then
```
gcc rtlreadlog.c -O3 -lserialport -o rtlreadlog
```
The file `rtlreadlog` is a compiled program for Linux (amd64).

## Limitations
- Only messages printed by the APP using macros documented in the SDK User Guide can be read by this program;
- Floating-point numbers cannot be printed directly. (the same as DebugAnalyzer)
- Maximum printing speed is about the same as DebugAnalyzer and might not be improved by multi-thread handling, thus this program is single-threaded.
