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
- Only messages print by the APP can be shown;
- I do not know if there is a checksum (1B) in each message and how is it calculated if it exists;
- Floating-point numbers cannot be printed directly (the same as DebugAnalyzer)
- Maximum printing speed is about the same as DebugAnalyzer and might not be improved by multi-thread handling, thus this program is single-threaded.
