# rtlreadlog
Alternative for the Realtek RTL8762A, RTL8762C, RTL8763B and RTL8761ATT Log Debug Analyzer on Linux.

I wrote this program because the vendor's DebugAnalyzer doesn't work on Mono or Wine with .NET installed.

## Compile
Install `libserialport0`, `libserialport-dev`, then
```
gcc rtlreadlog.c -O3 -lserialport -o rtlreadlog
```
The file `rtlreadlog` is a compiled program for Linux (amd64).

## Notes
- Limitation: Only messages printed by the APP using macros documented in the SDK User Guide can be read by this program;
- Floating-point numbers can only be printed by `DBG_DIRECT` which influences the performance of the MCU program; (the same as DebugAnalyzer)
- Maximum printing speed is about the same as DebugAnalyzer, probably it cannot not be improved by a multi-thread design, so this program is designed as single-threaded.
