# rtlreadlog
Alternative for the Realtek RTL8762x Log Debug Analyzer on Linux.

I wrote this program because the vendor's DebugAnalyzer doesn't work on Mono or Wine with .NET installed.

## Compile
Install `libserialport0`, `libserialport-dev`, then
```
gcc rtlreadlog.c -O3 -lserialport -o rtlreadlog
```

## Notes
- Only messages printed by the APP using macros documented in the SDK User Guide can be read by this program. Currently DSP App trace data is ignored. All data not from the APP is ignored because the vendor has not made those corresponding trace files publicly available.
- Floating-point numbers must be printed by `DBG_DIRECT` which influences the performance of the MCU program. (the same as DebugAnalyzer)
- Maximum printing speed is about the same as DebugAnalyzer, probably it cannot not be improved by a multi-thread design, so this program is designed as single-threaded.
