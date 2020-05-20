
# Ps3GhidraScripts

A collection of scripts for parsing PS3 executables with Ghidra.

Relocations are not currently supported.

When loading a prx/elf into Ghidra be sure to select the following language (By default this is the one under the automatic selection when the recommended checkbox is disabled)
```
PowerPC:BE:64:A2ALT-32addr:default
```

## AnalyzePs3Binary.java
The main script, this should be used BEFORE analysis is run on the program.
This will ask for the location of the nids.txt file.
It will then parse the infomation sections and define imports/exports and name the ones it can from the nids file, and then set the TOC.

After this you should run the auto analysis tool within ghidra, and then run the syscall define script.

## DefinePs3Syscalls.java
Does what it says on the tin, resolves ps3 syscalls to the correct name and defines functions for them, should be ran after AnalyzePs3Binary and auto analysis have completed.

