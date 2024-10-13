
# Ps3GhidraScripts
A collection of scripts for parsing PS3 executables with Ghidra.

Relocations are not currently supported.

When loading a prx/elf into Ghidra be sure to select the following language (By default this is the one under the automatic selection when the recommended checkbox is disabled)
```
PowerISA-Altivec-64-32addr
```
Make sure to select the BIG endian, otherwise the scripts will throw an error upon running them.

## Installation

These scripts are meant to be used as a Ghidra extension.

Simply grab the .zip in release corresponding to your Ghidra version and install in Ghidra through "File=>Install Extension...".

Make sure the extension is active(there should be a checkmark on the left), scripts should then be accessible in CodeBrowser through "Window=>Script Manager".

## Required change
To avoid issues with decompilation the following change is needed in `Ghidra\Processors\PowerPC\data\languages\ppc_64_32.cspec`

Add `<register name="r2"/>` to the `<unaffected>` list

## Possible problems
Some cell specific instructions are currently not supported in Ghidra, these are the vector store/get lvlx etc, these appear in games and may break decompilation currently.

## AnalyzePs3Binary.java
The main script, this should be used BEFORE analysis is run on the program.

It will then parse the information sections and define imports/exports and name the ones it can from the nids file, and then set the TOC.

After this you should run the auto analysis tool within Ghidra, and then run the syscall define script.

## DefinePs3Syscalls.java
Does what it says on the tin.

Resolves PS3 syscalls to the correct name and defines functions for them.

Should be ran after AnalyzePs3Binary and auto analysis have completed.
