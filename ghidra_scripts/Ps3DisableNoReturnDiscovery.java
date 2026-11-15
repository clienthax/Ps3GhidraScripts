// Turns off Ghidra's "Non-Returning Functions - Discovered" analyzer for this program.
// On gcc/PS3 code it marks functions such as operator new, getters and math helpers as non-returning,
// which cuts the flow after every call to them and truncates the decompiled callers.
// Run it before auto analysis (headless: -preScript Ps3DisableNoReturnDiscovery.java).
//@category Analysis

import ghidra.app.script.GhidraScript;

public class Ps3DisableNoReturnDiscovery extends GhidraScript {
    @Override
    protected void run() throws Exception {
        setAnalysisOption(currentProgram, "Non-Returning Functions - Discovered", "false");
        println("Disabled analyzer: Non-Returning Functions - Discovered");
    }
}
