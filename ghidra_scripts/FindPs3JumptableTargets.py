# Finds jumptable targets for PS3 jumptables (generated for C 'switch'es) and adds
# refs to the indirect jump instruction so that decompilation for the cases is present
# (instead of Ghidra complaining with an error in the switch as it often does).
# Select the block with the address offsets before running (first mark them all as
# addresses with `P` and `[`).
# After you run this you'll probably want to select the indirect jump instruction
# (usually `bctr`) and run the SwitchOverride.java script.

#@author VelocityRa
#@category Repair
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.symbol import RefType

start = currentSelection.minAddress

instr = getInstructionBefore(start)
print(instr)

for i in range(currentSelection.getNumAddresses() / 4):
	data = getDataAt(currentSelection.minAddress).getComponentAt(i*4) 
	addr = start.addWrapSpace(data.value.offset)
	print(addr, data)
	data.removeValueReference(data.value)
	data.addValueReference(addr, RefType.DATA)

	createMemoryReference(instr, 0, addr, RefType.COMPUTED_JUMP)

#	createBookmark(addr, "FindJumptableTargetsMine.py", "target for " + str(start))