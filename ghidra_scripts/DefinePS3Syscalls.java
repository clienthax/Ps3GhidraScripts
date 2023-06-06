/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Uses overriding references and the symbolic propogator to resolve system calls
//@category Analysis

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;


public class DefinePS3Syscalls extends GhidraScript {

    // disassembles to "CALL dword ptr GS:[0x10]"
    private static final byte[] ppc64_bytes = {0x44, 0x00, 0x00, 0x02};

    private static final String powerPC = "PowerPC";

    private static final String SYSCALL_SPACE_NAME = "SYSCALLS";

    private static final int SYSCALL_SPACE_LENGTH = 1024; // 0x10000

    // tests whether an instruction is making a system call
    private Predicate<Instruction> tester;

    // register holding the syscall number
    private String syscallRegister;

    /**
     * Checks whether an instruction is a system call
     *
     * @param inst instruction to check
     * @return true precisely when the instruction is a system call
     */
    private static boolean checkInstruction(Instruction inst) {
        try {
            return Arrays.equals(ppc64_bytes, inst.getBytes());
        } catch (MemoryAccessException e) {
            Msg.info(DefinePS3Syscalls.class, "MemoryAccessException at " + inst.getAddress().toString());
            return false;
        }
    }

    @Override
    protected void run() throws Exception {

        if (!(currentProgram.getExecutableFormat().equals(ElfLoader.ELF_NAME) &&
                currentProgram.getLanguage().getProcessor().toString().equals(powerPC))) {
            popup("This script is intended for PS3 files");
            return;
        }

        final Address syscallTableAddr = currentProgram.getAddressFactory().getAddress("0x8000000");
        MemoryBlock syscallBlock = currentProgram.getMemory().getBlock(SYSCALL_SPACE_NAME);
        if (syscallBlock == null) {
            syscallBlock = MemoryBlockUtils.createUninitializedBlock(currentProgram, false, SYSCALL_SPACE_NAME, syscallTableAddr, SYSCALL_SPACE_LENGTH, "PS3 Syscalls", null, true, true, true, null);
        }

        //determine whether the executable is 32 or 64 bit and set fields appropriately
        tester = DefinePS3Syscalls::checkInstruction;
        syscallRegister = "r11";
        // datatype archive containing signature of system calls
        String datatypeArchiveName = "generic_clib";
        // file containing map from syscall numbers to syscall names
        // note that different architectures can have different system call numbers, even
        // if they're both Linux...
        String syscallFileName = "ps3_syscall_numbers";
        // the type of overriding reference to apply
        RefType overrideType = RefType.CALLOTHER_OVERRIDE_CALL;
        // the calling convention to use for system calls (must be defined in the appropriate .cspec file)
        String callingConvention = "__stdcall";//syscall type not supported :|

        //get the space where the system calls live.
        //If it doesn't exist, create it.
        AddressSpace syscallSpace = syscallTableAddr.getAddressSpace();

        //get all of the functions that contain system calls
        //note that this will not find system call instructions that are not in defined functions
        Map<Function, Set<Address>> funcsToCalls = getSyscallsInFunctions(currentProgram, monitor);
        printf("FGound %d syscalls callers\n", funcsToCalls.size());

        if (funcsToCalls.isEmpty()) {
            printf("No system calls found (within defined functions)\n");
            return;
        }

        //get the system call number at each callsite of a system call.
        //note that this is not guaranteed to succeed at a given system call call site -
        //it might be hard (or impossible) to determine a specific constant
        Map<Address, Long> addressesToSyscalls = resolveConstants(funcsToCalls, currentProgram, monitor);

        if (addressesToSyscalls.isEmpty()) {
            popup("Couldn't resolve any syscall constants");
            return;
        }

        //get the map from system call numbers to system call names
        //you might have to create this yourself!
        Map<Long, String> syscallNumbersToNames = getSyscallNumberMap();

        for (long i = 1; i < 990; i++) {
            if (syscallNumbersToNames.get(i) == null) {
                //println("Missing mapping for syscall "+i);
            }

        }

        //at each system call call site where a constant could be determined, create
        //the system call (if not already created), then add the appropriate overriding reference
        //use syscallNumbersToNames to name the created functions
        //if there's not a name corresponding to the constant use a default
        for (Entry<Address, Long> entry : addressesToSyscalls.entrySet()) {
            Address callSite = entry.getKey();//sc instruction location
            Long offset = entry.getValue();
            Address callTarget = syscallBlock.getStart().add(offset);//syscall addr
            Function callee = currentProgram.getFunctionManager().getFunctionAt(callTarget);//syscall func
            if (callee == null) {//For testing
                String funcName = "syscall_" + String.format("%08X", offset);
                if (syscallNumbersToNames.get(offset) != null) {
                    funcName = syscallNumbersToNames.get(offset);
                }

                //printf("meh\n");
                //printf("meh %s\n", funcName);

                if (funcName.startsWith("syscall_")) {
                    println("Couldnt find mapping for " + funcName);
                }

                callee = createFunction(callTarget, "syscall_" + funcName);
                if (callee == null) {
                    printf("Something went wrong up at " + callSite + " syscall " + callTarget + " \n");
                    continue;
                }
                callee.setCallingConvention(callingConvention);
            }
            Reference ref = currentProgram.getReferenceManager().addMemoryReference(callSite,
                    callTarget, overrideType, SourceType.USER_DEFINED, Reference.MNEMONIC);

            //overriding references must be primary to be active
            currentProgram.getReferenceManager().setPrimary(ref, true);


        }

        //finally, open the appropriate data type archive and apply its function data types
        //to the new system call space, so that the system calls have the correct signatures
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
        DataTypeManagerService service = mgr.getDataTypeManagerService();
        List<DataTypeManager> dataTypeManagers = new ArrayList<>();

        final DataTypeManager e1 = service.openDataTypeArchive(datatypeArchiveName);
        dataTypeManagers.add(e1);

        dataTypeManagers.add(currentProgram.getDataTypeManager());
        ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(dataTypeManagers,
                new AddressSet(syscallSpace.getMinAddress(), syscallSpace.getMaxAddress()),
                SourceType.USER_DEFINED, false, false);
        cmd.applyTo(currentProgram);

    }

    // TODO: better error checking!
    private Map<Long, String> getSyscallNumberMap() {
        Map<Long, String> syscallMap = new HashMap<>();
        File file = new File(Ps3ElfUtils.getExtensionInstallDataPath("Ps3GhidraScripts"), "data/syscall.txt");
        if (!file.exists()) {
            try {
                file = askFile("Locate syscall.txt", "Accept");
            } catch (Exception e) {
                Msg.showError(this, null, "Error reading syscall map file", e.getMessage(), e);
                return syscallMap;
            }
        }
        try (FileReader fReader = new FileReader(file); BufferedReader bReader = new BufferedReader(fReader)) {
            String line;
            while ((line = bReader.readLine()) != null) {
                //lines starting with # are comments
                if (!line.startsWith("#")) {
                    String[] parts = line.trim().split(" ");
                    Long number = Long.parseLong(parts[0]);
                    syscallMap.put(number, parts[1]);
                }
            }
        } catch (IOException e) {
            Msg.showError(this, null, "Error reading syscall map file", e.getMessage(), e);
        }
        return syscallMap;
    }

    /**
     * Scans through all of the functions defined in {@code program} and returns
     * a map which takes a function to the set of address in its body which contain
     * system calls
     *
     * @param program  program containing functions
     * @param tMonitor monitor
     * @return map function -> addresses in function containing syscalls
     * @throws CancelledException if the user cancels
     */
    private Map<Function, Set<Address>> getSyscallsInFunctions(Program program, TaskMonitor tMonitor) throws CancelledException {


        Map<Function, Set<Address>> funcsToCalls = new HashMap<>();
        for (Function func : program.getFunctionManager().getFunctionsNoStubs(true)) {
            tMonitor.checkCanceled();
            AddressSetView functionAddressRange = func.getBody();
            if (functionAddressRange.getMinAddress().equals(functionAddressRange.getMaxAddress())) {
                println("Function " + func.getName() + " at " + func.getEntryPoint() + " Doesn't look like its defined correctly :c .. (Try clear flow and repair!)");
            }
            for (Instruction inst : program.getListing().getInstructions(functionAddressRange, true)) {
                if (tester.test(inst)) {
                    Set<Address> callSites = funcsToCalls.get(func);
                    if (callSites == null) {
                        callSites = new HashSet<>();
                        funcsToCalls.put(func, callSites);
                    }
                    callSites.add(inst.getAddress());
                }
            }
        }
        return funcsToCalls;
    }

    /**
     * Uses the symbolic propogator to attempt to determine the constant value in
     * the syscall register at each system call instruction
     *
     * @param funcsToCalls map from functions containing syscalls to address in each function of
     *                     the system call
     * @param program      containing the functions
     * @return map from addresses of system calls to system call numbers
     * @throws CancelledException if the user cancels
     */
    private Map<Address, Long> resolveConstants(Map<Function, Set<Address>> funcsToCalls, Program program, TaskMonitor tMonitor) throws CancelledException {
        // Sometimes this doesn't find all SC's :|
        Map<Address, Long> addressesToSyscalls = new HashMap<>();
        Register syscallReg = program.getLanguage().getRegister(syscallRegister);
        for (Function func : funcsToCalls.keySet()) {
            Address start = func.getEntryPoint();
            ContextEvaluator eval = new ConstantPropagationContextEvaluator(tMonitor, true);
            SymbolicPropogator symEval = new SymbolicPropogator(program);
            symEval.flowConstants(start, func.getBody(), eval, true, tMonitor);
            for (Address callSite : funcsToCalls.get(func)) {
                Value val = symEval.getRegisterValue(callSite, syscallReg);
                if (val == null) {
                    createBookmark(callSite, "System Call",
                            "Couldn't resolve value of " + syscallReg);
                    printf("Couldn't resolve value of " + syscallReg + " at " + callSite + "\n");
                    continue;
                }
                addressesToSyscalls.put(callSite, val.getValue());
            }
        }
        return addressesToSyscalls;
    }

}