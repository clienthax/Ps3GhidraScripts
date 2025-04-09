import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;
import java.util.Collections;

@SuppressWarnings("unused")
public class AnalyzePs3Binary extends GhidraScript {

    private Ps3ElfUtils utils = null;

    protected void run() throws Exception {
        // Create Ps3 data structure types
        Ps3DataStructureTypes.createStructureTypes();

        // Initialise utils
        utils = new Ps3ElfUtils(this, currentProgram);

        // Process program
        process();
    }

    private void handlePrx() throws Exception {
        println("Processing PRX");
        createModuleInfo();
    }

    private void handleExec() throws Exception {
        println("Processing EXEC");

        final Data elfData = getDataAt(utils.getElfHeader().getStart());
        final long elfEntryPtr = elfData.getComponent(11).getLong(0); // e_entry
        printf("e_entry: %X\n", elfEntryPtr);

        Address opdAddress = currentAddress.getNewAddress(0);
        long opdSize = 0;
        boolean foundOpd = false;


        // Heuristic to find OPD section: we assume it's the one that the entry point
        // pointer is in
        for (int i = 1; i < utils.getSections().size(); ++i) {
            if (elfEntryPtr < utils.getSections().get(i).getvAddr()) {
                final ElfSection opdSection = utils.getSections().get(i - 1);
                opdAddress = currentAddress.getNewAddress(opdSection.getvAddr());
                opdSize = opdSection.getSize();

                foundOpd = true;
                break;
            }
        }
        if (!foundOpd) {
            println("Could not find OPD");
        }

        printf("OPD: %X\n", opdAddress.getOffset());

        final Address firstTocBaseAddr = opdAddress.add(4);

        utils.applyDataForce(Pointer32DataType.dataType, "tocPtr", opdAddress);
        createData(firstTocBaseAddr, Pointer32DataType.dataType);

        final Address elfEntryPtrAddr = currentAddress.getNewAddress(elfEntryPtr);
        createData(elfEntryPtrAddr, Pointer32DataType.dataType);

        final Address elfEntry = (Address) getDataAt(elfEntryPtrAddr).getValue();
        addFunction(elfEntry, "_start");

        // Sometimes there are multiple tocs.., we should use the toc in the opd to define the r2 value
        final int tocBase = (int) getDataAt(firstTocBaseAddr).getAddress(0).getOffset();
        printf("TOC: %X\n", tocBase);

        applyProcessInfo();

        if (foundOpd) {
            createFunctionsFromOPD(opdAddress, opdSize);
        }

        // TODO force analysis for opd functions then set r2
        setR2(tocBase);
    }

    private void process() throws Exception {

        if(utils.loadingPrx()) {
            handlePrx();
        } else if(utils.loadingExec()) {
            handleExec();
        } else {
            println("Unknown program detected type: "+String.format("0x%08X", utils.findPs3ProgramType()));
        }
    }

    private void applyProcessInfo() throws Exception {// https://github.com/aerosoul94/ida_gel/blob/master/src/ps3/cell_loader.cpp#L669
        final Address phdrArrayAddress = utils.getPhdrArrayAddress();
        println("Reading PHDR array at "+phdrArrayAddress);
        final Data phdr_array = getDataAt(phdrArrayAddress);
        println(phdr_array.getDataType()+"");

        for (int i = 0; i < phdr_array.getNumComponents(); i++) {
            println("phdr "+i);

            final Data phdr = phdr_array.getComponent(i);

            final int p_type = phdr.getComponent(0).getInt(0);
            long p_vaddr = phdr.getComponent(3).getLong(0);
            long p_filesz = phdr.getComponent(5).getLong(0);

            if (p_type == Ps3ElfUtils.PT_PROC_PARAM) {
                println("TODO sys_process_param_t");

                if(p_vaddr == 0) {
                    // TODO psp stuff seems blanked, possibly same with vsh
                    println("Section seems blanked, ignoring");
                    continue;
                }

                final Address newAddress = currentAddress.getNewAddress(p_vaddr);
                println("Applying sys_process_param_t to "+newAddress);
                utils.applyStruct(Ps3DataStructureTypes.sysProcessParamTDataType, newAddress);

            } else if(p_type == Ps3ElfUtils.PT_PROC_PRX) {
                // VSH has this segment zeroed and stripped.
                if(p_filesz == 0) {
                    findImports();
                    findExports();
                } else {
                    final Address newAddress = currentAddress.getNewAddress(p_vaddr);
                    println("Applying sys_process_prx_info_t to "+newAddress);
                    utils.applyStruct(Ps3DataStructureTypes.sysProcessPrxInfoTDataType, newAddress);
                    createImportStubsFromPrxInfo(newAddress);
                    createExportEntsFromPrxInfo(newAddress);

                }

            }

            println();
        }

        Collections.sort(utils.getSections());
    }

    private void addFunction(Address funcStart) throws Exception {
        addFunctionImpl(funcStart, "");
    }

    private void addFunction(Address funcStart, @SuppressWarnings("SameParameterValue") String funcName) throws Exception {
        addFunctionImpl(funcStart, funcName);
    }

    private void addFunctionImpl(Address funcStart, String funcName) throws Exception {
        if (!disassemble(funcStart)) {
            printf("failed to disasm at %X\n", funcStart.getOffset());
            return;
        }
        if (getFunctionAt(funcStart) == null) {
            Function func = createFunction(funcStart, null);
            if (func == null) {
                printf("failed to create func at %X\n", funcStart.getOffset());
            } else if (!funcName.equals("")) {
                func.setName(funcName, SourceType.ANALYSIS);
            }
        }
    }

    private void createFunctionsFromOPD(Address opdAddr, long opdSize) throws Exception {
        Address addr = opdAddr;

        for (long i = 0; i < opdSize; i += 8) {
            final Address funcAddressPtr = opdAddr.add(i);
            utils.applyDataForce(Pointer32DataType.dataType, "", funcAddressPtr);
            Data data = getDataAt(funcAddressPtr);
            Address funcAddress = (Address) data.getValue();
            addFunction(funcAddress);

            final Address funcTocAddress = opdAddr.add(i + 4);
            utils.applyDataForce(Pointer32DataType.dataType, "", funcTocAddress);
        }
    }

    private void findExports() throws Exception {
        boolean found = false;

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }

            if(block.getSize() < 0x1C * 2) {
                if(block.getSize() == 0x1C) {
                    final int structSize = block.getByte(block.getStart()) & 0xff;
                    if(structSize == 0x1C) {
                        createImportStubsFromMemoryBlock(block);
                        found = true;
                        break;
                    }
                }
                continue;
            }

            final Address sectaddr = block.getStart();
            final int structsize = block.getByte(sectaddr) & 0xff;
            if(structsize > block.getSize()) {
                continue;
            }

            final int structsize2 = block.getByte(sectaddr.add(structsize)) & 0xff;
            if(structsize == structsize2) {
                if(structsize == 0x1C) {
                    createExportEntsFromMemoryBlock(block);
                    found = true;
                }
            }
        }

        if(!found) {
            printf("Couldn't find exports\n");
        }
    }

    private void findImports() throws Exception {

        boolean found = false;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }

            if(block.getSize() < 0x2c * 2) {
                if(block.getSize() == 0x2c) {
                    final int structsize = block.getByte(block.getStart()) & 0xff;
                    if(structsize == 0x2c) {
                        createImportStubsFromMemoryBlock(block);
                        found = true;
                        break;
                    }
                }
                continue;
            }

            final Address sectaddr = block.getStart();
            final int structsize = block.getByte(sectaddr) & 0xff;
            if(structsize > block.getSize()) {
                continue;
            }

            final int structsize2 = block.getByte(sectaddr.add(structsize)) & 0xff;
            if(structsize == structsize2) {
                if(structsize == 0x2C) {
                    createImportStubsFromMemoryBlock(block);
                    found = true;
                    break;
                }
            }
        }

        if(!found) {
            printf("Couldn't find imports\n");
        }

    }

    private void createModuleInfo() throws Exception {
        // Try and get elf header (why isnt this exposed as a getter..)
        final MemoryBlock elfProgramHeaders = currentProgram.getMemory().getBlock("_elfProgramHeaders");
        final Address start = elfProgramHeaders.getStart();
        final Data dataAt = getDataAt(start);
        if (!dataAt.isArray()) {
            println("Expected data array");
            return;
        }
        final Data firstProgHeader = dataAt.getComponent(0);//Get first program header
        final long p_offset = firstProgHeader.getLong(0x8);
        final long p_paddr = firstProgHeader.getLong(0x18);

        final long module_info_offset = p_paddr - p_offset;

        final Address module_info_addr = currentAddress.getNewAddress(module_info_offset);
        utils.applyStruct(Ps3DataStructureTypes.sceModuleInfoPpu32DataType, module_info_addr);

        printf("module_info offset = 0x%X\n", module_info_offset);

        createExportEntsFromModuleInfo(module_info_addr);
        createImportStubsFromModuleInfo(module_info_addr);

        setR2FromModuleInfo(module_info_addr);

    }

    private void setR2FromModuleInfo(Address module_info_addr) throws Exception {
        final Data module_info = getDataAt(module_info_addr);
        final int gp_value = module_info.getComponent(1).getInt(0);//gp_value
        setR2(gp_value);
    }

    private void setR2(int toc) throws Exception {
        final Register r2 = currentProgram.getProgramContext().getRegister("r2");

        // TODO find the correct segment to mark and use opd toc values
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            currentProgram.getProgramContext().setRegisterValue(block.getStart(), block.getEnd(), new RegisterValue(r2, new BigInteger(""+toc)));
        }

        createLabel(currentAddress.getNewAddress(toc), "TOC_BASE", true);
        printf("Toc / R2 set to 0x%08X\n", toc);
    }

    //ELFs generally have one section entirely of imports
    private void createImportStubsFromMemoryBlock(MemoryBlock block) throws Exception {
        final long stub_count = block.getSize() / Ps3DataStructureTypes.sceLibStubPpu32DataType.getLength();
        println("Entries = "+stub_count+" size="+block.getSize()+" struct_size="+Ps3DataStructureTypes.sceLibStubPpu32DataType.getLength());
        if(stub_count == 0) {
            println("No imports");
            return;
        }

        createImportStubs(block.getStart(), (int) stub_count);
    }

    //For PRXs that contain module info
    private void createImportStubsFromModuleInfo(Address module_info_addr) throws Exception {
        final Data module_info = getDataAt(module_info_addr);
        final long stub_top = module_info.getComponent(4).getInt(0);
        final long stub_end = module_info.getComponent(5).getInt(0);
        final long stub_size = stub_end - stub_top;
        final long stub_count = stub_size / Ps3DataStructureTypes.sceLibStubPpu32DataType.getLength();

        println("Entries = "+stub_count+" size="+stub_size+" struct_size="+Ps3DataStructureTypes.sceLibStubPpu32DataType.getLength());

        if(stub_count == 0) {
            //Can happen, eg libL10n
            println("No imports");
            return;
        }

        createImportStubs(currentAddress.getNewAddress(stub_top), (int) stub_count);
    }

    private void createImportStubsFromPrxInfo(Address prxInfo_addr) throws Exception {
        final Data sys_process_prx_info_t = getDataAt(prxInfo_addr);
        final long stub_top = sys_process_prx_info_t.getComponent(6).getInt(0);
        final long stub_end = sys_process_prx_info_t.getComponent(7).getInt(0);
        final long stub_size = stub_end - stub_top;
        final long stub_count = stub_size / Ps3DataStructureTypes.sceLibStubPpu32DataType.getLength();
        println("Entries = "+stub_count+" size="+stub_size+" struct_size="+Ps3DataStructureTypes.sceLibStubPpu32DataType.getLength());
        if(stub_count == 0) {
            println("No imports");
            return;
        }

        createImportStubs(currentAddress.getNewAddress(stub_top), (int) stub_count);
    }

    private void createImportStubsFromRange(Address start, Address end) throws Exception {
        final long stub_count = (end.getOffset() - start.getOffset()) / Ps3DataStructureTypes.sceLibStubPpu32DataType.getLength();
        if(stub_count == 0) {
            println("No imports");
            return;
        }

        createImportStubs(start, (int) stub_count);

    }

    private void createImportStubs(Address start_addr, int stub_count) throws Exception {

        utils.applyStructArray(Ps3DataStructureTypes.sceLibStubPpu32DataType, stub_count, start_addr);

        // TODO loop through and mark the entries with the lib name etc?
        // TODO mark fnids / pointer tables

        final Data libStubArray = getDataAt(start_addr);//sceLibStubPpu32DataType array
        for (int i = 0; i < libStubArray.getNumComponents(); i++) {
            final Data libStubData = libStubArray.getComponent(i);
            printf("\n");
            printf("libStubData addr 0x%S\n", libStubData.getAddress());
            final long namePtr = libStubData.getComponent(1).getInt(0);//libname ptr
            final long funcNidTablePtr = libStubData.getComponent(2).getInt(0);
            final long funcTablePtr = libStubData.getComponent(3).getInt(0);
            final long varNidTablePtr = libStubData.getComponent(4).getInt(0);
            final long varTablePtr = libStubData.getComponent(5).getInt(0);
            final long tlsNidTablePtr = libStubData.getComponent(6).getInt(0);
            final long tlsTablePtr = libStubData.getComponent(7).getInt(0);

            String libname = "NONAME";
            if(namePtr != 0) {
                final Address namePtr_ = currentAddress.getNewAddress(namePtr);
                removeDataAt(namePtr_);// TODO check for string
                createData(namePtr_, StringDataType.dataType);
                libname = (String) getDataAt(namePtr_).getValue();
            }
            printf("Import:");
            printf("Library name: %s\n", libname);
            printf("Func Nid table: 0x%X\n", funcNidTablePtr);
            printf("Func table: 0x%X\n", funcTablePtr);
            printf("Var Nid table: 0x%X\n", varNidTablePtr);
            printf("Var table: 0x%X\n", varTablePtr);
            printf("TLS Nid table: 0x%X\n", tlsNidTablePtr);
            printf("TLS table: 0x%X\n", tlsTablePtr);

            //Create import library
            if (currentProgram.getSymbolTable().getExternalSymbol(libname) == null) {
                currentProgram.getSymbolTable().createExternalLibrary(libname, SourceType.ANALYSIS);
            }

            final Data common = libStubData.getComponent(0);
            final int num_func = common.getComponent(4).getUnsignedShort(0);
            final int num_var = common.getComponent(5).getUnsignedShort(0);
            final int num_tlsvar = common.getComponent(6).getUnsignedShort(0);
            final int totalNids = num_func + num_var + num_tlsvar;

            printf("num_func: %d\n", num_func);
            printf("num_var: %d\n", num_var);
            printf("num_tlsvar: %d\n", num_tlsvar);

            // TODO name these
            if(num_func != 0) {
                // Create func nid table
                final Address nidTableAddress = currentAddress.getNewAddress(funcNidTablePtr);
                utils.applyDataForce(new ArrayDataType(IntegerDataType.dataType, num_func, 1), libname+"_func_nid_table", nidTableAddress);
                // Create var address table
                final Address addressTableAddress = currentAddress.getNewAddress(funcTablePtr);
                utils.applyDataForce(new ArrayDataType(Pointer32DataType.dataType, num_func, 1), libname+"_func_address_table", addressTableAddress);

                // Label fnid references
                final Data nidArray = getDataAt(nidTableAddress);
                final Data funcAddrArray = getDataAt(addressTableAddress);
                for (int j = 0; j < num_func; j++) {
                    int fnid = nidArray.getComponent(j).getInt(0);
                    final String fnid_name = FnidUtils.getNameForFnid(this, libname, fnid);

                    // Create fnid label
                    createLabel(nidArray.getComponent(j).getAddress(), "FNID_"+fnid_name, true);

                    // Create func label
                    final Address funcAddress = currentAddress.getNewAddress(funcAddrArray.getComponent(j).getInt(0));
                    final Function functionAt = getFunctionAt(funcAddress);
                    if(functionAt != null) {
                        //functionAt.setName(libname+"::"+fnid_name, SourceType.ANALYSIS);
                        if(!functionAt.getName().equals(fnid_name)) {
                            functionAt.setName(fnid_name, SourceType.ANALYSIS);
                        }
                    } else {
                        createFunction(funcAddress, fnid_name);
                    }


                    // Create import TODO see if its possible to remap the stubs to the external, ideally we can just use a call override to point at the external directly o.o
                    currentProgram.getExternalManager().addExtFunction(libname, fnid_name, null, SourceType.ANALYSIS);

                }



            }

            if(num_var != 0) {
                // Create var nid table
                final Address nidTableAddress = currentAddress.getNewAddress(varNidTablePtr);
                utils.applyDataForce(new ArrayDataType(IntegerDataType.dataType, num_var, 1), libname+"_var_nid_table", nidTableAddress);
                // Create var address table
                final Address addressTableAddress = currentAddress.getNewAddress(varTablePtr);
                utils.applyDataForce(new ArrayDataType(Pointer32DataType.dataType, num_var, 1), libname+"_var_address_table", addressTableAddress);

                // Label nid references
                final Data nidArray = getDataAt(nidTableAddress);
                final Data funcAddrArray = getDataAt(addressTableAddress);
                for (int j = 0; j < num_var; j++) {
                    int fnid = nidArray.getComponent(j).getInt(0);
                    final String fnid_name = FnidUtils.getNameForFnid(this, libname, fnid);

                    // Create nid label
                    createLabel(nidArray.getComponent(j).getAddress(), "FNID_"+fnid_name, true);

                    // Create var label
                    final Address varAddress = currentAddress.getNewAddress(funcAddrArray.getComponent(j).getInt(0));
                    // TODO HMMM, how do we determine the datatype?
                    createLabel(varAddress, libname+"::"+fnid_name, true);
                }
            }

            if(num_tlsvar != 0) {
                // Create tls var nid table
                utils.applyDataForce(new ArrayDataType(IntegerDataType.dataType, num_tlsvar, 1), libname+"_tls_var_nid_table", currentAddress.getNewAddress(tlsNidTablePtr));
                // Create tls var address table
                utils.applyDataForce(new ArrayDataType(Pointer32DataType.dataType, num_tlsvar, 1), libname+"_tls_var_address_table", currentAddress.getNewAddress(tlsTablePtr));
            }

            printf("\n");

        }
    }

    private void createExportEntsFromMemoryBlock(MemoryBlock block) throws Exception {
        final long ent_count = block.getSize() / Ps3DataStructureTypes.sceLibEntPpu32DataType.getLength();
        println("Entries = "+ent_count+" size="+block.getSize()+" struct_size="+Ps3DataStructureTypes.sceLibEntPpu32DataType.getLength());
        if(ent_count == 0) {
            println("No exports");
            return;
        }

        createExportEnts(block.getStart(), (int) ent_count);
    }

    private void createExportEntsFromModuleInfo(Address module_info_addr) throws Exception {
        final Data module_info = getDataAt(module_info_addr);
        final long ent_top = module_info.getComponent(2).getInt(0);
        final long ent_end = module_info.getComponent(3).getInt(0);
        final long ent_size = ent_end - ent_top;
        final long ent_count = ent_size / Ps3DataStructureTypes.sceLibEntPpu32DataType.getLength();

        println("Entries = "+ent_count+" size="+ent_size+" struct_size="+Ps3DataStructureTypes.sceLibEntPpu32DataType.getLength());

        createExportEnts(currentAddress.getNewAddress(ent_top), (int) ent_count);
    }

    private void createExportEntsFromPrxInfo(Address prxInfo_addr) throws Exception {
        final Data sys_process_prx_info_t = getDataAt(prxInfo_addr);
        final long ent_top = sys_process_prx_info_t.getComponent(4).getInt(0);
        final long ent_end = sys_process_prx_info_t.getComponent(5).getInt(0);
        final long ent_size = ent_end - ent_top;
        final long ent_count = ent_size / Ps3DataStructureTypes.sceLibEntPpu32DataType.getLength();
        println("Entries = "+ent_count+" size="+ent_size+" struct_size="+Ps3DataStructureTypes.sceLibEntPpu32DataType.getLength());
        if(ent_count == 0) {
            println("No exports");
            return;
        }

        createExportEnts(currentAddress.getNewAddress(ent_top), (int) ent_count);
    }

    private void createExportEntsFromRange(Address start, Address end) throws Exception {
        final long stub_count = (end.getOffset() - start.getOffset()) / Ps3DataStructureTypes.sceLibEntPpu32DataType.getLength();
        if(stub_count == 0) {
            println("No exports");
            return;
        }

        createExportEnts(start, (int) stub_count);

    }

    private void createExportEnts(Address start_addr, int exportCount) throws Exception {//Exports


        final Address ent_top_addr = start_addr;
        utils.applyStructArray(Ps3DataStructureTypes.sceLibEntPpu32DataType, exportCount, ent_top_addr);

        //TODO loop through and mark the entries with the lib name etc?
        //TODO mark fnids / pointer tables

        final Data libEntArray = getDataAt(ent_top_addr);//_scelibent_ppu32 array
        for (int i = 0; i < libEntArray.getNumComponents(); i++) {
            final Data libEntData = libEntArray.getComponent(i);
            printf("libEntData addr 0x%S\n", libEntData.getAddress());
            final long namePtr = libEntData.getComponent(1).getInt(0);//libname ptr
            final long nidTablePtr = libEntData.getComponent(2).getInt(0);
            final long addTablePtr = libEntData.getComponent(3).getInt(0);

            String libname = "NONAME";
            if(namePtr != 0) {
                final Address namePtr_ = currentAddress.getNewAddress(namePtr);
                removeDataAt(namePtr_);//TODO check for string
                createData(namePtr_, StringDataType.dataType);
                libname = (String) getDataAt(namePtr_).getValue();//
            }
            printf("Export:");
            printf("Library name: %s\n", libname);
            printf("Nid table: 0x%X\n", nidTablePtr);
            printf("Add table: 0x%X\n", addTablePtr);

            //Add export
            //TODO

            final Data common = libEntData.getComponent(0);
            final int num_func = common.getComponent(4).getUnsignedShort(0);
            final int num_var = common.getComponent(5).getUnsignedShort(0);
            final int num_tlsvar = common.getComponent(6).getUnsignedShort(0);//TODO find something with all of these to verify how it works
            final int totalNids = num_func + num_var + num_tlsvar;

            printf("num_func: %d\n", num_func);
            printf("num_var: %d\n", num_var);
            printf("num_tlsvar: %d\n", num_tlsvar);

            //Create int array for fnid table
            final Address nidTableAddress = currentAddress.getNewAddress(nidTablePtr);
            utils.applyDataForce(new ArrayDataType(IntegerDataType.dataType, totalNids, 1), libname+"_nid_table", nidTableAddress);
            //TODO mark nid labels with names

            //Create pointer array for address table
            final Address addressTableAddress = currentAddress.getNewAddress(addTablePtr);
            utils.applyDataForce(new ArrayDataType(Pointer32DataType.dataType, totalNids, 1), libname+"_address_table", addressTableAddress);

            //Go through tables and mark data properly
            //It seems that in exports the table follows the form of funcs then vars then tlsvars
            //Label nid references
            final Data nidArray = getDataAt(nidTableAddress);
            final Data addrArray = getDataAt(addressTableAddress);
            for (int j = 0; j < totalNids; j++) {
                int fnid = nidArray.getComponent(j).getInt(0);
                final String fName = FnidUtils.getNameForFnid(this, libname, fnid);
                //printf("gah %d 0x%8X %s\n", j, fnid, fName);

                //Create nid label
                createLabel(nidArray.getComponent(j).getAddress(), "FNID_"+fName, true);

                //Create label
                final Address addr = currentAddress.getNewAddress(addrArray.getComponent(j).getInt(0));

                //TODO mark exported vars

                if(j < num_func) {
                    //TODO it seems that this references a pointer to the function
                    //Create func
                    final Address ptrptr = currentAddress.getNewAddress(addrArray.getComponent(j).getInt(0));
                    if(getDataAt(ptrptr) == null) {
                        //Mark as pointer if not already
                        createData(ptrptr, Pointer32DataType.dataType);
                    }
                    final Address funcAddress = currentAddress.getNewAddress(getDataAt(ptrptr).getInt(0));
                    final Function functionAt = getFunctionAt(funcAddress);
                    if(functionAt != null) {
                        if(!functionAt.getName().equals(fName)) {
                            //if (functionAt.getName().contains("::")) {
                            //    println("renaming existing function at " + funcAddress + " existing name: " + functionAt.getName() + " new name: " + fName);
                                try {
                                    functionAt.setName(fName, SourceType.ANALYSIS);
                                } catch (Exception e){}// TODO Handle properly

                            //}
                        }
                    } else {
                        createFunction(funcAddress, fName);
                    }
                    currentProgram.getSymbolTable().addExternalEntryPoint(funcAddress);//Mark as exported function (confusing names)

                } else {
                    //Var
                    createLabel(addr, fName, true);//For whatever reason these can be duplicated
                    currentProgram.getSymbolTable().addExternalEntryPoint(addr);//Mark as exported var
                }
            }


            printf("\n");

        }


    }

    public static <T extends Plugin> T getPlugin(PluginTool tool, Class<T> c) {
        List<Plugin> list = tool.getManagedPlugins();
        Iterator<Plugin> it = list.iterator();
        while (it.hasNext()) {
            Plugin p = it.next();
            if (p.getClass() == c) {
                return c.cast(p);
            }
        }
        return null;
    }




}
