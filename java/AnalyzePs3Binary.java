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
import ghidra.util.Msg;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.math.BigInteger;
import java.lang.Comparable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Collections;

@SuppressWarnings("Duplicates")
public class AnalyzePs3Binary extends GhidraScript {
	class ElfSection implements Comparable<ElfSection> {
	    public long vAddr = 0;
	    public long size = 0;

	    public int compareTo(ElfSection compareElfSection) {
	        return (int) (this.vAddr - compareElfSection.vAddr);
	    }
	}

    private static final String NIDS_PATH = "nids.txt";

    private List<ElfSection> sections = new ArrayList<>();

    private final static long PT_PROC_PARAM = 0x60000001;
    private final static long PT_PROC_PRX   = 0x60000002;

    private final static short ET_NONE = 0;
    private final static short ET_REL  = 1;
    private final static short ET_EXEC = 2;
    private final static short ET_DYN  = 3;
    private final static short ET_CORE = 4;

    private final static short ET_SCE_PPURELEXEC = (short) 0xffa4;


    /*

aerosoul, [29.03.20 19:29]
short

aerosoul, [29.03.20 19:33]
and then for exec type elf's

aerosoul, [29.03.20 19:34]
the segment with p_type 0x60000002 will take you to sys_process_prx_info_t

aerosoul, [29.03.20 19:35]
which also has libent and libstub pointers
     */

    @Override
    protected void run() throws Exception {
        //Create data structure types
        createStructureTypes();

        process();// New method

        //TOOD make sexy
    }

    MemoryBlock elfHeader = null;

    private short getType() throws Exception {
        //Find elf header block
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            final Data dataAt = getDataAt(block.getStart());
            if(dataAt != null && dataAt.getDataType().getName().equals("Elf64_Ehdr")) {
                elfHeader = block;
                break;
            }
        }

        if(elfHeader == null) {
            printerr("Well.. this shouldn't happen :|\n");
            return -1;
        }

        return getDataAt(elfHeader.getStart()).getComponent(8).getShort(0);//e_type
    }

    boolean loadingExec() throws Exception {
        return getType() == ET_EXEC;
    }

    boolean loadingPrx() throws Exception {
        return getType() == ET_SCE_PPURELEXEC;
    }

    private void process() throws Exception {

        if(loadingPrx()) {
            println("prx");

            createModuleInfo();

        } else if(loadingExec()) {
            println("exec");

            final Data elfData = getDataAt(elfHeader.getStart());
            final long elfEntryPtr = elfData.getComponent(11).getLong(0); // e_entry
            printf("e_entry: %X\n", elfEntryPtr);

            Address opdAddress = currentAddress.getNewAddress(0);
            long opdSize = 0;
            boolean foundOpd = false;

            parseSections(elfData);

            // Heuristic to find OPD section: we assume it's the one that the entry point
            // pointer is in
            for (int i = 1; i < sections.size(); ++i) {
                if (elfEntryPtr < sections.get(i).vAddr) {
                    final ElfSection opdSection = sections.get(i - 1);
                    opdAddress = currentAddress.getNewAddress(opdSection.vAddr);
                    opdSize = opdSection.size;

                    foundOpd = true;
                    break;
                }
            }
            if (!foundOpd) {
                println("Could not find OPD");
            }

            printf("OPD: %X\n", opdAddress.getOffset());

            final Address firstTocBaseAddr = opdAddress.add(4);

            applyDataForce(Pointer32DataType.dataType, "tocPtr", opdAddress);
            createData(firstTocBaseAddr, Pointer32DataType.dataType);

            final Address elfEntryPtrAddr = currentAddress.getNewAddress(elfEntryPtr);
            createData(elfEntryPtrAddr, Pointer32DataType.dataType);

            final Address elfEntry = (Address) getDataAt(elfEntryPtrAddr).getValue();
            addFunction(elfEntry, "_start");

            final int tocBase = (int) getDataAt(firstTocBaseAddr).getAddress(0).getOffset();
            printf("TOC: %X\n", tocBase);

            applyProcessInfo();

            if (foundOpd) {
                parseOpd(opdAddress, opdSize);
            }
            setR2(tocBase);
        } else {
            println("What the heck did you try and load!?");
        }
    }

    private void parseSections(Data elfData) throws Exception {
        // final long sectionOffset = elfData.getComponent(13).getLong(0); // e_shoff
        // printf("e_shoff: 0x%X\n", sectionOffset);
        final int sectionCount = elfData.getComponent(19).getShort(0); // e_shnum
        printf("e_shnum: 0x%X\n", sectionCount);
        final int sectionSize = elfData.getComponent(18).getShort(0); // e_shentsize
        printf("e_shentsize: 0x%X\n", sectionSize);

        Address sectHdrAddr = currentAddress.getNewAddress(0);
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            println(block.getName());

            if (block.getName().equals("_elfSectionHeaders")) {
                sectHdrAddr = block.getStart();
                break;
            }
        }

        final Data sectHdr = getDataAt(sectHdrAddr);

        for (int shIdx = 0; shIdx < sectionCount; ++shIdx) {
            final Data shData = sectHdr.getComponent(shIdx);

            final long shAddr = shData.getComponent(3).getLong(0);
            final long shSize = shData.getComponent(5).getLong(0);

            ElfSection newSection = new ElfSection();
            newSection.vAddr = shAddr;
            newSection.size = shSize;
            sections.add(newSection);

            printf("section: addr=0x%X size=0x%X\n", shAddr, shSize);
        }
    }

    private void applyProcessInfo() throws Exception {// https://github.com/aerosoul94/ida_gel/blob/master/src/ps3/cell_loader.cpp#L669
        final Address add = elfHeader.getStart().add(64);
        final Data phdr_array = getDataAt(add);//Lazy way to skip to the phdrs
        println(phdr_array.getDataType()+"");

        for (int i = 0; i < phdr_array.getNumComponents(); i++) {
            println("phdr "+i);

            final Data phdr = phdr_array.getComponent(i);

            final int p_type = phdr.getComponent(0).getInt(0);
            long p_vaddr = phdr.getComponent(3).getLong(0);
            long p_filesz = phdr.getComponent(5).getLong(0);

            if(p_type == PT_PROC_PARAM) {
                println("TODO sys_process_param_t");

                if(p_vaddr == 0) {
                    //TODO psp stuff seems blanked, possibly same with vsh
                    println("Section seems blanked, ignoring");
                    continue;
                }
                final Address newAddress = currentAddress.getNewAddress(p_vaddr);
                println("Applying sys_process_param_t to "+newAddress);
                applyStruct(sysProcessParamTDataType, newAddress);

            } else if(p_type == PT_PROC_PRX) {
                println("TODO prx");

                //VSH has this segment zeroed and stripped.
                if(p_filesz == 0) {
                    findImports();
                    findExports();
                } else {
                    final Address newAddress = currentAddress.getNewAddress(p_vaddr);
                    println("Applying sys_process_prx_info_t to "+newAddress);
                    applyStruct(sysProcessPrxInfoTDataType, newAddress);
                    createImportStubsFromPrxInfo(newAddress);
                    createExportEntsFromPrxInfo(newAddress);

                }

            }

            println();
        }

        Collections.sort(sections);
    }

    private void addFunction(Address funcStart) throws Exception {
        addFunctionImpl(funcStart, "");
    }

    private void addFunction(Address funcStart, String funcName) throws Exception {
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

    private void parseOpd(Address opdAddr, long opdSize) {
        Address addr = opdAddr;

        for (long i = 0; i < opdSize; i += 8) {
            final Address funcAddressPtr = opdAddr.add(i);
            Address funcAddress = currentAddress.getNewAddress(0);

            if (funcAddress.getOffset() == 0) {
            	continue;
            }

            try {
                Data data = this.createData(funcAddressPtr, Pointer32DataType.dataType);
                if (data != null) {
                    funcAddress = (Address) data.getValue();
                    addFunction(funcAddress);
                }
            } catch (Exception e) {
                printf("Error creating data at %X\n", funcAddress.getOffset());
            }

            final Address funcTocAddress = opdAddr.add(i + 4);

            if (getDataAt(funcTocAddress) == null) {
                try {
                    this.createData(funcTocAddress, Pointer32DataType.dataType);
                } catch (Exception e) {
                    printf("Error creating data at %X\n", funcTocAddress.getOffset());
                }
            }
        }
    }

    private void findExports() throws Exception {
        boolean found = false;

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }

            if(block.getSize() < 0x1C * 2) {
                //printf("skipping block %S\n", block.getName());
                if(block.getSize() == 0x1C) {
                    //printf("HMMMMMMM block matchs struct size exactly..\n");
                    final int structsize = block.getByte(block.getStart()) & 0xff;
                    if(structsize == 0x1C) {
                        //printf("Found ya\n");
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
        //Try and get elf header (why isnt this exposed as a getter..)
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
        applyStruct(sceModuleInfoPpu32DataType, module_info_addr);

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

        //TODO find the correct segment to mark and use opd toc values
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            currentProgram.getProgramContext().setRegisterValue(block.getStart(), block.getEnd(), new RegisterValue(r2, new BigInteger(""+toc)));
        }

        createLabel(currentAddress.getNewAddress(toc), "TOC_BASE", true);
        printf("Toc / R2 set to 0x%08X\n", toc);
    }

    //ELFs generally have one section entirely of imports
    private void createImportStubsFromMemoryBlock(MemoryBlock block) throws Exception {
        final long stub_count = block.getSize() / sceLibStubPpu32DataType.getLength();
        println("Entries = "+stub_count+" size="+block.getSize()+" struc_size="+sceLibStubPpu32DataType.getLength());
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
        final long stub_count = stub_size / sceLibStubPpu32DataType.getLength();

        println("Entries = "+stub_count+" size="+stub_size+" struc_size="+sceLibStubPpu32DataType.getLength());

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
        final long stub_count = stub_size / sceLibStubPpu32DataType.getLength();
        println("Entries = "+stub_count+" size="+stub_size+" struc_size="+sceLibStubPpu32DataType.getLength());
        if(stub_count == 0) {
            println("No imports");
            return;
        }

        createImportStubs(currentAddress.getNewAddress(stub_top), (int) stub_count);
    }

    private void createImportStubsFromRange(Address start, Address end) throws Exception {
        final long stub_count = (end.getOffset() - start.getOffset()) / sceLibStubPpu32DataType.getLength();
        if(stub_count == 0) {
            println("No imports");
            return;
        }

        createImportStubs(start, (int) stub_count);

    }

    private void createImportStubs(Address start_addr, int stub_count) throws Exception {//Imports

        applyStructArray(sceLibStubPpu32DataType, stub_count, start_addr);

        //TODO loop through and mark the entries with the lib name etc?
        //TODO mark fnids / pointer tables

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
                removeDataAt(namePtr_);//TODO check for string
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

            //TODO name these
            if(num_func != 0) {
                //Create func nid table
                final Address nidTableAddress = currentAddress.getNewAddress(funcNidTablePtr);
                applyDataForce(new ArrayDataType(IntegerDataType.dataType, num_func, 1), libname+"_func_nid_table", nidTableAddress);
                //Create var address table
                final Address addressTableAddress = currentAddress.getNewAddress(funcTablePtr);
                applyDataForce(new ArrayDataType(Pointer32DataType.dataType, num_func, 1), libname+"_func_address_table", addressTableAddress);

                //Label fnid references
                final Data nidArray = getDataAt(nidTableAddress);
                final Data funcAddrArray = getDataAt(addressTableAddress);
                for (int j = 0; j < num_func; j++) {
                    int fnid = nidArray.getComponent(j).getInt(0);
                    final String fnid_name = get_fnid_name(libname, fnid);

                    //Create fnid label
                    createLabel(nidArray.getComponent(j).getAddress(), "FNID_"+fnid_name, true);

                    //Create func label
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


                    //Create import TODO see if its possible to remap the stubs to the external, ideally we can just use a call override to point at the external directly o.o
                    currentProgram.getExternalManager().addExtFunction(libname, fnid_name, null, SourceType.ANALYSIS);

                }



            }

            if(num_var != 0) {
                //Create var nid table
                final Address nidTableAddress = currentAddress.getNewAddress(varNidTablePtr);
                applyDataForce(new ArrayDataType(IntegerDataType.dataType, num_var, 1), libname+"_var_nid_table", nidTableAddress);
                //Create var address table
                final Address addressTableAddress = currentAddress.getNewAddress(varTablePtr);
                applyDataForce(new ArrayDataType(Pointer32DataType.dataType, num_var, 1), libname+"_var_address_table", addressTableAddress);

                //Label nid references
                final Data nidArray = getDataAt(nidTableAddress);
                final Data funcAddrArray = getDataAt(addressTableAddress);
                for (int j = 0; j < num_var; j++) {
                    int fnid = nidArray.getComponent(j).getInt(0);
                    final String fnid_name = get_fnid_name(libname, fnid);

                    //Create nid label
                    createLabel(nidArray.getComponent(j).getAddress(), "VNID_"+fnid_name, true);

                    //Create var label
                    final Address varAddress = currentAddress.getNewAddress(funcAddrArray.getComponent(j).getInt(0));
                    //TODO HMMM, how do we determine the datatype?
                    createLabel(varAddress, libname+"::"+fnid_name, true);
                }
            }

            if(num_tlsvar != 0) {
                //Create tls var nid table
                applyDataForce(new ArrayDataType(IntegerDataType.dataType, num_tlsvar, 1), libname+"_tls_var_nid_table", currentAddress.getNewAddress(tlsNidTablePtr));
                //Create tls var address table
                applyDataForce(new ArrayDataType(Pointer32DataType.dataType, num_tlsvar, 1), libname+"_tls_var_address_table", currentAddress.getNewAddress(tlsTablePtr));
            }

            printf("\n");

        }
    }

    private void createExportEntsFromMemoryBlock(MemoryBlock block) throws Exception {
        final long ent_count = block.getSize() / sceLibEntPpu32DataType.getLength();
        println("Entries = "+ent_count+" size="+block.getSize()+" struc_size="+sceLibEntPpu32DataType.getLength());
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
        final long ent_count = ent_size / sceLibEntPpu32DataType.getLength();

        println("Entries = "+ent_count+" size="+ent_size+" struc_size="+sceLibEntPpu32DataType.getLength());

        createExportEnts(currentAddress.getNewAddress(ent_top), (int) ent_count);
    }

    private void createExportEntsFromPrxInfo(Address prxInfo_addr) throws Exception {
        final Data sys_process_prx_info_t = getDataAt(prxInfo_addr);
        final long ent_top = sys_process_prx_info_t.getComponent(4).getInt(0);
        final long ent_end = sys_process_prx_info_t.getComponent(5).getInt(0);
        final long ent_size = ent_end - ent_top;
        final long ent_count = ent_size / sceLibEntPpu32DataType.getLength();
        println("Entries = "+ent_count+" size="+ent_size+" struc_size="+sceLibEntPpu32DataType.getLength());
        if(ent_count == 0) {
            println("No exports");
            return;
        }

        createExportEnts(currentAddress.getNewAddress(ent_top), (int) ent_count);
    }

    private void createExportEntsFromRange(Address start, Address end) throws Exception {
        final long stub_count = (end.getOffset() - start.getOffset()) / sceLibEntPpu32DataType.getLength();
        if(stub_count == 0) {
            println("No exports");
            return;
        }

        createExportEnts(start, (int) stub_count);

    }

    private void createExportEnts(Address start_addr, int exportCount) throws Exception {//Exports


        final Address ent_top_addr = start_addr;
        applyStructArray(sceLibEntPpu32DataType, exportCount, ent_top_addr);

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
            applyDataForce(new ArrayDataType(IntegerDataType.dataType, totalNids, 1), libname+"_nid_table", nidTableAddress);
            //TODO mark nid labels with names

            //Create pointer array for address table
            final Address addressTableAddress = currentAddress.getNewAddress(addTablePtr);
            applyDataForce(new ArrayDataType(Pointer32DataType.dataType, totalNids, 1), libname+"_address_table", addressTableAddress);

            //Go through tables and mark data properly
            //It seems that in exports the table follows the form of funcs then vars then tlsvars
            //Label nid references
            final Data nidArray = getDataAt(nidTableAddress);
            final Data addrArray = getDataAt(addressTableAddress);
            for (int j = 0; j < totalNids; j++) {
                int fnid = nidArray.getComponent(j).getInt(0);
                final String fName = get_fnid_name(libname, fnid);
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
                                } catch (Exception e){}//TODO Handle properly

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

    private void createStructureTypes() {
        //Module info
        createSceModuleInfoCommonDataStruc();
        createSceModuleInfoPpu32Struc();
        createSceModuleInfoPpu64Struc();

        //Imports
        createSceLibStubCommonStruc();
        createSceLibStubPpu32Struc();
        createSceLibStubPpu64Struc();

        //Exports
        createSceLibEntCommonStruc();
        createSceLibEntPpu32Struc();
        createSceLibEntPpu64Struc();

        //Process param
        createSysProcessParamTDataStruc();

        //Process Prx
        createSysProcessPrxInfoTDataStruc();

    }

    /* Process PRX */

    StructureDataType sysProcessPrxInfoTDataType;
    private void createSysProcessPrxInfoTDataStruc() {
        sysProcessPrxInfoTDataType = new StructureDataType(new CategoryPath("/PS3"), "sys_process_prx_info_t", 0);
        sysProcessPrxInfoTDataType.add(UnsignedIntegerDataType.dataType, "size", "");
        sysProcessPrxInfoTDataType.add(UnsignedIntegerDataType.dataType, "magic", "");
        sysProcessPrxInfoTDataType.add(UnsignedIntegerDataType.dataType, "version", "");
        sysProcessPrxInfoTDataType.add(UnsignedIntegerDataType.dataType, "sdk_version", "");
        sysProcessPrxInfoTDataType.add(UnsignedIntegerDataType.dataType, "libent_start", "");
        sysProcessPrxInfoTDataType.add(UnsignedIntegerDataType.dataType, "libent_end", "");
        sysProcessPrxInfoTDataType.add(UnsignedIntegerDataType.dataType, "libstub_start", "");
        sysProcessPrxInfoTDataType.add(UnsignedIntegerDataType.dataType, "libstub_end", "");
        sysProcessPrxInfoTDataType.add(UnsignedCharDataType.dataType, "major_version", "");
        sysProcessPrxInfoTDataType.add(UnsignedCharDataType.dataType, "minor_version", "");
        sysProcessPrxInfoTDataType.add(new ArrayDataType(UnsignedCharDataType.dataType, 6, 1), "reserved", "");
    }

    /* Process Param */

    StructureDataType sysProcessParamTDataType;
    private void createSysProcessParamTDataStruc() {
        sysProcessParamTDataType = new StructureDataType(new CategoryPath("/PS3"), "sys_process_param_t", 0);
        sysProcessParamTDataType.add(UnsignedIntegerDataType.dataType, "size", "");
        sysProcessParamTDataType.add(UnsignedIntegerDataType.dataType, "magic", "");
        sysProcessParamTDataType.add(UnsignedIntegerDataType.dataType, "version", "");
        sysProcessParamTDataType.add(UnsignedIntegerDataType.dataType, "sdk_version", "");
        sysProcessParamTDataType.add(IntegerDataType.dataType, "primary_prio", "");
        sysProcessParamTDataType.add(UnsignedIntegerDataType.dataType, "primary_stacksize", "");
        sysProcessParamTDataType.add(UnsignedIntegerDataType.dataType, "malloc_pagesize", "");
        sysProcessParamTDataType.add(UnsignedIntegerDataType.dataType, "ppc_seg", "");
        sysProcessParamTDataType.add(UnsignedIntegerDataType.dataType, "crash_dump_param_addr", "");//TODO hmmmm
    }


    /* Module Info */
    int MODULE_NAME_MAX_LEN = 27;
    StructureDataType sceModuleInfoCommonDataType;
    private void createSceModuleInfoCommonDataStruc() {
        sceModuleInfoCommonDataType = new StructureDataType(new CategoryPath("/PS3"), "_scemoduleinfo_common", 0);//0x20 in length
        sceModuleInfoCommonDataType.add(UnsignedShortDataType.dataType, "module_attribute", "");
        sceModuleInfoCommonDataType.add(new ArrayDataType(UnsignedCharDataType.dataType, 2, 1), "module_version", "");
        sceModuleInfoCommonDataType.add(new ArrayDataType(CharDataType.dataType, MODULE_NAME_MAX_LEN, 1), "module_name", "");
        sceModuleInfoCommonDataType.add(UnsignedCharDataType.dataType, "infover", "");//Terminal?
    }

    StructureDataType sceModuleInfoPpu32DataType;
    private void createSceModuleInfoPpu32Struc() {
        sceModuleInfoPpu32DataType = new StructureDataType(new CategoryPath("/PS3"), "_scemoduleinfo_ppu32", 0);
        sceModuleInfoPpu32DataType.add(sceModuleInfoCommonDataType, "c", null);
        sceModuleInfoPpu32DataType.add(Pointer32DataType.dataType, "gp_value", null);//TOC? atleast according to aerosoul
        sceModuleInfoPpu32DataType.add(Pointer32DataType.dataType, "ent_top", null);// _scelibent_ppu32
        sceModuleInfoPpu32DataType.add(Pointer32DataType.dataType, "ent_end", null);//
        sceModuleInfoPpu32DataType.add(Pointer32DataType.dataType, "stub_top", null);// _scelibstub_ppu32
        sceModuleInfoPpu32DataType.add(Pointer32DataType.dataType, "stub_end", null);//
    }

    StructureDataType sceModuleInfoPpu64DataType;
    private void createSceModuleInfoPpu64Struc() {
        sceModuleInfoPpu64DataType = new StructureDataType(new CategoryPath("/PS3"), "_scemoduleinfo_ppu64", 0);
        sceModuleInfoPpu64DataType.add(sceModuleInfoCommonDataType, "c", null);
        sceModuleInfoPpu64DataType.add(Pointer64DataType.dataType, "gp_value", null);//TOC? atleast according to aerosoul
        sceModuleInfoPpu64DataType.add(Pointer64DataType.dataType, "ent_top", null);// _scelibent_ppu64
        sceModuleInfoPpu64DataType.add(Pointer64DataType.dataType, "ent_end", null);//
        sceModuleInfoPpu64DataType.add(Pointer64DataType.dataType, "stub_top", null);// _scelibstub_ppu64
        sceModuleInfoPpu64DataType.add(Pointer64DataType.dataType, "stub_end", null);//
    }

    /* Imports */

    StructureDataType sceLibStubCommonDataType;
    private void createSceLibStubCommonStruc() {
        sceLibStubCommonDataType = new StructureDataType(new CategoryPath("/PS3"), "_scelibstub_common", 0);//sceKernelLibraryStubTable_common
        sceLibStubCommonDataType.add(UnsignedCharDataType.dataType, "structsize", "");
        sceLibStubCommonDataType.add(new ArrayDataType(UnsignedCharDataType.dataType, 1, 1), "reserved1", "");
        sceLibStubCommonDataType.add(UnsignedShortDataType.dataType, "version", "");
        sceLibStubCommonDataType.add(UnsignedShortDataType.dataType, "attribute", "");
        sceLibStubCommonDataType.add(UnsignedShortDataType.dataType, "num_func", "");
        sceLibStubCommonDataType.add(UnsignedShortDataType.dataType, "num_var", "");
        sceLibStubCommonDataType.add(UnsignedShortDataType.dataType, "num_tlsvar", "");
        sceLibStubCommonDataType.add(new ArrayDataType(UnsignedCharDataType.dataType, 4, 1), "reserved2", "");
    }

    StructureDataType sceLibStubPpu32DataType;
    private void createSceLibStubPpu32Struc() {
        sceLibStubPpu32DataType = new StructureDataType(new CategoryPath("/PS3"), "_scelibstub_ppu32", 0);//sceKernelLibraryStubTable_ppu32
        sceLibStubPpu32DataType.add(sceLibStubCommonDataType, "c", null);
        sceLibStubPpu32DataType.add(Pointer32DataType.dataType, "libname", null);
        sceLibStubPpu32DataType.add(Pointer32DataType.dataType, "func_nidtable", null);
        sceLibStubPpu32DataType.add(Pointer32DataType.dataType, "func_table", null);
        sceLibStubPpu32DataType.add(Pointer32DataType.dataType, "var_nidtable", null);
        sceLibStubPpu32DataType.add(Pointer32DataType.dataType, "var_table", null);
        sceLibStubPpu32DataType.add(Pointer32DataType.dataType, "tls_nidtable", null);
        sceLibStubPpu32DataType.add(Pointer32DataType.dataType, "tls_table", null);
    }

    StructureDataType sceLibStubPpu64DataType;
    private void createSceLibStubPpu64Struc() {
        sceLibStubPpu64DataType = new StructureDataType(new CategoryPath("/PS3"), "_scelibstub_ppu64", 0);//sceKernelLibraryStubTable_ppu64
        sceLibStubPpu64DataType.add(sceLibStubCommonDataType, "c", null);
        sceLibStubPpu64DataType.add(Pointer64DataType.dataType, "libname", null);
        sceLibStubPpu64DataType.add(Pointer64DataType.dataType, "func_nidtable", null);
        sceLibStubPpu64DataType.add(Pointer64DataType.dataType, "func_table", null);
        sceLibStubPpu64DataType.add(Pointer64DataType.dataType, "var_nidtable", null);
        sceLibStubPpu64DataType.add(Pointer64DataType.dataType, "var_table", null);
        sceLibStubPpu64DataType.add(Pointer64DataType.dataType, "tls_nidtable", null);
        sceLibStubPpu64DataType.add(Pointer64DataType.dataType, "tls_table", null);
    }

    /* Exports */

    StructureDataType sceLibEntCommonDataType;
    private void createSceLibEntCommonStruc() {
        sceLibEntCommonDataType = new StructureDataType(new CategoryPath("/PS3"), "_scelibent_common", 0);//sceKernelLibraryEntryTable_common
        sceLibEntCommonDataType.add(UnsignedCharDataType.dataType, "structsize", null);
        sceLibEntCommonDataType.add(UnsignedCharDataType.dataType, "auxattribute", null);
        sceLibEntCommonDataType.add(UnsignedShortDataType.dataType, "version", null);
        sceLibEntCommonDataType.add(UnsignedShortDataType.dataType, "attribute", null);
        sceLibEntCommonDataType.add(UnsignedShortDataType.dataType, "num_func", null);
        sceLibEntCommonDataType.add(UnsignedShortDataType.dataType, "num_var", null);
        sceLibEntCommonDataType.add(UnsignedShortDataType.dataType, "num_tlsvar", null);
        sceLibEntCommonDataType.add(UnsignedCharDataType.dataType, "hashinfo", null);
        sceLibEntCommonDataType.add(UnsignedCharDataType.dataType, "hashinfotls", null);
        sceLibEntCommonDataType.add(new ArrayDataType(UnsignedCharDataType.dataType, 1, 1), "reserved2", "");
        sceLibEntCommonDataType.add(UnsignedCharDataType.dataType, "nidaltsets", null);
    }

    StructureDataType sceLibEntPpu32DataType;
    private void createSceLibEntPpu32Struc() {
        sceLibEntPpu32DataType = new StructureDataType(new CategoryPath("/PS3"), "_scelibent_ppu32", 0);//sceKernelLibraryEntryTable_ppu32
        sceLibEntPpu32DataType.add(sceLibEntCommonDataType, "c", null);
        sceLibEntPpu32DataType.add(Pointer32DataType.dataType, "libname", null);
        sceLibEntPpu32DataType.add(Pointer32DataType.dataType, "nidtable", null);
        sceLibEntPpu32DataType.add(Pointer32DataType.dataType, "addtable", null);
    }

    StructureDataType sceLibEntPpu64DataType;
    private void createSceLibEntPpu64Struc() {
        sceLibEntPpu64DataType = new StructureDataType(new CategoryPath("/PS3"), "_scelibent_ppu64", 0);//sceKernelLibraryEntryTable_ppu64
        sceLibEntPpu64DataType.add(sceLibEntCommonDataType, "c", null);
        sceLibEntPpu64DataType.add(Pointer64DataType.dataType, "libname", null);
        sceLibEntPpu64DataType.add(Pointer64DataType.dataType, "nidtable", null);
        sceLibEntPpu64DataType.add(Pointer64DataType.dataType, "addtable", null);
    }

    private void applyStruct(StructureDataType struct, Address address) throws Exception {
        clearListing(address, address.add(struct.getLength()-1));
        createData(address, struct);
        createLabel(address, struct.getName(), true);
    }

    private void applyStructArray(StructureDataType struct, int amount, Address address) throws Exception {
        clearListing(address, address.add((struct.getLength()*amount)-1));
        createData(address, new ArrayDataType(struct, amount, 1));
        createLabel(address, struct.getName(), true);
    }

    private void applyDataForce(DataType data, String name, Address address) throws Exception {
        clearListing(address, address.add((data.getLength())-1));
        createData(address, data);
        createLabel(address, name, true);
    }




    private String get_fnid_comment(String name, int fnid) {
        return "";//TODO
    }


    private HashMap<String, String> fnids = null;

    private String get_fnid_name(String moduleName, int fnid) throws Exception {

        if(fnids == null) {
            fnids = new HashMap<>();
            File file = new File(NIDS_PATH);
            if (!file.exists()) {
                file = askFile("Locate nids.txt", "Load");
            }

            @SuppressWarnings("unchecked")
            List<String> list = FileUtils.readLines(file);
            for (String s : list) {
                final String[] split = s.split(" ");
                fnids.put(split[0], split[1]);
            }
        }

        if(moduleName.equals("NONAME")) {
            moduleName = "";
        }

        final String fnidHex = String.format("0x%08X", fnid);
        String name = fnids.get(fnidHex);
        if(name == null) {
            printf("Missing fnid, module: %s %s\n", moduleName, fnidHex);
            return moduleName+"_"+fnidHex;
        }

        return name;
    }

}
