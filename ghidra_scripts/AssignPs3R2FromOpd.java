import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import static ghidra.app.util.bin.format.elf.ElfConstants.ET_EXEC;

@SuppressWarnings("unused")
public class AssignPs3R2FromOpd extends GhidraScript {

    private List<ElfSection> sections = new ArrayList<>();
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
            printerr("Couldn't find Elf64_Ehdr\n");
            return -1;
        }

        return getDataAt(elfHeader.getStart()).getComponent(8).getShort(0);//e_type
    }

    @Override
    protected void run() throws Exception {
        process();
    }

    boolean loadingExec() throws Exception {
        return getType() == ET_EXEC;
    }

    private void parseSections(Data elfData) throws Exception {
        final int sectionCount = elfData.getComponent(19).getShort(0); // e_shnum

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

            ElfSection newSection = new ElfSection(shAddr, shSize);
            sections.add(newSection);
        }
    }


    private void process() throws Exception {
        if (!loadingExec()) {
            // TODO handle finding opd in prxs
            println("Wrong type of file");
            return;
        }

        final Data elfData = getDataAt(elfHeader.getStart());
        final long elfEntryPtr = elfData.getComponent(11).getLong(0); // e_entry
        parseSections(elfData);


        boolean foundOpd = false;
        Address opdAddress = null;

        long opdSize = 0;
        // Heuristic to find OPD section: we assume it's the one that the entry point
        // pointer is in
        for (int i = 1; i < sections.size(); ++i) {
            if (elfEntryPtr < sections.get(i).getvAddr()) {
                final ElfSection opdSection = sections.get(i - 1);
                opdAddress = currentAddress.getNewAddress(opdSection.getvAddr());
                opdSize = opdSection.getSize();

                foundOpd = true;
                break;
            }
        }
        if (!foundOpd) {
            println("Could not find OPD");
            return;
        }

        println("opd address: "+opdAddress);

        final long opdEntries = opdSize / 8;
        println("opdEntries: "+opdEntries);


        // Go through opd and assign R2
        int meh = 0;
        final Memory memory = currentProgram.getMemory();
        HashSet<Integer> tocs = new HashSet<>();
        for (long i = 0; i < opdSize; i+= 8) {
            final int dataPtr = memory.getInt(opdAddress.add(i)); // To function / data
            final int tocPtr = memory.getInt(opdAddress.add(i + 4));
            tocs.add(tocPtr);
            println("data: "+dataPtr+" toc: "+tocPtr);

            final Address funcOrData = currentAddress.getNewAddress(dataPtr);
            final Function functionAt = currentProgram.getFunctionManager().getFunctionAt(funcOrData);
            if (functionAt != null) {
                println(""+functionAt.getBody());
                setFunctionR2(functionAt, tocPtr);
            }

        }
        println("Found "+tocs.size()+" tocs.");

    }

    private void setFunctionR2(Function function, int toc) throws Exception {
        final Register r2 = currentProgram.getProgramContext().getRegister("r2");
        currentProgram.getProgramContext().setRegisterValue(function.getBody().getMinAddress(), function.getBody().getMaxAddress(), new RegisterValue(r2, new BigInteger(""+toc)));
    }

}
