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
//DO NOT RUN: Parses PS3 ELF files and provides utility functions for working with them
//@category Utilities
import ghidra.app.script.GhidraScript;
import ghidra.util.extensions.ExtensionDetails;
import ghidra.util.extensions.ExtensionUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static ghidra.app.util.bin.format.elf.ElfConstants.ET_EXEC;

public class Ps3ElfUtils extends GhidraScript {

    private final static short ET_SCE_PPURELEXEC = (short) 0xffa4;

    public final static long PT_PROC_PARAM = 0x60000001;
    public final static long PT_PROC_PRX   = 0x60000002;

    private final GhidraScript script;
    private final Program program;

    private final MemoryBlock elfHeader;
    private final short programType;
    private final List<ElfSection> sections;

    @Override
    protected void run() throws Exception {
        printf("This file is not meant to be run manually. It is used by other scripts.\n");
    }

    public Ps3ElfUtils() {
        this.script = null;
        this.program = null;
        this.elfHeader = null;
        this.programType = -1;
        this.sections = new ArrayList<>();
    }


    public Ps3ElfUtils(GhidraScript runningScript, Program program) throws Exception {
        this.script = runningScript;
        this.program = program;

        this.elfHeader = findElfHeader();
        this.sections = parseSections(script.getDataAt(elfHeader.getStart()));
        programType = findPs3ProgramType();
    }

    private MemoryBlock findElfHeader() {
        // Find elf header block
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            final Data dataAt = script.getDataAt(block.getStart());
            if(dataAt != null && dataAt.getDataType().getName().equals("Elf64_Ehdr")) {
                return block;
            }
        }

        return null;
    }

    public MemoryBlock getElfHeader() {
        return elfHeader;
    }

    public short findPs3ProgramType() throws Exception {
        if(getElfHeader() == null) {
            script.printerr("Couldn't find Elf64_Ehdr\n");
            return -1;
        }

        return script.getDataAt(elfHeader.getStart()).getComponent(8).getShort(0);// e_type
    }

    public boolean loadingExec() throws Exception {
        return programType == ET_EXEC;
    }

    public boolean loadingPrx() throws Exception {
        return programType == ET_SCE_PPURELEXEC;
    }

    // there should be a offset to this...
    // TODO use e_phoffset instead
    public Address getPhdrArrayAddress() throws Exception {

        for(long i = elfHeader.getStart().getOffset(); i < elfHeader.getEnd().getOffset(); i++) {
            Address addr = elfHeader.getStart().getNewAddress(i);
            final Data dataAt = script.getDataAt(addr);
            if (dataAt != null) {
                script.println(""+dataAt.getDataType().getName());
            }
            if(dataAt != null && dataAt.getDataType().getName().startsWith("Elf64_Phdr")) {
                return addr;
            }
        }



        script.printerr("Couldn't find Elf64_Phdr[]\n");
        return null;
    }

    private List<ElfSection> parseSections(Data elfData) throws Exception {

        List<ElfSection> sections = new ArrayList<>();

        // final long sectionOffset = elfData.getComponent(13).getLong(0); // e_shoff
        // printf("e_shoff: 0x%X\n", sectionOffset);
        final int sectionCount = elfData.getComponent(19).getShort(0); // e_shnum
        script.printf("e_shnum: 0x%X\n", sectionCount);
        final int sectionSize = elfData.getComponent(18).getShort(0); // e_shentsize
        script.printf("e_shentsize: 0x%X\n", sectionSize);

        Address sectHdrAddr = script.toAddr(0);
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            script.println(block.getName());

            if (block.getName().equals("_elfSectionHeaders")) {
                sectHdrAddr = block.getStart();
                break;
            }
        }

        final Data sectHdr = script.getDataAt(sectHdrAddr);

        for (int shIdx = 0; shIdx < sectionCount; ++shIdx) {
            final Data shData = sectHdr.getComponent(shIdx);

            final long shAddr = shData.getComponent(3).getLong(0);
            final long shSize = shData.getComponent(5).getLong(0);

            ElfSection newSection = new ElfSection(shAddr, shSize);
            sections.add(newSection);

            script.printf("section: addr=0x%X size=0x%X\n", shAddr, shSize);
        }

        return sections;
    }

    public List<ElfSection> getSections() {
        return sections;
    }

    public void applyStruct(StructureDataType struct, Address address) throws Exception {
        script.clearListing(address, address.add(struct.getLength()-1));
        script.createData(address, struct);
        script.createLabel(address, struct.getName(), true);
    }

    public void applyStructArray(StructureDataType struct, int amount, Address address) throws Exception {
        script.clearListing(address, address.add(((long) struct.getLength() *amount)-1));
        script.createData(address, new ArrayDataType(struct, amount, 1));
        script.createLabel(address, struct.getName(), true);
    }

    public void applyDataForce(DataType data, String name, Address address) throws Exception {
        script.clearListing(address, address.add((data.getLength())-1));
        script.createData(address, data);
        if (!name.isEmpty()) {
            script.createLabel(address, name, true);
        }
    }

    public static String getExtensionInstallDataPath(String extensionName) {
        final List<ExtensionDetails> ps3GhidraScripts;
        try {
            ps3GhidraScripts = ExtensionUtils.getInstalledExtensions()
                    .stream()
                    .filter(extension -> extension.getName().equals(extensionName))
                    .collect(Collectors.toList());
            final ExtensionDetails extensionDetails = ps3GhidraScripts.get(0);
            return extensionDetails.getInstallPath();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "";
    }

}
