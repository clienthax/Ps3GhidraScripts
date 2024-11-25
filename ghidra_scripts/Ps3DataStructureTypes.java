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
//Creates data types for PS3 data structures
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class Ps3DataStructureTypes extends GhidraScript {

    @Override
    protected void run() throws Exception {
        createStructureTypes();
    }

    /**
     * Creates the data types for PS3 data structures
     */
    public static void createStructureTypes() {
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

    static StructureDataType sysProcessPrxInfoTDataType;
    private static void createSysProcessPrxInfoTDataStruc() {
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

    static StructureDataType sysProcessParamTDataType;
    private static void createSysProcessParamTDataStruc() {
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
    static final int MODULE_NAME_MAX_LEN = 27;
    static StructureDataType sceModuleInfoCommonDataType;
    private static void createSceModuleInfoCommonDataStruc() {
        sceModuleInfoCommonDataType = new StructureDataType(new CategoryPath("/PS3"), "_scemoduleinfo_common", 0);//0x20 in length
        sceModuleInfoCommonDataType.add(UnsignedShortDataType.dataType, "module_attribute", "");
        sceModuleInfoCommonDataType.add(new ArrayDataType(UnsignedCharDataType.dataType, 2, 1), "module_version", "");
        sceModuleInfoCommonDataType.add(new ArrayDataType(CharDataType.dataType, MODULE_NAME_MAX_LEN, 1), "module_name", "");
        sceModuleInfoCommonDataType.add(UnsignedCharDataType.dataType, "infover", "");//Terminal?
    }

    static StructureDataType sceModuleInfoPpu32DataType;
    private static void createSceModuleInfoPpu32Struc() {
        sceModuleInfoPpu32DataType = new StructureDataType(new CategoryPath("/PS3"), "_scemoduleinfo_ppu32", 0);
        sceModuleInfoPpu32DataType.add(sceModuleInfoCommonDataType, "c", null);
        sceModuleInfoPpu32DataType.add(Pointer32DataType.dataType, "gp_value", null);//TOC? atleast according to aerosoul
        sceModuleInfoPpu32DataType.add(Pointer32DataType.dataType, "ent_top", null);// _scelibent_ppu32
        sceModuleInfoPpu32DataType.add(Pointer32DataType.dataType, "ent_end", null);//
        sceModuleInfoPpu32DataType.add(Pointer32DataType.dataType, "stub_top", null);// _scelibstub_ppu32
        sceModuleInfoPpu32DataType.add(Pointer32DataType.dataType, "stub_end", null);//
    }

    static StructureDataType sceModuleInfoPpu64DataType;
    private static void createSceModuleInfoPpu64Struc() {
        sceModuleInfoPpu64DataType = new StructureDataType(new CategoryPath("/PS3"), "_scemoduleinfo_ppu64", 0);
        sceModuleInfoPpu64DataType.add(sceModuleInfoCommonDataType, "c", null);
        sceModuleInfoPpu64DataType.add(Pointer64DataType.dataType, "gp_value", null);//TOC? atleast according to aerosoul
        sceModuleInfoPpu64DataType.add(Pointer64DataType.dataType, "ent_top", null);// _scelibent_ppu64
        sceModuleInfoPpu64DataType.add(Pointer64DataType.dataType, "ent_end", null);//
        sceModuleInfoPpu64DataType.add(Pointer64DataType.dataType, "stub_top", null);// _scelibstub_ppu64
        sceModuleInfoPpu64DataType.add(Pointer64DataType.dataType, "stub_end", null);//
    }

    /* Imports */

    static StructureDataType sceLibStubCommonDataType;
    private static void createSceLibStubCommonStruc() {
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

    static StructureDataType sceLibStubPpu32DataType;
    private static void createSceLibStubPpu32Struc() {
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

    static StructureDataType sceLibStubPpu64DataType;
    private static void createSceLibStubPpu64Struc() {
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

    static StructureDataType sceLibEntCommonDataType;
    private static void createSceLibEntCommonStruc() {
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

    static StructureDataType sceLibEntPpu32DataType;
    private static void createSceLibEntPpu32Struc() {
        sceLibEntPpu32DataType = new StructureDataType(new CategoryPath("/PS3"), "_scelibent_ppu32", 0);//sceKernelLibraryEntryTable_ppu32
        sceLibEntPpu32DataType.add(sceLibEntCommonDataType, "c", null);
        sceLibEntPpu32DataType.add(Pointer32DataType.dataType, "libname", null);
        sceLibEntPpu32DataType.add(Pointer32DataType.dataType, "nidtable", null);
        sceLibEntPpu32DataType.add(Pointer32DataType.dataType, "addtable", null);
    }

    static StructureDataType sceLibEntPpu64DataType;
    private static void createSceLibEntPpu64Struc() {
        sceLibEntPpu64DataType = new StructureDataType(new CategoryPath("/PS3"), "_scelibent_ppu64", 0);//sceKernelLibraryEntryTable_ppu64
        sceLibEntPpu64DataType.add(sceLibEntCommonDataType, "c", null);
        sceLibEntPpu64DataType.add(Pointer64DataType.dataType, "libname", null);
        sceLibEntPpu64DataType.add(Pointer64DataType.dataType, "nidtable", null);
        sceLibEntPpu64DataType.add(Pointer64DataType.dataType, "addtable", null);
    }


}
