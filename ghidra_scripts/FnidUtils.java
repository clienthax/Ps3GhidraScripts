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
//DO NOT RUN: Provides utility functions for working with PS3 function IDs
//@category Utilities
import ghidra.app.script.GhidraScript;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;

public class FnidUtils extends GhidraScript {

    @Override
    protected void run() throws Exception {
        printf("This file is not meant to be run manually. It is used by other scripts.\n");
    }

    private static final String NIDS_PATH = "nids.txt";
    private static HashMap<String, String> fnids = null;

    public static String getNameForFnid(GhidraScript script, String moduleName, int fnid) throws Exception {

        if(fnids == null) {
            loadFnids(script);
        }

        if(moduleName.equals("NONAME")) {
            moduleName = "";
        }

        final String fnidHex = String.format("0x%08X", fnid);
        String name = fnids.get(fnidHex);
        if(name == null) {
            script.printf("Missing fnid, module: %s %s\n", moduleName, fnidHex);
            return moduleName+"_"+fnidHex;
        }

        return name;
    }

    private static void loadFnids(GhidraScript script) throws Exception {
        fnids = new HashMap<>();
        File file = new File(Ps3ElfUtils.getExtensionInstallDataPath("Ps3GhidraScripts"), "data/"+NIDS_PATH);
        if (!file.exists()) {
            file = script.askFile("Locate nids.txt", "Load");
        }

        List<String> list = FileUtils.readLines(file,Charset.defaultCharset());
        for (String s : list) {
            final String[] split = s.split(" ");
            fnids.put(split[0], split[1]);
        }
    }

}
