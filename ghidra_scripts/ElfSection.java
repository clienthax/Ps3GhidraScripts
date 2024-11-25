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
//DO NOT RUN: Utility class for working with ELF sections
//@category Utilities
class ElfSection implements Comparable<ElfSection> {

    private long vAddr;
    private long size;

    public ElfSection(long vAddr, long size) {
        this.vAddr = vAddr;
        this.size = size;
    }

    public long getvAddr() {
        return vAddr;
    }

    public long getSize() {
        return size;
    }

    public int compareTo(ElfSection compareElfSection) {
        return (int) (this.vAddr - compareElfSection.vAddr);
    }

}
