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
