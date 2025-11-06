#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

#include "bytes.hpp"

// --- tiny utils ---
static bool VERBOSE = false;
static bool has(const std::vector<uint8_t>& b, size_t off, size_t need) {
    return off + need <= b.size();
}

// --- PE helpers (for inspecting Windows binaries sitting on disk) ---
static bool looks_mz(const std::vector<uint8_t>& b) { return b.size()>=2 && b[0]=='M' && b[1]=='Z'; }

static void inspect_pe(const std::vector<uint8_t>& b) {
    std::cout << "type: PE\n";
    if (!has(b,0x3C,4)) { std::cout<<"error: too small for DOS header\n"; return; }
    uint32_t e_lfanew = le32(&b[0x3C]);
    if (!has(b,e_lfanew,4)) { std::cout<<"error: invalid e_lfanew\n"; return; }
    if (!(b[e_lfanew]=='P' && b[e_lfanew+1]=='E' && b[e_lfanew+2]==0 && b[e_lfanew+3]==0)) {
        std::cout<<"note: MZ found but PE signature missing at e_lfanew\n"; return;
    }

    size_t coff = e_lfanew + 4;
    if (!has(b,coff,20)) { std::cout<<"error: incomplete COFF header\n"; return; }

    uint16_t Machine          = le16(&b[coff+0]);
    uint16_t NumberOfSections = le16(&b[coff+2]);
    uint32_t TimeDateStamp    = le32(&b[coff+4]);
    uint16_t SizeOptHdr       = le16(&b[coff+16]);
    uint16_t Characteristics  = le16(&b[coff+18]);

    std::cout << "machine: 0x" << std::hex << Machine << std::dec << "\n";
    std::cout << "sections: " << NumberOfSections << "\n";
    std::cout << "timestamp: " << TimeDateStamp << " (unix epoch)\n";
    std::cout << "opt_hdr_size: " << SizeOptHdr << "\n";
    std::cout << "characteristics: 0x" << std::hex << Characteristics << std::dec << "\n";

    size_t opt = coff + 20;
    if (has(b,opt,2)) {
        uint16_t magic = le16(&b[opt]);
        std::string which = (magic==0x10b ? "PE32" : (magic==0x20b ? "PE32+" : "unknown"));
        std::cout << "opt_magic: 0x" << std::hex << magic << std::dec << " (" << which << ")\n";
    }
}

// --- Mach-O + FAT (Universal) constants ---
enum : uint32_t {
    MACHO_32_BE = 0xFEEDFACE,
    MACHO_32_LE = 0xCEFAEDFE,
    MACHO_64_BE = 0xFEEDFACF,
    MACHO_64_LE = 0xCFFAEDFE,
    FAT_BE      = 0xCAFEBABE,
    FAT_LE      = 0xBEBAFECA,
    FAT64_BE    = 0xCAFEBABF,
    FAT64_LE    = 0xBFBAFECA
};

// cpu type -> name mapper (common values)
static const char* cpu_name(uint32_t cputype) {
    switch (cputype) {
        case 7:          return "x86";
        case 0x01000007: return "x86_64";
        case 12:         return "arm";
        case 0x0100000C: return "arm64";
        case 18:         return "ppc";
        case 0x01000012: return "ppc64";
        default:         return "unknown";
    }
}

static bool looks_macho(const std::vector<uint8_t>& b) {
    if (!has(b,0,4)) return false;
    uint32_t m = be32(&b[0]);
    return (m==MACHO_32_BE || m==MACHO_32_LE || m==MACHO_64_BE || m==MACHO_64_LE);
}
static bool looks_fat(const std::vector<uint8_t>& b) {
    if (!has(b,0,4)) return false;
    uint32_t m = be32(&b[0]);
    return (m==FAT_BE || m==FAT_LE || m==FAT64_BE || m==FAT64_LE);
}

static void inspect_macho(const std::vector<uint8_t>& b) {
    uint32_t magic = be32(&b[0]); // compare to known magics
    bool is_le = (magic==MACHO_32_LE || magic==MACHO_64_LE);
    bool is_64 = (magic==MACHO_64_LE || magic==MACHO_64_BE);

    std::cout << "type: Mach-O" << (is_64?" 64":" 32") << (is_le?" (little)":" (big)") << "\n";

    // mach_header layout (32): magic,cputype,cpusub,filetype,ncmds,sizeofcmds,flags
    // mach_header_64 adds a reserved field after flags
    auto rd32 = [&](size_t off)->uint32_t{
        if (!has(b,off,4)) return 0;
        return is_le ? le32(&b[off]) : be32(&b[off]);
    };

    uint32_t cputype    = rd32(4);
    uint32_t cpusubtype = rd32(8);
    uint32_t filetype   = rd32(12);
    uint32_t ncmds      = rd32(16);
    uint32_t sizeofcmds = rd32(20);
    uint32_t flags      = rd32(24);

    std::cout << "cputype: " << cpu_name(cputype) << " (0x" << std::hex << cputype << std::dec << ")\n";
    std::cout << "filetype: " << filetype << "  (1=obj,2=exec,6=dylib,7=bundle)\n";
    std::cout << "ncmds: " << ncmds << "  sizeofcmds: " << sizeofcmds << "\n";
    std::cout << "flags: 0x" << std::hex << flags << std::dec << "\n";
}

static void inspect_fat(const std::vector<uint8_t>& b) {
    uint32_t magic_be = be32(&b[0]);
    bool is_le = (magic_be==FAT_LE || magic_be==FAT64_LE);
    bool is_64 = (magic_be==FAT64_BE || magic_be==FAT64_LE);

    auto rd32 = [&](size_t off)->uint32_t{
        if (!has(b,off,4)) return 0;
        return is_le ? le32(&b[off]) : be32(&b[off]);
    };
    auto rd64 = [&](size_t off)->uint64_t{
        if (!has(b,off,8)) return 0;
        // FAT64 fields are still stored as a 64-bit big/little; handle both
        return is_le ? le64(&b[off]) : ( (uint64_t)be32(&b[off]) << 32 ) | be32(&b[off+4]);
    };

    std::cout << "type: Mach-O FAT (Universal";
    if (is_64) std::cout << ", 64";
    std::cout << ")\n";

    if (!has(b,4,4)) { std::cout<<"error: truncated fat header\n"; return; }
    uint32_t nfat_arch = rd32(4);
    std::cout << "architectures: " << nfat_arch << "\n";

    // fat_arch (32): cputype(4) cpusub(4) offset(4) size(4) align(4) => 20 bytes
    // fat_arch_64 :  cputype(4) cpusub(4) offset(8) size(8) align(4) reserved(4) => 32 bytes
    size_t arch_off = 8;
    size_t stride   = is_64 ? 32 : 20;

    for (uint32_t i = 0; i < nfat_arch; ++i) {
        size_t off = arch_off + i * stride;
        if (!has(b, off, stride)) {
            std::cout << "  ["<<i<<"] (truncated)\n"; break;
        }

        uint32_t cputype = rd32(off + 0);
        uint32_t cpusub  = rd32(off + 4);
        uint64_t fo      = is_64 ? rd64(off + 8)  : rd32(off + 8);
        uint64_t fs      = is_64 ? rd64(off + 16) : rd32(off + 12);
        uint32_t align   = rd32(is_64 ? (off + 24) : (off + 16));

        std::cout << "  [" << i << "] "
                  << cpu_name(cputype) << " (cputype=0x" << std::hex << cputype
                  << ", cpusub=0x" << cpusub << std::dec << ")\n";
        std::cout << "       offset=" << fo << "  size=" << fs << "  align=" << align << "\n";
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: exe_inspector <file> [--verbose]\n";
        return 1;
    }
    std::string path = argv[1];
    if (argc >= 3 && std::string(argv[2])=="--verbose") VERBOSE = true;

    auto bytes = read_all(path);
    if (bytes.empty()) {
        std::cerr << "err: couldn't read file or empty: " << path << "\n";
        return 2;
    }
    if (VERBOSE) std::cout << "debug: read " << bytes.size() << " bytes\n";

    std::cout << "file: " << path << "\n";

    if (looks_fat(bytes)) {
        inspect_fat(bytes);
    } else if (looks_macho(bytes)) {
        inspect_macho(bytes);
    } else if (looks_mz(bytes)) {
        inspect_pe(bytes);
    } else {
        std::cout << "type: UNKNOWN\n";
        if (VERBOSE && bytes.size()>=4) {
            std::cout << "magic(first4): 0x" << std::hex << be32(&bytes[0]) << std::dec << "\n";
        }
    }
    return 0;
}
