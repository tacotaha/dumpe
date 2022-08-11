#ifndef PE_H
#define PE_H

#include <stdint.h>

#define NT_HDR(x) ((nt_hdr_t*)((char*)&x->dos_hdr + x->dos_hdr.e_lfanew))
#define OHDR(MAGIC, HDR, FIELD)                          \
  (MAGIC == NT_OHDR32_MAGIC ? ((nt_ohdr32_t*)HDR)->FIELD \
                            : ((nt_ohdr_t*)HDR)->FIELD)
#define SHDR(pe)                            \
  (((void*)(&NT_HDR(pe)->OptionalHeader)) + \
   NT_HDR(pe)->FileHeader.SizeOfOptionalHeader)

#define DOS_MAGIC 0x5A4D    /* MZ   */
#define NT_MAGIC 0x00004550 /* PE00 */
#define NT_OHDR32_MAGIC 0x10b
#define NT_OHDR64_MAGIC 0x20b
#define NDIRENTS 16
#define SECTION_NAME 8

typedef enum DIRENT {
  DIRENT_EXPORT = 0,
  DIRENT_IMPORT,
  DIRENT_RESOURCE,
  DIRENT_EXCEPTION,
  DIRENT_SECURITY,
  DIRENT_BASERELOC,
  DIRENT_DEBUG,
  DIRENT_COPYRIGHT,
  DIRENT_GLOBALPTR,
  DIRENT_TLS,
  DIRENT_LOAD_CONFIG,
  DIRENT_BOUND_IMPORT,
  DIRENT_IAT,
  DIRENT_DELAY_IMPORT,
  DIRENT_COM_DESCRIPTOR,
} DIRENT;

typedef struct dos_hdr_t {
  uint16_t e_magic;
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  uint32_t e_lfanew;
} dos_hdr_t;

typedef struct nt_fhdr_t {
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
} nt_fhdr_t;

typedef struct nt_ddir_t {
  uint32_t VirtualAddress;
  uint32_t Size;
} nt_ddir_t;

typedef struct nt_ohdr_t {
  uint16_t Magic;
  uint16_t MajorLinkerVersion;
  uint16_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  nt_ddir_t DataDirectory[NDIRENTS];
} nt_ohdr_t;

typedef struct nt_ohdr32_t {
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint32_t BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  nt_ddir_t DataDirectory[NDIRENTS];
} nt_ohdr32_t;

typedef struct nt_hdr_t {
  uint32_t Signature;
  nt_fhdr_t FileHeader;
  char OptionalHeader[];
} nt_hdr_t;

typedef struct pe_shdr_t {
  uint8_t Name[SECTION_NAME];
  union {
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
  } Misc;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
} pe_shdr_t;

typedef struct pe_t {
  dos_hdr_t dos_hdr;
  char stub[];
} pe_t;

pe_t* pe_init(const char*);
void pe_free(pe_t**);

static inline int valid(pe_t* pe) {
  return pe->dos_hdr.e_magic == DOS_MAGIC && NT_HDR(pe)->Signature == NT_MAGIC;
}

#endif /* PE_H */
