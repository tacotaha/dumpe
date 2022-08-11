#ifndef DUMP_H
#define DUMP_H

#include "pe.h"

#define DUMP(k, v) printf(" %-30s\t0x%-.8X\n", k, v);

#define DUMPA(k, v, l)                               \
  printf(" %-30s\t", k);                             \
  for (int i = 0; i < l; i++) printf("%.4x ", v[i]); \
  printf("\n");

#define DDIR(NAME, MAGIC, HDR, INDEX)                                      \
  DUMP(NAME " VA", OHDR(magic, hdr, DataDirectory)[INDEX].VirtualAddress); \
  DUMP(NAME " Size", OHDR(magic, hdr, DataDirectory)[INDEX].Size);

static inline void dos_dump_header(pe_t *pe) {
  dos_hdr_t *hdr = pe ? &pe->dos_hdr : NULL;
  if (hdr) {
    DUMP("e_magic", hdr->e_magic);
    DUMP("e_cblp", hdr->e_cblp);
    DUMP("e_cp", hdr->e_cp);
    DUMP("e_crlc", hdr->e_crlc);
    DUMP("e_cparhdr", hdr->e_cparhdr);
    DUMP("e_minalloc", hdr->e_minalloc);
    DUMP("e_maxalloc", hdr->e_maxalloc);
    DUMP("e_ss", hdr->e_ss);
    DUMP("e_sp", hdr->e_sp);
    DUMP("e_csum", hdr->e_csum);
    DUMP("e_ip", hdr->e_ip);
    DUMP("e_cs", hdr->e_cs);
    DUMP("e_lfarlc", hdr->e_lfarlc);
    DUMP("e_ovno", hdr->e_ovno);
    DUMPA("e_res", hdr->e_res, 4);
    DUMP("e_oemid", hdr->e_oemid);
    DUMP("e_oeminfo", hdr->e_oeminfo);
    DUMPA("e_res2", hdr->e_res2, 10);
    DUMP("e_lfanew", hdr->e_lfanew);
  }
}

static inline void pe_dump_fheader(pe_t *pe) {
  nt_fhdr_t *hdr = pe ? &NT_HDR(pe)->FileHeader : NULL;
  if (hdr) {
    DUMP("Machine", hdr->Machine);
    DUMP("NumberOfSections", hdr->NumberOfSections);
    DUMP("TimeDateStamp", hdr->TimeDateStamp);
    DUMP("PointerToSymbolTable", hdr->PointerToSymbolTable);
    DUMP("NumberOfSymbols", hdr->NumberOfSymbols);
    DUMP("SizeOfOptionalHeader", hdr->SizeOfOptionalHeader);
    DUMP("Characteristics", hdr->Characteristics);
  }
}

static inline void pe_dump_oheader(pe_t *pe) {
  void *hdr = pe ? &NT_HDR(pe)->OptionalHeader : NULL;
  if (hdr) {
    uint16_t magic = *((uint16_t *)hdr);
    DUMP("Magic", OHDR(magic, hdr, Magic));
    DUMP("MajorLinkerVersion", OHDR(magic, hdr, MajorLinkerVersion));
    DUMP("MinorLinkerVersion", OHDR(magic, hdr, MinorLinkerVersion));
    DUMP("SizeOfCode", OHDR(magic, hdr, SizeOfCode));
    DUMP("SizeOfInitializedData", OHDR(magic, hdr, SizeOfInitializedData));
    DUMP("SizeOfUninitializedData", OHDR(magic, hdr, SizeOfUninitializedData));
    DUMP("AddressOfEntryPoint", OHDR(magic, hdr, AddressOfEntryPoint));
    DUMP("BaseOfCode", OHDR(magic, hdr, BaseOfCode));
    if (magic == NT_OHDR32_MAGIC)
      DUMP("BaseOfData", ((nt_ohdr32_t *)hdr)->BaseOfData);
    DUMP("ImageBase", OHDR(magic, hdr, ImageBase));
    DUMP("SectionAlignment", OHDR(magic, hdr, SectionAlignment));
    DUMP("FileAlignment", OHDR(magic, hdr, FileAlignment));
    DUMP("MajorOperatingSystemVersion",
         OHDR(magic, hdr, MajorOperatingSystemVersion));
    DUMP("MinorOperatingSystemVersion",
         OHDR(magic, hdr, MinorOperatingSystemVersion));
    DUMP("MajorImageVersion", OHDR(magic, hdr, MajorImageVersion));
    DUMP("MinorImageVersion", OHDR(magic, hdr, MinorImageVersion));
    DUMP("MajorSubsystemVersion", OHDR(magic, hdr, MajorSubsystemVersion));
    DUMP("MinorSubsystemVersion", OHDR(magic, hdr, MinorSubsystemVersion));
    DUMP("Win32VersionValue", OHDR(magic, hdr, Win32VersionValue));
    DUMP("SizeOfImage", OHDR(magic, hdr, SizeOfImage));
    DUMP("SizeOfHeaders", OHDR(magic, hdr, SizeOfHeaders));
    DUMP("CheckSum", OHDR(magic, hdr, CheckSum));
    DUMP("Subsystem", OHDR(magic, hdr, Subsystem));
    DUMP("DllCharacteristics", OHDR(magic, hdr, DllCharacteristics));
    DUMP("SizeOfStackReserve", OHDR(magic, hdr, SizeOfStackReserve));
    DUMP("SizeOfStackCommit", OHDR(magic, hdr, SizeOfStackCommit));
    DUMP("SizeOfHeapReserve", OHDR(magic, hdr, SizeOfHeapReserve));
    DUMP("SizeOfHeapCommit", OHDR(magic, hdr, SizeOfHeapCommit));
    DUMP("LoaderFlags", OHDR(magic, hdr, LoaderFlags));
    DUMP("NumberOfRvaAndSizes", OHDR(magic, hdr, NumberOfRvaAndSizes));
  }
}

static inline void pe_dump_ddirs(pe_t *pe) {
  void *hdr = pe ? &NT_HDR(pe)->OptionalHeader : NULL;
  if (hdr) {
    uint16_t magic = *((uint16_t *)hdr);
    DDIR("Export Directory", magic, hdr, DIRENT_EXPORT)
    DDIR("Import Directory", magic, hdr, DIRENT_IMPORT)
    DDIR("Resource Directory", magic, hdr, DIRENT_RESOURCE)
    DDIR("Exception Directory", magic, hdr, DIRENT_EXCEPTION)
    DDIR("Security Directory", magic, hdr, DIRENT_SECURITY)
    DDIR("Relocation Directory RVA", magic, hdr, DIRENT_BASERELOC)
    DDIR("Debug Directory", magic, hdr, DIRENT_DEBUG)
    DDIR("Architecture Directory", magic, hdr, DIRENT_COPYRIGHT)
    DDIR("Global Pointer", magic, hdr, DIRENT_GLOBALPTR)
    DDIR("TLS", magic, hdr, DIRENT_TLS)
    DDIR("Configuration", magic, hdr, DIRENT_LOAD_CONFIG)
    DDIR("Bound Import", magic, hdr, DIRENT_BOUND_IMPORT)
    DDIR("Import Address Table", magic, hdr, DIRENT_IAT)
    DDIR("Delay Import Directory", magic, hdr, DIRENT_DELAY_IMPORT)
    DDIR(".NET Metadata", magic, hdr, DIRENT_COM_DESCRIPTOR)
  }
}

static inline void pe_dump_shdrs(pe_t *pe) {
  nt_fhdr_t *hdr = pe ? &NT_HDR(pe)->FileHeader : NULL;
  if (hdr) {
    pe_shdr_t *s = SHDR(pe);
    for (int i = 0; i < hdr->NumberOfSections; ++i) {
      printf("%-8s\n", s->Name);
      DUMP(" Virtual Size", s->Misc.VirtualSize);
      DUMP(" Virtual Address", s->VirtualAddress);
      DUMP(" Raw Size", s->SizeOfRawData);
      DUMP(" Raw Address", s->PointerToRawData);
      DUMP(" Reloc Address", s->PointerToRelocations);
      DUMP(" Line Numbers", s->PointerToLinenumbers);
      DUMP(" Relocations", s->NumberOfRelocations);
      DUMP(" Number of Line Numbers", s->NumberOfLinenumbers);
      DUMP(" Characteristics", s->Characteristics);
      s = ((void *)s) + sizeof(pe_shdr_t);
    }
  }
}

static inline void pe_dump_header(pe_t *pe) {
  if (pe) {
    DUMP("Signature", NT_HDR(pe)->Signature);
    printf("\nFile Header\n");
    pe_dump_fheader(pe);
    printf("\nOptional Header\n");
    pe_dump_oheader(pe);
    printf("\nData Directories\n");
    pe_dump_ddirs(pe);
    printf("\nSection Headers\n");
    pe_dump_shdrs(pe);
  }
}

static inline void dump(pe_t *pe) {
  printf("DOS Header\n");
  dos_dump_header(pe);
  printf("\nNT Headers\n");
  pe_dump_header(pe);
  printf("\n");
}

#endif /* DUMP_H */
