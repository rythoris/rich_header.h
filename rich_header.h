// rich_header.h --- PE file rich header parsing library
//
// rich_header.h is a simple and flexible header only C/C++ library for reading
// and deciphering the undocumented rich header from the portable executable
// (PE) files.
//
// Copyright (C) 2024 Ryan Thoris <rythoris@proton.me>
//
// Version: 0.1.0
//
// rich_header.h is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License (version 3) as published
// by the Free Software Foundation.

#ifndef _RICH_HEADER_H
#define _RICH_HEADER_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h> // memcmp

// This macro calculates the length of the products in the rich header based on
// the rich header size.
#define rich_header_products_len(rich_header_size) \
    (((rich_header_size) - (sizeof(uint32_t)*4)) / sizeof(IMAGE_MASKED_RICH_HEADER_PRODUCT))

typedef struct {
  uint16_t BuildNumber;
  uint16_t ProductID;
  uint32_t ObjectCount;
} IMAGE_MASKED_RICH_HEADER_PRODUCT;

// Head of the rich header wich is xor'ed with the IMAGE_RICH_HEADER.Key
// therefore it's called "MASKED".
typedef struct {
  uint32_t MaskedSignature;
  uint32_t NullPadding[3];
  IMAGE_MASKED_RICH_HEADER_PRODUCT Products[];
} IMAGE_MASKED_RICH_HEADER;

// Tail of the rich header which contains the "Rich" signature and the key
// (aka checksum).
typedef struct {
  uint32_t RichSignature;
  uint32_t Key;
} IMAGE_RICH_HEADER;

#ifdef __cplusplus
extern "C" { // Stop changing my function names!
#endif

long rich_header_from_data(const void *data, size_t data_size, IMAGE_RICH_HEADER **rhdr);
void rich_header_unmask(const IMAGE_RICH_HEADER *rhdr, size_t masked_rhdr_size, char masked_rhdr[masked_rhdr_size]);
const char* rich_header_productid_to_cstr(uint16_t product_id);
const char *rich_header_productid_to_vsver_cstr(uint16_t product_id);

#ifdef __cplusplus
} // close extern C
#endif

#endif // _RICH_HEADER_H

#ifdef RICH_HEADER_IMPLEMENTATION

// Find the rich header based on the "Rich" signature and calculate the length
// using the masked "DanS" signature.
//
// The function returns the size of the rich header, returns -1 if rich header
// is not found, and -2 if the rich header found but the length could not be
// calculated.
long
rich_header_from_data(const void *data, size_t data_size, IMAGE_RICH_HEADER **rhdr)
{
  static const char rich_header_signature[] = { 'R', 'i', 'c', 'h' };
  static const char rich_header_dans[] = { 'D', 'a', 'n', 'S' };
  bool found_header = false;

  // Since there is no correct way to detect the size of the DOS stub we have to
  // just skip it. The size of the IMAGE_DOS_HEADER is 64 bytes which means we
  // are aligned correctly and we can just move on from here.
  uint32_t *p = (uint32_t*)((char*)data + 64);
  while((char*)p + sizeof(rich_header_signature) < (char*)data + data_size) {
    if (memcmp((void*)p, rich_header_signature, sizeof(rich_header_signature)) == 0) {
      found_header = true;
      *rhdr = (IMAGE_RICH_HEADER*)p;
      break;
    }
    p += 1;
  }

  if (!found_header) return -1;

  // calculate the size of the header based on the "DanS" masked signature.
  for (uint32_t *p = (uint32_t *)*rhdr; (void*)p >= data; --p) {
    if ((*p ^ (*rhdr)->Key) == *(uint32_t *)rich_header_dans) {
      return (char *)*rhdr - (char *)p;
    }
  }

  return -2;
}

// Decipher (xor) the masked rich header based on the IMAGE_RICH_HEADER pointer
// and the offset (i.e. the size of the rich header) and write it to the
// provided IMAGE_MASKED_RICH_HEADER buffer.
//
// Note that the pointer to the masked rich header is calculated from the given
// rich header pointer this means the pointer must point to the rich header in
// the file content.
//
// The API is designed this way so you could be able to calculate the address of
// the masked rich header (see how `p` is defined bellow) so you could just use
// same buffer as the file and just overwrite it with the unmasked header.
void
rich_header_unmask(const IMAGE_RICH_HEADER *rhdr, size_t masked_rhdr_size, char masked_rhdr[masked_rhdr_size])
{
  uint32_t *p = (uint32_t*)((char*)rhdr - masked_rhdr_size);
  for (size_t i = 0; i < masked_rhdr_size / sizeof(uint32_t); ++i) {
    ((uint32_t*)masked_rhdr)[i] = p[i] ^ rhdr->Key;
  }
}

// Based on:
//   - https://github.com/kirschju/richheader
const char*
rich_header_productid_to_cstr(uint16_t product_id)
{
    switch (product_id) {
    case 0x0000: return "Unknown";
    case 0x0001: return "Import0";
    case 0x0002: return "Linker510";
    case 0x0003: return "Cvtomf510";
    case 0x0004: return "Linker600";
    case 0x0005: return "Cvtomf600";
    case 0x0006: return "Cvtres500";
    case 0x0007: return "Utc11_Basic";
    case 0x0008: return "Utc11_C";
    case 0x0009: return "Utc12_Basic";
    case 0x000a: return "Utc12_C";
    case 0x000b: return "Utc12_CPP";
    case 0x000c: return "AliasObj60";
    case 0x000d: return "VisualBasic60";
    case 0x000e: return "Masm613";
    case 0x000f: return "Masm710";
    case 0x0010: return "Linker511";
    case 0x0011: return "Cvtomf511";
    case 0x0012: return "Masm614";
    case 0x0013: return "Linker512";
    case 0x0014: return "Cvtomf512";
    case 0x0015: return "Utc12_C_Std";
    case 0x0016: return "Utc12_CPP_Std";
    case 0x0017: return "Utc12_C_Book";
    case 0x0018: return "Utc12_CPP_Book";
    case 0x0019: return "Implib700";
    case 0x001a: return "Cvtomf700";
    case 0x001b: return "Utc13_Basic";
    case 0x001c: return "Utc13_C";
    case 0x001d: return "Utc13_CPP";
    case 0x001e: return "Linker610";
    case 0x001f: return "Cvtomf610";
    case 0x0020: return "Linker601";
    case 0x0021: return "Cvtomf601";
    case 0x0022: return "Utc12_1_Basic";
    case 0x0023: return "Utc12_1_C";
    case 0x0024: return "Utc12_1_CPP";
    case 0x0025: return "Linker620";
    case 0x0026: return "Cvtomf620";
    case 0x0027: return "AliasObj70";
    case 0x0028: return "Linker621";
    case 0x0029: return "Cvtomf621";
    case 0x002a: return "Masm615";
    case 0x002b: return "Utc13_LTCG_C";
    case 0x002c: return "Utc13_LTCG_CPP";
    case 0x002d: return "Masm620";
    case 0x002e: return "ILAsm100";
    case 0x002f: return "Utc12_2_Basic";
    case 0x0030: return "Utc12_2_C";
    case 0x0031: return "Utc12_2_CPP";
    case 0x0032: return "Utc12_2_C_Std";
    case 0x0033: return "Utc12_2_CPP_Std";
    case 0x0034: return "Utc12_2_C_Book";
    case 0x0035: return "Utc12_2_CPP_Book";
    case 0x0036: return "Implib622";
    case 0x0037: return "Cvtomf622";
    case 0x0038: return "Cvtres501";
    case 0x0039: return "Utc13_C_Std";
    case 0x003a: return "Utc13_CPP_Std";
    case 0x003b: return "Cvtpgd1300";
    case 0x003c: return "Linker622";
    case 0x003d: return "Linker700";
    case 0x003e: return "Export622";
    case 0x003f: return "Export700";
    case 0x0040: return "Masm700";
    case 0x0041: return "Utc13_POGO_I_C";
    case 0x0042: return "Utc13_POGO_I_CPP";
    case 0x0043: return "Utc13_POGO_O_C";
    case 0x0044: return "Utc13_POGO_O_CPP";
    case 0x0045: return "Cvtres700";
    case 0x0046: return "Cvtres710p";
    case 0x0047: return "Linker710p";
    case 0x0048: return "Cvtomf710p";
    case 0x0049: return "Export710p";
    case 0x004a: return "Implib710p";
    case 0x004b: return "Masm710p";
    case 0x004c: return "Utc1310p_C";
    case 0x004d: return "Utc1310p_CPP";
    case 0x004e: return "Utc1310p_C_Std";
    case 0x004f: return "Utc1310p_CPP_Std";
    case 0x0050: return "Utc1310p_LTCG_C";
    case 0x0051: return "Utc1310p_LTCG_CPP";
    case 0x0052: return "Utc1310p_POGO_I_C";
    case 0x0053: return "Utc1310p_POGO_I_CPP";
    case 0x0054: return "Utc1310p_POGO_O_C";
    case 0x0055: return "Utc1310p_POGO_O_CPP";
    case 0x0056: return "Linker624";
    case 0x0057: return "Cvtomf624";
    case 0x0058: return "Export624";
    case 0x0059: return "Implib624";
    case 0x005a: return "Linker710";
    case 0x005b: return "Cvtomf710";
    case 0x005c: return "Export710";
    case 0x005d: return "Implib710";
    case 0x005e: return "Cvtres710";
    case 0x005f: return "Utc1310_C";
    case 0x0060: return "Utc1310_CPP";
    case 0x0061: return "Utc1310_C_Std";
    case 0x0062: return "Utc1310_CPP_Std";
    case 0x0063: return "Utc1310_LTCG_C";
    case 0x0064: return "Utc1310_LTCG_CPP";
    case 0x0065: return "Utc1310_POGO_I_C";
    case 0x0066: return "Utc1310_POGO_I_CPP";
    case 0x0067: return "Utc1310_POGO_O_C";
    case 0x0068: return "Utc1310_POGO_O_CPP";
    case 0x0069: return "AliasObj710";
    case 0x006a: return "AliasObj710p";
    case 0x006b: return "Cvtpgd1310";
    case 0x006c: return "Cvtpgd1310p";
    case 0x006d: return "Utc1400_C";
    case 0x006e: return "Utc1400_CPP";
    case 0x006f: return "Utc1400_C_Std";
    case 0x0070: return "Utc1400_CPP_Std";
    case 0x0071: return "Utc1400_LTCG_C";
    case 0x0072: return "Utc1400_LTCG_CPP";
    case 0x0073: return "Utc1400_POGO_I_C";
    case 0x0074: return "Utc1400_POGO_I_CPP";
    case 0x0075: return "Utc1400_POGO_O_C";
    case 0x0076: return "Utc1400_POGO_O_CPP";
    case 0x0077: return "Cvtpgd1400";
    case 0x0078: return "Linker800";
    case 0x0079: return "Cvtomf800";
    case 0x007a: return "Export800";
    case 0x007b: return "Implib800";
    case 0x007c: return "Cvtres800";
    case 0x007d: return "Masm800";
    case 0x007e: return "AliasObj800";
    case 0x007f: return "PhoenixPrerelease";
    case 0x0080: return "Utc1400_CVTCIL_C";
    case 0x0081: return "Utc1400_CVTCIL_CPP";
    case 0x0082: return "Utc1400_LTCG_MSIL";
    case 0x0083: return "Utc1500_C";
    case 0x0084: return "Utc1500_CPP";
    case 0x0085: return "Utc1500_C_Std";
    case 0x0086: return "Utc1500_CPP_Std";
    case 0x0087: return "Utc1500_CVTCIL_C";
    case 0x0088: return "Utc1500_CVTCIL_CPP";
    case 0x0089: return "Utc1500_LTCG_C";
    case 0x008a: return "Utc1500_LTCG_CPP";
    case 0x008b: return "Utc1500_LTCG_MSIL";
    case 0x008c: return "Utc1500_POGO_I_C";
    case 0x008d: return "Utc1500_POGO_I_CPP";
    case 0x008e: return "Utc1500_POGO_O_C";
    case 0x008f: return "Utc1500_POGO_O_CPP";
    case 0x0090: return "Cvtpgd1500";
    case 0x0091: return "Linker900";
    case 0x0092: return "Export900";
    case 0x0093: return "Implib900";
    case 0x0094: return "Cvtres900";
    case 0x0095: return "Masm900";
    case 0x0096: return "AliasObj900";
    case 0x0097: return "Resource";
    case 0x0098: return "AliasObj1000";
    case 0x0099: return "Cvtpgd1600";
    case 0x009a: return "Cvtres1000";
    case 0x009b: return "Export1000";
    case 0x009c: return "Implib1000";
    case 0x009d: return "Linker1000";
    case 0x009e: return "Masm1000";
    case 0x009f: return "Phx1600_C";
    case 0x00a0: return "Phx1600_CPP";
    case 0x00a1: return "Phx1600_CVTCIL_C";
    case 0x00a2: return "Phx1600_CVTCIL_CPP";
    case 0x00a3: return "Phx1600_LTCG_C";
    case 0x00a4: return "Phx1600_LTCG_CPP";
    case 0x00a5: return "Phx1600_LTCG_MSIL";
    case 0x00a6: return "Phx1600_POGO_I_C";
    case 0x00a7: return "Phx1600_POGO_I_CPP";
    case 0x00a8: return "Phx1600_POGO_O_C";
    case 0x00a9: return "Phx1600_POGO_O_CPP";
    case 0x00aa: return "Utc1600_C";
    case 0x00ab: return "Utc1600_CPP";
    case 0x00ac: return "Utc1600_CVTCIL_C";
    case 0x00ad: return "Utc1600_CVTCIL_CPP";
    case 0x00ae: return "Utc1600_LTCG_C";
    case 0x00af: return "Utc1600_LTCG_CPP";
    case 0x00b0: return "Utc1600_LTCG_MSIL";
    case 0x00b1: return "Utc1600_POGO_I_C";
    case 0x00b2: return "Utc1600_POGO_I_CPP";
    case 0x00b3: return "Utc1600_POGO_O_C";
    case 0x00b4: return "Utc1600_POGO_O_CPP";
    case 0x00b5: return "AliasObj1010";
    case 0x00b6: return "Cvtpgd1610";
    case 0x00b7: return "Cvtres1010";
    case 0x00b8: return "Export1010";
    case 0x00b9: return "Implib1010";
    case 0x00ba: return "Linker1010";
    case 0x00bb: return "Masm1010";
    case 0x00bc: return "Utc1610_C";
    case 0x00bd: return "Utc1610_CPP";
    case 0x00be: return "Utc1610_CVTCIL_C";
    case 0x00bf: return "Utc1610_CVTCIL_CPP";
    case 0x00c0: return "Utc1610_LTCG_C";
    case 0x00c1: return "Utc1610_LTCG_CPP";
    case 0x00c2: return "Utc1610_LTCG_MSIL";
    case 0x00c3: return "Utc1610_POGO_I_C";
    case 0x00c4: return "Utc1610_POGO_I_CPP";
    case 0x00c5: return "Utc1610_POGO_O_C";
    case 0x00c6: return "Utc1610_POGO_O_CPP";
    case 0x00c7: return "AliasObj1100";
    case 0x00c8: return "Cvtpgd1700";
    case 0x00c9: return "Cvtres1100";
    case 0x00ca: return "Export1100";
    case 0x00cb: return "Implib1100";
    case 0x00cc: return "Linker1100";
    case 0x00cd: return "Masm1100";
    case 0x00ce: return "Utc1700_C";
    case 0x00cf: return "Utc1700_CPP";
    case 0x00d0: return "Utc1700_CVTCIL_C";
    case 0x00d1: return "Utc1700_CVTCIL_CPP";
    case 0x00d2: return "Utc1700_LTCG_C";
    case 0x00d3: return "Utc1700_LTCG_CPP";
    case 0x00d4: return "Utc1700_LTCG_MSIL";
    case 0x00d5: return "Utc1700_POGO_I_C";
    case 0x00d6: return "Utc1700_POGO_I_CPP";
    case 0x00d7: return "Utc1700_POGO_O_C";
    case 0x00d8: return "Utc1700_POGO_O_CPP";
    case 0x00d9: return "AliasObj1200";
    case 0x00da: return "Cvtpgd1800";
    case 0x00db: return "Cvtres1200";
    case 0x00dc: return "Export1200";
    case 0x00dd: return "Implib1200";
    case 0x00de: return "Linker1200";
    case 0x00df: return "Masm1200";
    case 0x00e0: return "Utc1800_C";
    case 0x00e1: return "Utc1800_CPP";
    case 0x00e2: return "Utc1800_CVTCIL_C";
    case 0x00e3: return "Utc1800_CVTCIL_CPP";
    case 0x00e4: return "Utc1800_LTCG_C";
    case 0x00e5: return "Utc1800_LTCG_CPP";
    case 0x00e6: return "Utc1800_LTCG_MSIL";
    case 0x00e7: return "Utc1800_POGO_I_C";
    case 0x00e8: return "Utc1800_POGO_I_CPP";
    case 0x00e9: return "Utc1800_POGO_O_C";
    case 0x00ea: return "Utc1800_POGO_O_CPP";
    case 0x00eb: return "AliasObj1210";
    case 0x00ec: return "Cvtpgd1810";
    case 0x00ed: return "Cvtres1210";
    case 0x00ee: return "Export1210";
    case 0x00ef: return "Implib1210";
    case 0x00f0: return "Linker1210";
    case 0x00f1: return "Masm1210";
    case 0x00f2: return "Utc1810_C";
    case 0x00f3: return "Utc1810_CPP";
    case 0x00f4: return "Utc1810_CVTCIL_C";
    case 0x00f5: return "Utc1810_CVTCIL_CPP";
    case 0x00f6: return "Utc1810_LTCG_C";
    case 0x00f7: return "Utc1810_LTCG_CPP";
    case 0x00f8: return "Utc1810_LTCG_MSIL";
    case 0x00f9: return "Utc1810_POGO_I_C";
    case 0x00fa: return "Utc1810_POGO_I_CPP";
    case 0x00fb: return "Utc1810_POGO_O_C";
    case 0x00fc: return "Utc1810_POGO_O_CPP";
    case 0x00fd: return "AliasObj1400";
    case 0x00fe: return "Cvtpgd1900";
    case 0x00ff: return "Cvtres1400";
    case 0x0100: return "Export1400";
    case 0x0101: return "Implib1400";
    case 0x0102: return "Linker1400";
    case 0x0103: return "Masm1400";
    case 0x0104: return "Utc1900_C";
    case 0x0105: return "Utc1900_CPP";
    case 0x0106: return "Utc1900_CVTCIL_C";
    case 0x0107: return "Utc1900_CVTCIL_CPP";
    case 0x0108: return "Utc1900_LTCG_C";
    case 0x0109: return "Utc1900_LTCG_CPP";
    case 0x010a: return "Utc1900_LTCG_MSIL";
    case 0x010b: return "Utc1900_POGO_I_C";
    case 0x010c: return "Utc1900_POGO_I_CPP";
    case 0x010d: return "Utc1900_POGO_O_C";
    case 0x010e: return "Utc1900_POGO_O_CPP";
    default: return "";
    }
}

// Based on:
//   - https://github.com/hasherezade/bearparser/blob/master/parser/pe/RichHdrWrapper.cpp
//   - https://github.com/kirschju/richheader
const char *
rich_header_productid_to_vsver_cstr(uint16_t product_id)
{
  if (product_id >= 0x0106 && product_id <= 0x010a)
    return "Visual Studio 2017 14.01+";
  else if (product_id >= 0x00fd && product_id <= 0x0106)
    return "Visual Studio 2015 14.00";
  else if (product_id >= 0x00eb && product_id <= 0x00fd)
    return "Visual Studio 2013 12.10";
  else if (product_id >= 0x00d9 && product_id <= 0x00eb)
    return "Visual Studio 2013 12.00";
  else if (product_id >= 0x00c7 && product_id <= 0x00d9)
    return "Visual Studio 2012 11.00";
  else if (product_id >= 0x00b5 && product_id <= 0x00c7)
    return "Visual Studio 2010 10.10";
  else if (product_id >= 0x0098 && product_id <= 0x00b5)
    return "Visual Studio 2010 10.00";
  else if (product_id >= 0x0083 && product_id <= 0x0098)
    return "Visual Studio 2008 09.00";
  else if (product_id >= 0x006d && product_id <= 0x0083)
    return "Visual Studio 2005 08.00";
  else if (product_id >= 0x005a && product_id <= 0x006d)
    return "Visual Studio 2003 07.10";
  else if (product_id >= 0x0019 && product_id <= 0x0045)
    return "Visual Studio 2002 07.00";
  else if ((product_id >= 0xA && product_id <= 0xD) ||
           (product_id >= 0x15 && product_id <= 0x16))
    return "Visual Studio 6.0 06.00";
  else if (product_id == 0x2 || product_id == 0x6 || product_id == 0xC || product_id == 0xE)
    return "Visual Studio 97 05.00";
  else if (product_id == 1)
    return "Visual Studio";
  return "";
}

#endif // RICH_HEADER_IMPLEMENTATION
