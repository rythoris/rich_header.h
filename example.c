// example.c --- example usage of the rich_header.h library
//
// Copyright (C) 2024 Ryan Thoris <rythoris@proton.me>
//
// example.c is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License (version 3) as published by the
// Free Software Foundation.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define RICH_HEADER_IMPLEMENTATION
#include "rich_header.h"

int
main(int argc, char **argv)
{
  if (argc != 2) {
    printf("Usage: %s <PE_FILE>\n", argv[0]);
    return EXIT_FAILURE;
  }

  char *file_path = argv[1];

  FILE *f = fopen(file_path, "rb");
  assert(f != NULL);

  struct stat st;
  assert(!stat(file_path, &st));
  size_t file_size = st.st_size;

  char *content = malloc(file_size);
  assert(content != NULL);

  unsigned long n = fread(content, sizeof(char), file_size, f);
  assert(n > 0);

  // check MS-DOS header magic number: "MZ"
  assert(*((uint16_t*)content) == (uint16_t)0x5a4d);

  IMAGE_RICH_HEADER *rich_header;
  long rich_header_size = rich_header_from_data(content, file_size, &rich_header);
  assert(rich_header_size > 0);

  // Since we want to decipher and overwrite the header in place we calculate
  // the pointer ourselves (instead of allocating memory).
  //
  //read the 'rich_header_unmask' function comment for more information.
  IMAGE_MASKED_RICH_HEADER *masked_rich_header = (IMAGE_MASKED_RICH_HEADER*)((char*)rich_header - rich_header_size);

  rich_header_unmask(rich_header, rich_header_size, (char*)masked_rich_header);

  for (size_t i = 0; i < rich_header_products_len(rich_header_size); ++i) {
    IMAGE_MASKED_RICH_HEADER_PRODUCT product = masked_rich_header->Products[i];

    printf("%-3zu buildNo: 0x%08x objCount: %-5d product_id(%03d): %-30s %s\n",
           i, product.BuildNumber, product.ProductID, product.ObjectCount,
           rich_header_productid_to_vsver_cstr(product.ProductID),
           rich_header_productid_to_cstr(product.ProductID));
  }

  return EXIT_SUCCESS;
}
