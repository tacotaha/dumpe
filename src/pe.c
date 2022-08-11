#include "pe.h"

#include <stdio.h>
#include <stdlib.h>

pe_t *pe_init(const char *pe_file) {
  FILE *fp;
  pe_t *pe;
  size_t file_size;

  fp = fopen(pe_file, "rb");
  fseek(fp, 0, SEEK_END);
  file_size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  if ((pe = malloc(file_size)))
    if (fread((char *)pe, 1, file_size, fp) < file_size) free(pe);

  fclose(fp);

  return (pe && valid(pe)) ? pe : NULL;
}

void pe_free(pe_t **pe) {
  if (pe && *pe) {
    free(*pe);
    *pe = NULL;
  }
}
