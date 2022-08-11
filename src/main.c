#include <stdio.h>
#include <stdlib.h>

#include "dumpe.h"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <PE File>\n", argv[0]);
    exit(-1);
  }

  const char *pe_file = argv[1];
  pe_t *pe = pe_init(pe_file);
  if (!pe) {
    fprintf(stderr, "Invalid PE file %s\n", argv[1]);
    exit(-1);
  }

  dump(pe);
  pe_free(&pe);

  return 0;
}
