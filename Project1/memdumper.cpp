#include "../BinaryLoader/loader.hpp"
#include <iostream>
#include <string.h>

int main() {
  std::string filename = "project1";
  Binary bin = Binary();
  load_binary(filename, &bin, Binary::BIN_TYPE_ELF);

  // Symbols
  for (Symbol sym : bin.symbols)
    printf("%-40s\t0x%016jx\n", sym.name.c_str(), sym.addr);

  // Sections
  for (Section sec : bin.sections) {
    std::cout << std::endl << std::endl << sec.name;
    for (size_t i = 0; i < sec.size; i++) {
      if (i % 48 == 0)
        std::cout << std::endl;
      if (i % 8 == 0)
        std::cout << " ";

      printf("%02x", sec.bytes[i]);
    }
  }

  std::cout << std::endl;

  unload_binary(&bin);
}
