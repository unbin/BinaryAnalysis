#include <bfd.h>
#include "loader.hpp"

static int load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type);
static bfd* open_bfd(std::string &fname);
static int load_symbols_bfd(bfd *bfd_h, Binary *bin);
static int load_dynsym_bfd(bfd *bfd_h, Binary *bin);
static int load_sections_bfd(bfd *bfd_h, Binary *bin);

int load_binary(std::string &fname, Binary *bin, Binary::BinaryType type) {
	return load_binary_bfd(fname, bin, type);
}

void unload_binary(Binary *bin) {
	Section *sec = NULL;
	for (size_t i; i < bin->sections.size(); i++) {
		sec = &bin->sections[i];
		if (sec->bytes)
			free(sec->bytes);
	}
}

static bfd* open_bfd(std::string &fname) {
	static int bfd_inited = 0;
	bfd *bfd_h = NULL;

	if (!bfd_inited) {
		bfd_init();
		bfd_inited = 1;
	}

	bfd_h = bfd_openr(fname.c_str(), NULL);

	if (!bfd_h) {
		fprintf(stderr, "failed to open binary '%s' (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
		return NULL;
	}

	if (!bfd_check_format(bfd_h, bfd_object)) {
		fprintf(stderr, "file '%s' does not look like an executable (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
		return NULL;
	}

	bfd_set_error(bfd_error_no_error);

	if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) {
		fprintf(stderr, "unrecognized format for binary '%s' (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
		return NULL;
	}

	return bfd_h;
}

static int load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type) {
	int ret = 0;
	bfd *bfd_h = NULL;
	const bfd_arch_info_type *bfd_info = NULL;

	bfd_h = open_bfd(fname);
	if (!bfd_h)
		goto fail;

	bin->filename = fname;
	bin->entry = bfd_get_start_address(bfd_h);

	// Binary Type
	bin->type_str = bfd_h->xvec->name;
	switch (bfd_h->xvec->flavour) {
	case bfd_target_elf_flavour:
		bin->type = Binary::BIN_TYPE_ELF;
		break;
	case bfd_target_coff_flavour:
		bin->type = Binary::BIN_TYPE_PE;
		break;
	default:
		fprintf(stderr, "unsupported binary type (%s)\n", bfd_h->xvec->name);
		goto fail;
	}

	// Machine Architecture
	bfd_info = bfd_get_arch_info(bfd_h);
	bin->arch_str = bfd_info->printable_name;
	switch (bfd_info->mach) {
	case bfd_mach_i386_i386:
		bin->arch = Binary::ARCH_X86;
		bin->bits = 32;
		break;
	case bfd_mach_x86_64:
		bin->arch = Binary::ARCH_X86;
		bin->bits = 64;
		break;
	default:
		fprintf(stderr, "unsupported architecture (%s)\n", bfd_info->printable_name);
		goto fail;
	}

	// Symbols
	load_symbols_bfd(bfd_h, bin);
	load_dynsym_bfd(bfd_h, bin);

	// Sections
	if (load_sections_bfd(bfd_h, bin) < 0)
		goto fail;

	ret = 0;
	goto cleanup;

fail:
	ret = -1;

cleanup:
	if (bfd_h)
		bfd_close(bfd_h);

	return ret;
}

static int load_symbols_bfd(bfd *bfd_h, Binary *bin) {
	int ret = 0;
	long n = 0, nsyms = 0;
	asymbol **bfd_symtab = NULL;

	// get size of 'bfd_symtab' buffer
	n = bfd_get_symtab_upper_bound(bfd_h);
	if (n < 0) {
		fprintf(stderr, "failed to read symtab (%s)\n", bfd_errmsg(bfd_get_error()));
		goto fail;
	}
	else if (n) {
		// allocate 'bfd_symtab'
		bfd_symtab = (asymbol**)malloc(n);
		if (!bfd_symtab) {
			fprintf(stderr, "out of memory\n");
			goto fail;
		}
		// fill 'bfd_symtab'
		nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
		if (nsyms < 0) {
			fprintf(stderr, "failed to read symtab (%s)\n", bfd_errmsg(bfd_get_error()));
			goto fail;
		}
		// fill symbol buffer in 'bin' with function symbols
		Symbol *sym = NULL; // shorthand for 'bin->symbols.back()'
		uint32_t flags; // shorthand for 'bfd_symtab[i]->flags'
		std::vector<bool> weaksyms;
		for (long i = 0; i < nsyms; i++) {
			flags = bfd_symtab[i]->flags;
			if (flags & BSF_FUNCTION || flags & BSF_LOCAL || flags & BSF_GLOBAL) {
				bin->symbols.push_back(Symbol());
				sym = &bin->symbols.back();
				sym->name = bfd_symtab[i]->name;
				sym->addr = bfd_asymbol_value(bfd_symtab[i]);
				if (flags & BSF_FUNCTION)
					sym->type = Symbol::SYM_TYPE_FUNC;
				else if (flags & BSF_LOCAL || flags & BSF_GLOBAL)
					sym->type = Symbol::SYM_TYPE_DATA;

				weaksyms.push_back(false);
				// mark weak symbols
				if (flags & BSF_WEAK)
					weaksyms.back() = true;
				// override weak symbols
				else {
					for (size_t j = 0; j < bin->symbols.size(); j++) {
						if ((bin->symbols[j].name == bfd_symtab[i]->name) && weaksyms[j]) {
							bin->symbols.erase(bin->symbols.begin() + j);
							weaksyms.erase(weaksyms.begin() + j);
						}
					}
				}
			}
		}
	}

	goto cleanup;

fail:
	ret = -1;

cleanup:
	if (bfd_symtab)
		free(bfd_symtab);

	return ret;
}

static int load_dynsym_bfd(bfd *bfd_h, Binary *bin) {
	int ret = 0;
	int n = 0, nsyms = 0;
	asymbol **bfd_dynsym = NULL;

	// get size of 'bfd_dynsym' buffer
	n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
	if (n < 0) {
		fprintf(stderr, "failed to load dynsym (%s)\n", bfd_errmsg(bfd_get_error()));
		goto fail;
	}
	else if (n) {
		// allocate 'bfd_dynsym'
		bfd_dynsym = (asymbol**)malloc(n);
		if (!bfd_dynsym) {
			fprintf(stderr, "out of memory\n");
			goto fail;
		}
		// fill 'bfd_dynsym'
		nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
		if (nsyms < 0) {
			fprintf(stderr, "failed to load dynsym (%s)\n", bfd_errmsg(bfd_get_error()));
			goto fail;
		}
		// fill symbol buffer in 'bin' with dynamic function symbols
		Symbol *sym = NULL; // shorthand for 'bin->symbols.back()'
		uint32_t flags; // shorthand for 'bfd_dynsym[i]->flags'
		for (long i = 0; i < nsyms; i++) {
			flags = bfd_dynsym[i]->flags;
			if (flags & BSF_FUNCTION || flags & BSF_LOCAL || flags & BSF_GLOBAL) {
				bin->symbols.push_back(Symbol());
				sym = &bin->symbols.back();
				sym->name = bfd_dynsym[i]->name;
				sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
				if (flags & BSF_FUNCTION)
					sym->type = Symbol::SYM_TYPE_FUNC;
				else if (flags & BSF_LOCAL || flags & BSF_GLOBAL)
					sym->type = Symbol::SYM_TYPE_DATA;
			}
		}
	}

	goto cleanup;

fail:
	ret = -1;

cleanup:
	if (bfd_dynsym)
		free(bfd_dynsym);

	return ret;
}

static int load_sections_bfd(bfd *bfd_h, Binary *bin) {
	int bfd_flags;
	uint64_t vma, size;
	const char *secname;
	asection *bfd_sec;
	Section *sec;
	Section::SectionType sectype;

	for (bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
		// set flags
		bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);

		sectype = Section::SEC_TYPE_NONE;
		if (bfd_flags & SEC_CODE)
			sectype = Section::SEC_TYPE_CODE;
		else if (bfd_flags & SEC_DATA)
			sectype = Section::SEC_TYPE_DATA;
		else
			continue;

		// extract data
		vma = bfd_section_vma(bfd_h, bfd_sec);
		size = bfd_section_size(bfd_h, bfd_sec);
		secname = bfd_section_name(bfd_h, bfd_sec);
		if (!secname)
			secname = "<unnamed>";

		// add section to 'bin->sections' vector
		bin->sections.push_back(Section());
		sec = &bin->sections.back();

		sec->binary = bin;
		sec->name = secname;
		sec->type = sectype;
		sec->vma = vma;
		sec->size = size;
		sec->bytes = (uint8_t*)malloc(size);
		if (!sec->bytes) {
			fprintf(stderr, "out of memeory\n");
			return -1;
		}

		if (!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size)) {
			fprintf(stderr, "failed to read section (%s)\n", bfd_errmsg(bfd_get_error()));
			return -1;
		}
	}

	return 0;
}
