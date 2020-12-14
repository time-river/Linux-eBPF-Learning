#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <libelf.h>
#include <gelf.h>

int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stdout, "Usage: %s <eBPF program>\n", argv[0]);
		return 0;
	}

	return 0;
}

static int get_sec(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname,
		   GElf_Shdr *shdr, Elf_Data **data);

int parse_elf(const char *file) {
	int elf_fd;
	char *shname;
	Elf *elf;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	Elf_Data *data;
	char license[128] = {0};
	int strtabidx = -1;
	Elf_Data *symbols = NULL;
	int is_kprobe = 0;
	char *d_data, *prog_name;
	size_t d_size;

	if ((elf_fd = open(file, O_RDONLY)) < 0) {
		fprintf(stderr, "ERROR： open('%s'): %s\n",
			file, strerror(errno));
		return 1;
	}

	if ((elf = elf_begin(elf_fd, ELF_C_READ, NULL)) == NULL) {
		fprintf(stderr, "ERROR: elf_begin(): %s\n", strerror(errno));
		return 1;
	}

	if (gelf_getehdr(elf, &ehdr) == NULL) {
		fprintf(stderr, "ERROR: gelf_getehdr(): %s\n", strerror(errno));
		return 1;
	}

	for (int i = 0; i < ehdr.e_shnum; i++) {
		if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
			continue;

		printf("section %d:%s data %p size %zd link %d flags %d\n",
		       i, shname, data->d_buf, data->d_size,
		       shdr.sh_link, (int) shdr.sh_flags);

		if (strcmp(shname, "license") == 0)
			memcpy(license, data->d_buf, data->d_size);
		else if (strncmp(shname, "kprobe/", 7) == 0) {
			is_kprobe = 1;
			d_data = data->d_buf;
			d_size = data->d_size;
			prog_name = shname + 7;
		}
	}

	if (is_kprobe) {
		return bpf_load_program(BPF_PROG_TYPE_KPROBE,
					d_data, d_size, license,
					prog_name, NULL, 0);
	}

	return -EINVAL;
}

static int get_sec(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname,
		   GElf_Shdr *shdr, Elf_Data **data) {
	Elf_Scn *scn;

	if ((scn = elf_getscn(elf, i)) == NULL) {
		//TODO
		return 1;
	}

	if (gelf_getshdr(scn, shdr) == NULL)
		return 2;

	*shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
	if (!*shname || !shdr->sh_size)
		return 3;

	*data = elf_getdata(scn, 0);
	if (!*data || elf_getdata(scn, *data) != NULL)
		return 4;

	return 0;

}
