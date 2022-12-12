#include <common.h>
#include <malloc.h>
#include <mapmem.h>
#include "interface_overlay.h"

#define MAX_OVERLAY_NAME_LENGTH 128

static unsigned long hw_skip_comment(char *text)
{
	int i = 0;
	if(*text == '#') {
		while(*(text + i) != 0x00)
		{
			if(*(text + (i++)) == 0x0a)
				break;
		}
	}
	return i;
}

static unsigned long hw_skip_line(char *text)
{
	if(*text == 0x0a)
		return 1;
	else
		return 0;
}

static unsigned long get_append(char *text)
{
	int i = 0;
	int append_len = 0;

	while(*(text + i) != 0x00)
	{
		if(*(text + i) == 0x0a) {
			append_len = i;
			i++;
			break;
		} else
			i++;
	}

	if (append_len) {
		char *append = (char*)calloc(append_len, sizeof(char));

		memcpy(append, text, append_len);
		printf("get append cmdline: %s\n", append);
		env_update("bootargs", append);
		free(append);
	}

	return i;
}

static int set_file_conf(char *text, struct hw_config *hw_conf, int start_point, int file_ptr)
{
	char *ptr;
	int name_length;

	name_length = file_ptr - start_point;

	if(name_length && name_length < MAX_OVERLAY_NAME_LENGTH) {
		ptr = (char*)calloc(MAX_OVERLAY_NAME_LENGTH, sizeof(char));
		memcpy(ptr, text + start_point, name_length);
		ptr[name_length] = 0x00;
		hw_conf->overlay_file[hw_conf->overlay_count] = ptr;
		hw_conf->overlay_count += 1;
	}
	//Pass a space for next string.
	start_point = file_ptr + 1;

	return start_point;
}

void get_overlay_count(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	int start_point = 0;
	int overlay_count = 0;
	int name_length;

	while(*(text + i) != 0x00)
	{
		if(*(text + i) == 0x20 || *(text + i) == 0x0a) {
			name_length = i - start_point;
			if(name_length && name_length < MAX_OVERLAY_NAME_LENGTH)
				overlay_count += 1;
		}

		if(*(text + i) == 0x20)
			start_point = i + 1;
		else if(*(text + i) == 0x0a)
			break;
		i++;
	}

	hw_conf->overlay_file = (char**)calloc(overlay_count, sizeof(char*));
}

static unsigned long get_overlay(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	int start_point = 0;

	hw_conf->overlay_count = 0;
	while(*(text + i) != 0x00)
	{
		if(*(text + i) == 0x20 || *(text + i) == 0x0a)
			start_point = set_file_conf(text, hw_conf, start_point, i);

		if(*(text + i) == 0x0a) {
			i++;
			break;
		} else
			i++;
	}

	return i;
}

static unsigned long hw_parse_property(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	if(memcmp(text, "overlay=", 8) == 0) {
		i = 8;
		get_overlay_count(text + i, hw_conf);
		i = i + get_overlay(text + i, hw_conf);
	} else {
		printf("[conf] hw_parse_property: illegal line\n");
		//It's not a legal line, skip it.
		while(*(text + i) != 0x00) {
			if(*(text + (i++)) == 0x0a)
				break;
		}
	}
	return i;
}

void set_mmcroot(void)
{
	char *rootmmc0 = "root=/dev/mmcblk0p7"; /* eMMC Boot */
	char *rootmmc1 = "root=/dev/mmcblk1p7"; /* SDcard Boot */

	char *devtype = env_get("devtype");
	char *devnum = env_get("devnum");

	if (!strcmp(devtype, "mmc")) {
		if (!strcmp(devnum, "0")) {
			printf("Set %s\n", rootmmc0);
			env_update("bootargs", rootmmc0);
		} else if (!strcmp(devnum, "1")) {
			printf("Set %s\n", rootmmc1);
			env_update("bootargs", rootmmc1);
		}
	}
}

void parse_cmdline(void)
{
	unsigned long count, offset = 0, addr, size;
	char *file_addr, *devnum;
	static char *fs_argv[5];

	int valid = 0;

	devnum = env_get("devnum");
	if (!devnum) {
		printf("Can't get devnum\n");
		goto end;
	}

	file_addr = env_get("cmdline_addr");
	if (!file_addr) {
		printf("Can't get cmdline_addr address\n");
		goto end;
	}

	addr = simple_strtoul(file_addr, NULL, 16);
	if (!addr)
		printf("Can't set addr\n");

	fs_argv[0] = "ext2load";
	fs_argv[1] = "mmc";

	if (!strcmp(devnum, "0"))
		fs_argv[2] = "0:6";
	else if (!strcmp(devnum, "1"))
		fs_argv[2] = "1:6";
	else {
		printf("Invalid devnum\n");
		goto end;
	}

	fs_argv[3] = file_addr;
	fs_argv[4] = "cmdline.txt";

	if (do_ext2load(NULL, 0, 5, fs_argv)) {
		printf("[cmdline] do_ext2load fail\n");
		goto end;
	}

	size = env_get_ulong("filesize", 16, 0);
	if (!size) {
		printf("[cmdline] Can't get filesize\n");
		goto end;
	}

	valid = 1;

	printf("cmdline.txt size = %lu\n", size);

	*((char *)file_addr + size) = 0x00;

	while(offset != size)
	{
		count = hw_skip_comment((char *)(addr + offset));
		if(count > 0) {
			offset = offset + count;
			continue;
		}
		count = hw_skip_line((char *)(addr + offset));
		if(count > 0) {
			offset = offset + count;
			continue;
		}
		count = get_append((char *)(addr + offset));
		if(count > 0) {
			offset = offset + count;
			continue;
		}
	}

end:
	printf("cmdline.txt valid = %d\n", valid);
}

void parse_hw_config(struct hw_config *hw_conf)
{
	unsigned long count, offset = 0, addr, size;
	char *file_addr, *devnum;
	static char *fs_argv[5];

	int valid = 0;

	devnum = env_get("devnum");
	if (!devnum) {
		printf("Can't get devnum\n");
		goto end;
	}

	file_addr = env_get("conf_addr");
	if (!file_addr) {
		printf("Can't get conf_addr address\n");
		goto end;
	}

	addr = simple_strtoul(file_addr, NULL, 16);
	if (!addr)
		printf("Can't set addr\n");

	fs_argv[0] = "ext2load";
	fs_argv[1] = "mmc";

	if (!strcmp(devnum, "0"))
		fs_argv[2] = "0:6";
	else if (!strcmp(devnum, "1"))
		fs_argv[2] = "1:6";
	else {
		printf("Invalid devnum\n");
		goto end;
	}

	fs_argv[3] = file_addr;
	fs_argv[4] = "config.txt";

	if (do_ext2load(NULL, 0, 5, fs_argv)) {
		printf("[conf] do_ext2load fail\n");
		goto end;
	}

	size = env_get_ulong("filesize", 16, 0);
	if (!size) {
		printf("[conf] Can't get filesize\n");
		goto end;
	}

	valid = 1;
	printf("config.txt size = %lu\n", size);

	*((char *)file_addr + size) = 0x00;

	while(offset != size)
	{
		count = hw_skip_comment((char *)(addr + offset));
		if(count > 0) {
			offset = offset + count;
			continue;
		}
		count = hw_skip_line((char *)(addr + offset));
		if(count > 0) {
			offset = offset + count;
			continue;
		}
		count = hw_parse_property((char *)(addr + offset), hw_conf);
		if(count > 0) {
			offset = offset + count;
			continue;
		}
	}
end:
	hw_conf->valid = valid;
}

struct fdt_header *resize_working_fdt(void)
{
	struct fdt_header *working_fdt;
	unsigned long file_addr;
	int err;

	file_addr = env_get_ulong("fdt_addr_r", 16, 0);
	if (!file_addr) {
		printf("Can't get fdt address\n");
		return NULL;
	}

	working_fdt = map_sysmem(file_addr, 0);
	err = fdt_open_into(working_fdt, working_fdt, (1024 * 1024));
	if (err != 0) {
		printf("libfdt fdt_open_into(): %s\n", fdt_strerror(err));
		return NULL;
	}

	printf("fdt magic number %x\n", working_fdt->magic);
	printf("fdt size %u\n", fdt_totalsize(working_fdt));

	return working_fdt;
}

#ifdef CONFIG_OF_LIBFDT_OVERLAY
static int fdt_valid(struct fdt_header **blobp)
{
	const void *blob = *blobp;
	int err;

	if (blob == NULL) {
		printf ("The address of the fdt is invalid (NULL).\n");
		return 0;
	}

	err = fdt_check_header(blob);
	if (err == 0)
		return 1;	/* valid */

	if (err < 0) {
		printf("libfdt fdt_check_header(): %s", fdt_strerror(err));
		/*
		 * Be more informative on bad version.
		 */
		if (err == -FDT_ERR_BADVERSION) {
			if (fdt_version(blob) < FDT_FIRST_SUPPORTED_VERSION) {
				printf (" - too old, fdt %d < %d", fdt_version(blob), FDT_FIRST_SUPPORTED_VERSION);
			}
			if (fdt_last_comp_version(blob) > FDT_LAST_SUPPORTED_VERSION) {
				printf (" - too new, fdt %d > %d", fdt_version(blob), FDT_LAST_SUPPORTED_VERSION);
			}
		}
		printf("\n");
		*blobp = NULL;
		return 0;
	}
	return 1;
}

static int merge_dts_overlay(cmd_tbl_t *cmdtp, struct fdt_header *working_fdt, char *overlay_name)
{
	unsigned long addr;
	char *file_addr, *devnum;
	struct fdt_header *blob;
	int ret;
	char overlay_file[MAX_OVERLAY_NAME_LENGTH] = "overlays/";

	static char *fs_argv[5];

	devnum = env_get("devnum");
	if (!devnum) {
		printf("Can't get devnum\n");
		goto fail;
	}

	file_addr = env_get("fdt_overlay_addr");
	if (!file_addr) {
		printf("Can't get fdt overlay address\n");
		goto fail;
	}

	addr = simple_strtoul(file_addr, NULL, 16);

	strcat(overlay_file, overlay_name);
	strncat(overlay_file, ".dtbo", 6);

	fs_argv[0] = "ext2load";
	fs_argv[1] = "mmc";

	if (!strcmp(devnum, "0"))
		fs_argv[2] = "0:6";
	else if (!strcmp(devnum, "1"))
		fs_argv[2] = "1:6";
	else {
		printf("Invalid devnum\n");
		goto fail;
	}

	fs_argv[3] = file_addr;
	fs_argv[4] = overlay_file;

	if (do_ext2load(NULL, 0, 5, fs_argv)) {
		printf("[merge_dts_overlay] do_ext2load fail\n");
		goto fail;
	}

	blob = map_sysmem(addr, 0);
	if (!fdt_valid(&blob)) {
		printf("[merge_dts_overlay] fdt_valid is invalid\n");
		goto fail;
	} else
		printf("fdt_valid\n");

	ret = fdt_overlay_apply(working_fdt, blob);
	if (ret) {
		printf("[merge_dts_overlay] fdt_overlay_apply(): %s\n", fdt_strerror(ret));
		goto fail;
	}

	return 0;

fail:
	return -1;
}
#endif

void handle_hw_conf(cmd_tbl_t *cmdtp, struct fdt_header *working_fdt, struct hw_config *hw_conf)
{
	if(working_fdt == NULL)
		return;

#ifdef CONFIG_OF_LIBFDT_OVERLAY
	int i;
	for (i = 0; i < hw_conf->overlay_count; i++) {
		if (merge_dts_overlay(cmdtp, working_fdt, hw_conf->overlay_file[i]) < 0)
			printf("Can't merge dts overlay: %s\n", hw_conf->overlay_file[i]);
		else
			printf("Merged dts overlay: %s\n", hw_conf->overlay_file[i]);

		free(hw_conf->overlay_file[i]);
	}
	free(hw_conf->overlay_file);
#endif
}
