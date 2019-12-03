/*
 * Copyright (c) 2011 Sebastian Andrzej Siewior <bigeasy@linutronix.de>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <adc.h>
#include <image.h>
#include <android_image.h>
#include <android_bootloader.h>
#include <malloc.h>
#include <mapmem.h>
#include <errno.h>
#include <boot_rkimg.h>
#include <sysmem.h>
#ifdef CONFIG_RKIMG_BOOTLOADER
#include <asm/arch/resource_img.h>
#endif
#ifdef CONFIG_RK_AVB_LIBAVB_USER
#include <android_avb/avb_slot_verify.h>
#include <android_avb/avb_ops_user.h>
#include <android_avb/rk_avb_ops_user.h>
#endif
#include <optee_include/OpteeClientInterface.h>

DECLARE_GLOBAL_DATA_PTR;

#define ANDROID_IMAGE_DEFAULT_KERNEL_ADDR	0x10008000
#define ANDROID_ARG_FDT_FILENAME "rk-kernel.dtb"

#define MAX_OVERLAY_NAME_LENGTH 128
struct hw_config
{
	int valid;

	int fiq_debugger;
	int i2c6, i2c7;
	int uart0, uart4;
	int i2s0;
	int spi1, spi5;
	int pwm0, pwm1, pwm3a;

	int gmac, adc5_bid;

	int overlay_count;
	char **overlay_file;
};

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

static unsigned long get_intf_value(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	if(memcmp(text, "fiq_debugger=",  13) == 0) {
		i = 13;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->fiq_debugger = 1;
			hw_conf->uart0 = -1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->fiq_debugger = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if(memcmp(text, "i2c6=",  5) == 0) {
		i = 5;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->i2c6 = 1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->i2c6 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if(memcmp(text, "i2c7=",  5) == 0) {
		i = 5;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->i2c7 = 1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->i2c7 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if(memcmp(text, "uart0=",  6) == 0) {
		i = 6;
		if(memcmp(text + i, "on", 2) == 0) {
			if(hw_conf->fiq_debugger != 1)
				hw_conf->uart0 = 1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->uart0 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if(memcmp(text, "uart4=",  6) == 0) {
		i = 6;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->uart4 = 1;
			hw_conf->spi1 = -1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->uart4 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if(memcmp(text, "i2s0=",  5) == 0) {
		i = 5;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->i2s0 = 1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->i2s0 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if(memcmp(text, "spi1=",  5) == 0) {
		i = 5;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->spi1 = 1;
			hw_conf->uart4 = -1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->spi1 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if(memcmp(text, "spi5=",  5) == 0) {
		i = 5;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->spi5 = 1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->spi5 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if(memcmp(text, "pwm0=",  5) == 0) {
		i = 5;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->pwm0 = 1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->pwm0 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if(memcmp(text, "pwm1=",  5) == 0) {
		i = 5;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->pwm1 = 1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->pwm1 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if(memcmp(text, "pwm3a=",  6) == 0) {
		i = 6;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->pwm3a = 1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->pwm3a = -1;
			i = i + 3;
		} else
			goto invalid_line;

	} else
		goto invalid_line;

	while(*(text + i) != 0x00)
	{
		if(*(text + (i++)) == 0x0a)
			break;
	}
	return i;

invalid_line:
	//It's not a legal line, skip it.
	//printf("get_value: illegal line\n");
	while(*(text + i) != 0x00)
	{
		if(*(text + (i++)) == 0x0a)
			break;
	}
	return i;
}

static unsigned long get_conf_value(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	if (memcmp(text, "eth_wakeup=", 11) == 0) {
		i = 11;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->gmac = 1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->gmac = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else
		goto invalid_line;

	while(*(text + i) != 0x00)
	{
		if(*(text + (i++)) == 0x0a)
			break;
	}
	return i;

invalid_line:
	//It's not a legal line, skip it.
	//printf("get_value: illegal line\n");
	while(*(text + i) != 0x00)
	{
		if(*(text + (i++)) == 0x0a)
			break;
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

		//Pass a space for next string.
		start_point = file_ptr + 1;
	}

	return start_point;
}

static unsigned long get_overlay(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	int start_point = 0;

	hw_conf->overlay_count = 0;
	while(*(text + i) != 0x00)
	{
		if(*(text + i) == 0x20)
			start_point = set_file_conf(text, hw_conf, start_point, i);

		if(*(text + i) == 0x0a)
			break;
		i++;
	}

	start_point = set_file_conf(text, hw_conf, start_point, i);

	return i;
}

static unsigned long hw_parse_property(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	if(memcmp(text, "intf:", 5) == 0) {
		i = 5;
		i = i + get_intf_value(text + i, hw_conf);
	} else if (memcmp(text, "conf:",  5) == 0) {
		i = 5;
		i = i + get_conf_value(text + i, hw_conf);
	} else if(memcmp(text, "overlay=", 8) == 0) {
		i = 8;
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

static void parse_hw_config(struct hw_config *hw_conf)
{
	unsigned long count, offset = 0, addr, size;
	char *file_addr;
	static char *fs_argv[5];

	int valid = 0;

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
	fs_argv[2] = "0:7";
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

static int set_hw_property(struct fdt_header *working_fdt, char *path, char *property, char *value, int length)
{
	int offset;
	int ret;

	printf("set_hw_property: %s %s %s\n", path, property, value);
	offset = fdt_path_offset (working_fdt, path);
	if (offset < 0) {
		printf("libfdt fdt_path_offset() returned %s\n", fdt_strerror(offset));
		return -1;
	}
	ret = fdt_setprop(working_fdt, offset, property, value, length);
	if (ret < 0) {
		printf("libfdt fdt_setprop(): %s\n", fdt_strerror(ret));
		return -1;
	}

	return 0;
}

static struct fdt_header *resize_working_fdt(void)
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
	char *file_addr;
	struct fdt_header *blob;
	int ret;
	char overlay_file[] = "overlays/";

	static char *fs_argv[5];

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
	fs_argv[2] = "0:7";
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

static void handle_adc5_bid(cmd_tbl_t *cmdtp, struct fdt_header *working_fdt, struct hw_config *hw_conf)
{
	if(working_fdt == NULL)
		return;

	if (hw_conf->adc5_bid == -1)
		set_hw_property(working_fdt, "/ADC5-BOARD-ID", "boardver", "-1", 3);
	else if (hw_conf->adc5_bid == 0)
		set_hw_property(working_fdt, "/ADC5-BOARD-ID", "boardver", "0", 2);
	else if (hw_conf->adc5_bid == 1)
		set_hw_property(working_fdt, "/ADC5-BOARD-ID", "boardver", "1", 2);
	else if (hw_conf->adc5_bid == 2)
		set_hw_property(working_fdt, "/ADC5-BOARD-ID", "boardver", "2", 2);
	else if (hw_conf->adc5_bid == 3)
		set_hw_property(working_fdt, "/ADC5-BOARD-ID", "boardver", "3", 2);
	else if (hw_conf->adc5_bid == 4)
		set_hw_property(working_fdt, "/ADC5-BOARD-ID", "boardver", "4", 2);
}

static void handle_hw_conf(cmd_tbl_t *cmdtp, struct fdt_header *working_fdt, struct hw_config *hw_conf)
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
#endif

	if (hw_conf->fiq_debugger == 1)
		set_hw_property(working_fdt, "/fiq-debugger", "status", "okay", 5);
	else if (hw_conf->fiq_debugger == -1)
		set_hw_property(working_fdt, "/fiq-debugger", "status", "disabled", 9);

	if (hw_conf->i2c6 == 1)
		set_hw_property(working_fdt, "/i2c@ff150000", "status", "okay", 5);
	else if (hw_conf->i2c6 == -1)
		set_hw_property(working_fdt, "/i2c@ff150000", "status", "disabled", 9);
	if (hw_conf->i2c7 == 1)
		set_hw_property(working_fdt, "/i2c@ff160000", "status", "okay", 5);
	else if (hw_conf->i2c7 == -1)
		set_hw_property(working_fdt, "/i2c@ff160000", "status", "disabled", 9);

	if (hw_conf->uart0 == 1)
		set_hw_property(working_fdt, "/serial@ff180000", "status", "okay", 5);
	else if (hw_conf->uart0 == -1)
		set_hw_property(working_fdt, "/serial@ff180000", "status", "disabled", 9);
	if (hw_conf->uart4 == 1)
		set_hw_property(working_fdt, "/serial@ff370000", "status", "okay", 5);
	else if (hw_conf->uart4 == -1)
		set_hw_property(working_fdt, "/serial@ff370000", "status", "disabled", 9);

	if (hw_conf->i2s0 == 1)
		set_hw_property(working_fdt, "/i2s@ff880000", "status", "okay", 5);
	else if (hw_conf->i2s0 == -1)
		set_hw_property(working_fdt, "/i2s@ff880000", "status", "disabled", 9);

	if (hw_conf->spi1 == 1)
		set_hw_property(working_fdt, "/spi@ff1d0000", "status", "okay", 5);
	else if (hw_conf->spi1 == -1)
		set_hw_property(working_fdt, "/spi@ff1d0000", "status", "disabled", 9);
	if (hw_conf->spi5 == 1)
		set_hw_property(working_fdt, "/spi@ff200000", "status", "okay", 5);
	else if (hw_conf->spi5 == -1)
		set_hw_property(working_fdt, "/spi@ff200000", "status", "disabled", 9);

	if (hw_conf->pwm0 == 1)
		set_hw_property(working_fdt, "/pwm@ff420000", "status", "okay", 5);
	else if (hw_conf->pwm0 == -1)
		set_hw_property(working_fdt, "/pwm@ff420000", "status", "disabled", 9);
	if (hw_conf->pwm1 == 1)
		set_hw_property(working_fdt, "/pwm@ff420010", "status", "okay", 5);
	else if (hw_conf->pwm1 == -1)
		set_hw_property(working_fdt, "/pwm@ff420010", "status", "disabled", 9);
	if (hw_conf->pwm3a == 1)
		set_hw_property(working_fdt, "/pwm@ff420030", "status", "okay", 5);
	else if (hw_conf->pwm3a == -1)
		set_hw_property(working_fdt, "/pwm@ff420030", "status", "disabled", 9);

	if (hw_conf->gmac == 1)
		set_hw_property(working_fdt, "/ethernet@fe300000", "wakeup-enable", "1", 2);
	else if (hw_conf->gmac == -1)
		set_hw_property(working_fdt, "/ethernet@fe300000", "wakeup-enable", "0", 2);
}

static char andr_tmp_str[ANDR_BOOT_ARGS_SIZE + 1];
static u32 android_kernel_comp_type = IH_COMP_NONE;

static ulong android_image_get_kernel_addr(const struct andr_img_hdr *hdr)
{
	/*
	 * All the Android tools that generate a boot.img use this
	 * address as the default.
	 *
	 * Even though it doesn't really make a lot of sense, and it
	 * might be valid on some platforms, we treat that address as
	 * the default value for this field, and try to execute the
	 * kernel in place in such a case.
	 *
	 * Otherwise, we will return the actual value set by the user.
	 */
	if (hdr->kernel_addr == ANDROID_IMAGE_DEFAULT_KERNEL_ADDR)
		return (ulong)hdr + hdr->page_size;

#ifdef CONFIG_ARCH_ROCKCHIP
	/*
	 * If kernel is compressed, kernel_addr is set as decompressed address
	 * after compressed being loaded to ram, so let's use it.
	 */
	if (android_kernel_comp_type != IH_COMP_NONE &&
	    android_kernel_comp_type != IH_COMP_ZIMAGE)
		return hdr->kernel_addr;

	/*
	 * Compatble with rockchip legacy packing with kernel/ramdisk/second
	 * address base from 0x60000000(SDK versiont < 8.1), these are invalid
	 * address, so we calc it by real size.
	 */
	return (ulong)hdr + hdr->page_size;
#else
	return hdr->kernel_addr;
#endif

}

void android_image_set_comp(struct andr_img_hdr *hdr, u32 comp)
{
	android_kernel_comp_type = comp;
}

u32 android_image_get_comp(const struct andr_img_hdr *hdr)
{
	return android_kernel_comp_type;
}

int android_image_parse_kernel_comp(const struct andr_img_hdr *hdr)
{
	ulong kaddr = android_image_get_kernel_addr(hdr);
	return bootm_parse_comp((const unsigned char *)kaddr);
}

/**
 * android_image_get_kernel() - processes kernel part of Android boot images
 * @hdr:	Pointer to image header, which is at the start
 *			of the image.
 * @verify:	Checksum verification flag. Currently unimplemented.
 * @os_data:	Pointer to a ulong variable, will hold os data start
 *			address.
 * @os_len:	Pointer to a ulong variable, will hold os data length.
 *
 * This function returns the os image's start address and length. Also,
 * it appends the kernel command line to the bootargs env variable.
 *
 * Return: Zero, os start address and length on success,
 *		otherwise on failure.
 */
int android_image_get_kernel(const struct andr_img_hdr *hdr, int verify,
			     ulong *os_data, ulong *os_len)
{
	u32 kernel_addr = android_image_get_kernel_addr(hdr);

	/*
	 * Not all Android tools use the id field for signing the image with
	 * sha1 (or anything) so we don't check it. It is not obvious that the
	 * string is null terminated so we take care of this.
	 */
	strncpy(andr_tmp_str, hdr->name, ANDR_BOOT_NAME_SIZE);
	andr_tmp_str[ANDR_BOOT_NAME_SIZE] = '\0';
	if (strlen(andr_tmp_str))
		printf("Android's image name: %s\n", andr_tmp_str);

	printf("Kernel load addr 0x%08x size %u KiB\n",
	       kernel_addr, DIV_ROUND_UP(hdr->kernel_size, 1024));

	int len = 0;
	if (*hdr->cmdline) {
		debug("Kernel command line: %s\n", hdr->cmdline);
		len += strlen(hdr->cmdline);
	}

	char *bootargs = env_get("bootargs");
	if (bootargs)
		len += strlen(bootargs);

	char *newbootargs = malloc(len + 2);
	if (!newbootargs) {
		puts("Error: malloc in android_image_get_kernel failed!\n");
		return -ENOMEM;
	}
	*newbootargs = '\0';

	if (bootargs) {
		strcpy(newbootargs, bootargs);
		strcat(newbootargs, " ");
	}
	if (*hdr->cmdline)
		strcat(newbootargs, hdr->cmdline);

	env_set("bootargs", newbootargs);

	if (os_data) {
		*os_data = (ulong)hdr;
		*os_data += hdr->page_size;
	}
	if (os_len)
		*os_len = hdr->kernel_size;
	return 0;
}

int android_image_check_header(const struct andr_img_hdr *hdr)
{
	return memcmp(ANDR_BOOT_MAGIC, hdr->magic, ANDR_BOOT_MAGIC_SIZE);
}

ulong android_image_get_end(const struct andr_img_hdr *hdr)
{
	ulong end;
	/*
	 * The header takes a full page, the remaining components are aligned
	 * on page boundary
	 */
	end = (ulong)hdr;
	end += hdr->page_size;
	end += ALIGN(hdr->kernel_size, hdr->page_size);
	end += ALIGN(hdr->ramdisk_size, hdr->page_size);
	end += ALIGN(hdr->second_size, hdr->page_size);

	if (hdr->header_version >= 1)
		end += ALIGN(hdr->recovery_dtbo_size, hdr->page_size);

	return end;
}

u32 android_image_get_ksize(const struct andr_img_hdr *hdr)
{
	return hdr->kernel_size;
}

void android_image_set_kload(struct andr_img_hdr *hdr, u32 load_address)
{
	hdr->kernel_addr = load_address;
}

ulong android_image_get_kload(const struct andr_img_hdr *hdr)
{
	return android_image_get_kernel_addr(hdr);
}

int android_image_get_ramdisk(const struct andr_img_hdr *hdr,
			      ulong *rd_data, ulong *rd_len)
{
	if (!hdr->ramdisk_size) {
		*rd_data = *rd_len = 0;
		return -1;
	}

	/* We have load ramdisk at "ramdisk_addr_r" */
#ifdef CONFIG_ANDROID_BOOT_IMAGE_SEPARATE
	ulong ramdisk_addr_r;

	ramdisk_addr_r = env_get_ulong("ramdisk_addr_r", 16, 0);
	if (!ramdisk_addr_r) {
		printf("No Found Ramdisk Load Address.\n");
		return -1;
	}

	*rd_data = ramdisk_addr_r;
#else
	*rd_data = (unsigned long)hdr;
	*rd_data += hdr->page_size;
	*rd_data += ALIGN(hdr->kernel_size, hdr->page_size);
#endif

	*rd_len = hdr->ramdisk_size;

	printf("RAM disk load addr 0x%08lx size %u KiB\n",
	       *rd_data, DIV_ROUND_UP(hdr->ramdisk_size, 1024));

	return 0;
}

int android_image_get_fdt(const struct andr_img_hdr *hdr,
			      ulong *rd_data)
{
	if (!hdr->second_size) {
		*rd_data = 0;
		return -1;
	}

	/* We have load fdt at "fdt_addr_r" */
#if defined(CONFIG_USING_KERNEL_DTB) || \
    defined(CONFIG_ANDROID_BOOT_IMAGE_SEPARATE)
	ulong fdt_addr_r;

	fdt_addr_r = env_get_ulong("fdt_addr_r", 16, 0);
	if (!fdt_addr_r) {
		printf("No Found FDT Load Address.\n");
		return -1;
	}

	*rd_data = fdt_addr_r;
#else
	*rd_data = (unsigned long)hdr;
	*rd_data += hdr->page_size;
	*rd_data += ALIGN(hdr->kernel_size, hdr->page_size);
	*rd_data += ALIGN(hdr->ramdisk_size, hdr->page_size);
#endif

	debug("FDT load addr 0x%08x size %u KiB\n",
	      hdr->second_addr, DIV_ROUND_UP(hdr->second_size, 1024));

	return 0;
}

#ifdef CONFIG_ANDROID_BOOT_IMAGE_SEPARATE
int android_image_load_separate(struct andr_img_hdr *hdr,
				const disk_partition_t *part,
				void *load_address, void *ram_src)
{
	struct blk_desc *dev_desc = rockchip_get_bootdev();
	ulong fdt_addr_r = env_get_ulong("fdt_addr_r", 16, 0);
	char *fdt_high = env_get("fdt_high");
	char *ramdisk_high = env_get("initrd_high");
	ulong blk_start, blk_cnt, size;
	int ret, blk_read = 0;
	ulong start;

	unsigned int in_voltage5_raw;
	float voltage_scale = 1.8066, voltage5_raw, vresult;
	int adc5_channel = 5;

	struct fdt_header *working_fdt;
	struct hw_config hw_conf;
	memset(&hw_conf, 0, sizeof(struct hw_config));
	parse_hw_config(&hw_conf);

	printf("config.txt valid = %d\n", hw_conf.valid);
	if(hw_conf.valid == 1) {
		printf("config on: 1, config off: -1, no config: 0\n");
		printf("intf.i2c6 = %d\n", hw_conf.i2c6);
		printf("intf.i2c7 = %d\n", hw_conf.i2c7);
		printf("intf.uart0 = %d\n", hw_conf.uart0);
		printf("intf.uart4 = %d\n", hw_conf.uart4);
		printf("intf.i2s0 = %d\n", hw_conf.i2s0);
		printf("intf.spi1 = %d\n", hw_conf.spi1);
		printf("intf.spi5 = %d\n", hw_conf.spi5);
		printf("intf.pwm0 = %d\n", hw_conf.pwm0);
		printf("intf.pwm1 = %d\n", hw_conf.pwm1);
		printf("intf.pwm3a = %d\n", hw_conf.pwm3a);
		printf("conf.gmac = %d\n", hw_conf.gmac);

		for (int i = 0; i < hw_conf.overlay_count; i++)
			printf("get overlay name: %s\n", hw_conf.overlay_file[i]);
	}

	ret = adc_channel_single_shot("saradc", adc5_channel, &in_voltage5_raw);
	if (ret)
		hw_conf.adc5_bid = -1;
	else {
		voltage5_raw = (float)in_voltage5_raw;
		vresult = voltage5_raw * voltage_scale;

		if (vresult < 1900 && vresult > 1700)
			hw_conf.adc5_bid = 2;
		else if (vresult < 1300 && vresult > 1100)
			hw_conf.adc5_bid = 4;
		else if (vresult < 1000 && vresult > 800)
			hw_conf.adc5_bid = 1;
		else if (vresult < 100)
			hw_conf.adc5_bid = 3;
		else
			hw_conf.adc5_bid = 0;
	}

	if (hdr->kernel_size) {
		size = hdr->kernel_size + hdr->page_size;
		blk_cnt = DIV_ROUND_UP(size, dev_desc->blksz);
		if (!sysmem_alloc_base(MEMBLK_ID_KERNEL,
				       (phys_addr_t)load_address,
				       blk_cnt * dev_desc->blksz))
			return -ENXIO;

		if (ram_src) {
			start = (ulong)ram_src;
			memcpy((char *)load_address, (char *)start, size);
		} else {
			blk_start = part->start;
			ret = blk_dread(dev_desc, blk_start,
					blk_cnt, load_address);
			if (ret != blk_cnt) {
				printf("%s: read kernel failed, ret=%d\n",
				      __func__, ret);
				return -1;
			}
			blk_read += ret;
		}
	}

	if (hdr->ramdisk_size) {
		ulong ramdisk_addr_r = env_get_ulong("ramdisk_addr_r", 16, 0);

		size = hdr->page_size + ALIGN(hdr->kernel_size, hdr->page_size);
		blk_cnt = DIV_ROUND_UP(hdr->ramdisk_size, dev_desc->blksz);
		if (!sysmem_alloc_base(MEMBLK_ID_RAMDISK,
				       ramdisk_addr_r,
				       blk_cnt * dev_desc->blksz))
			return -ENXIO;
		if (ram_src) {
			start = (unsigned long)ram_src;
			start += hdr->page_size;
			start += ALIGN(hdr->kernel_size, hdr->page_size);
			memcpy((char *)ramdisk_addr_r,
			       (char *)start, hdr->ramdisk_size);
		} else {
			blk_start = part->start +
				DIV_ROUND_UP(size, dev_desc->blksz);
			ret = blk_dread(dev_desc, blk_start,
					blk_cnt, (void *)ramdisk_addr_r);
			if (ret != blk_cnt) {
				printf("%s: read ramdisk failed, ret=%d\n",
				      __func__, ret);
				return -1;
			}
			blk_read += ret;
		}
	}

	if ((gd->fdt_blob != (void *)fdt_addr_r) && hdr->second_size) {
#ifdef CONFIG_RKIMG_BOOTLOADER
		/* Rockchip AOSP, resource.img is in second position */
		ulong fdt_size;

		fdt_size = rockchip_read_dtb_file((void *)fdt_addr_r);
		if (fdt_size < 0) {
			printf("%s: read fdt failed\n", __func__);
			return ret;
		}

		blk_read += DIV_ROUND_UP(fdt_size, dev_desc->blksz);
#else
		/* Standard AOSP, dtb is in second position */
		ulong blk_start, blk_cnt;

		size = hdr->page_size +
		       ALIGN(hdr->kernel_size, hdr->page_size) +
		       ALIGN(hdr->ramdisk_size, hdr->page_size);
		blk_cnt = DIV_ROUND_UP(hdr->second_size, dev_desc->blksz);
		if (!sysmem_alloc_base(MEMBLK_ID_FDT_AOSP,
				       fdt_addr_r,
				       blk_cnt * dev_desc->blksz +
				       CONFIG_SYS_FDT_PAD))
			return -ENXIO;

		if (ram_src) {
			start = (unsigned long)ram_src;
			start += hdr->page_size;
			start += ALIGN(hdr->kernel_size, hdr->page_size);
			start += ALIGN(hdr->ramdisk_size, hdr->page_size);
			memcpy((char *)fdt_addr_r,
			       (char *)start, hdr->second_size);
		} else {
			blk_start = part->start +
					DIV_ROUND_UP(size, dev_desc->blksz);
			ret = blk_dread(dev_desc, blk_start, blk_cnt,
					(void *)fdt_addr_r);
			if (ret != blk_cnt) {
				printf("%s: read dtb failed, ret=%d\n",
				      __func__, ret);
				return -1;
			}

			blk_read += blk_cnt;
		}
#endif /* CONFIG_RKIMG_BOOTLOADER */
	}

	if (blk_read > 0 || ram_src) {
		if (!fdt_high) {
			env_set_hex("fdt_high", -1UL);
			printf("Fdt ");
		}
		if (!ramdisk_high) {
			env_set_hex("initrd_high", -1UL);
			printf("Ramdisk ");
		}
		if (!fdt_high || !ramdisk_high)
			printf("skip relocation\n");
	}

	working_fdt = resize_working_fdt();
	if (working_fdt != NULL) {
		handle_adc5_bid(NULL, working_fdt, &hw_conf);

		if(hw_conf.valid)
			handle_hw_conf(NULL, working_fdt, &hw_conf);
	}

	return blk_read;
}
#endif /* CONFIG_ANDROID_BOOT_IMAGE_SEPARATE */

long android_image_load(struct blk_desc *dev_desc,
			const disk_partition_t *part_info,
			unsigned long load_address,
			unsigned long max_size) {
	void *buf;
	long blk_cnt = 0;
	long blk_read = 0;
	u32 comp;
	u32 kload_addr;
	u32 blkcnt;
	struct andr_img_hdr *hdr;

	if (max_size < part_info->blksz)
		return -1;

	/*
	 * Read the Android boot.img header and a few parts of
	 * the head of kernel image(2 blocks maybe enough).
	 */
	blkcnt = DIV_ROUND_UP(sizeof(*hdr), 512) + 2;
	hdr = memalign(ARCH_DMA_MINALIGN, blkcnt * 512);
	if (!hdr) {
		printf("%s: no memory\n", __func__);
		return -1;
	}

	if (blk_dread(dev_desc, part_info->start, blkcnt, hdr) != blkcnt)
		blk_read = -1;

	if (!blk_read && android_image_check_header(hdr) != 0) {
		printf("** Invalid Android Image header **\n");
		blk_read = -1;
	}

	/* page_size for image header */
	load_address -= hdr->page_size;

	/* We don't know the size of the Android image before reading the header
	 * so we don't limit the size of the mapped memory.
	 */
	buf = map_sysmem(load_address, 0 /* size */);
	if (!blk_read) {
		blk_cnt = (android_image_get_end(hdr) - (ulong)hdr +
			   part_info->blksz - 1) / part_info->blksz;
		comp = android_image_parse_kernel_comp(hdr);
		/*
		 * We should load compressed kernel Image to high memory at
		 * address "kernel_addr_c".
		 */
		if (comp != IH_COMP_NONE) {
			ulong kernel_addr_c;

			env_set_ulong("os_comp", comp);
			kernel_addr_c = env_get_ulong("kernel_addr_c", 16, 0);
			if (kernel_addr_c) {
				load_address = kernel_addr_c - hdr->page_size;
				unmap_sysmem(buf);
				buf = map_sysmem(load_address, 0 /* size */);
			}
#ifdef CONFIG_ARM64
			else {
				printf("Warn: \"kernel_addr_c\" is not defined "
				       "for compressed kernel Image!\n");
				load_address += android_image_get_ksize(hdr) * 3;
				load_address = ALIGN(load_address, ARCH_DMA_MINALIGN);
				env_set_ulong("kernel_addr_c", load_address);

				load_address -= hdr->page_size;
				unmap_sysmem(buf);
				buf = map_sysmem(load_address, 0 /* size */);
			}
#endif
		}

		if (blk_cnt * part_info->blksz > max_size) {
			debug("Android Image too big (%lu bytes, max %lu)\n",
			      android_image_get_end(hdr) - (ulong)hdr,
			      max_size);
			blk_read = -1;
		} else {
			debug("Loading Android Image (%lu blocks) to 0x%lx... ",
			      blk_cnt, load_address);

#ifdef CONFIG_ANDROID_BOOT_IMAGE_SEPARATE
			blk_read =
			android_image_load_separate(hdr, part_info, buf, NULL);
#else
			if (!sysmem_alloc_base(MEMBLK_ID_ANDROID,
					       (phys_addr_t)buf,
						blk_cnt * part_info->blksz))
				return -ENXIO;

			blk_read = blk_dread(dev_desc, part_info->start,
					     blk_cnt, buf);
#endif
		}

		/*
		 * zImage is not need to decompress
		 * kernel will handle decompress itself
		 */
		if (comp != IH_COMP_NONE && comp != IH_COMP_ZIMAGE) {
			kload_addr = env_get_ulong("kernel_addr_r", 16, 0x02080000);
			android_image_set_kload(buf, kload_addr);
			android_image_set_comp(buf, comp);
		} else {
			android_image_set_comp(buf, IH_COMP_NONE);
		}

	}

	free(hdr);
	unmap_sysmem(buf);

#ifndef CONFIG_ANDROID_BOOT_IMAGE_SEPARATE
	debug("%lu blocks read: %s\n",
	      blk_read, (blk_read == blk_cnt) ? "OK" : "ERROR");
	if (blk_read != blk_cnt)
		return -1;
#else
	debug("%lu blocks read\n", blk_read);
	if (blk_read < 0)
		return blk_read;
#endif

	return load_address;
}

#if !defined(CONFIG_SPL_BUILD)
/**
 * android_print_contents - prints out the contents of the Android format image
 * @hdr: pointer to the Android format image header
 *
 * android_print_contents() formats a multi line Android image contents
 * description.
 * The routine prints out Android image properties
 *
 * returns:
 *     no returned results
 */
void android_print_contents(const struct andr_img_hdr *hdr)
{
	const char * const p = IMAGE_INDENT_STRING;
	/* os_version = ver << 11 | lvl */
	u32 os_ver = hdr->os_version >> 11;
	u32 os_lvl = hdr->os_version & ((1U << 11) - 1);
	u32 header_version = hdr->header_version;

	printf("%skernel size:      %x\n", p, hdr->kernel_size);
	printf("%skernel address:   %x\n", p, hdr->kernel_addr);
	printf("%sramdisk size:     %x\n", p, hdr->ramdisk_size);
	printf("%sramdisk addrress: %x\n", p, hdr->ramdisk_addr);
	printf("%ssecond size:      %x\n", p, hdr->second_size);
	printf("%ssecond address:   %x\n", p, hdr->second_addr);
	printf("%stags address:     %x\n", p, hdr->tags_addr);
	printf("%spage size:        %x\n", p, hdr->page_size);
	printf("%sheader_version:   %x\n", p, header_version);
	/* ver = A << 14 | B << 7 | C         (7 bits for each of A, B, C)
	 * lvl = ((Y - 2000) & 127) << 4 | M  (7 bits for Y, 4 bits for M) */
	printf("%sos_version:       %x (ver: %u.%u.%u, level: %u.%u)\n",
	       p, hdr->os_version,
	       (os_ver >> 7) & 0x7F, (os_ver >> 14) & 0x7F, os_ver & 0x7F,
	       (os_lvl >> 4) + 2000, os_lvl & 0x0F);
	printf("%sname:             %s\n", p, hdr->name);
	printf("%scmdline:          %s\n", p, hdr->cmdline);

	if (header_version >= 1) {
		printf("%srecovery dtbo size:    %x\n", p, hdr->recovery_dtbo_size);
		printf("%srecovery dtbo offset:  %llx\n", p, hdr->recovery_dtbo_offset);
		printf("%sheader size:           %x\n", p, hdr->header_size);
	}
}
#endif
