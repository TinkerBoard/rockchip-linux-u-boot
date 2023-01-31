#ifndef INTERFACE_OVERLAY_H
#define INTERFACE_OVERLAY_H

struct hw_config
{
	int valid;

	int uart4, uart9;
	int i2c5, i2s3_2ch, spi3, spdif_8ch;
	int pwm12, pwm13, pwm14, pwm15;

	int auto_ums;

	int overlay_count;
	char **overlay_file;
};

void set_lan_status(struct fdt_header *);

void set_mmcroot(void);

void parse_cmdline(void);

void parse_hw_config(struct hw_config *);

struct fdt_header *resize_working_fdt(void);

void handle_hw_conf(cmd_tbl_t *, struct fdt_header *, struct hw_config *);

#endif
