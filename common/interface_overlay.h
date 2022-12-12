#ifndef INTERFACE_OVERLAY_H
#define INTERFACE_OVERLAY_H

struct hw_config
{
	int valid;

	int overlay_count;
	char **overlay_file;
};

void set_mmcroot(void);

void parse_cmdline(void);

void parse_hw_config(struct hw_config *);

struct fdt_header *resize_working_fdt(void);

void handle_hw_conf(cmd_tbl_t *, struct fdt_header *, struct hw_config *);

#endif
