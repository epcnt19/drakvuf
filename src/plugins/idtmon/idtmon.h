#ifndef IDTMON_H
#define IDTMON_H
#define ENTRY_NUM 256

#include "plugins/private.h"
#include "plugins/plugins.h"

class idtmon: public plugin {
	
public:
		output_format_t format;
		drakvuf_t drakvuf;
		
		drakvuf_trap_t trap;
		os_t os;

		addr_t idtr_base;
		uint64_t idtr_limit;
		uint8_t reg_size;

		addr_t idt[ENTRY_NUM];

		idtmon(drakvuf_t drakvuf,const void *config,output_format_t output);
		~idtmon();
};

#endif
