#ifndef IDTMON_H
#define IDTMON_H

#include "plugins/private.h"
#include "plugins/plugins.h"

class idtmon: public plugin {
	
public:
		output_format_t format;
		drakvuf_t drakvuf;
		
		drakvuf_trap_t idtwrite;
		drakvuf_trap_t idtwrite2;
		
		addr_t idtr_base;
		uint64_t idtr_limit;
		uint8_t reg_size;

		idtmon(drakvuf_t drakvuf,const void *config,output_format_t output);
		~idtmon();
};

#endif
