#ifndef IDTMON_H
#define IDTMON_H

#include "plugins/private.h"
#include "plugins/plugins.h"
#define CPU_CORE_NUM 2


class idtmon: public plugin {
	public:
		output_format_t format;
		drakvuf_t drakvuf;

		/*
		drakvuf_trap_t checkidt[CPU_CORE_NUM];
		reg_t idtr_base[CPU_CORE_NUM];
		reg_t idtr_limit[CPU_CORE_NUM];
		*/
		
		//drakvuf_trap_t checkidt[CPU_CORE_NUM];
		drakvuf_trap_t trap_idt_w;
	
		idtmon(drakvuf_t drakvuf,const void *config,output_format_t output);
		~idtmon();
};

#endif
