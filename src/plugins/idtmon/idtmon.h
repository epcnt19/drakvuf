#ifndef IDTMON_H
#define IDTMON_H

#include "plugins/private.h"
#include "plugins/plugins.h"

class idtmon: public plugin {
	public:
		output_format_t format;
		drakvuf_trap_t checkidt;
		drakvuf_t drakvuf;

		idtmon(drakvuf_t drakvuf,const void *config,output_format_t output);
		~idtmon();
};

#endif
