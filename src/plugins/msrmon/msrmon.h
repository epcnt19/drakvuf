#ifndef MSRMON_H
#define MSRMON_H

#include "plugins/private.h"
#include "plugins/plugins.h"

class msrmon: public plugin {
    public:
        output_format_t format;
		drakvuf_trap_t sysenter;
		drakvuf_t drakvuf;
		addr_t rva;
		uint8_t reg_size;

        msrmon(drakvuf_t drakvuf, const void *config, output_format_t output);
        ~msrmon();
};

#endif
