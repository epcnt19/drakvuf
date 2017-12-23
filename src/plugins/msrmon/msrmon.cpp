#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dirent.h>
#include <glib.h>
#include <err.h>

#include <libvmi/libvmi.h>
#include "../plugins.h"
#include "private.h"
#include "msrmon.h"


event_response_t sysenter_cb(drakvuf_t drakvuf,drakvuf_trap_info_t* info){
	msrmon* s = (msrmon*)info->trap->data;
	addr_t ntoskrnl = drakvuf_get_kernel_base(drakvuf);
	addr_t reg_rva = info->regs->msr_lstar - ntoskrnl;

	if(reg_rva != s->rekall_rva){
		printf("[DETECTION] hooking address 0x%" PRIx64 "\n",info->regs->msr_lstar);
	}

	switch(s->format){
		case OUTPUT_CSV:
			printf("msr,%" PRIu32 ",0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 ",%s,%" PRIi64 "\n",
			info->vcpu,info->regs->cr3,info->regs->msr_lstar,reg_rva,info->procname,info->userid);
			break;
		default:
		case OUTPUT_DEFAULT:
			printf("[MSR] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",MSRs LSTAR:0x%" PRIx64 ",RVA:0x%" PRIx64 ",%s,%" PRIi64 "\n",
			info->vcpu,info->regs->cr3,info->regs->msr_lstar,reg_rva,info->procname,info->userid);
			break;
	};

	return 0;
}


msrmon::msrmon(drakvuf_t drakvuf, const void *config, output_format_t output) {
    const char *rekall_profile = (const char*)config;

	this->format = output;
	this->drakvuf = drakvuf;
	this->sysenter.cb = sysenter_cb;
	this->sysenter.data = (void*)this;
	this->sysenter.reg = CR3;
	this->sysenter.type = REGISTER;
	
	if(!drakvuf_get_function_rva(rekall_profile,"KiSystemCall64",&this->rekall_rva)){
		throw -1;
	}

	if(!drakvuf_add_trap(drakvuf,&this->sysenter)){
		fprintf(stderr,"Failed to register SYSCALL plugin\n");
		throw -1;
	}
}

msrmon::~msrmon() {}
