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
	addr_t rva;

	if(4 == s->reg_size){
		rva = info->regs->sysenter_eip - ntoskrnl;
				
		if(rva != s->rva){
			switch(s->format){
				case OUTPUT_CSV:
					printf("msr,%" PRIu32 ",0x%" PRIx32 ",0x%" PRIx32 ",0x%" PRIx32 "\n",info->vcpu,info->regs->cr3,info->regs->sysenter_eip,rva);
				break;
				default:
				case OUTPUT_DEFAULT:
					printf("[MSR] VCPU:%" PRIu32 " CR3:0x%" PRIx32 ",SYSENTER_EIP:0x%" PRIx32 ",RVA:0x%" PRIx32 "\n",info->vcpu,info->regs->cr3,info->regs->sysenter_eip,rva);
				break;
			};
		}

	}

	if(8 == s->reg_size){
		rva = info->regs->msr_lstar - ntoskrnl;

		if(rva != s->rva){
			switch(s->format){
				case OUTPUT_CSV:
					printf("msr,%" PRIu32 ",0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 "\n",info->vcpu,info->regs->cr3,info->regs->msr_lstar,rva);
				break;
				default:
				case OUTPUT_DEFAULT:
					printf("[MSR] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",MSR_LSTAR:0x%" PRIx64 ",RVA:0x%" PRIx64 "\n",info->vcpu,info->regs->cr3,info->regs->msr_lstar,rva);
				break;
			};
		}
	}

	return 0;
}


msrmon::msrmon(drakvuf_t drakvuf, const void *config, output_format_t output) {
    const char *rekall_profile = (const char*)config;
	
	this->format = output;
	this->drakvuf = drakvuf;
	this->sysenter.cb = sysenter_cb;
	this->sysenter.data = (void *)this;
	this->sysenter.type = BREAKPOINT;
	this->sysenter.name = "KiFastCallEntry";
	this->sysenter.breakpoint.lookup_type = LOOKUP_PID;
	this->sysenter.breakpoint.pid = 4;
	this->sysenter.breakpoint.addr_type = ADDR_VA;
	this->sysenter.breakpoint.module = "ntoskrnl.exe";

	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	this->reg_size = vmi_get_address_width(vmi);
	addr_t ntoskrnl = drakvuf_get_kernel_base(drakvuf);
	
	if(!drakvuf_get_function_rva(rekall_profile,"KiFastCallEntry",&this->rva)){
		throw -1;
	}
	
	this->sysenter.breakpoint.addr = ntoskrnl + this->rva;

	if(!drakvuf_add_trap(drakvuf,&this->sysenter)){
		fprintf(stderr,"Failed to MSR plugin\n");
		throw -1;
	}

	drakvuf_release_vmi(drakvuf);
}

msrmon::~msrmon() {}
