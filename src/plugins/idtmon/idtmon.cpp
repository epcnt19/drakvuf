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
#include "idtmon.h"


event_response_t checkidt_cb(drakvuf_t drakvuf,drakvuf_trap_info_t* info){
	idtmon* s = (idtmon *)info->trap->data;

	uint64_t entry_addr;
	uint64_t idtr_base;
	uint64_t idtr_limit;
	uint64_t addr1;
	uint64_t addr2;

	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	vmi_get_vcpureg(vmi,&idtr_base,IDTR_BASE,info->vcpu);
	vmi_get_vcpureg(vmi,&idtr_limit,IDTR_LIMIT,info->vcpu);
	
	if(s->reg_size == 4){
		for(int i=0;i<ENTRY_NUM;i++){
			vmi_read_16_va(vmi,(addr_t)idtr_base+i*8,0,(uint16_t *)&addr1);
			vmi_read_16_va(vmi,(addr_t)idtr_base+i*8+6,0,(uint16_t *)&addr2);
			entry_addr = ((addr_t)addr2 << 16) + ((addr_t)addr1);

			if(entry_addr != s->idt[i]){
				printf("[IDTmon] ENTRY_NUM:%" PRIx32 ",ADDR:%" PRIx32 "\n",i,entry_addr);
			}

			s->idt[i] = entry_addr;
		}
	}

	drakvuf_release_vmi(drakvuf);

	return 0;
}


idtmon::idtmon(drakvuf_t drakvuf,const void *config,output_format_t output){
	const char *rekall_profile = (const char *)config;

	this->format = output;
	this->drakvuf = drakvuf;
	this->os = drakvuf_get_os_type(drakvuf);	
	this->trap.cb = checkidt_cb;
	this->trap.breakpoint.lookup_type = LOOKUP_PID;
	this->trap.breakpoint.pid = 4;
	this->trap.breakpoint.addr_type = ADDR_RVA;
	this->trap.breakpoint.module = "ntoskrnl.exe";
	this->trap.name = "KiDispatchException";
	this->trap.type = BREAKPOINT;
	this->trap.data = (void *)this;

	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	this->reg_size = vmi_get_address_width(vmi);

	printf("[IDTmon] IDT plugin Initialize\n");
	
	if(!drakvuf_get_function_rva(rekall_profile,"KiDispatchException",&this->trap.breakpoint.rva))
		throw -1;
		
	if(!drakvuf_add_trap(drakvuf,&this->trap))
		throw -1;
	
	for(int i=0;i<ENTRY_NUM;i++){
		idt[i] = 0x0;
	}

	printf("[IDTmon] IDT plugin add trap for KiDispatchException\n");
	drakvuf_release_vmi(drakvuf);
}

idtmon::~idtmon(){}
