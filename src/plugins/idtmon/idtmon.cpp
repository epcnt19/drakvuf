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

event_response_t checkidt_cb(drakvuf_t drakvuf,drakvuf_trap_info* info){
	idtmon* s = (idtmon*)info->trap->data;
	reg_t idtr_base,idtr_limit;
	addr_t int_addr;
	
	uint16_t addr1,addr2;
	uint32_t addr3;
	int entry_num = 0;

	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	vmi_get_vcpureg(vmi,&idtr_base,IDTR_BASE,info->vcpu);
	vmi_get_vcpureg(vmi,&idtr_limit,IDTR_LIMIT,info->vcpu);
	drakvuf_release_vmi(drakvuf);

	entry_num = idtr_limit/16;
	
	printf("[IDTR] idtr_base,0x%" PRIu64 ",0x%" PRIx64 "\n",info->vcpu,idtr_base);
	printf("[IDTR] idtr_limit,0x%" PRIu64 ",0x%" PRIx64 "\n",info->vcpu,idtr_limit);

	for(int i=0;i<entry_num;i++){
		vmi_read_16_va(vmi,idtr_base+i*16,0,&addr1);
		vmi_read_16_va(vmi,idtr_base+i*16+6,0,&addr2);
		vmi_read_32_va(vmi,idtr_base+i*16+8,0,&addr3);
		int_addr = ((addr_t)addr3 << 32) + ((addr_t)addr2 << 16) + ((addr_t)addr1);
		printf("[IDTR] entry %d,0x%" PRIx64 "\n",i,int_addr);
	}

	return 0;
}


idtmon::idtmon(drakvuf_t drakvuf,const void *config,output_format_t output){
	const char *rekall_profile = (const char *)config;
	
	this->format = output;
	this->drakvuf = drakvuf;
	this->checkidt.cb = checkidt_cb;
	this->checkidt.data = (void*)this;
	this->checkidt.reg = CR3;
	this->checkidt.type = REGISTER;

	if(!drakvuf_add_trap(drakvuf,&this->checkidt)){
		fprintf(stderr,"Failed to register IDT plugin\n");
	}
}

idtmon::~idtmon(){}
