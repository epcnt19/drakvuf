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
	idtmon* s = (idtmon*)info->trap->data;
	reg_t idtr_base,idtr_limit;
	addr_t int_addr;
	
	uint16_t addr1,addr2;
	uint32_t addr3;
	int entry_num;

	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	vmi_get_vcpureg(vmi,&idtr_base,IDTR_BASE,info->vcpu);
	vmi_get_vcpureg(vmi,&idtr_limit,IDTR_LIMIT,info->vcpu);
	entry_num = idtr_limit/16;
	
	for(int i=0;i<entry_num;i++){
		vmi_read_16_va(vmi,idtr_base+i*16,0,&addr1);
		vmi_read_16_va(vmi,idtr_base+i*16+6,0,&addr2);
		vmi_read_32_va(vmi,idtr_base+i*16+8,0,&addr3);
		int_addr = ((addr_t)addr3 << 32) + ((addr_t)addr2 << 16) + ((addr_t)addr1);
		printf("[IDTR] entry %d,0x%" PRIx64 "\n",i,int_addr);
	}
	
	drakvuf_release_vmi(drakvuf);
	return 0;
}



idtmon::idtmon(drakvuf_t drakvuf,const void *config,output_format_t output){
	const char *rekall_profile = (const char *)config;
	reg_t idtr_base,idtr_limit;	
	
	this->format = output;
	this->drakvuf = drakvuf;
	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	
	/*
	for(int i=0;i<CPU_CORE_NUM;i++){
		this->checkidt[i].cb = checkidt_cb;
		this->checkidt[i].data = (void*)this;
		this->checkidt[i].type = MEMACCESS;
		this->checkidt[i].memaccess.type = PRE;
		this->checkidt[i].memaccess.access = VMI_MEMACCESS_W;
	
		vmi_get_vcpureg(vmi,&idtr_base,IDTR_BASE,i);
		vmi_get_vcpureg(vmi,&idtr_limit,IDTR_LIMIT,i);
	
		this->checkidt[i].memaccess.gfn = idtr_base;
	
		printf("[IDTR] idtr_base,0x%" PRIx64 "\n",idtr_base);
		printf("[IDTR] idtr_base trap,0x%" PRIx64 "\n",this->checkidt[i].memaccess.gfn);
		printf("[IDTR] idtr_limit,0x%" PRIx64 "\n",idtr_limit);
		
		if(!drakvuf_add_trap(drakvuf,&this->checkidt[i])){
			fprintf(stderr,"IDT plugin failed to trap on \n");
		}		
	}
	*/
	vmi_get_vcpureg(vmi,&idtr_base,IDTR_BASE,0);
	vmi_get_vcpureg(vmi,&idtr_limit,IDTR_LIMIT,0);
	idtr_base = idtr_base+0x6;

	this->trap_idt_w.cb = checkidt_cb;
	this->trap_idt_w.data = (void *)this;
	this->trap_idt_w.type = MEMACCESS;
	this->trap_idt_w.memaccess.type = PRE;
	this->trap_idt_w.memaccess.access = VMI_MEMACCESS_W;
	this->trap_idt_w.memaccess.gfn = idtr_base;
	
	printf("[IDT] idtr_base,0x%" PRIx64 "\n",idtr_base);
	printf("[IDT] trap address 0x%" PRIx64 "\n",this->trap_idt_w.memaccess.gfn);
	
	if(!drakvuf_add_trap(drakvuf,&this->trap_idt_w)){
		fprintf(stderr,"IDT plugin faild to trap on \n");
	}

	drakvuf_release_vmi(drakvuf);
}

idtmon::~idtmon(){}
