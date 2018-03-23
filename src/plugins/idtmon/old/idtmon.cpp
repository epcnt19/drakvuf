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

/*
event_response_t checkidt_cb(drakvuf_t drakvuf,drakvuf_trap_info_t* info){
	idtmon* s = (idtmon*)info->trap->data;

	addr_t int_addr;
	uint16_t addr1,addr2;
	uint32_t addr3;
	int entry_num;

	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	vmi_get_vcpureg(vmi,&this->idtr_base,IDTR_BASE,0);
	vmi_get_vcpureg(vmi,&this->idtr_limit,IDTR_LIMIT,0);
	entry_num = (this->idtr_limit)/16;
	
	printf("checkidt_cb\n");

	for(int i=0;i<entry_num;i++){
		vmi_read_16_va(vmi,this->idtr_base+i*16,0,&addr1);
		vmi_read_16_va(vmi,this->idtr_base+i*16+6,0,&addr2);
		vmi_read_32_va(vmi,this->idtr_base+i*16+8,0,&addr3);
		int_addr = ((addr_t)addr3 << 32) + ((addr_t)addr2 << 16) + ((addr_t)addr1);
		printf("[IDTR] entry %d,0x%" PRIx64 "\n",i,int_addr);
	}
	
	drakvuf_release_vmi(drakvuf);
	return 0;
}
*/


event_response_t checkidt_cb(drakvuf_t drakvuf,drakvuf_trap_info_t* info){
	idtmon* s = (idtmon *)info->trap->data;

	printf("checkidt_cb\n");
	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	drakvuf_release_vmi(drakvuf);

	return 0;
}



idtmon::idtmon(drakvuf_t drakvuf,const void *config,output_format_t output){
	const char *rekall_profile = (const char *)config;
	addr_t idtwrite_end;	

	this->format = output;
	this->drakvuf = drakvuf;
	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	
	vmi_get_vcpureg(vmi,&this->idtr_base,IDTR_BASE,0);
	vmi_get_vcpureg(vmi,&this->idtr_limit,IDTR_LIMIT,0);

	this->idtwrite.cb = checkidt_cb;
	this->idtwrite.data = (void *)this;
	this->idtwrite.type = MEMACCESS;
	this->idtwrite.memaccess.type = PRE;
	this->idtwrite.memaccess.access = VMI_MEMACCESS_RWX;
	this->reg_size = vmi_get_address_width(vmi);

	//32bit	
	if(this->reg_size == 4){
		this->idtwrite.memaccess.gfn = this->idtr_base >> 8;
		idtwrite_end = (this->idtr_base + 4*255) >> 8;
	//64bit
	}else if(this->reg_size == 8){
		this->idtwrite.memaccess.gfn = this->idtr_base >> 12;
		idtwrite_end = (this->idtr_base + 16*255) >> 12;
	}
	
	//32bit
	if(this->reg_size == 4){
		printf("[IDT] idtr_base,0x%" PRIx32 "\n",this->idtr_base);
		printf("[IDT] idtwrite.memaccess.gfn,0x%" PRIx32 "\n",this->idtwrite.memaccess.gfn);
		printf("[IDT] idtwrite_end,0x%" PRIx32 "\n",idtwrite_end);
		printf("[IDT] idtr_limit,0x%" PRIx32 "\n",this->idtr_limit);
	//64bit
	}else if (this->reg_size == 8){
		printf("[IDT] idtr_base,0x%" PRIx64 "\n",this->idtr_base);
		printf("[IDT] idtwrite.memaccess.gfn,0x%" PRIx64 "\n",this->idtwrite.memaccess.gfn);
		printf("[IDT] idtwrite_end,0x%" PRIx64 "\n",idtwrite_end);
		printf("[IDT] idtr_limit,0x%" PRIx64 "\n",this->idtr_limit);
	}

	if(!drakvuf_add_trap(drakvuf,&this->idtwrite)){
		fprintf(stderr,"IDT plugin faild to trap on \n");
		throw -1;
	}

	if(idtwrite_end != this->idtwrite.memaccess.gfn){
		this->idtwrite2 = this->idtwrite;
		this->idtwrite2.memaccess.gfn = idtwrite_end;

		if(!drakvuf_add_trap(drakvuf,&this->idtwrite2))
			throw -1;
	}

	drakvuf_release_vmi(drakvuf);
}

idtmon::~idtmon(){}
