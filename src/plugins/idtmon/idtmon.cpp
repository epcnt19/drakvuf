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

	printf("checkidt_cb\n");
	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	drakvuf_release_vmi(drakvuf);

	return 0;
}


idtmon::idtmon(drakvuf_t drakvuf,const void *config,output_format_t output){
	const char *rekall_profile = (const char *)config;

	this->format = output;
	this->drakvuf = drakvuf;
	this->os = drakvuf_get_os_type(drakvuf);	
	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	this->reg_size = vmi_get_address_width(vmi);
	
	vmi_get_vcpureg(vmi,&this->idtr_base,IDTR_BASE,0);
	vmi_get_vcpureg(vmi,&this->idtr_limit,IDTR_LIMIT,0);

	printf("[IDT] IDT plugins Initialize\n");
	
	if(this->os == VMI_OS_LINUX){
		
		addr_t rva = 0;
	
		if(!drakvuf_get_constant_rva(rekall_profile,"_text",&rva)){
			fprintf(stderr,"IDT plugin faild to get_constant_rva\n");
			throw -1;
		}

		addr_t idt_table = 0;
	
		if(!drakvuf_get_constant_rva(rekall_profile,"idt_table",&idt_table)){
			fprintf(stderr,"IDT plugin faild to get_function_rva - idt_table\n");
			throw -1;
		}

		addr_t kaslr = drakvuf_get_kernel_base(drakvuf) - rva;
	
		this->write_idt.cb = checkidt_cb;
		this->write_idt.data = (void *)this;
		this->write_idt.type = MEMACCESS;
		this->write_idt.memaccess.type = PRE;
		this->write_idt.memaccess.access = VMI_MEMACCESS_RWX;
		this->write_idt.memaccess.gfn = idt_table + kaslr;
	
		printf("[IDT] idt_table,0x%" PRIx32 "\n",this->write_idt.memaccess.gfn);

		if(!drakvuf_add_trap(drakvuf,&this->write_idt)){
			fprintf(stderr,"IDT plugin faild to trap on \n");
			throw -1;
		}
	}
	
	if(this->os == VMI_OS_WINDOWS){

		this->write_idt.cb = checkidt_cb;
		this->write_idt.data = (void *)this;
		this->write_idt.type = MEMACCESS;	
		this->write_idt.memaccess.type = PRE;
		this->write_idt.memaccess.access = VMI_MEMACCESS_RWX;
		this->write_idt.memaccess.gfn = idtr_base;
	
		printf("[IDT] idt_table,0x%" PRIx32 "\n",this->write_idt.memaccess.gfn);

		if(!drakvuf_add_trap(drakvuf,&this->write_idt)){
			fprintf(stderr,"IDT plugin faild to trap on \n");
			throw -1;
		}
	}

	drakvuf_release_vmi(drakvuf);
}

idtmon::~idtmon(){}
