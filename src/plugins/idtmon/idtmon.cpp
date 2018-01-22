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
	reg_t idtr;	

	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	vmi_get_vcpureg(vmi,&idtr,IDTR_BASE,info->vcpu);
	drakvuf_release_vmi(drakvuf);

	printf("[IDTR] idtr,0x%" PRIu64 ",0x%" PRIx64 "\n",info->vcpu,idtr);
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
