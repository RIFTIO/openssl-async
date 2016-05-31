/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 *
 *   GPL LICENSE SUMMARY
 *
 *   Copyright(c) 2007,2008,2009,2010,2011,2012,2013,2014 Intel Corporation.
 *   All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 *
 *   Contact Information:
 *   Intel Corporation
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2007,2008,2009,2010,2011,2012,2013,2014 Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 *
 ***************************************************************************/
#define _XOPEN_SOURCE 600

#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

/* Linux doesn't conform to the POSIX standard here:
 * #include <stropts.h> */
#include <sys/ioctl.h>

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "qat_mem.h"

#define SEG_LEN 64

/******************************************************************************
* function:
*         main(void)
*
* description:
*   Entry point.
*
******************************************************************************/
int main(void)
{
	int qat_memfd = -1;
	qat_mem_config qmcfg;
	void *addr = MAP_FAILED;
	qat_mem_config *mem_to_free=NULL;

	if ((qat_memfd = open("/dev/qat_mem", O_RDWR)) == -1) {
		perror("open qat_mem");
		goto cleanup;
	}
	qmcfg.length = SEG_LEN;
	if (ioctl(qat_memfd, QAT_MEM_MALLOC, &qmcfg) == -1) {
		perror("ioctl QAT_MEM_MALLOC");
		goto cleanup;
	}

	if ((addr =
	     mmap(NULL, SEG_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE, qat_memfd,
		  qmcfg.virtualAddress)) == MAP_FAILED) {
		perror("mmap");
		goto cleanup;
	}
	mem_to_free = addr;
        printf("seg mapped to %p, virtualAddress in seg %p, length %d\n", addr,
               (void *)mem_to_free->virtualAddress, mem_to_free->length);
	strcpy(addr + sizeof(qat_mem_config), "Hello World!");
	puts(addr + sizeof(qat_mem_config));
 cleanup:
	if (qat_memfd != -1 && mem_to_free !=NULL 
            && ioctl(qat_memfd, QAT_MEM_FREE, mem_to_free) == -1)
		perror("ioctl QAT_MEM_FREE");
	if (addr != MAP_FAILED && munmap(addr, SEG_LEN) == -1)
		perror("munmap");
	if (qat_memfd != -1 && close(qat_memfd) == -1)
		perror("close qat_mem");
	exit(EXIT_SUCCESS);
}
