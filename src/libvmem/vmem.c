/*
 * Copyright 2014-2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * vmem.c -- memory pool & allocation entry points for libvmem
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>

#include "libvmem.h"

#include "palloc.h"
#include "pmemcommon.h"
#include "sys_util.h"
#include "valgrind_internal.h"
#include "vmem.h"

/*
 * private to this file...
 */
static size_t Header_size;

struct vmem_alloc_header {
	char padding[40];
	uint64_t off;
};

/*
 * vmem_init -- initialization for vmem
 *
 * Called automatically by the run-time loader or on the first use of vmem.
 */
void
vmem_init(void)
{
	COMPILE_ERROR_ON(PALLOC_DATA_OFF != sizeof(struct vmem_alloc_header));

	static bool initialized = false;
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

	if (initialized)
		return;

	util_mutex_lock(&lock);

	if (!initialized) {
		common_init(VMEM_LOG_PREFIX, VMEM_LOG_LEVEL_VAR,
				VMEM_LOG_FILE_VAR, VMEM_MAJOR_VERSION,
				VMEM_MINOR_VERSION);
		LOG(3, NULL);
		Header_size = roundup(sizeof(VMEM), Pagesize);

		initialized = true;
	}

	util_mutex_unlock(&lock);
}

/*
 * vmem_construct -- load-time initialization for vmem
 *
 * Called automatically by the run-time loader.
 */
ATTR_CONSTRUCTOR
void
vmem_construct(void)
{
	vmem_init();
}

/*
 * vmem_fini -- libvmem cleanup routine
 *
 * Called automatically when the process terminates.
 */
ATTR_DESTRUCTOR
void
vmem_fini(void)
{
	LOG(3, NULL);
	common_fini();
}

static void
vmem_persist(void *base, const void *addr, size_t sz)
{
}

static void
vmem_flush(void *base, const void *addr, size_t sz)
{
}

static void
vmem_drain(void *base)
{
}

static void *
vmem_memcpy(void *base, void *dest, const void *src, size_t len)
{
	return memcpy(dest, src, len);
}

static void *
vmem_memset(void *base, void *dest, int c, size_t len)
{
	return memset(dest, c, len);
}

/*
 * vmem_create -- create a memory pool in a temp file
 */
VMEM *
vmem_create(const char *dir, size_t size)
{
	vmem_init();
	LOG(3, "dir \"%s\" size %zu", dir, size);

	if (size < VMEM_MIN_POOL) {
		ERR("size %zu smaller than %zu", size, VMEM_MIN_POOL);
		errno = EINVAL;
		return NULL;
	}

	/* silently enforce multiple of page size */
	size = roundup(size, Pagesize);

	void *addr;
	if ((addr = util_map_tmpfile(dir, size, 4 << 20)) == NULL)
		return NULL;

	/* store opaque info at beginning of mapped area */
	struct vmem *vmp = addr;
	memset(&vmp->hdr, '\0', sizeof(vmp->hdr));
	memcpy(vmp->hdr.signature, VMEM_HDR_SIG, POOL_HDR_SIG_LEN);
	vmp->addr = addr;
	vmp->size = size;
	vmp->caller_mapped = 0;

	void *heap_start = (void *)((uintptr_t)addr + Header_size);
	uint64_t heap_size = size - Header_size;
	struct pmem_ops p_ops;

	memset(&p_ops, 0, sizeof(p_ops));
	p_ops.persist = vmem_persist;
	p_ops.flush = vmem_flush;
	p_ops.drain = vmem_drain;
	p_ops.memcpy_persist = vmem_memcpy;
	p_ops.memset_persist = vmem_memset;
	p_ops.base = NULL;
	p_ops.pool_size = 0;

	if (palloc_init(heap_start, heap_size, &p_ops))
		goto err;
	if (palloc_boot(&vmp->heap, heap_start, heap_size, heap_start, &p_ops))
		goto err;

	/*
	 * If possible, turn off all permissions on the pool header page.
	 *
	 * The prototype PMFS doesn't allow this when large pages are in
	 * use. It is not considered an error if this fails.
	 */
	util_range_none(addr, sizeof(struct pool_hdr));

	LOG(3, "vmp %p", vmp);
	return vmp;
err:
	util_unmap(vmp->addr, vmp->size);
	return NULL;
}

/*
 * vmem_create_in_region -- create a memory pool in a given range
 */
VMEM *
vmem_create_in_region(void *addr, size_t size)
{
	vmem_init();
	LOG(3, "addr %p size %zu", addr, size);

	if (((uintptr_t)addr & (Pagesize - 1)) != 0) {
		ERR("addr %p not aligned to pagesize %llu", addr, Pagesize);
		errno = EINVAL;
		return NULL;
	}

	if (size < VMEM_MIN_POOL) {
		ERR("size %zu smaller than %zu", size, VMEM_MIN_POOL);
		errno = EINVAL;
		return NULL;
	}

	/* store opaque info at beginning of mapped area */
	struct vmem *vmp = addr;
	memset(&vmp->hdr, '\0', sizeof(vmp->hdr));
	memcpy(vmp->hdr.signature, VMEM_HDR_SIG, POOL_HDR_SIG_LEN);
	vmp->addr = addr;
	vmp->size = size;
	vmp->caller_mapped = 1;

	void *heap_start = (void *)((uintptr_t)addr + Header_size);
	uint64_t heap_size = size - Header_size;
	struct pmem_ops p_ops;

	memset(&p_ops, 0, sizeof(p_ops));
	p_ops.persist = vmem_persist;
	p_ops.flush = vmem_flush;
	p_ops.drain = vmem_drain;
	p_ops.memcpy_persist = vmem_memcpy;
	p_ops.memset_persist = vmem_memset;
	p_ops.base = NULL;
	p_ops.pool_size = 0;

	if (palloc_init(heap_start, heap_size, &p_ops))
		return NULL;
	if (palloc_boot(&vmp->heap, heap_start, heap_size, heap_start, &p_ops))
		return NULL;

	/*
	 * If possible, turn off all permissions on the pool header page.
	 *
	 * The prototype PMFS doesn't allow this when large pages are in
	 * use. It is not considered an error if this fails.
	 */
	util_range_none(addr, sizeof(struct pool_hdr));

	LOG(3, "vmp %p", vmp);
	return vmp;
}

/*
 * vmem_delete -- delete a memory pool
 */
void
vmem_delete(VMEM *vmp)
{
	LOG(3, "vmp %p", vmp);

	palloc_heap_cleanup(&vmp->heap);

	util_range_rw(vmp->addr, sizeof(struct pool_hdr));

	if (vmp->caller_mapped == 0)
		util_unmap(vmp->addr, vmp->size);
}

/*
 * vmem_check -- memory pool consistency check
 */
int
vmem_check(VMEM *vmp)
{
	vmem_init();
	LOG(3, "vmp %p", vmp);

	void *heap_start = (void *)((uintptr_t)vmp->addr + Header_size);
	uint64_t heap_size = vmp->size - Header_size;
	if (palloc_heap_check(heap_start, heap_size))
		return 0;

	return 1;
}

/*
 * vmem_stats_print -- spew memory allocator stats for a pool
 */
void
vmem_stats_print(VMEM *vmp, const char *opts)
{
	LOG(3, "vmp %p opts \"%s\"", vmp, opts ? opts : "");
}

static int
constructor_alloc(void *ctx, void *ptr, size_t usable_size, void *arg)
{
	LOG(3, NULL);

	ASSERTne(ptr, NULL);

	struct vmem_alloc_header *hdr = (void *)((char *)ptr - PALLOC_DATA_OFF);

	/* temporarily add the OOB header */
	VALGRIND_ADD_TO_TX(hdr, PALLOC_DATA_OFF);

	hdr->off = 0;

	VALGRIND_REMOVE_FROM_TX(hdr, PALLOC_DATA_OFF);

	/* do not report changes to the new object */
	VALGRIND_ADD_TO_TX(ptr, usable_size);

	return 0;
}

/*
 * vmem_malloc -- allocate memory
 */
void *
vmem_malloc(VMEM *vmp, size_t size)
{
	LOG(3, "vmp %p size %zu", vmp, size);

	uint64_t off;
	struct operation_context ctx;
	operation_init(&ctx, NULL, NULL, NULL);
	ctx.p_ops = &vmp->heap.p_ops;

	int ret = palloc_operation(&vmp->heap, 0, &off, size + PALLOC_DATA_OFF,
			constructor_alloc, NULL, &ctx);
	if (ret)
		return NULL;

	return (char *)vmp->heap.base + off;
}

/*
 * vmem_free -- free memory
 */
void
vmem_free(VMEM *vmp, void *ptr)
{
	LOG(3, "vmp %p ptr %p", vmp, ptr);
	if (ptr == NULL)
		return;
	uint64_t hdr_off = *((uint64_t *)ptr - 1);
	ptr = (char *)ptr - hdr_off;

	uint64_t off = (uintptr_t)ptr - (uintptr_t)vmp->heap.base;
	struct operation_context ctx;
	operation_init(&ctx, NULL, NULL, NULL);
	ctx.p_ops = &vmp->heap.p_ops;

	int ret = palloc_operation(&vmp->heap, off, &off, 0, NULL, NULL, &ctx);
	ASSERTeq(ret, 0);
}

/*
 * vmem_calloc -- allocate zeroed memory
 */
void *
vmem_calloc(VMEM *vmp, size_t nmemb, size_t size)
{
	LOG(3, "vmp %p nmemb %zu size %zu", vmp, nmemb, size);

	void *mem = vmem_malloc(vmp, nmemb * size);
	memset(mem, 0, nmemb * size);

	return mem;
}

/*
 * vmem_realloc -- resize a memory allocation
 */
void *
vmem_realloc(VMEM *vmp, void *ptr, size_t size)
{
	LOG(3, "vmp %p ptr %p size %zu", vmp, ptr, size);
	if (ptr == NULL)
		return vmem_malloc(vmp, size);

	uint64_t hdr_off = *((uint64_t *)ptr - 1);
	ptr = (char *)ptr - hdr_off;

	uint64_t off = (uintptr_t)ptr - (uintptr_t)vmp->heap.base;
	struct operation_context ctx;
	operation_init(&ctx, NULL, NULL, NULL);
	ctx.p_ops = &vmp->heap.p_ops;

	int ret = palloc_operation(&vmp->heap, off, &off,
			size + PALLOC_DATA_OFF, constructor_alloc, NULL, &ctx);
	if (ret)
		return NULL;

	return (char *)vmp->heap.base + off;
}

/*
 * vmem_aligned_alloc -- allocate aligned memory
 */
void *
vmem_aligned_alloc(VMEM *vmp, size_t alignment, size_t size)
{
	LOG(3, "vmp %p alignment %zu size %zu", vmp, alignment, size);

	uint64_t off;
	struct operation_context ctx;
	operation_init(&ctx, NULL, NULL, NULL);
	ctx.p_ops = &vmp->heap.p_ops;

	int ret = palloc_operation(&vmp->heap, 0, &off,
			size + PALLOC_DATA_OFF + alignment - 1,
			constructor_alloc, NULL, &ctx);
	if (ret)
		return NULL;
	char *mem = (char *)vmp->heap.base + off;
	uint64_t hdr_off = (((uintptr_t)mem + alignment) & ~(alignment - 1)) -
			(uintptr_t)mem;
	if (hdr_off && hdr_off != alignment) {
		mem += hdr_off;
		*((uint64_t *)mem - 1) = hdr_off;
	}

	return mem;
}

/*
 * vmem_strdup -- allocate memory for copy of string
 */
char *
vmem_strdup(VMEM *vmp, const char *s)
{
	LOG(3, "vmp %p s %p", vmp, s);

	size_t size = strlen(s) + 1;
	void *retaddr = vmem_malloc(vmp, size);
	if (retaddr == NULL)
		return NULL;

	return (char *)memcpy(retaddr, s, size);
}

/*
 * vmem_malloc_usable_size -- get usable size of allocation
 */
size_t
vmem_malloc_usable_size(VMEM *vmp, void *ptr)
{
	LOG(3, "vmp %p ptr %p", vmp, ptr);
	if (ptr == NULL)
		return 0;

	uint64_t hdr_off = *((uint64_t *)ptr - 1);
	ptr = (char *)ptr - hdr_off;

	uint64_t off = (uintptr_t)ptr - (uintptr_t)vmp->heap.base;

	return palloc_usable_size(&vmp->heap, off) - PALLOC_DATA_OFF - hdr_off;
}
