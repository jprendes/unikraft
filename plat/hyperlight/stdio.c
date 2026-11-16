/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, The Unikraft Authors. */

#include <uk/config.h>
#if CONFIG_LIBDEVFS && CONFIG_LIBPOSIX_FDTAB
#include <uk/alloc.h>
#include <uk/file/nops.h>
#include <uk/file/iovutil.h>
#include <uk/posix-fdtab.h>
#include <uk/thread.h>
#include <sys/stat.h>
#include <string.h>
#include <hyperlight/hcall.h>
#include <hyperlight/step.h>

#define HL_STDIO_CHUNK 4096UL
static const char hl_stdio_volume[] = "hyperlight-stdio";

struct hl_stdio {
	struct uk_file file;
	struct uk_file_state state;
	uk_file_refcnt ref;
	struct hl_async_wait *wait;
	__u64 execution;
	unsigned int stream;
	int error;
	int opened;
};

static __u32 stdio_u32(const __u8 *p)
{
	return (__u32)p[0] | ((__u32)p[1] << 8) |
		((__u32)p[2] << 16) | ((__u32)p[3] << 24);
}

static uk_pollevent stdio_events(__u32 events)
{
	if (events & EPOLLIN)
		events |= UKFD_POLLIN;
	if (events & EPOLLOUT)
		events |= UKFD_POLLOUT;
	return events;
}

static int stdio_call(struct hl_stdio *s, const char *name,
		      struct hl_param *params, int nparams,
		      __u8 *reply, __sz cap, __sz *len)
{
	struct uk_thread *current = uk_thread_current();
	__u64 previous = hl_thread_execution(current);
	int error;

	hl_thread_set_execution(current, s->execution);
	error = hl_hcall_vecbytes(name, params, nparams, reply, cap, len);
	hl_thread_set_execution(current, previous);
	if (error || !*len)
		return -EIO;
	if (reply[0] == 1)
		return *len == 5 ? -(int)stdio_u32(reply + 1) : -EPROTO;
	return 0;
}

static void stdio_ready(void *arg, int error, const __u8 *reply, __u64 len)
{
	struct hl_stdio *s = arg;
	uk_pollevent events = UKFD_POLLIN | UKFD_POLLOUT | EPOLLERR;

	s->wait = NULL;
	if (!error && len == 5 && reply[0] == 0)
		events = stdio_events(stdio_u32(reply + 1));
	else if (error != EINTR)
		s->error = error ? error : EIO;
	uk_file_event_set(&s->file, events);
}

static uk_pollevent stdio_poll(const struct uk_file *f, uk_pollevent mask)
{
	struct hl_stdio *s = f->node;
	struct hl_param p = { .type = HL_PV_HLULONG, .u64_val = s->stream };
	struct uk_thread *current = uk_thread_current();
	__u64 previous = hl_thread_execution(current);
	__u8 reply[9];
	__sz len;
	int error;

	if (s->error)
		return mask & (EPOLLERR | EPOLLHUP);
	if (s->wait)
		return 0;
	error = stdio_call(s, "CommandPoll", &p, 1, reply, sizeof(reply), &len);
	if (!error && len == 5 && reply[0] == 0)
		return mask & stdio_events(stdio_u32(reply + 1));
	if (!error && len == 9 && reply[0] == 2) {
		__u64 id = stdio_u32(reply + 1) |
			((__u64)stdio_u32(reply + 5) << 32);

		hl_thread_set_execution(current, s->execution);
		error = hl_async_watch(id, stdio_ready, s, &s->wait);
		hl_thread_set_execution(current, previous);
		if (!error)
			return 0;
	}
	s->error = error ? -error : EPROTO;
	return mask & EPOLLERR;
}

static ssize_t stdio_read(const struct uk_file *f, const struct iovec *iov,
			  size_t iovcnt, size_t off, long flags __unused)
{
	struct hl_stdio *s = f->node;
	__u8 reply[HL_STDIO_CHUNK + 1];
	size_t count = MIN(uk_iov_len(iov, iovcnt), HL_STDIO_CHUNK);
	struct hl_param p = { .type = HL_PV_HLULONG, .u64_val = count };
	__sz len;
	size_t index = 0, pos = 0;
	int error;

	if (off)
		return -ESPIPE;
	if (!count)
		return 0;
	if (s->error)
		return s->error == ECANCELED ? 0 : -s->error;
	error = stdio_call(s, "CommandRead", &p, 1, reply, sizeof(reply), &len);
	if (error)
		return error;
	if (reply[0] != 0 || len > count + 1)
		return -EPROTO;
	return uk_iov_scatter(iov, iovcnt, (const char *)reply + 1,
			      len - 1, &index, &pos);
}

static ssize_t stdio_write(const struct uk_file *f, const struct iovec *iov,
			   size_t iovcnt, size_t off, long flags __unused)
{
	struct hl_stdio *s = f->node;
	__u8 bytes[HL_STDIO_CHUNK], reply[5];
	size_t count = MIN(uk_iov_len(iov, iovcnt), HL_STDIO_CHUNK);
	size_t index = 0, pos = 0;
	struct hl_param p[2] = {
		{ .type = HL_PV_HLULONG, .u64_val = s->stream },
		{ .type = HL_PV_HLVECBYTES,
		  .vec = { .ptr = iovcnt == 1 ? iov[0].iov_base : bytes,
			   .len = count } }
	};
	__sz len;
	int error;

	if (off)
		return -ESPIPE;
	if (!count)
		return 0;
	if (s->error)
		return s->error == ECANCELED ? -EPIPE : -s->error;
	if (iovcnt != 1)
		uk_iov_gather((char *)bytes, iov, iovcnt, count, &index, &pos);
	error = stdio_call(s, "CommandWrite", p, 2, reply, sizeof(reply), &len);
	if (error)
		return error;
	return len == 1 && reply[0] == 0 ? (ssize_t)count : -EPROTO;
}

static int stdio_stat(const struct uk_file *f, unsigned int mask __unused,
		      struct uk_statx *stat)
{
	stat->stx_mask = UK_STATX_TYPE | UK_STATX_MODE | UK_STATX_INO;
	stat->stx_blksize = HL_STDIO_CHUNK;
	stat->stx_mode = S_IFIFO | 0600;
	stat->stx_ino = (uintptr_t)f;
	return 0;
}

static const struct uk_file_ops stdio_read_ops = {
	.read = stdio_read, .write = uk_file_nop_write,
	.mem = uk_file_nop_mem, .getstat = stdio_stat,
	.setstat = uk_file_nop_setstat, .ctl = uk_file_nop_ctl
};

static const struct uk_file_ops stdio_write_ops = {
	.read = uk_file_nop_read, .write = stdio_write,
	.mem = uk_file_nop_mem, .getstat = stdio_stat,
	.setstat = uk_file_nop_setstat, .ctl = uk_file_nop_ctl
};

static void stdio_release(const struct uk_file *f, int what)
{
	struct hl_stdio *s = f->node;

	if (what & UK_FILE_RELEASE_RES) {
		if (s->wait)
			hl_async_unwatch(s->wait);
		if (s->opened)
			hl_execution_close(s->execution, s->stream);
	}
	if (what & UK_FILE_RELEASE_OBJ)
		uk_free(uk_alloc_get_default(), s);
}

int hl_stdio_open(unsigned int stream)
{
	struct hl_stdio *s = uk_calloc(uk_alloc_get_default(), 1, sizeof(*s));
	int fd;

	if (!s)
		return -ENOMEM;
	s->stream = stream;
	s->execution = hl_thread_execution(uk_thread_current());
	s->state = UK_FILE_POLLED_STATE_INIT_VALUE(s->state, stdio_poll);
	s->ref = UK_FILE_REFCNT_INIT_VALUE(s->ref);
	s->file = (struct uk_file) {
		.vol = hl_stdio_volume, .node = s, .refcnt = &s->ref,
		.state = &s->state,
		.ops = stream ? &stdio_write_ops : &stdio_read_ops,
		._release = stdio_release
	};
	fd = uk_fdtab_open(&s->file, (stream ? O_WRONLY : O_RDONLY) |
				   O_CLOEXEC | UKFD_O_NOSEEK);
	if (fd >= 0)
		s->opened = 1;
	uk_file_release(&s->file);
	return fd;
}
#endif
