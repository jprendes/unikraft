/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, Unikraft GmbH and The Unikraft Authors. */

#ifndef __HYPERLIGHT_POSTCARD_H__
#define __HYPERLIGHT_POSTCARD_H__

#include <string.h>
#include <hyperlight/hcall.h>

/* hyperlight-common flatbuffer_wrappers/wire.rs: the module retains its
 * historical name, but control values now use serde/Postcard.
 */
struct hl_pc_writer {
	__u8 *buf;
	__u64 cap, len;
	int failed;
};

struct hl_pc_reader {
	const __u8 *buf;
	__u64 len, pos;
	int failed;
};

static inline void hl_pc_bytes(struct hl_pc_writer *w, const void *p,
			       __u64 len)
{
	if (w->failed || len > w->cap - w->len) {
		w->failed = 1;
		return;
	}
	if (len)
		memcpy(w->buf + w->len, p, len);
	w->len += len;
}

static inline void hl_pc_uint(struct hl_pc_writer *w, __u64 value)
{
	__u8 b;

	do {
		b = value & 0x7f;
		value >>= 7;
		if (value)
			b |= 0x80;
		hl_pc_bytes(w, &b, 1);
	} while (value && !w->failed);
}

static inline void hl_pc_string(struct hl_pc_writer *w, const char *s,
				__u64 len)
{
	hl_pc_uint(w, len);
	hl_pc_bytes(w, s, len);
}

static inline const __u8 *hl_pc_take(struct hl_pc_reader *r, __u64 len)
{
	const __u8 *p;

	if (r->failed || len > r->len - r->pos) {
		r->failed = 1;
		return NULL;
	}
	p = r->buf + r->pos;
	r->pos += len;
	return p;
}

/* Integer varints have at most ceil(bits/7) bytes. Check the last byte
 * before shifting, including when a peer declares a u64 maximum.
 */
static inline __u64 hl_pc_read_uint(struct hl_pc_reader *r, unsigned int bits)
{
	__u64 value = 0;
	unsigned int shift;
	const __u8 *p;

	for (shift = 0; shift < bits; shift += 7) {
		p = hl_pc_take(r, 1);
		if (!p)
			return 0;
		if (bits - shift < 7 && *p >= (1U << (bits - shift)))
			break;
		value |= (__u64)(*p & 0x7f) << shift;
		if (!(*p & 0x80))
			return value;
	}
	r->failed = 1;
	return 0;
}

static inline __u64 hl_pc_utf8_decode(const __u8 *s, __u64 len, __u32 *cp)
{
	__u32 c, min;
	__u64 n, i;

	if (!len)
		return 0;
	c = s[0];
	if (c < 0x80) {
		*cp = c;
		return 1;
	}
	if ((c & 0xe0) == 0xc0) {
		n = 2; c &= 0x1f; min = 0x80;
	} else if ((c & 0xf0) == 0xe0) {
		n = 3; c &= 0x0f; min = 0x800;
	} else if ((c & 0xf8) == 0xf0) {
		n = 4; c &= 0x07; min = 0x10000;
	} else {
		return 0;
	}
	if (len < n)
		return 0;
	for (i = 1; i < n; i++) {
		if ((s[i] & 0xc0) != 0x80)
			return 0;
		c = (c << 6) | (s[i] & 0x3f);
	}
	if (c < min || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
		return 0;
	*cp = c;
	return n;
}

static inline int hl_pc_bool(struct hl_pc_reader *r)
{
	const __u8 *p = hl_pc_take(r, 1);

	if (!p || *p > 1) {
		r->failed = 1;
		return 0;
	}
	return *p;
}

static inline int hl_pc_utf8_valid(const __u8 *s, __u64 len)
{
	__u64 n;
	__u32 cp;

	for (; len; s += n, len -= n) {
		n = hl_pc_utf8_decode(s, len, &cp);
		if (!n)
			return 0;
	}
	return 1;
}

static inline const __u8 *hl_pc_read_string(struct hl_pc_reader *r, __u64 *len)
{
	const __u8 *p;

	*len = hl_pc_read_uint(r, 64);
	p = hl_pc_take(r, *len);
	if (p && !hl_pc_utf8_valid(p, *len))
		r->failed = 1;
	return p;
}

/* Keep HL_PV_* as the kernel/driver ABI; these are Postcard WireValue tags. */
static inline __u64 hl_pc_encode_call(__u8 *buf, __u64 cap, const char *name,
				     __u8 ret_type,
				     const struct hl_param *params, int np,
				     __u64 *control_len)
{
	struct hl_pc_writer w = { .buf = buf, .cap = cap };
	int i;

	if (np < 0 || np > HL_MAX_PARAMS || (np && !params) ||
	    ret_type > 10 || !hl_pc_utf8_valid((const __u8 *)name, strlen(name)))
		return 0;
	hl_pc_string(&w, name, strlen(name));
	hl_pc_uint(&w, 1); /* CallHead.host */
	hl_pc_uint(&w, ret_type);
	hl_pc_uint(&w, np);
	for (i = 0; i < np; i++) {
		switch (params[i].type) {
		case HL_PV_HLINT:
			hl_pc_uint(&w, 0);
			hl_pc_uint(&w, ((__u32)params[i].i32_val << 1) ^
				   (0U - (params[i].i32_val < 0)));
			break;
		case HL_PV_HLUINT:
			hl_pc_uint(&w, 1);
			hl_pc_uint(&w, params[i].u32_val);
			break;
		case HL_PV_HLLONG:
			hl_pc_uint(&w, 2);
			hl_pc_uint(&w, ((__u64)params[i].i64_val << 1) ^
				   (0ULL - (params[i].i64_val < 0)));
			break;
		case HL_PV_HLULONG:
			hl_pc_uint(&w, 3);
			hl_pc_uint(&w, params[i].u64_val);
			break;
		case HL_PV_HLSTRING:
			if (!hl_pc_utf8_valid((const __u8 *)params[i].str.ptr,
					     params[i].str.len))
				return 0;
			hl_pc_uint(&w, 6);
			hl_pc_string(&w, params[i].str.ptr, params[i].str.len);
			break;
		case HL_PV_HLVECBYTES:
			hl_pc_uint(&w, 9);
			hl_pc_uint(&w, params[i].vec.len);
			hl_pc_uint(&w, 0); /* contiguous VecBytes */
			break;
		default:
			return 0;
		}
	}
	*control_len = w.len;
	for (i = 0; i < np; i++)
		if (params[i].type == HL_PV_HLVECBYTES)
			hl_pc_bytes(&w, params[i].vec.ptr, params[i].vec.len);
	return w.failed ? 0 : w.len;
}

struct hl_pc_call {
	const char *name;
	__u64 name_len;
	__u8 ret_type;
	int np;
	struct hl_param params[HL_MAX_PARAMS];
};

/* Decode the parameter kinds accepted by the guest call API. */
static inline int hl_pc_decode_call(const __u8 *buf, __u64 len, __u64 control,
				    struct hl_pc_call *call)
{
	struct hl_pc_reader r = { .buf = buf, .len = control };
	__u64 count, tag, value, size, external = control;
	const __u8 *p;
	int i;

	if (control > len)
		return -1;
	call->name = (const char *)hl_pc_read_string(&r, &call->name_len);
	if (hl_pc_bool(&r) != 0) /* CallHead.host must be false */
		return -1;
	value = hl_pc_read_uint(&r, 32);
	count = hl_pc_read_uint(&r, 64);
	if (r.failed || value > 10 || count > HL_MAX_PARAMS)
		return -1;
	call->ret_type = value;
	call->np = count;
	for (i = 0; i < call->np; i++) {
		struct hl_param *param = &call->params[i];

		tag = hl_pc_read_uint(&r, 32);
		switch (tag) {
		case 0:
		case 1:
			value = hl_pc_read_uint(&r, 32);
			param->type = tag ? HL_PV_HLUINT : HL_PV_HLINT;
			param->u32_val = tag ? value :
				(value >> 1) ^ (0U - (__u32)(value & 1));
			break;
		case 2:
		case 3:
			value = hl_pc_read_uint(&r, 64);
			param->type = tag == 3 ? HL_PV_HLULONG : HL_PV_HLLONG;
			param->u64_val = tag == 3 ? value :
				(value >> 1) ^ (0ULL - (value & 1));
			break;
		case 6:
			p = hl_pc_read_string(&r, &size);
			if (size > (__u32)-1)
				return -1;
			param->type = HL_PV_HLSTRING;
			param->str.ptr = (const char *)p;
			param->str.len = size;
			break;
		case 9:
			size = hl_pc_read_uint(&r, 64);
			if (hl_pc_bool(&r) != 0 ||
			    size > len - external || size > (__u32)-1)
				return -1;
			param->type = HL_PV_HLVECBYTES;
			param->vec.ptr = buf + external;
			param->vec.len = size;
			external += size;
			break;
		default:
			return -1;
		}
		if (r.failed)
			return -1;
	}
	return r.pos == control && external == len ? 0 : -1;
}

static inline int hl_pc_name_is(const struct hl_pc_call *call, const char *name)
{
	return call->name_len == strlen(name) &&
		!memcmp(call->name, name, call->name_len);
}

static inline __u64 hl_pc_env_version(const struct hl_pc_call *call)
{
	const struct hl_param *p;

	if (!call->np)
		return 0;
	p = &call->params[call->np - 1];
	return p->type == HL_PV_HLULONG ? p->u64_val : 0;
}

struct hl_pc_result {
	int error;
	__u32 tag;
	__u64 value;
	const __u8 *data;
	__u64 len;
};

static inline int hl_pc_decode_result(const __u8 *buf, __u64 len, __u64 control,
				      struct hl_pc_result *result)
{
	struct hl_pc_reader r = { .buf = buf, .len = control };
	__u64 variant, size;

	if (control > len)
		return -1;
	memset(result, 0, sizeof(*result));
	variant = hl_pc_read_uint(&r, 32);
	if (variant == 1) {
		result->error = 1;
		result->value = hl_pc_read_uint(&r, 64);
		result->data = hl_pc_read_string(&r, &result->len);
	} else if (variant == 0) {
		result->tag = hl_pc_read_uint(&r, 32);
		switch (result->tag) {
		case 0:
		case 1:
			result->value = hl_pc_read_uint(&r, 32);
			break;
		case 2:
		case 3:
			result->value = hl_pc_read_uint(&r, 64);
			break;
		case 4:
		case 5:
			size = result->tag == 4 ? 4 : 8;
			result->data = hl_pc_take(&r, size);
			result->len = size;
			break;
		case 6:
			result->data = hl_pc_read_string(&r, &result->len);
			break;
		case 7:
			result->value = hl_pc_bool(&r);
			break;
		case 8:
			break;
		case 9:
			result->len = hl_pc_read_uint(&r, 64);
			if (hl_pc_bool(&r) != 0 ||
			    result->len != len - control)
				return -1;
			result->data = buf + control;
			break;
		default:
			return -1;
		}
	} else {
		return -1;
	}
	if (r.failed || r.pos != control)
		return -1;
	return !result->error && result->tag == 9 ? 0 :
		(control == len ? 0 : -1);
}

static inline void hl_pc_log_string(struct hl_pc_writer *w, const char *s,
				    __u64 len)
{
	__u64 i = 0, n;
	__u32 cp;
	const char replacement = '?';

	hl_pc_uint(w, len);
	while (i < len && !w->failed) {
		n = hl_pc_utf8_decode((const __u8 *)s + i, len - i, &cp);
		hl_pc_bytes(w, n ? s + i : &replacement, n ? n : 1);
		i += n ? n : 1;
	}
}

static inline __u64 hl_pc_encode_log(__u8 *buf, __u64 cap, __u8 level,
				     const char *source, const char *file,
				     __u32 line, const char *msg, __u64 len)
{
	struct hl_pc_writer w = { .buf = buf, .cap = cap };

	if (level > HL_LOG_CRITICAL)
		return 0;
	hl_pc_log_string(&w, msg, len);
	hl_pc_log_string(&w, source, strlen(source));
	hl_pc_uint(&w, level);
	hl_pc_string(&w, "", 0); /* caller */
	hl_pc_log_string(&w, file, strlen(file));
	hl_pc_uint(&w, line);
	return w.failed ? 0 : w.len;
}

#endif /* __HYPERLIGHT_POSTCARD_H__ */
