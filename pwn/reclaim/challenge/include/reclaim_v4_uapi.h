/* SPDX-License-Identifier: MIT */
#ifndef RECLAIM_V4_RELEASE_UAPI_H
#define RECLAIM_V4_RELEASE_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define RECLAIM_CASE_PATH   "/dev/reclaim"
#define RECLAIM_LEDGER_PATH "/dev/reclaim-ledger"
#define RECLAIM_CODEC_PATH  "/dev/reclaim-codec"
#define RECLAIM_WORK_PATH   "/dev/reclaim-work"
#define RECLAIM_EVIDENCE_PATH "/dev/reclaim-evidence"

#define RECLAIM_MAX_REVIEWERS 8U
#define RECLAIM_MAX_RECEIPTS 16U
#define RECLAIM_MAX_POLICY_SIZE (8U * 1024U * 1024U)
#define RECLAIM_MAX_LEDGER_RECORDS 4096U
#define RECLAIM_LEDGER_STATEMENTS 512U
#define RECLAIM_LEDGER_MEMOS 16U
#define RECLAIM_LEDGER_NOTICES 16U
#define RECLAIM_STATEMENTS_PER_CPU 256U
#define RECLAIM_WORK_MAX 128U

struct reclaim_reviewer {
	__u32 policy_size;
	__u32 policy_rounds;
	__u64 seed;
	__u32 reviewer_id;
	__u32 reserved;
};

struct reclaim_attach {
	__u64 token;
};

struct reclaim_publish {
	__u64 receipt_fds;
	__u32 capacity;
	__u32 count;
	__u64 digest;
};

struct reclaim_view {
	__u64 buffer;
	__u32 capacity;
	__s32 result;
};

struct reclaim_generation {
	__u64 generation;
	__u32 count;
	__u32 reserved;
};

struct reclaim_ledger_record {
	__u32 index;
	__u32 reserved;
	__u64 token;
	__u64 fingerprint;
};

struct reclaim_memo_append {
	__u8 data[64];
	__u32 length;
	__u32 reserved;
	__u64 token;
};

struct reclaim_notice_pulse {
	__u64 token;
	__u64 amount;
};

struct reclaim_token_request {
	__u64 token;
};

struct reclaim_codec_record {
	__u32 index;
	__u32 reserved;
	__u64 value;
};

#define RECLAIM_WORK_SCRATCH 1U
#define RECLAIM_WORK_MIRROR  2U
#define RECLAIM_WORK_SHARED  3U

struct reclaim_work_create {
	__u64 source;
	__u32 length;
	__u32 mode;
	__u32 index;
	__u32 reserved;
};

struct reclaim_work_digest {
	__u32 index;
	__u32 reserved;
	__u64 digest;
};

#define RECLAIM_CASE_IOC_MAGIC 0xa4
#define RECLAIM_CASE_IOC_ADD_REVIEWER \
	_IOWR(RECLAIM_CASE_IOC_MAGIC, 0x01, struct reclaim_reviewer)
#define RECLAIM_CASE_IOC_ATTACH \
	_IOW(RECLAIM_CASE_IOC_MAGIC, 0x02, struct reclaim_attach)
#define RECLAIM_CASE_IOC_PUBLISH \
	_IOWR(RECLAIM_CASE_IOC_MAGIC, 0x03, struct reclaim_publish)

#define RECLAIM_RECEIPT_IOC_VIEW \
	_IOWR(RECLAIM_CASE_IOC_MAGIC, 0x20, struct reclaim_view)
#define RECLAIM_RECEIPT_IOC_APPLY _IO(RECLAIM_CASE_IOC_MAGIC, 0x21)
#define RECLAIM_RECEIPT_IOC_RECONCILE _IO(RECLAIM_CASE_IOC_MAGIC, 0x22)
#define RECLAIM_RECEIPT_IOC_DISARM _IO(RECLAIM_CASE_IOC_MAGIC, 0x23)

#define RECLAIM_LEDGER_IOC_MAGIC 0xa5
#define RECLAIM_LEDGER_IOC_SYNC \
	_IOWR(RECLAIM_LEDGER_IOC_MAGIC, 0x01, struct reclaim_generation)
#define RECLAIM_LEDGER_IOC_READ \
	_IOWR(RECLAIM_LEDGER_IOC_MAGIC, 0x02, struct reclaim_ledger_record)
#define RECLAIM_LEDGER_IOC_APPEND_MEMO \
	_IOWR(RECLAIM_LEDGER_IOC_MAGIC, 0x05, struct reclaim_memo_append)
#define RECLAIM_LEDGER_IOC_PULSE \
	_IOW(RECLAIM_LEDGER_IOC_MAGIC, 0x06, struct reclaim_notice_pulse)
#define RECLAIM_LEDGER_IOC_WITHDRAW \
	_IOW(RECLAIM_LEDGER_IOC_MAGIC, 0x07, struct reclaim_token_request)

#define RECLAIM_CODEC_IOC_MAGIC 0xa6
#define RECLAIM_CODEC_IOC_READ \
	_IOWR(RECLAIM_CODEC_IOC_MAGIC, 0x01, struct reclaim_codec_record)

#define RECLAIM_WORK_IOC_MAGIC 0xa7
#define RECLAIM_WORK_IOC_CREATE \
	_IOWR(RECLAIM_WORK_IOC_MAGIC, 0x01, struct reclaim_work_create)
#define RECLAIM_WORK_IOC_DIGEST \
	_IOWR(RECLAIM_WORK_IOC_MAGIC, 0x02, struct reclaim_work_digest)

/* Logical signed-statement envelope; no native address or type material. */
#define RECLAIM_ENVELOPE_TAG 0x5245434f52445634ULL
struct reclaim_envelope {
	__u64 tag;
	__u64 generation;
	__u64 epoch_cookie;
	__u64 statement_digest;
	__u32 ordinal;
	__u32 group;
	__u32 payload_size;
	__u32 reserved;
	__u64 checksum;
	__u64 padding;
};

struct reclaim_notice_view {
	__u64 sequence;
	__u64 token_digest;
};

#define RECLAIM_ARCHIVE_ANCHORS 15U
#define RECLAIM_ARCHIVE_XATTR_VALUE 176U
#define RECLAIM_ARCHIVE_NOTIFY_NAME 183U
#define RECLAIM_ARCHIVE_EVENT_TAG 0x6c65617365763421ULL

struct reclaim_archive_bookmark {
	__u64 marker;
	__u64 token;
};

struct reclaim_archive_snapshot {
	/* Public fingerprint from the ordinary ledger serialization. */
	__u64 fingerprint;
	__u64 revision;
	__u32 frame_count;
	__u32 reserved;
};

struct reclaim_archive_description {
	__u64 generation;
	__u64 locator;
};

struct reclaim_archive_event_descriptor {
	__u64 generation;
	__u64 locator;
	__u64 tag;
	__u64 checksum;
};

struct reclaim_archive_export_record {
	__u64 fingerprint;
	__u32 length;
	__u32 reserved;
	__u8 data[32];
};

#define RECLAIM_LEDGER_IOC_BOOKMARK \
	_IOWR(RECLAIM_LEDGER_IOC_MAGIC, 0x08, struct reclaim_archive_bookmark)
#define RECLAIM_LEDGER_IOC_SNAPSHOT \
	_IOWR(RECLAIM_LEDGER_IOC_MAGIC, 0x09, struct reclaim_archive_snapshot)
#endif
