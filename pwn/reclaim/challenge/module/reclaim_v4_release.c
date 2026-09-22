// SPDX-License-Identifier: GPL-2.0
/* Private pre-release implementation.  Do not package before shortcut audit. */
#include <linux/anon_inodes.h>
#include <crypto/algapi.h>
#include <crypto/sha2.h>
#include <linux/cpu.h>
#include <linux/cred.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/key.h>
#include <linux/key-type.h>
#include <keys/user-type.h>
#include <linux/inotify.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/rbtree.h>
#include <linux/rbtree_augmented.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/srcu.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/xattr.h>

#include "reclaim_v4_uapi.h"

#ifndef RECLAIM_ROUTE_KEY
#define RECLAIM_ROUTE_KEY 1
#endif
#ifndef RECLAIM_ROUTE_ARCHIVE
#define RECLAIM_ROUTE_ARCHIVE 1
#endif
#ifndef RECLAIM_GROUP_DEFICIT_CAP
#define RECLAIM_GROUP_DEFICIT_CAP 0
#endif
#ifndef RECLAIM_ROUTE_WORK
#define RECLAIM_ROUTE_WORK 0
#endif

enum reclaim_backend_kind {
	RECLAIM_BACKEND_NONE,
	RECLAIM_BACKEND_STATEMENT,
	RECLAIM_BACKEND_MEMO,
	RECLAIM_BACKEND_NOTICE,
	RECLAIM_BACKEND_ARCHIVE_CURSOR,
	RECLAIM_BACKEND_ARCHIVE_FRAME,
};

struct reclaim_memo {
	refcount_t refs;
	u32 length;
	u32 reserved;
	u64 tag;
	u8 data[64];
};

struct reclaim_notice {
	refcount_t refs;
	atomic64_t sequence;
	u64 token_digest;
};

struct reclaim_archive_ctx;

struct reclaim_archive_entry {
	refcount_t refs;
	u32 selector;
	struct list_head anchor_link;
	const struct cred *owner_cred;
	struct reclaim_archive_ctx *ctx;
	struct rb_node node;
	u64 nonce;
	u8 payload[136];
	u8 indexed;
	u8 anchor;
	u8 ordinal;
	u8 reserved[5];
};

struct reclaim_archive_frame {
	refcount_t refs;
	u32 domain;
	struct reclaim_archive_ctx *ctx;
	u64 fingerprint;
	u8 prefix[48];
	u64 generation;
	u64 locator;
	u8 tail[128];
};

struct reclaim_archive_ctx {
	refcount_t refs;
	struct mutex lock;
	struct list_head anchors;
	struct rb_root index;
	struct reclaim_archive_entry *cursor;
	atomic_t active_receipts;
	atomic_t active_frames;
	u32 anchor_count;
	u32 next_cursor;
	bool closing;
	bool round_active;
	bool cursor_final_released;
	u64 order_generation;
	u64 order_locator;
	u32 order_selector;
	u64 lease_generation;
	u64 lease_locator;
	u32 lease_selector;
	u32 lease_removed_mask;
	u32 audit_materialized_mask;
	u32 retention_materialized_mask;
};

struct reclaim_inotify_overlay {
	struct list_head list;
	u32 mask;
	int wd;
	u32 cookie;
	int name_len;
	char name[];
};

struct reclaim_archive_secret {
	u8 key[SHA256_DIGEST_SIZE];
};

/* Keep the randomized layout, but make its required >=4-candidate invariant
 * an initialization guarantee rather than a user-visible -ENOMEM lottery. */
#define RECLAIM_ARCHIVE_LAYOUT_ATTEMPTS 512U

static_assert(sizeof(struct reclaim_archive_entry) == 216);
static_assert(offsetof(struct reclaim_archive_entry, node) ==
	      offsetof(struct simple_xattr, value));
static_assert(sizeof(struct simple_xattr) + RECLAIM_ARCHIVE_XATTR_VALUE ==
	      sizeof(struct reclaim_archive_entry));
static_assert(sizeof(struct reclaim_archive_frame) ==
	      sizeof(struct reclaim_archive_entry));
static_assert(offsetof(struct reclaim_archive_frame, locator) ==
	      offsetof(struct reclaim_archive_entry, payload) + sizeof(u64));
static_assert(sizeof(struct reclaim_inotify_overlay) == 32);
static_assert(sizeof(struct reclaim_inotify_overlay) +
	      RECLAIM_ARCHIVE_NOTIFY_NAME + 1 ==
	      sizeof(struct reclaim_archive_entry));

struct reclaim_ledger_slot {
	u64 token;
	u64 fingerprint;
	u64 generation;
	u32 ordinal;
	u32 group;
	u8 kind;
	u8 live;
	u8 deficit_claimed;
	u8 reserved;
	union {
		int key_serial;
		struct reclaim_memo *memo;
		struct reclaim_notice *notice;
		void *opaque;
	};
};

struct reclaim_global {
	struct mutex lock;
	struct key *statement_keyring;
	struct reclaim_ledger_slot slots[RECLAIM_MAX_LEDGER_RECORDS];
	u32 count;
	u64 generation;
	bool synced;
};

struct reclaim_reviewer_node {
	struct list_head link;
	u8 *policy;
	u32 size;
	u32 rounds;
	u32 id;
	u64 seed;
};

struct reclaim_resource {
	enum reclaim_backend_kind kind;
	u32 group;
	void *object;
};

struct reclaim_case_ctx {
	struct mutex lock;
	struct srcu_struct readers;
	struct list_head reviewers;
	u32 reviewer_count;
	u32 next_reviewer_id;
	bool dispatching;
	bool dispatched;
	struct reclaim_resource resource;
};

struct reclaim_receipt {
	struct reclaim_resource resource;
	struct reclaim_archive_ctx *archive_ctx;
	bool armed;
};

#if RECLAIM_ROUTE_WORK
struct reclaim_work_ctx {
	struct mutex lock;
	struct page *pages[RECLAIM_WORK_MAX];
	u8 modes[RECLAIM_WORK_MAX];
	u32 count;
};

static_assert(offsetof(struct reclaim_work_ctx, pages) == 0x20);
#endif

struct reclaim_key_build {
	void **pages;
	u32 *groups;
	u32 count;
};

struct reclaim_key_cpu_job {
	struct reclaim_key_build *build;
	u32 first;
	u32 count;
};

static struct reclaim_global reclaim_global;
static struct kmem_cache *reclaim_memo_cache;
static struct kmem_cache *reclaim_notice_cache;
static struct reclaim_archive_secret *reclaim_archive_secret __maybe_unused;

#if RECLAIM_ROUTE_WORK
#define RECLAIM_MIRROR_QUARANTINE_MAX 1024U
static DEFINE_MUTEX(reclaim_mirror_lock);
static struct page *reclaim_mirror_quarantine[
	RECLAIM_MIRROR_QUARANTINE_MAX];
static u32 reclaim_mirror_count;
#endif

static struct key_type reclaim_checkpoint_key_type = {
	.name = "reclaim_checkpoint",
};
static DEFINE_MUTEX(reclaim_checkpoint_lock);
static bool reclaim_checkpoint_registered;

struct reclaim_codec_slot {
	u64 fingerprint;
	unsigned long codec;
};

#define RECLAIM_CODEC_PUBLIC 7U
#define RECLAIM_CODEC_PRIVATE 5U
#define RECLAIM_CODEC_TOTAL (RECLAIM_CODEC_PUBLIC + RECLAIM_CODEC_PRIVATE)

/* Module-local schema identities are data, never callable codec methods. */
static const u64 reclaim_codec_identity[4] = {
	0x243f6a8885a308d3ULL,
	0x13198a2e03707344ULL,
	0xa4093822299f31d0ULL,
	0x082efa98ec4e6c89ULL,
};

static const struct reclaim_codec_slot reclaim_codecs[RECLAIM_CODEC_TOTAL] = {
	{ 0x6a09e667f3bcc908ULL, 0x80 },
	{ 0xbb67ae8584caa73bULL, 0x100 },
	{ 0x3c6ef372fe94f82bULL, 0x180 },
	{ 0xa54ff53a5f1d36f1ULL, 0x200 },
	{ 0x510e527fade682d1ULL, 0x300 },
	{ 0x9b05688c2b3e6c1fULL, 0x400 },
	{ 0x1f83d9abfb41bd6bULL, 0x800 },
	{ 0x5be0cd19137e2179ULL, (unsigned long)&reclaim_codec_identity[0] },
	{ 0xcbbb9d5dc1059ed8ULL, (unsigned long)&reclaim_codec_identity[1] },
	{ 0x629a292a367cd507ULL, (unsigned long)&reclaim_codec_identity[2] },
	{ 0x9159015a3070dd17ULL, (unsigned long)noop_llseek },
	{ 0x152fecd8f70e5939ULL, (unsigned long)&reclaim_codec_identity[3] },
};

static u64 reclaim_envelope_checksum(const struct reclaim_envelope *payload)
{
	u64 value = payload->tag ^ rol64(payload->generation, 7);

	value ^= rol64(payload->epoch_cookie, 17);
	value ^= rol64(payload->statement_digest, 29);
	value ^= ((u64)payload->group << 32) | payload->ordinal;
	value ^= ((u64)payload->reserved << 32) | payload->payload_size;
	value ^= payload->padding;
	return value ^ 0x9e3779b97f4a7c15ULL;
}

static int reclaim_key_checkpoint(void)
{
	int ret = 0;

	rcu_barrier();
	mutex_lock(&reclaim_checkpoint_lock);
	if (reclaim_checkpoint_registered) {
		unregister_key_type(&reclaim_checkpoint_key_type);
		reclaim_checkpoint_registered = false;
	} else {
		ret = register_key_type(&reclaim_checkpoint_key_type);
		if (!ret) {
			reclaim_checkpoint_registered = true;
			unregister_key_type(&reclaim_checkpoint_key_type);
			reclaim_checkpoint_registered = false;
		}
	}
	mutex_unlock(&reclaim_checkpoint_lock);
	return ret;
}

static u64 reclaim_new_token_locked(void)
{
	u64 token;
	u32 i;

	do {
		token = get_random_u64();
		if (!token)
			continue;
		for (i = 0; i < reclaim_global.count; i++)
			if (reclaim_global.slots[i].token == token)
				break;
	} while (!token || i != reclaim_global.count);
	return token;
}

static u32 reclaim_new_group(struct reclaim_key_build *build)
{
	u32 group;
	u32 i;

	do {
		group = get_random_u32();
		if (!group)
			continue;
		for (i = 0; i < build->count; i++)
			if (build->groups[i] == group)
				break;
	} while (!group || i != build->count);
	return group;
}

static u32 reclaim_key_group(struct reclaim_key_build *build,
			     struct key *key)
{
	void *page = (void *)((unsigned long)key & PAGE_MASK);
	u32 i;

	for (i = 0; i < build->count; i++)
		if (build->pages[i] == page)
			return build->groups[i];
	return reclaim_new_group(build);
}

static long reclaim_build_keys_on_cpu(void *opaque)
{
	struct reclaim_key_cpu_job *job = opaque;
	struct reclaim_key_build *build = job->build;
	struct reclaim_envelope payload;
	char description[48];
	u32 i;

	for (i = job->first; i < job->first + job->count; i++) {
		struct reclaim_ledger_slot *slot = &reclaim_global.slots[i];
		struct key *key;
		u32 group;
		int ret;

		snprintf(description, sizeof(description), "statement-%016llx-%03u",
			 (unsigned long long)reclaim_global.generation, i);
		key = key_alloc(&key_type_user, description, GLOBAL_ROOT_UID,
				GLOBAL_ROOT_GID, current_cred(), 0,
				KEY_ALLOC_NOT_IN_QUOTA, NULL);
		if (IS_ERR(key))
			return PTR_ERR(key);
		group = reclaim_key_group(build, key);
		memset(&payload, 0, sizeof(payload));
		payload.tag = RECLAIM_ENVELOPE_TAG;
		payload.generation = reclaim_global.generation;
		payload.epoch_cookie = rol64(payload.generation, 13) ^
			0xa0761d6478bd642fULL;
		payload.statement_digest = get_random_u64();
		payload.ordinal = i;
		payload.group = group;
		payload.payload_size = sizeof(payload);
		payload.checksum = reclaim_envelope_checksum(&payload);
		ret = key_instantiate_and_link(key, &payload, sizeof(payload),
					       reclaim_global.statement_keyring, NULL);
		if (ret) {
			key_put(key);
			return ret;
		}
		slot->token = reclaim_new_token_locked();
		slot->fingerprint = payload.statement_digest;
		slot->generation = payload.generation;
		slot->ordinal = i;
		slot->group = group;
		slot->kind = RECLAIM_BACKEND_STATEMENT;
		slot->live = 1;
		slot->key_serial = key->serial;
		build->pages[i] = (void *)((unsigned long)key & PAGE_MASK);
		build->groups[i] = group;
		build->count++;
		reclaim_global.count++;
		key_put(key);
	}
	return 0;
}

static void reclaim_memo_put(struct reclaim_memo *memo)
{
	if (memo && refcount_dec_and_test(&memo->refs)) {
		memzero_explicit(memo, sizeof(*memo));
		kmem_cache_free(reclaim_memo_cache, memo);
	}
}

static void reclaim_notice_put(struct reclaim_notice *notice)
{
	if (notice && refcount_dec_and_test(&notice->refs)) {
		memzero_explicit(notice, sizeof(*notice));
		kmem_cache_free(reclaim_notice_cache, notice);
	}
}

static int reclaim_append_memo_locked(const u8 *data, u32 length, u64 *token)
{
	struct reclaim_ledger_slot *slot;
	struct reclaim_memo *memo;

	if (length > 64 || reclaim_global.count >= RECLAIM_MAX_LEDGER_RECORDS)
		return -ENOSPC;
	memo = kmem_cache_zalloc(reclaim_memo_cache, GFP_KERNEL);
	if (!memo)
		return -ENOMEM;
	refcount_set(&memo->refs, 1);
	memo->length = length;
	memo->tag = 0x6d656d6f76340000ULL ^ get_random_u64();
	memcpy(memo->data, data, length);
	slot = &reclaim_global.slots[reclaim_global.count++];
	slot->token = reclaim_new_token_locked();
	slot->fingerprint = get_random_u64();
	slot->generation = reclaim_global.generation;
	slot->kind = RECLAIM_BACKEND_MEMO;
	slot->live = 1;
	slot->memo = memo;
	*token = slot->token;
	return 0;
}

static int reclaim_append_notice_locked(u64 *token)
{
	struct reclaim_ledger_slot *slot;
	struct reclaim_notice *notice;

	if (reclaim_global.count >= RECLAIM_MAX_LEDGER_RECORDS)
		return -ENOSPC;
	notice = kmem_cache_zalloc(reclaim_notice_cache, GFP_KERNEL);
	if (!notice)
		return -ENOMEM;
	refcount_set(&notice->refs, 1);
	atomic64_set(&notice->sequence, 0);
	notice->token_digest = get_random_u64();
	slot = &reclaim_global.slots[reclaim_global.count++];
	slot->token = reclaim_new_token_locked();
	slot->fingerprint = get_random_u64();
	slot->generation = reclaim_global.generation;
	slot->kind = RECLAIM_BACKEND_NOTICE;
	slot->live = 1;
	slot->notice = notice;
	*token = slot->token;
	return 0;
}

static void reclaim_shuffle_slots_locked(void)
{
	u32 i;

	for (i = reclaim_global.count; i > 1; i--) {
		u32 other = get_random_u32() % i;
		struct reclaim_ledger_slot temporary =
			reclaim_global.slots[i - 1];

		reclaim_global.slots[i - 1] = reclaim_global.slots[other];
		reclaim_global.slots[other] = temporary;
	}
}

static int reclaim_sync_generation(struct reclaim_generation *request)
{
	struct reclaim_key_build build = { };
	struct reclaim_key_cpu_job job;
	u32 first = 0, i;
	int cpu, ret = 0;

	if (request->reserved)
		return -EINVAL;
	mutex_lock(&reclaim_global.lock);
	if (reclaim_global.synced) {
		mutex_unlock(&reclaim_global.lock);
		return -EALREADY;
	}
	reclaim_global.generation = get_random_u64();
	if (!reclaim_global.generation)
		reclaim_global.generation = 1;
	if (RECLAIM_ROUTE_KEY) {
		build.pages = kcalloc(RECLAIM_LEDGER_STATEMENTS,
				      sizeof(*build.pages), GFP_KERNEL);
		build.groups = kcalloc(RECLAIM_LEDGER_STATEMENTS,
				       sizeof(*build.groups), GFP_KERNEL);
		if (!build.pages || !build.groups) {
			ret = -ENOMEM;
			goto out;
		}
		ret = reclaim_key_checkpoint();
		if (ret)
			goto out;
		for_each_online_cpu(cpu) {
			if (first >= RECLAIM_LEDGER_STATEMENTS)
				break;
			job.build = &build;
			job.first = first;
			job.count = min_t(u32, RECLAIM_STATEMENTS_PER_CPU,
				RECLAIM_LEDGER_STATEMENTS - first);
			ret = work_on_cpu(cpu, reclaim_build_keys_on_cpu, &job);
			if (ret)
				goto out;
			first += job.count;
		}
		if (first != RECLAIM_LEDGER_STATEMENTS) {
			ret = -ENODEV;
			goto out;
		}
	}
	for (i = 0; i < RECLAIM_LEDGER_MEMOS; i++) {
		u8 data[64] = { };
		u64 token;

		snprintf(data, sizeof(data), "routine memo %u", i);
		ret = reclaim_append_memo_locked(data, strlen(data) + 1, &token);
		if (ret)
			goto out;
	}
	for (i = 0; i < RECLAIM_LEDGER_NOTICES; i++) {
		u64 token;

		ret = reclaim_append_notice_locked(&token);
		if (ret)
			goto out;
	}
	reclaim_shuffle_slots_locked();
	reclaim_global.synced = true;
	request->generation = reclaim_global.generation;
	request->count = reclaim_global.count;
out:
	mutex_unlock(&reclaim_global.lock);
	kfree(build.groups);
	kfree(build.pages);
	return ret;
}

static struct reclaim_ledger_slot *reclaim_find_slot_locked(u64 token)
{
	u32 i;

	for (i = 0; i < reclaim_global.count; i++)
		if (reclaim_global.slots[i].live &&
		    reclaim_global.slots[i].token == token)
			return &reclaim_global.slots[i];
	return NULL;
}

static u64 reclaim_archive_event_checksum(
	const struct reclaim_archive_event_descriptor *descriptor)
{
	u64 value = descriptor->generation ^ rol64(descriptor->locator, 19);

	value ^= rol64(descriptor->tag, 41);
	return value ^ 0xd6e8feb86659fd93ULL;
}

static int reclaim_archive_parse_hex_u64(const char *source, u64 *output)
{
	u64 value = 0;
	u32 i;

	for (i = 0; i < 16; i++) {
		u8 digit = source[i];

		value <<= 4;
		if (digit >= '0' && digit <= '9')
			value |= digit - '0';
		else if (digit >= 'a' && digit <= 'f')
			value |= digit - 'a' + 10;
		else
			return -EINVAL;
	}
	*output = value;
	return 0;
}

static int reclaim_archive_parse_event(
	const char *name, struct reclaim_archive_event_descriptor *descriptor)
{
	if (reclaim_archive_parse_hex_u64(name, &descriptor->generation) ||
	    reclaim_archive_parse_hex_u64(name + 16, &descriptor->locator) ||
	    reclaim_archive_parse_hex_u64(name + 32, &descriptor->tag) ||
	    reclaim_archive_parse_hex_u64(name + 48, &descriptor->checksum))
		return -EINVAL;
	return 0;
}

static u64 reclaim_archive_fingerprint(const struct reclaim_archive_entry *entry)
{
	u64 fingerprint;

	memcpy(&fingerprint, entry->payload + SHA256_DIGEST_SIZE,
	       sizeof(fingerprint));
	return fingerprint;
}

static void reclaim_archive_set_fingerprint(struct reclaim_archive_entry *entry,
					    u64 fingerprint)
{
	memcpy(entry->payload + SHA256_DIGEST_SIZE, &fingerprint,
	       sizeof(fingerprint));
}

static void reclaim_archive_insert_locked(struct reclaim_archive_ctx *ctx,
					  struct reclaim_archive_entry *entry)
{
	struct rb_node **link = &ctx->index.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		struct reclaim_archive_entry *cursor =
			rb_entry(*link, struct reclaim_archive_entry, node);

		parent = *link;
		if (entry->selector < cursor->selector)
			link = &(*link)->rb_left;
		else
			link = &(*link)->rb_right;
	}
	rb_link_node(&entry->node, parent, link);
	rb_insert_color(&entry->node, &ctx->index);
	entry->indexed = 1;
}

static struct reclaim_archive_entry *reclaim_archive_by_selector_locked(
	struct reclaim_archive_ctx *ctx, u32 selector)
{
	struct reclaim_archive_entry *entry;

	list_for_each_entry(entry, &ctx->anchors, anchor_link)
		if (entry->selector == selector)
			return entry;
	return NULL;
}

static struct reclaim_archive_entry *reclaim_archive_by_fingerprint_locked(
	struct reclaim_archive_ctx *ctx, u64 fingerprint)
{
	struct reclaim_archive_entry *entry;

	list_for_each_entry(entry, &ctx->anchors, anchor_link)
		if (reclaim_archive_fingerprint(entry) == fingerprint)
			return entry;
	return NULL;
}

static struct reclaim_archive_entry *reclaim_archive_by_locator_locked(
	struct reclaim_archive_ctx *ctx, u64 locator)
{
	struct reclaim_archive_entry *entry;

	list_for_each_entry(entry, &ctx->anchors, anchor_link)
		if (entry->nonce == locator)
			return entry;
	return NULL;
}

static bool reclaim_archive_reachable_locked(struct reclaim_archive_ctx *ctx,
					      struct reclaim_archive_entry *candidate)
{
	struct rb_node *node;

	for (node = rb_first(&ctx->index); node; node = rb_next(node))
		if (rb_entry(node, struct reclaim_archive_entry, node) == candidate)
			return true;
	return false;
}

static bool reclaim_archive_order_candidate_locked(
	struct reclaim_archive_ctx *ctx, struct reclaim_archive_entry *entry)
{
	struct rb_node *parent;

	if (!entry || !entry->indexed || entry->node.rb_left ||
	    entry->node.rb_right || rb_is_black(&entry->node) ||
	    !reclaim_archive_reachable_locked(ctx, entry))
		return false;
	parent = rb_parent(&entry->node);
	return parent && parent->rb_right == &entry->node;
}

static struct reclaim_archive_entry *reclaim_archive_parent_locked(
	struct reclaim_archive_ctx *ctx, struct reclaim_archive_entry *child)
{
	struct reclaim_archive_entry *entry;

	if (!child)
		return NULL;
	list_for_each_entry(entry, &ctx->anchors, anchor_link)
		if (entry->node.rb_left == &child->node ||
		    entry->node.rb_right == &child->node)
			return entry;
	return NULL;
}

static void reclaim_archive_ctx_get(struct reclaim_archive_ctx *ctx)
{
	refcount_inc(&ctx->refs);
}

static void reclaim_archive_ctx_destroy(struct reclaim_archive_ctx *ctx)
{
	struct reclaim_archive_entry *entry, *next;

	if (!ctx)
		return;
	list_for_each_entry_safe(entry, next, &ctx->anchors, anchor_link) {
		list_del(&entry->anchor_link);
		memzero_explicit(entry, sizeof(*entry));
		kfree(entry);
	}
	kfree(ctx);
}

static void reclaim_archive_ctx_put(struct reclaim_archive_ctx *ctx)
{
	if (ctx && refcount_dec_and_test(&ctx->refs))
		reclaim_archive_ctx_destroy(ctx);
}

static u32 reclaim_archive_candidate_count_locked(
	struct reclaim_archive_ctx *ctx,
	struct reclaim_archive_entry **candidates)
{
	struct reclaim_archive_entry *entry;
	u32 count = 0;

	list_for_each_entry(entry, &ctx->anchors, anchor_link)
		if (reclaim_archive_order_candidate_locked(ctx, entry)) {
			if (candidates)
				candidates[count] = entry;
			count++;
		}
	return count;
}

static struct reclaim_archive_ctx *reclaim_archive_ctx_create(void)
{
	struct reclaim_archive_entry *entries[RECLAIM_ARCHIVE_ANCHORS] = { };
	struct reclaim_archive_entry *order[RECLAIM_ARCHIVE_ANCHORS];
	struct reclaim_archive_entry *candidates[RECLAIM_ARCHIVE_ANCHORS];
	struct reclaim_archive_ctx *ctx;
	u32 attempt, i, j, candidate_count = 0;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;
	refcount_set(&ctx->refs, 1);
	mutex_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->anchors);
	ctx->index = RB_ROOT;
	atomic_set(&ctx->active_receipts, 0);
	atomic_set(&ctx->active_frames, 0);
	ctx->next_cursor = 1;

	for (i = 0; i < RECLAIM_ARCHIVE_ANCHORS; i++) {
		u32 selector;
		u64 locator, fingerprint;

		entries[i] = kzalloc(sizeof(*entries[i]), GFP_KERNEL_ACCOUNT);
		if (!entries[i])
			goto fail;
		INIT_LIST_HEAD(&entries[i]->anchor_link);
		entries[i]->anchor = 1;
		entries[i]->ordinal = i;
		entries[i]->ctx = ctx;
		do {
			selector = get_random_u32();
			for (j = 0; j < i; j++)
				if (entries[j]->selector == selector)
					break;
		} while (!selector || j != i);
		entries[i]->selector = selector;
		do {
			locator = get_random_u64();
			for (j = 0; j < i; j++)
				if (entries[j]->nonce == locator)
					break;
		} while (!locator || j != i);
		entries[i]->nonce = locator;
		get_random_bytes(entries[i]->payload,
				 sizeof(entries[i]->payload));
		do {
			fingerprint = get_random_u64();
			for (j = 0; j < i; j++)
				if (reclaim_archive_fingerprint(entries[j]) ==
				    fingerprint)
					break;
		} while (!fingerprint || j != i);
		reclaim_archive_set_fingerprint(entries[i], fingerprint);
		list_add_tail(&entries[i]->anchor_link, &ctx->anchors);
		ctx->anchor_count++;
	}

	for (attempt = 0; attempt < RECLAIM_ARCHIVE_LAYOUT_ATTEMPTS; attempt++) {
		ctx->index = RB_ROOT;
		for (i = 0; i < RECLAIM_ARCHIVE_ANCHORS; i++) {
			RB_CLEAR_NODE(&entries[i]->node);
			entries[i]->indexed = 0;
			order[i] = entries[i];
		}
		for (i = RECLAIM_ARCHIVE_ANCHORS; i > 1; i--) {
			u32 other = get_random_u32() % i;
			struct reclaim_archive_entry *temporary = order[i - 1];

			order[i - 1] = order[other];
			order[other] = temporary;
		}
		for (i = 0; i < RECLAIM_ARCHIVE_ANCHORS; i++)
			reclaim_archive_insert_locked(ctx, order[i]);
		candidate_count = reclaim_archive_candidate_count_locked(ctx,
								 candidates);
		if (candidate_count >= 4)
			break;
	}
	if (candidate_count < 4)
		goto fail;
	i = get_random_u32() % candidate_count;
	memcpy(candidates[i]->payload, reclaim_archive_secret->key,
	       SHA256_DIGEST_SIZE);
	for (j = 0; j < RECLAIM_ARCHIVE_ANCHORS; j++)
		if (!memcmp(entries[j]->payload + 64,
			    reclaim_archive_secret->key, SHA256_DIGEST_SIZE))
			entries[j]->payload[64] ^= 1;
	return ctx;

fail:
	reclaim_archive_ctx_destroy(ctx);
	return NULL;
}

static void __maybe_unused reclaim_archive_entry_put(
	struct reclaim_archive_entry *entry)
{
	struct reclaim_archive_ctx *ctx;

	if (!entry || !refcount_dec_and_test(&entry->refs))
		return;
	ctx = entry->ctx;
	mutex_lock(&ctx->lock);
	if (ctx->cursor == entry) {
		ctx->cursor = NULL;
		ctx->cursor_final_released = true;
	}
	if (entry->indexed) {
		rb_erase(&entry->node, &ctx->index);
		entry->indexed = 0;
	}
	mutex_unlock(&ctx->lock);
	if (entry->owner_cred)
		put_cred(entry->owner_cred);
	kfree(entry);
	reclaim_archive_ctx_put(ctx);
}

static void __maybe_unused reclaim_archive_frame_put(
	struct reclaim_archive_frame *frame)
{
	struct reclaim_archive_ctx *ctx;

	if (!frame || !refcount_dec_and_test(&frame->refs))
		return;
	ctx = frame->ctx;
	atomic_dec(&ctx->active_frames);
	kfree(frame);
	reclaim_archive_ctx_put(ctx);
}

static u64 reclaim_archive_new_fingerprint_locked(void)
{
	u64 fingerprint;
	u32 i;

	do {
		fingerprint = get_random_u64();
		if (!fingerprint)
			continue;
		for (i = 0; i < reclaim_global.count; i++)
			if (reclaim_global.slots[i].fingerprint == fingerprint)
				break;
	} while (!fingerprint || i != reclaim_global.count);
	return fingerprint;
}

static void reclaim_archive_reset_round_locked(struct reclaim_archive_ctx *ctx)
{
	ctx->round_active = false;
	ctx->cursor_final_released = false;
	ctx->order_generation = 0;
	ctx->order_locator = 0;
	ctx->order_selector = 0;
	ctx->lease_generation = 0;
	ctx->lease_locator = 0;
	ctx->lease_selector = 0;
}

static bool reclaim_archive_round_idle_locked(struct reclaim_archive_ctx *ctx)
{
	return ctx->round_active && !ctx->cursor &&
	       !atomic_read(&ctx->active_frames) &&
	       !atomic_read(&ctx->active_receipts);
}

static int reclaim_archive_bookmark(struct reclaim_archive_ctx *ctx,
				    struct reclaim_archive_bookmark *request)
{
	struct reclaim_archive_description description;
	struct reclaim_archive_entry *entry;
	struct reclaim_ledger_slot *slot;
	int ret = 0;

	if (!request->marker)
		return -EINVAL;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL_ACCOUNT);
	if (!entry)
		return -ENOMEM;
	refcount_set(&entry->refs, 1);
	INIT_LIST_HEAD(&entry->anchor_link);
	entry->owner_cred = get_current_cred();
	entry->ctx = ctx;
	entry->nonce = request->marker;
	reclaim_archive_ctx_get(ctx);

	mutex_lock(&ctx->lock);
	if (reclaim_archive_round_idle_locked(ctx))
		reclaim_archive_reset_round_locked(ctx);
	if (ctx->closing || ctx->round_active || ctx->cursor ||
	    atomic_read(&ctx->active_frames) ||
	    atomic_read(&ctx->active_receipts)) {
		ret = -EBUSY;
		goto out_ctx;
	}
	mutex_lock(&reclaim_global.lock);
	if (!reclaim_global.synced) {
		ret = -ESTALE;
		goto out_global;
	}
	if (reclaim_global.count >= RECLAIM_MAX_LEDGER_RECORDS) {
		ret = -ENOSPC;
		goto out_global;
	}
	slot = &reclaim_global.slots[reclaim_global.count++];
	memset(slot, 0, sizeof(*slot));
	slot->token = reclaim_new_token_locked();
	slot->fingerprint = reclaim_archive_new_fingerprint_locked();
	slot->generation = reclaim_global.generation;
	slot->ordinal = ctx->next_cursor++;
	slot->kind = RECLAIM_BACKEND_ARCHIVE_CURSOR;
	slot->live = 1;
	slot->opaque = entry;
	description.generation = slot->generation;
	description.locator = request->marker;
	memcpy(entry->payload, &description, sizeof(description));
	request->token = slot->token;
	ctx->cursor = entry;
	ctx->round_active = true;
	ctx->cursor_final_released = false;
	entry = NULL;
out_global:
	mutex_unlock(&reclaim_global.lock);
out_ctx:
	mutex_unlock(&ctx->lock);
	if (entry) {
		put_cred(entry->owner_cred);
		kfree(entry);
		reclaim_archive_ctx_put(ctx);
	}
	return ret;
}

static int reclaim_resource_get(struct reclaim_resource *resource)
{
	switch (resource->kind) {
#if RECLAIM_ROUTE_KEY
	case RECLAIM_BACKEND_STATEMENT:
		key_get(resource->object);
		return 0;
#endif
	case RECLAIM_BACKEND_MEMO:
		return refcount_inc_not_zero(
			&((struct reclaim_memo *)resource->object)->refs) ? 0 : -ENOENT;
	case RECLAIM_BACKEND_NOTICE:
		return refcount_inc_not_zero(
			&((struct reclaim_notice *)resource->object)->refs) ? 0 : -ENOENT;
	#if RECLAIM_ROUTE_ARCHIVE
	case RECLAIM_BACKEND_ARCHIVE_CURSOR:
		return refcount_inc_not_zero(
			&((struct reclaim_archive_entry *)resource->object)->refs) ?
			0 : -ENOENT;
	case RECLAIM_BACKEND_ARCHIVE_FRAME:
		return refcount_inc_not_zero(
			&((struct reclaim_archive_frame *)resource->object)->refs) ?
			0 : -ENOENT;
	#endif
	default:
		return -EOPNOTSUPP;
	}
}

static void reclaim_resource_put(struct reclaim_resource *resource)
{
	switch (resource->kind) {
#if RECLAIM_ROUTE_KEY
	case RECLAIM_BACKEND_STATEMENT:
		key_put(resource->object);
		break;
#endif
	case RECLAIM_BACKEND_MEMO:
		reclaim_memo_put(resource->object);
		break;
	case RECLAIM_BACKEND_NOTICE:
		reclaim_notice_put(resource->object);
		break;
	#if RECLAIM_ROUTE_ARCHIVE
	case RECLAIM_BACKEND_ARCHIVE_CURSOR:
		reclaim_archive_entry_put(resource->object);
		break;
	case RECLAIM_BACKEND_ARCHIVE_FRAME:
		reclaim_archive_frame_put(resource->object);
		break;
	#endif
	default:
		break;
	}
}

static int reclaim_acquire_token(u64 token, struct reclaim_resource *resource)
{
	struct reclaim_ledger_slot *slot;
	int ret = 0;

	memset(resource, 0, sizeof(*resource));
	mutex_lock(&reclaim_global.lock);
	slot = reclaim_find_slot_locked(token);
	if (!slot) {
		ret = -ENOENT;
		goto out;
	}
	resource->kind = slot->kind;
	resource->group = slot->group;
	switch (slot->kind) {
#if RECLAIM_ROUTE_KEY
	case RECLAIM_BACKEND_STATEMENT:
		resource->object = key_lookup(slot->key_serial);
		if (IS_ERR(resource->object)) {
			ret = PTR_ERR(resource->object);
			resource->object = NULL;
		}
		break;
#endif
	case RECLAIM_BACKEND_MEMO:
		resource->object = slot->memo;
		if (!refcount_inc_not_zero(&slot->memo->refs))
			ret = -ENOENT;
		break;
	case RECLAIM_BACKEND_NOTICE:
		resource->object = slot->notice;
		if (!refcount_inc_not_zero(&slot->notice->refs))
			ret = -ENOENT;
		break;
	#if RECLAIM_ROUTE_ARCHIVE
	case RECLAIM_BACKEND_ARCHIVE_CURSOR:
		resource->object = slot->opaque;
		if (!refcount_inc_not_zero(
			&((struct reclaim_archive_entry *)slot->opaque)->refs))
			ret = -ENOENT;
		break;
	case RECLAIM_BACKEND_ARCHIVE_FRAME:
		resource->object = slot->opaque;
		if (!refcount_inc_not_zero(
			&((struct reclaim_archive_frame *)slot->opaque)->refs))
			ret = -ENOENT;
		break;
	#endif
	default:
		ret = -EOPNOTSUPP;
		break;
	}
out:
	mutex_unlock(&reclaim_global.lock);
	if (ret)
		memset(resource, 0, sizeof(*resource));
	return ret;
}

/*
 * A storage group is a single normal retention unit.  Only the first fan-out
 * accounting dispute in that unit is left unresolved; later deficits are
 * balanced before their receipts become visible.  This keeps independent
 * cases useful while preventing one physical key slab from being converted
 * into a bank of append-only one-shot stale readers.
 */
#if RECLAIM_GROUP_DEFICIT_CAP
static bool reclaim_claim_statement_deficit(u32 group)
{
	bool claimed = false;
	u32 i;

	if (!group)
		return false;
	mutex_lock(&reclaim_global.lock);
	for (i = 0; i < reclaim_global.count; i++) {
		struct reclaim_ledger_slot *slot = &reclaim_global.slots[i];

		if (slot->kind == RECLAIM_BACKEND_STATEMENT &&
		    slot->group == group && slot->deficit_claimed) {
			claimed = true;
			break;
		}
	}
	if (!claimed)
		for (i = 0; i < reclaim_global.count; i++) {
			struct reclaim_ledger_slot *slot =
				&reclaim_global.slots[i];

			if (slot->kind == RECLAIM_BACKEND_STATEMENT &&
			    slot->group == group)
				slot->deficit_claimed = 1;
		}
	mutex_unlock(&reclaim_global.lock);
	return !claimed;
}
#endif

static u64 reclaim_policy_digest(const struct reclaim_reviewer_node *reviewer)
{
	u64 state = reviewer->seed ^ 0x6a09e667f3bcc909ULL;
	u32 round;
	size_t i;

	for (round = 0; round < reviewer->rounds; round++)
		for (i = 0; i < reviewer->size; i++) {
			state ^= (u64)reviewer->policy[i] << (i & 56);
			state += 0xbb67ae8584caa73bULL + round + i;
			state = rol64(state, 29) * 0xbf58476d1ce4e5b9ULL;
		}
	return state;
}

static int reclaim_resource_view(struct reclaim_resource *resource,
				 void *buffer, size_t capacity)
{
	switch (resource->kind) {
#if RECLAIM_ROUTE_KEY
	case RECLAIM_BACKEND_STATEMENT: {
		struct key *key = resource->object;
		long result;

		down_read(&key->sem);
		if (!key->type || !key->type->read)
			result = -EOPNOTSUPP;
		else
			result = key->type->read(key, buffer, capacity);
		up_read(&key->sem);
		return result;
	}
#endif
	case RECLAIM_BACKEND_MEMO: {
		struct reclaim_memo *memo = resource->object;
		u32 length = READ_ONCE(memo->length);

		if (length > sizeof(memo->data))
			return -EPROTO;
		if (capacity >= length)
			memcpy(buffer, memo->data, length);
		return length;
	}
	case RECLAIM_BACKEND_NOTICE: {
		struct reclaim_notice *notice = resource->object;
		struct reclaim_notice_view view = {
			.sequence = atomic64_read(&notice->sequence),
			.token_digest = READ_ONCE(notice->token_digest),
		};

		if (capacity >= sizeof(view))
			memcpy(buffer, &view, sizeof(view));
		return sizeof(view);
	}
	#if RECLAIM_ROUTE_ARCHIVE
	case RECLAIM_BACKEND_ARCHIVE_CURSOR: {
		struct reclaim_archive_entry *entry = resource->object;
		struct reclaim_archive_description description;

		memcpy(&description, entry->payload, sizeof(description));
		if (capacity >= sizeof(description))
			memcpy(buffer, &description, sizeof(description));
		return sizeof(description);
	}
	case RECLAIM_BACKEND_ARCHIVE_FRAME: {
		struct reclaim_archive_frame *frame = resource->object;
		struct reclaim_archive_description description = {
			.generation = READ_ONCE(frame->generation),
			.locator = 0,
		};

		if (capacity >= sizeof(description))
			memcpy(buffer, &description, sizeof(description));
		return sizeof(description);
	}
	#endif
	default:
		return -EOPNOTSUPP;
	}
}

static int reclaim_archive_validate_xattr(struct simple_xattr *xattr)
{
	char name[64];
	char *kernel_name;

	if (READ_ONCE(xattr->size) != RECLAIM_ARCHIVE_XATTR_VALUE)
		return -EPROTOTYPE;
	kernel_name = READ_ONCE(xattr->name);
	if (!kernel_name || copy_from_kernel_nofault(name, kernel_name,
						 sizeof(name)))
		return -EPROTOTYPE;
	if (memcmp(name, "user.", 5) || !memchr(name, '\0', sizeof(name)))
		return -EPROTOTYPE;
	return 0;
}

static int __maybe_unused reclaim_archive_apply(struct reclaim_receipt *receipt)
{
	struct reclaim_archive_entry *stale = receipt->resource.object;
	struct reclaim_archive_ctx *ctx = receipt->archive_ctx;
	struct reclaim_archive_description description;
	struct reclaim_archive_entry *target, *parent;
	struct rb_node *forged = &stale->node;
	unsigned long target_color;
	int ret;

	ret = reclaim_archive_validate_xattr((struct simple_xattr *)stale);
	if (ret)
		return ret;
	memcpy(&description, stale->payload, sizeof(description));
	mutex_lock(&ctx->lock);
	if (!ctx->round_active || !ctx->cursor_final_released) {
		ret = -ESTALE;
		goto out;
	}
	if (!ctx->order_generation ||
	    description.generation != ctx->order_generation ||
	    description.locator != ctx->order_locator) {
		ret = -EKEYREJECTED;
		goto out;
	}
	target = reclaim_archive_by_selector_locked(ctx, ctx->order_selector);
	parent = reclaim_archive_by_locator_locked(ctx, ctx->order_locator);
	if (!target || !parent || !target->indexed ||
	    parent->node.rb_right != &target->node ||
	    rb_parent(&target->node) != &parent->node ||
	    target->node.rb_left || target->node.rb_right) {
		ret = -EPERM;
		goto out;
	}
	if (forged->rb_left || forged->rb_right) {
		ret = -EINVAL;
		goto out;
	}
	target_color = target->node.__rb_parent_color & 3UL;
	forged->__rb_parent_color = (unsigned long)&parent->node |
		target_color;
	rb_erase(forged, &ctx->index);
	target->indexed = 0;
	ret = 0;
out:
	mutex_unlock(&ctx->lock);
	return ret;
}

static int __maybe_unused reclaim_archive_reconcile(
	struct reclaim_receipt *receipt)
{
	struct reclaim_inotify_overlay *event = receipt->resource.object;
	struct reclaim_archive_ctx *ctx = receipt->archive_ctx;
	struct reclaim_archive_event_descriptor descriptor;
	struct reclaim_archive_entry *target;
	u32 bit;
	int ret = 0;

	if (READ_ONCE(event->name_len) != RECLAIM_ARCHIVE_NOTIFY_NAME ||
	    !(READ_ONCE(event->mask) & IN_ATTRIB) || READ_ONCE(event->wd) < 0)
		return -EPROTOTYPE;
	if (reclaim_archive_parse_event(event->name, &descriptor))
		return -EBADMSG;
	if (descriptor.tag != RECLAIM_ARCHIVE_EVENT_TAG ||
	    descriptor.checksum != reclaim_archive_event_checksum(&descriptor))
		return -EBADMSG;

	mutex_lock(&ctx->lock);
	if (!ctx->round_active || !ctx->cursor_final_released) {
		ret = -ESTALE;
		goto out;
	}
	if (!ctx->lease_generation ||
	    descriptor.generation != ctx->lease_generation ||
	    descriptor.locator != 0) {
		ret = -EKEYREJECTED;
		goto out;
	}
	target = reclaim_archive_by_selector_locked(ctx, ctx->lease_selector);
	if (!target || target->nonce != ctx->lease_locator) {
		ret = -EPERM;
		goto out;
	}
	bit = BIT(target->ordinal);
	if (ctx->lease_removed_mask & bit) {
		ret = -EALREADY;
		goto out;
	}
	ctx->lease_removed_mask |= bit;
out:
	mutex_unlock(&ctx->lock);
	return ret;
}

static u32 reclaim_archive_frame_selector(
	const struct reclaim_archive_frame *frame)
{
	u32 selector;

	memcpy(&selector, frame->prefix, sizeof(selector));
	return selector;
}

static int __maybe_unused reclaim_archive_frame_apply(
	struct reclaim_archive_frame *frame)
{
	struct reclaim_archive_ctx *ctx = frame->ctx;
	struct reclaim_archive_entry *target;
	u32 selector, bit;
	int ret = 0;

	if (READ_ONCE(frame->domain) != 3)
		return -EOPNOTSUPP;
	selector = reclaim_archive_frame_selector(frame);
	mutex_lock(&ctx->lock);
	target = reclaim_archive_by_selector_locked(ctx, selector);
	if (!target) {
		ret = -ENOENT;
		goto out;
	}
	bit = BIT(target->ordinal);
	if (ctx->audit_materialized_mask & bit)
		ret = -EALREADY;
	else
		ctx->audit_materialized_mask |= bit;
out:
	mutex_unlock(&ctx->lock);
	return ret;
}

static int __maybe_unused reclaim_archive_frame_reconcile(
	struct reclaim_archive_frame *frame)
{
	struct reclaim_archive_ctx *ctx = frame->ctx;
	struct reclaim_archive_entry *target;
	u32 selector, bit;
	int ret = 0;

	if (READ_ONCE(frame->domain) != 4)
		return -EOPNOTSUPP;
	selector = reclaim_archive_frame_selector(frame);
	mutex_lock(&ctx->lock);
	target = reclaim_archive_by_selector_locked(ctx, selector);
	if (!target) {
		ret = -ENOENT;
		goto out;
	}
	bit = BIT(target->ordinal);
	if (ctx->retention_materialized_mask & bit)
		ret = -EALREADY;
	else
		ctx->retention_materialized_mask |= bit;
out:
	mutex_unlock(&ctx->lock);
	return ret;
}

static int reclaim_resource_apply(struct reclaim_receipt *receipt)
{
	struct reclaim_resource *resource = &receipt->resource;

	switch (resource->kind) {
#if RECLAIM_ROUTE_KEY
	case RECLAIM_BACKEND_STATEMENT: {
		struct key *key = resource->object;

		if (!key->type || !key->type->revoke)
			return -EOPNOTSUPP;
		key->type->revoke(key);
		return 0;
	}
#endif
	case RECLAIM_BACKEND_NOTICE:
		atomic64_inc(&((struct reclaim_notice *)resource->object)->sequence);
		return 0;
	case RECLAIM_BACKEND_MEMO:
		return -EOPNOTSUPP;
	#if RECLAIM_ROUTE_ARCHIVE
	case RECLAIM_BACKEND_ARCHIVE_CURSOR:
		return reclaim_archive_apply(receipt);
	case RECLAIM_BACKEND_ARCHIVE_FRAME:
		return reclaim_archive_frame_apply(resource->object);
	#endif
	default:
		return -EOPNOTSUPP;
	}
}

static int reclaim_resource_reconcile(struct reclaim_receipt *receipt)
{
#if RECLAIM_ROUTE_ARCHIVE
	if (receipt->resource.kind == RECLAIM_BACKEND_ARCHIVE_CURSOR)
		return reclaim_archive_reconcile(receipt);
	if (receipt->resource.kind == RECLAIM_BACKEND_ARCHIVE_FRAME)
		return reclaim_archive_frame_reconcile(receipt->resource.object);
	return -EOPNOTSUPP;
#else
	(void)receipt;
	return -EOPNOTSUPP;
#endif
}

static long reclaim_receipt_ioctl(struct file *file, unsigned int command,
				  unsigned long arg)
{
	struct reclaim_receipt *receipt = file->private_data;
	void __user *user = (void __user *)arg;

	if (!receipt || !receipt->resource.object)
		return -ENOENT;
	switch (command) {
	case RECLAIM_RECEIPT_IOC_DISARM:
		receipt->armed = false;
		return 0;
	case RECLAIM_RECEIPT_IOC_VIEW: {
		struct reclaim_view request;
		void *buffer = NULL;
		int result;

		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		if (request.capacity > PAGE_SIZE)
			return -E2BIG;
		if (request.capacity) {
			buffer = kzalloc(request.capacity, GFP_KERNEL);
			if (!buffer)
				return -ENOMEM;
		}
		result = reclaim_resource_view(&receipt->resource, buffer,
					       request.capacity);
		if (result >= 0 && buffer && request.capacity &&
		    copy_to_user(u64_to_user_ptr(request.buffer), buffer,
				 min_t(size_t, request.capacity, result))) {
			kfree_sensitive(buffer);
			return -EFAULT;
		}
		kfree_sensitive(buffer);
		request.result = result;
		return copy_to_user(user, &request, sizeof(request)) ?
			-EFAULT : 0;
	}
	case RECLAIM_RECEIPT_IOC_APPLY:
		return reclaim_resource_apply(receipt);
	case RECLAIM_RECEIPT_IOC_RECONCILE:
		return reclaim_resource_reconcile(receipt);
	default:
		return -ENOTTY;
	}
}

static int reclaim_receipt_release(struct inode *inode, struct file *file)
{
	struct reclaim_receipt *receipt = file->private_data;

	(void)inode;
	if (receipt) {
		if (receipt->armed)
			reclaim_resource_put(&receipt->resource);
		#if RECLAIM_ROUTE_ARCHIVE
		if (receipt->archive_ctx) {
			atomic_dec(&receipt->archive_ctx->active_receipts);
			reclaim_archive_ctx_put(receipt->archive_ctx);
		}
		#endif
		kfree(receipt);
	}
	return 0;
}

static const struct file_operations reclaim_receipt_fops = {
	.owner = THIS_MODULE,
	.release = reclaim_receipt_release,
	.unlocked_ioctl = reclaim_receipt_ioctl,
	.compat_ioctl = reclaim_receipt_ioctl,
	.llseek = noop_llseek,
};

static int reclaim_create_receipt(const struct reclaim_resource *resource)
{
	struct reclaim_receipt *receipt;
	int fd;

	receipt = kzalloc(sizeof(*receipt), GFP_KERNEL);
	if (!receipt)
		return -ENOMEM;
	receipt->resource = *resource;
	#if RECLAIM_ROUTE_ARCHIVE
	if (resource->kind == RECLAIM_BACKEND_ARCHIVE_CURSOR ||
	    resource->kind == RECLAIM_BACKEND_ARCHIVE_FRAME) {
		receipt->archive_ctx = resource->kind ==
			RECLAIM_BACKEND_ARCHIVE_CURSOR ?
			((struct reclaim_archive_entry *)resource->object)->ctx :
			((struct reclaim_archive_frame *)resource->object)->ctx;
		reclaim_archive_ctx_get(receipt->archive_ctx);
		atomic_inc(&receipt->archive_ctx->active_receipts);
	}
	#endif
	receipt->armed = true;
	fd = anon_inode_getfd("[reclaim-receipt]", &reclaim_receipt_fops,
			      receipt, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (receipt->archive_ctx) {
			atomic_dec(&receipt->archive_ctx->active_receipts);
			reclaim_archive_ctx_put(receipt->archive_ctx);
		}
		kfree(receipt);
	}
	return fd;
}

static int reclaim_case_add_reviewer(struct reclaim_case_ctx *ctx,
				     struct reclaim_reviewer *request)
{
	struct reclaim_reviewer_node *reviewer;
	size_t i;
	int ret = 0;

	if (!request->policy_size ||
	    request->policy_size > RECLAIM_MAX_POLICY_SIZE ||
	    !request->policy_rounds || request->policy_rounds > 8 ||
	    request->reserved)
		return -EINVAL;
	reviewer = kzalloc(sizeof(*reviewer), GFP_KERNEL);
	if (!reviewer)
		return -ENOMEM;
	reviewer->policy = vmalloc(request->policy_size);
	if (!reviewer->policy) {
		kfree(reviewer);
		return -ENOMEM;
	}
	reviewer->size = request->policy_size;
	reviewer->rounds = request->policy_rounds;
	reviewer->seed = request->seed;
	for (i = 0; i < reviewer->size; i++)
		reviewer->policy[i] = reviewer->seed + i * 181U + (i >> 8);

	mutex_lock(&ctx->lock);
	if (ctx->reviewer_count >= RECLAIM_MAX_REVIEWERS || ctx->dispatched) {
		ret = -ENOSPC;
	} else {
		reviewer->id = ctx->next_reviewer_id++;
		list_add_tail_rcu(&reviewer->link, &ctx->reviewers);
		ctx->reviewer_count++;
		request->reviewer_id = reviewer->id;
		reviewer = NULL;
	}
	mutex_unlock(&ctx->lock);
	if (reviewer) {
		vfree(reviewer->policy);
		kfree(reviewer);
	}
	return ret;
}

static int reclaim_case_attach(struct reclaim_case_ctx *ctx, u64 token)
{
	struct reclaim_resource resource;
	int ret;

	ret = reclaim_acquire_token(token, &resource);
	if (ret)
		return ret;
	mutex_lock(&ctx->lock);
	if (ctx->resource.object || ctx->dispatched || !ctx->reviewer_count) {
		ret = -EBUSY;
	} else {
		ctx->resource = resource;
		memset(&resource, 0, sizeof(resource));
	}
	mutex_unlock(&ctx->lock);
	if (resource.object)
		reclaim_resource_put(&resource);
	return ret;
}

static int reclaim_case_publish(struct reclaim_case_ctx *ctx,
				struct reclaim_publish *request)
{
	struct reclaim_reviewer_node *reviewer;
	struct reclaim_resource resource;
	int fds[RECLAIM_MAX_RECEIPTS];
	u32 count = 0;
	u32 extra_refs = 0;
	u64 digest = 0;
	int srcu_index, fd, ret = 0;

	if (!request->receipt_fds || !request->capacity ||
	    request->capacity > RECLAIM_MAX_RECEIPTS)
		return -EINVAL;
	mutex_lock(&ctx->lock);
	if (!ctx->resource.object || ctx->dispatching || ctx->dispatched) {
		ret = -EBUSY;
		goto out_unlock;
	}
	ctx->dispatching = true;
	resource = ctx->resource;
	mutex_unlock(&ctx->lock);

	srcu_index = srcu_read_lock(&ctx->readers);
	list_for_each_entry_rcu(reviewer, &ctx->reviewers, link,
				srcu_read_lock_held(&ctx->readers)) {
		bool last = list_is_last(&reviewer->link, &ctx->reviewers);
		u64 reviewer_digest;

		if (count >= request->capacity) {
			ret = -ENOSPC;
			break;
		}
		if (!last) {
			ret = reclaim_resource_get(&resource);
			if (ret)
				break;
			extra_refs++;
		}
		reviewer_digest = reclaim_policy_digest(reviewer);
		digest ^= rol64(reviewer_digest, reviewer->id & 63);
		fd = reclaim_create_receipt(&resource);
		if (fd < 0) {
			if (!last)
				reclaim_resource_put(&resource);
			ret = fd;
			break;
		}
		fds[count++] = fd;
	}
	srcu_read_unlock(&ctx->readers, srcu_index);
	if (!ret && count > extra_refs + 1) {
		bool balance = false;
		u32 missing = count - (extra_refs + 1);

		/*
		 * Snapshot frames are ordinary immutable fan-out records.  They do
		 * not participate in the mutable-reviewer ownership dispute: leaving
		 * their close path under-accounted would create a second 216-byte
		 * type-confusion root that bypasses the cursor provenance consumers.
		 */
		#if RECLAIM_ROUTE_ARCHIVE
		if (resource.kind == RECLAIM_BACKEND_ARCHIVE_FRAME)
			balance = true;
		#endif
		#if RECLAIM_GROUP_DEFICIT_CAP
		if (resource.kind == RECLAIM_BACKEND_STATEMENT &&
		    !reclaim_claim_statement_deficit(resource.group))
			balance = true;
		#endif
		if (balance)
			while (missing--) {
				ret = reclaim_resource_get(&resource);
				if (ret)
					break;
			}
	}

	mutex_lock(&ctx->lock);
	ctx->dispatching = false;
	ctx->dispatched = true;
	memset(&ctx->resource, 0, sizeof(ctx->resource));
	mutex_unlock(&ctx->lock);
	if (ret)
		goto out_close;
	if (copy_to_user(u64_to_user_ptr(request->receipt_fds), fds,
			 count * sizeof(fds[0]))) {
		ret = -EFAULT;
		goto out_close;
	}
	request->count = count;
	request->digest = digest;
	return 0;

out_close:
	while (count--)
		close_fd(fds[count]);
	return ret;
out_unlock:
	mutex_unlock(&ctx->lock);
	return ret;
}

static long reclaim_case_ioctl(struct file *file, unsigned int command,
			       unsigned long arg)
{
	struct reclaim_case_ctx *ctx = file->private_data;
	void __user *user = (void __user *)arg;

	switch (command) {
	case RECLAIM_CASE_IOC_ADD_REVIEWER: {
		struct reclaim_reviewer request;
		int ret;

		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		ret = reclaim_case_add_reviewer(ctx, &request);
		if (ret)
			return ret;
		return copy_to_user(user, &request, sizeof(request)) ?
			-EFAULT : 0;
	}
	case RECLAIM_CASE_IOC_ATTACH: {
		struct reclaim_attach request;

		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		return reclaim_case_attach(ctx, request.token);
	}
	case RECLAIM_CASE_IOC_PUBLISH: {
		struct reclaim_publish request;
		int ret;

		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		ret = reclaim_case_publish(ctx, &request);
		if (ret)
			return ret;
		return copy_to_user(user, &request, sizeof(request)) ?
			-EFAULT : 0;
	}
	default:
		return -ENOTTY;
	}
}

static int reclaim_case_open(struct inode *inode, struct file *file)
{
	struct reclaim_case_ctx *ctx;

	(void)inode;
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	mutex_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->reviewers);
	ctx->next_reviewer_id = 1;
	if (init_srcu_struct(&ctx->readers)) {
		kfree(ctx);
		return -ENOMEM;
	}
	file->private_data = ctx;
	return 0;
}

static int reclaim_case_release(struct inode *inode, struct file *file)
{
	struct reclaim_case_ctx *ctx = file->private_data;
	struct reclaim_reviewer_node *reviewer, *next;
	struct reclaim_resource resource;

	(void)inode;
	if (!ctx)
		return 0;
	mutex_lock(&ctx->lock);
	if (ctx->dispatching) {
		mutex_unlock(&ctx->lock);
		return -EBUSY;
	}
	resource = ctx->resource;
	memset(&ctx->resource, 0, sizeof(ctx->resource));
	mutex_unlock(&ctx->lock);
	if (resource.object)
		reclaim_resource_put(&resource);
	synchronize_srcu(&ctx->readers);
	list_for_each_entry_safe(reviewer, next, &ctx->reviewers, link) {
		list_del(&reviewer->link);
		vfree(reviewer->policy);
		kfree(reviewer);
	}
	cleanup_srcu_struct(&ctx->readers);
	kfree(ctx);
	return 0;
}

static const struct file_operations reclaim_case_fops = {
	.owner = THIS_MODULE,
	.open = reclaim_case_open,
	.release = reclaim_case_release,
	.unlocked_ioctl = reclaim_case_ioctl,
	.compat_ioctl = reclaim_case_ioctl,
	.llseek = noop_llseek,
};

static int reclaim_withdraw_token(u64 token)
{
	struct reclaim_ledger_slot *slot;
	struct reclaim_resource resource = { };
	#if RECLAIM_ROUTE_KEY
	struct key *statement = NULL;
	#endif
	int ret = 0;

	mutex_lock(&reclaim_global.lock);
	slot = reclaim_find_slot_locked(token);
	if (!slot) {
		ret = -ENOENT;
		goto out;
	}
	#if RECLAIM_ROUTE_KEY
	if (slot->kind == RECLAIM_BACKEND_STATEMENT) {
		statement = key_lookup(slot->key_serial);
		if (IS_ERR(statement)) {
			ret = PTR_ERR(statement);
			statement = NULL;
			goto out;
		}
		slot->live = 0;
		goto out;
	}
	#endif
	resource.kind = slot->kind;
	resource.group = slot->group;
	resource.object = slot->opaque;
	slot->live = 0;
	slot->opaque = NULL;
out:
	mutex_unlock(&reclaim_global.lock);
	#if RECLAIM_ROUTE_KEY
	if (!ret && statement) {
		ret = key_unlink(reclaim_global.statement_keyring, statement);
		key_put(statement);
		return ret;
	}
	#endif
	if (!ret)
		reclaim_resource_put(&resource);
	return ret;
}

#define RECLAIM_ARCHIVE_SNAPSHOT_FRAMES 4U

static int reclaim_archive_snapshot(struct reclaim_archive_ctx *ctx,
				    struct reclaim_archive_snapshot *request)
{
	struct reclaim_archive_frame *frames[RECLAIM_ARCHIVE_SNAPSHOT_FRAMES] = { };
	struct reclaim_archive_entry *target, *parent;
	u32 domains[RECLAIM_ARCHIVE_SNAPSHOT_FRAMES] = { 1, 2, 3, 4 };
	u64 generations[RECLAIM_ARCHIVE_SNAPSHOT_FRAMES];
	u32 i, j;
	int ret = 0;

	if (request->reserved || !request->fingerprint || !request->revision)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(frames); i++) {
		frames[i] = kzalloc(sizeof(*frames[i]), GFP_KERNEL_ACCOUNT);
		if (!frames[i]) {
			ret = -ENOMEM;
			goto out_free;
		}
		refcount_set(&frames[i]->refs, 1);
		frames[i]->ctx = ctx;
		get_random_bytes(frames[i]->prefix, sizeof(frames[i]->prefix));
		get_random_bytes(frames[i]->tail, sizeof(frames[i]->tail));
		reclaim_archive_ctx_get(ctx);
	}
	for (i = ARRAY_SIZE(domains); i > 1; i--) {
		u32 other = get_random_u32() % i;

		swap(domains[i - 1], domains[other]);
	}

	mutex_lock(&ctx->lock);
	if (ctx->closing || !ctx->round_active || ctx->order_generation ||
	    ctx->lease_generation || atomic_read(&ctx->active_frames)) {
		ret = -EBUSY;
		goto out_ctx;
	}
	target = reclaim_archive_by_fingerprint_locked(ctx,
						       request->fingerprint);
	if (!target) {
		ret = -ENOENT;
		goto out_ctx;
	}
	parent = reclaim_archive_order_candidate_locked(ctx, target) ?
		reclaim_archive_parent_locked(ctx, target) : NULL;

	mutex_lock(&reclaim_global.lock);
	if (!reclaim_global.synced) {
		ret = -ESTALE;
		goto out_global;
	}
	if (reclaim_global.count + ARRAY_SIZE(frames) >
	    RECLAIM_MAX_LEDGER_RECORDS) {
		ret = -ENOSPC;
		goto out_global;
	}
	for (i = 0; i < ARRAY_SIZE(frames); i++) {
		generations[i] = request->revision ^
			(0x9e3779b97f4a7c15ULL * i);
		if (!generations[i])
			generations[i] = request->revision ^
				(0xd6e8feb86659fd93ULL + i);
		for (j = 0; j < i; j++)
			if (generations[j] == generations[i])
				break;
		if (!generations[i] || j != i) {
			ret = -EINVAL;
			goto out_global;
		}
	}
	for (i = 0; i < ARRAY_SIZE(frames); i++) {
		struct reclaim_archive_frame *frame = frames[i];
		struct reclaim_ledger_slot *slot;
		u64 locator;

		frame->domain = domains[i];
		frame->generation = generations[i];
		memcpy(frame->prefix, &target->selector,
		       sizeof(target->selector));
		if (frame->domain == 1) {
			do {
				locator = parent ? parent->nonce : get_random_u64();
			} while (!locator);
			ctx->order_generation = frame->generation;
			ctx->order_locator = locator;
			ctx->order_selector = target->selector;
		} else if (frame->domain == 2) {
			locator = target->nonce;
			ctx->lease_generation = frame->generation;
			ctx->lease_locator = locator;
			ctx->lease_selector = target->selector;
		} else {
			do {
				locator = get_random_u64();
			} while (!locator);
		}
		frame->locator = locator;
		frame->fingerprint = reclaim_archive_new_fingerprint_locked();
		slot = &reclaim_global.slots[reclaim_global.count++];
		memset(slot, 0, sizeof(*slot));
		slot->token = reclaim_new_token_locked();
		slot->fingerprint = frame->fingerprint;
		slot->generation = reclaim_global.generation;
		slot->ordinal = ctx->next_cursor++;
		slot->kind = RECLAIM_BACKEND_ARCHIVE_FRAME;
		slot->live = 1;
		slot->opaque = frame;
		atomic_inc(&ctx->active_frames);
		frames[i] = NULL;
	}
	request->frame_count = RECLAIM_ARCHIVE_SNAPSHOT_FRAMES;
out_global:
	mutex_unlock(&reclaim_global.lock);
out_ctx:
	mutex_unlock(&ctx->lock);
out_free:
	for (i = 0; i < ARRAY_SIZE(frames); i++)
		if (frames[i]) {
			kfree(frames[i]);
			reclaim_archive_ctx_put(ctx);
		}
	return ret;
}

static ssize_t reclaim_archive_serialize(struct reclaim_archive_ctx *ctx,
					 char __user *buffer, size_t length)
{
	struct reclaim_archive_export_record records[RECLAIM_ARCHIVE_ANCHORS];
	struct reclaim_archive_entry *entry;
	u32 count = 0;
	size_t amount;

	if (!RECLAIM_ROUTE_ARCHIVE || !ctx)
		return -EOPNOTSUPP;
	amount = sizeof(records);
	if (length < amount)
		return -EMSGSIZE;
	memset(records, 0, sizeof(records));
	mutex_lock(&ctx->lock);
	list_for_each_entry(entry, &ctx->anchors, anchor_link) {
		struct reclaim_archive_export_record *record = &records[count++];
		u32 bit = BIT(entry->ordinal);

		record->fingerprint = reclaim_archive_fingerprint(entry);
		if (!reclaim_archive_reachable_locked(ctx, entry) &&
		    (ctx->lease_removed_mask & bit)) {
			record->length = sizeof(record->data);
			memcpy(record->data, entry->payload, sizeof(record->data));
		} else if ((ctx->audit_materialized_mask & bit) &&
			   (ctx->retention_materialized_mask & bit)) {
			record->length = sizeof(record->data);
			memcpy(record->data, entry->payload + 64,
			       sizeof(record->data));
		}
	}
	mutex_unlock(&ctx->lock);
	if (count != RECLAIM_ARCHIVE_ANCHORS)
		return -EIO;
	if (copy_to_user(buffer, records, amount))
		return -EFAULT;
	return amount;
}

static long reclaim_ledger_ioctl(struct file *file, unsigned int command,
				 unsigned long arg)
{
	void __user *user = (void __user *)arg;

	switch (command) {
	case RECLAIM_LEDGER_IOC_SYNC: {
		struct reclaim_generation request;
		int ret;

		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		ret = reclaim_sync_generation(&request);
		if (ret)
			return ret;
		return copy_to_user(user, &request, sizeof(request)) ?
			-EFAULT : 0;
	}
	case RECLAIM_LEDGER_IOC_READ: {
		struct reclaim_ledger_record request;
		struct reclaim_ledger_slot *slot;

		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		if (request.reserved)
			return -EINVAL;
		mutex_lock(&reclaim_global.lock);
		if (request.index >= reclaim_global.count) {
			mutex_unlock(&reclaim_global.lock);
			return -ERANGE;
		}
		slot = &reclaim_global.slots[request.index];
		request.token = slot->live ? slot->token : 0;
		request.fingerprint = slot->fingerprint;
		mutex_unlock(&reclaim_global.lock);
		return copy_to_user(user, &request, sizeof(request)) ?
			-EFAULT : 0;
	}
	case RECLAIM_LEDGER_IOC_APPEND_MEMO: {
		struct reclaim_memo_append request;
		int ret;

		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		if (request.reserved || request.length > sizeof(request.data))
			return -EINVAL;
		mutex_lock(&reclaim_global.lock);
		ret = reclaim_append_memo_locked(request.data, request.length,
						 &request.token);
		mutex_unlock(&reclaim_global.lock);
		if (ret)
			return ret;
		return copy_to_user(user, &request, sizeof(request)) ?
			-EFAULT : 0;
	}
	case RECLAIM_LEDGER_IOC_PULSE: {
		struct reclaim_notice_pulse request;
		struct reclaim_ledger_slot *slot;

		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		mutex_lock(&reclaim_global.lock);
		slot = reclaim_find_slot_locked(request.token);
		if (!slot || slot->kind != RECLAIM_BACKEND_NOTICE) {
			mutex_unlock(&reclaim_global.lock);
			return -ENOENT;
		}
		atomic64_add(request.amount, &slot->notice->sequence);
		mutex_unlock(&reclaim_global.lock);
		return 0;
	}
	case RECLAIM_LEDGER_IOC_WITHDRAW: {
		struct reclaim_token_request request;

		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		return reclaim_withdraw_token(request.token);
	}
	case RECLAIM_LEDGER_IOC_BOOKMARK: {
		struct reclaim_archive_bookmark request;
		int ret;

		if (!RECLAIM_ROUTE_ARCHIVE || !file->private_data)
			return -EOPNOTSUPP;
		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		ret = reclaim_archive_bookmark(file->private_data, &request);
		if (ret)
			return ret;
		return copy_to_user(user, &request, sizeof(request)) ?
			-EFAULT : 0;
	}
	case RECLAIM_LEDGER_IOC_SNAPSHOT: {
		struct reclaim_archive_snapshot request;
		int ret;

		if (!RECLAIM_ROUTE_ARCHIVE || !file->private_data)
			return -EOPNOTSUPP;
		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		ret = reclaim_archive_snapshot(file->private_data, &request);
		if (ret)
			return ret;
		return copy_to_user(user, &request, sizeof(request)) ?
			-EFAULT : 0;
	}
	default:
		return -ENOTTY;
	}
}

static ssize_t reclaim_ledger_read(struct file *file, char __user *buffer,
				   size_t length, loff_t *position)
{
	ssize_t result;

	if (*position)
		return 0;
	result = reclaim_archive_serialize(file->private_data, buffer, length);
	if (result > 0)
		*position += result;
	return result;
}

static loff_t reclaim_ledger_llseek(struct file *file, loff_t offset,
				    int whence)
{
	return fixed_size_llseek(file, offset, whence,
		RECLAIM_ARCHIVE_ANCHORS *
		sizeof(struct reclaim_archive_export_record));
}

static int reclaim_ledger_open(struct inode *inode, struct file *file)
{
	struct reclaim_archive_ctx *ctx;

	(void)inode;
	if (!RECLAIM_ROUTE_ARCHIVE) {
		file->private_data = NULL;
		return 0;
	}
	ctx = reclaim_archive_ctx_create();
	if (!ctx)
		return -ENOMEM;
	file->private_data = ctx;
	return 0;
}

static int reclaim_ledger_release(struct inode *inode, struct file *file)
{
	struct reclaim_archive_ctx *ctx = file->private_data;

	(void)inode;
	if (!ctx)
		return 0;
	mutex_lock(&ctx->lock);
	ctx->closing = true;
	mutex_unlock(&ctx->lock);
	file->private_data = NULL;
	#if RECLAIM_ROUTE_ARCHIVE
	reclaim_archive_ctx_put(ctx);
	#endif
	return 0;
}

static int reclaim_ledger_fsync(struct file *file, loff_t start, loff_t end,
				int datasync)
{
	(void)file;
	(void)start;
	(void)end;
	(void)datasync;
	return RECLAIM_ROUTE_KEY ? reclaim_key_checkpoint() : 0;
}

static const struct file_operations reclaim_ledger_fops = {
	.owner = THIS_MODULE,
	.open = reclaim_ledger_open,
	.release = reclaim_ledger_release,
	.read = reclaim_ledger_read,
	.unlocked_ioctl = reclaim_ledger_ioctl,
	.compat_ioctl = reclaim_ledger_ioctl,
	.fsync = reclaim_ledger_fsync,
	.llseek = reclaim_ledger_llseek,
};

static long reclaim_codec_ioctl(struct file *file, unsigned int command,
				unsigned long arg)
{
	struct reclaim_codec_record request;
	void __user *user = (void __user *)arg;

	(void)file;
	if (command != RECLAIM_CODEC_IOC_READ)
		return -ENOTTY;
	if (copy_from_user(&request, user, sizeof(request)))
		return -EFAULT;
	if (request.reserved)
		return -EINVAL;
	/* BUG: a byte capacity is confused with a record ordinal. */
	if (request.index >=
	    RECLAIM_CODEC_PUBLIC * sizeof(struct reclaim_codec_slot))
		return -ERANGE;
	if (request.index >= ARRAY_SIZE(reclaim_codecs))
		return -ERANGE;
	request.value = reclaim_codecs[request.index].codec;
	return copy_to_user(user, &request, sizeof(request)) ? -EFAULT : 0;
}

static const struct file_operations reclaim_codec_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = reclaim_codec_ioctl,
	.compat_ioctl = reclaim_codec_ioctl,
	.llseek = noop_llseek,
};

static ssize_t reclaim_evidence_read(struct file *file, char __user *buffer,
				     size_t length, loff_t *position)
{
	(void)file;
	if (!RECLAIM_ROUTE_ARCHIVE || !reclaim_archive_secret)
		return -ENOENT;
	return simple_read_from_buffer(buffer, length, position,
				       reclaim_archive_secret->key,
				       sizeof(reclaim_archive_secret->key));
}

static const struct file_operations reclaim_evidence_fops = {
	.owner = THIS_MODULE,
	.read = reclaim_evidence_read,
	.llseek = noop_llseek,
};

#if RECLAIM_ROUTE_WORK
static int reclaim_quarantine_mirror(struct page *page)
{
	int ret = 0;

	mutex_lock(&reclaim_mirror_lock);
	if (reclaim_mirror_count >= RECLAIM_MIRROR_QUARANTINE_MAX) {
		ret = -ENOSPC;
	} else {
		get_page(page);
		reclaim_mirror_quarantine[reclaim_mirror_count++] = page;
	}
	mutex_unlock(&reclaim_mirror_lock);
	return ret;
}

static int reclaim_work_create(struct reclaim_work_ctx *ctx,
			       struct reclaim_work_create *request)
{
	struct page *page;
	struct page *map_pages[1];
	void *mapping;
	gfp_t gfp;
	u32 index;
	int ret;

	if (request->reserved || request->length != PAGE_SIZE ||
	    !request->source)
		return -EINVAL;
	switch (request->mode) {
	case RECLAIM_WORK_SCRATCH:
		gfp = GFP_HIGHUSER_MOVABLE | __GFP_ZERO;
		break;
	case RECLAIM_WORK_MIRROR:
	case RECLAIM_WORK_SHARED:
		gfp = GFP_KERNEL | __GFP_ZERO;
		break;
	default:
		return -EINVAL;
	}
	mutex_lock(&ctx->lock);
	index = ctx->count;
	if (index >= RECLAIM_WORK_MAX) {
		mutex_unlock(&ctx->lock);
		return -ENOSPC;
	}
	ctx->count++;
	mutex_unlock(&ctx->lock);
	page = alloc_page(gfp);
	if (!page) {
		ret = -ENOMEM;
		goto out_unreserve;
	}
	map_pages[0] = page;
	mapping = vmap(map_pages, ARRAY_SIZE(map_pages), VM_MAP, PAGE_KERNEL);
	if (!mapping) {
		ret = -ENOMEM;
		goto out_page;
	}
	if (copy_from_user(mapping, u64_to_user_ptr(request->source),
			   PAGE_SIZE)) {
		vunmap(mapping);
		ret = -EFAULT;
		goto out_page;
	}
	vunmap(mapping);
	if (request->mode == RECLAIM_WORK_MIRROR) {
		ret = reclaim_quarantine_mirror(page);
		if (ret)
			goto out_page;
	}
	mutex_lock(&ctx->lock);
	ctx->pages[index] = page;
	ctx->modes[index] = request->mode;
	mutex_unlock(&ctx->lock);
	request->index = index;
	return 0;

out_page:
	put_page(page);
out_unreserve:
	mutex_lock(&ctx->lock);
	if (ctx->count == index + 1)
		ctx->count = index;
	mutex_unlock(&ctx->lock);
	return ret;
}

static long reclaim_work_ioctl(struct file *file, unsigned int command,
			       unsigned long arg)
{
	struct reclaim_work_ctx *ctx = file->private_data;
	void __user *user = (void __user *)arg;

	switch (command) {
	case RECLAIM_WORK_IOC_CREATE: {
		struct reclaim_work_create request;
		int ret;

		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		ret = reclaim_work_create(ctx, &request);
		if (ret)
			return ret;
		return copy_to_user(user, &request, sizeof(request)) ?
			-EFAULT : 0;
	}
	case RECLAIM_WORK_IOC_DIGEST: {
		struct reclaim_work_digest request;
		struct page *page;
		struct page *map_pages[1];
		const u8 *bytes;
		void *mapping;
		u64 digest = 0x9e3779b97f4a7c15ULL;
		u32 i;

		if (copy_from_user(&request, user, sizeof(request)))
			return -EFAULT;
		if (request.reserved || request.index >= RECLAIM_WORK_MAX)
			return -EINVAL;
		mutex_lock(&ctx->lock);
		page = ctx->pages[request.index];
		if (page)
			get_page(page);
		mutex_unlock(&ctx->lock);
		if (!page)
			return -ENOENT;
		map_pages[0] = page;
		mapping = vmap(map_pages, ARRAY_SIZE(map_pages), VM_MAP,
			       PAGE_KERNEL);
		if (!mapping) {
			put_page(page);
			return -ENOMEM;
		}
		bytes = mapping;
		for (i = 0; i < PAGE_SIZE; i++)
			digest = rol64(digest ^ bytes[i], 9) *
				0xbf58476d1ce4e5b9ULL;
		vunmap(mapping);
		put_page(page);
		request.digest = digest;
		return copy_to_user(user, &request, sizeof(request)) ?
			-EFAULT : 0;
	}
	default:
		return -ENOTTY;
	}
}

static int reclaim_work_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct reclaim_work_ctx *ctx = file->private_data;
	struct page *page;
	u32 index = vma->vm_pgoff;
	u8 mode;
	int ret;

	if (vma->vm_end - vma->vm_start != PAGE_SIZE ||
	    !(vma->vm_flags & VM_SHARED) || (vma->vm_flags & VM_EXEC) ||
	    index >= RECLAIM_WORK_MAX)
		return -EINVAL;
	mutex_lock(&ctx->lock);
	page = ctx->pages[index];
	mode = ctx->modes[index];
	if (page)
		get_page(page);
	mutex_unlock(&ctx->lock);
	if (!page)
		return -ENOENT;
	if (mode == RECLAIM_WORK_MIRROR) {
		if (vma->vm_flags & VM_WRITE) {
			ret = -EPERM;
			goto out;
		}
		vm_flags_clear(vma, VM_MAYWRITE);
	}
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
	ret = vm_insert_page(vma, vma->vm_start, page);
out:
	put_page(page);
	return ret;
}

static int reclaim_work_open(struct inode *inode, struct file *file)
{
	struct reclaim_work_ctx *ctx;

	(void)inode;
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	mutex_init(&ctx->lock);
	file->private_data = ctx;
	return 0;
}

static int reclaim_work_release(struct inode *inode, struct file *file)
{
	struct reclaim_work_ctx *ctx = file->private_data;
	u32 i;

	(void)inode;
	if (!ctx)
		return 0;
	for (i = 0; i < ctx->count; i++)
		if (ctx->pages[i])
			put_page(ctx->pages[i]);
	kfree(ctx);
	return 0;
}

static const struct file_operations reclaim_work_fops = {
	.owner = THIS_MODULE,
	.open = reclaim_work_open,
	.release = reclaim_work_release,
	.unlocked_ioctl = reclaim_work_ioctl,
	.compat_ioctl = reclaim_work_ioctl,
	.mmap = reclaim_work_mmap,
	.llseek = noop_llseek,
};
#endif

static struct miscdevice reclaim_case_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "reclaim",
	.fops = &reclaim_case_fops,
	.mode = 0600,
};

static struct miscdevice reclaim_ledger_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "reclaim-ledger",
	.fops = &reclaim_ledger_fops,
	.mode = 0600,
};

static struct miscdevice reclaim_codec_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "reclaim-codec",
	.fops = &reclaim_codec_fops,
	.mode = 0600,
};

static struct miscdevice reclaim_evidence_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "reclaim-evidence",
	.fops = &reclaim_evidence_fops,
	.mode = 0400,
};

#if RECLAIM_ROUTE_WORK
static struct miscdevice reclaim_work_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "reclaim-work",
	.fops = &reclaim_work_fops,
	.mode = 0600,
};
#endif

static void reclaim_drop_global_slots(void)
{
	u32 i;

	mutex_lock(&reclaim_global.lock);
	for (i = 0; i < reclaim_global.count; i++) {
		struct reclaim_ledger_slot *slot = &reclaim_global.slots[i];
		struct reclaim_resource resource = {
			.kind = slot->kind,
			.object = slot->opaque,
		};

		if (!slot->live || slot->kind == RECLAIM_BACKEND_STATEMENT)
			continue;
		slot->live = 0;
		slot->opaque = NULL;
		reclaim_resource_put(&resource);
	}
	mutex_unlock(&reclaim_global.lock);
}

static int __init reclaim_v4_release_init(void)
{
	int ret;

	mutex_init(&reclaim_global.lock);
	reclaim_memo_cache = kmem_cache_create("reclaim_memo", 256, 0,
		SLAB_ACCOUNT | SLAB_NO_MERGE, NULL);
	if (!reclaim_memo_cache)
		return -ENOMEM;
	reclaim_notice_cache = kmem_cache_create("reclaim_notice", 256, 0,
		SLAB_ACCOUNT | SLAB_NO_MERGE, NULL);
	if (!reclaim_notice_cache) {
		ret = -ENOMEM;
		goto out_memo;
	}
	if (RECLAIM_ROUTE_ARCHIVE) {
		reclaim_archive_secret = kzalloc(sizeof(*reclaim_archive_secret),
						 GFP_KERNEL);
		if (!reclaim_archive_secret) {
			ret = -ENOMEM;
			goto out_notice;
		}
		get_random_bytes(reclaim_archive_secret->key,
				 sizeof(reclaim_archive_secret->key));
	}
	if (RECLAIM_ROUTE_KEY) {
		reclaim_global.statement_keyring =
			keyring_alloc(".reclaim-statements", GLOBAL_ROOT_UID,
				      GLOBAL_ROOT_GID, current_cred(), 0,
				      KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
		if (IS_ERR(reclaim_global.statement_keyring)) {
			ret = PTR_ERR(reclaim_global.statement_keyring);
			reclaim_global.statement_keyring = NULL;
			goto out_secret;
		}
		ret = register_key_type(&reclaim_checkpoint_key_type);
		if (ret)
			goto out_keyring;
		reclaim_checkpoint_registered = true;
	}
	ret = misc_register(&reclaim_case_device);
	if (ret)
		goto out_checkpoint;
	ret = misc_register(&reclaim_ledger_device);
	if (ret)
		goto out_case;
	ret = misc_register(&reclaim_codec_device);
	if (ret)
		goto out_ledger;
	if (RECLAIM_ROUTE_ARCHIVE) {
		ret = misc_register(&reclaim_evidence_device);
		if (ret)
			goto out_codec;
	}
	#if RECLAIM_ROUTE_WORK
	ret = misc_register(&reclaim_work_device);
	if (ret)
		goto out_evidence;
	#endif
	return 0;

	#if RECLAIM_ROUTE_WORK
out_evidence:
	if (RECLAIM_ROUTE_ARCHIVE)
		misc_deregister(&reclaim_evidence_device);
	#endif
out_codec:
	misc_deregister(&reclaim_codec_device);
out_ledger:
	misc_deregister(&reclaim_ledger_device);
out_case:
	misc_deregister(&reclaim_case_device);
out_checkpoint:
	#if RECLAIM_ROUTE_KEY
	if (reclaim_checkpoint_registered) {
		unregister_key_type(&reclaim_checkpoint_key_type);
		reclaim_checkpoint_registered = false;
	}
	#endif
out_keyring:
	#if RECLAIM_ROUTE_KEY
	if (reclaim_global.statement_keyring) {
		key_put(reclaim_global.statement_keyring);
		reclaim_global.statement_keyring = NULL;
	}
	#endif
out_secret:
	#if RECLAIM_ROUTE_ARCHIVE
	if (reclaim_archive_secret) {
		memzero_explicit(reclaim_archive_secret,
				 sizeof(*reclaim_archive_secret));
		kfree(reclaim_archive_secret);
		reclaim_archive_secret = NULL;
	}
	#endif
out_notice:
	kmem_cache_destroy(reclaim_notice_cache);
out_memo:
	kmem_cache_destroy(reclaim_memo_cache);
	return ret;
}

static void __exit reclaim_v4_release_exit(void)
{
	#if RECLAIM_ROUTE_WORK
	u32 i;
	#endif

	#if RECLAIM_ROUTE_WORK
	misc_deregister(&reclaim_work_device);
	#endif
	if (RECLAIM_ROUTE_ARCHIVE)
		misc_deregister(&reclaim_evidence_device);
	misc_deregister(&reclaim_codec_device);
	misc_deregister(&reclaim_ledger_device);
	misc_deregister(&reclaim_case_device);
	reclaim_drop_global_slots();
	#if RECLAIM_ROUTE_KEY
	mutex_lock(&reclaim_checkpoint_lock);
	if (reclaim_checkpoint_registered) {
		unregister_key_type(&reclaim_checkpoint_key_type);
		reclaim_checkpoint_registered = false;
	}
	mutex_unlock(&reclaim_checkpoint_lock);
	if (reclaim_global.statement_keyring)
		key_put(reclaim_global.statement_keyring);
	#endif
	#if RECLAIM_ROUTE_WORK
	mutex_lock(&reclaim_mirror_lock);
	for (i = 0; i < reclaim_mirror_count; i++)
		put_page(reclaim_mirror_quarantine[i]);
	reclaim_mirror_count = 0;
	mutex_unlock(&reclaim_mirror_lock);
	#endif
	#if RECLAIM_ROUTE_ARCHIVE
	if (reclaim_archive_secret) {
		memzero_explicit(reclaim_archive_secret,
				 sizeof(*reclaim_archive_secret));
		kfree(reclaim_archive_secret);
		reclaim_archive_secret = NULL;
	}
	#endif
	kmem_cache_destroy(reclaim_notice_cache);
	kmem_cache_destroy(reclaim_memo_cache);
}

module_init(reclaim_v4_release_init);
module_exit(reclaim_v4_release_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RE:CLAIM evidence desk");
