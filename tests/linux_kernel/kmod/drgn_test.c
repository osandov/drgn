// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-or-later

// Linux kernel module for testing drgn helpers and kernel support. For now,
// this is all in one file for simplicity and to keep the compilation fast
// (since this is compiled for every kernel version in CI).
//
// This is intended to be used with drgn's vmtest framework, but in theory it
// can be used with any kernel that has debug info enabled (at your own risk).

#include <linux/version.h>

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/completion.h>
#include <linux/hrtimer.h>
#include <linux/io.h>
#include <linux/irq_work.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/llist.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define HAVE_MAPLE_TREE 1
#include <linux/maple_tree.h>
#else
#define HAVE_MAPLE_TREE 0
#endif
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/nodemask.h>
#include <linux/plist.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/rbtree_augmented.h>
#include <linux/rwsem.h>
#include <linux/sbitmap.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#ifdef CONFIG_STACKDEPOT
#include <linux/stackdepot.h>
#endif
#include <linux/sysfs.h>
#include <linux/timekeeping.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/swait.h>

// Before Linux kernel commit b3dae109fa89 ("sched/swait: Rename to exclusive")
// (in v4.19), prepare_to_swait_exclusive() was named prepare_to_swait().
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
#define prepare_to_swait_exclusive prepare_to_swait
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
#define HAVE_XARRAY 1
#include <linux/xarray.h>
#else
#define HAVE_XARRAY 0
#endif

// Page pools were added in Linux kernel commit ff7d6b27f894 ("page_pool:
// refurbish version of page_pool code") (in v4.18) and may not be enabled.
#ifdef CONFIG_PAGE_POOL
#define HAVE_PAGE_POOL 1
// The header file was moved in Linux kernel commit a9ca9f9ceff3 ("page_pool:
// split types and declarations from page_pool.h") (in v6.6).
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#include <net/page_pool/helpers.h>
#else
#include <net/page_pool.h>
#endif
#else
#define HAVE_PAGE_POOL 0
#endif

// Architecture-specific includes for triggering NMIs for stack traces
#ifdef __x86_64__
#include <asm/apic.h>
#include <asm/nmi.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
// These were added in b9ff604cff11 ("timekeeping: Add
// ktime_get_coarse_with_offset") (in v4.18-rc1).
static inline ktime_t ktime_get_coarse_boottime(void)
{
	struct timespec64 ts = get_monotonic_coarse64();

	return ktime_mono_to_any(timespec64_to_ktime(ts), TK_OFFS_BOOT);
}

static inline ktime_t ktime_get_coarse_clocktai(void)
{
	struct timespec64 ts = get_monotonic_coarse64();

	return ktime_mono_to_any(timespec64_to_ktime(ts), TK_OFFS_TAI);
}

// These were added in Linux kernel commit 06aa376903b6 ("timekeeping: Add more
// coarse clocktai/boottime interfaces") (in v4.18).
static inline time64_t ktime_get_boottime_seconds(void)
{
	return ktime_divns(ktime_get_coarse_boottime(), NSEC_PER_SEC);
}

static inline time64_t ktime_get_clocktai_seconds(void)
{
	return ktime_divns(ktime_get_coarse_clocktai(), NSEC_PER_SEC);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
// These were added in 4c54294d01e6 ("timekeeping: Add missing _ns functions for
// coarse accessors") (in v5.3).
static inline u64 ktime_get_coarse_boottime_ns(void)
{
	return ktime_to_ns(ktime_get_coarse_boottime());
}

static inline u64 ktime_get_coarse_clocktai_ns(void)
{
	return ktime_to_ns(ktime_get_coarse_clocktai());
}
#endif


// Convert a 4-character string to a seed for drgn_test_prng32().
static inline u32 drgn_test_prng32_seed(const char *s)
{
	BUG_ON(strlen(s) != 4);
	return ((u32)s[0] << 24) | ((u32)s[1] << 16) | ((u32)s[2] << 8) | (u32)s[3];
}

// x must not be 0; the return value is never 0.
static u32 drgn_test_prng32(u32 x)
{
	// Xorshift RNG with a period of 2^32 - 1.
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return x;
}

// constants

unsigned long drgn_test_THREAD_SIZE;
#ifdef NR_SECTION_ROOTS
unsigned long drgn_test_NR_SECTION_ROOTS;
#endif
#ifdef SECTIONS_PER_ROOT
unsigned long drgn_test_SECTIONS_PER_ROOT;
#endif
#ifdef SECTION_SIZE_BITS
unsigned long drgn_test_SECTION_SIZE_BITS;
#endif
#ifdef MAX_PHYSMEM_BITS
unsigned long drgn_test_MAX_PHYSMEM_BITS;
#endif
#ifdef CONFIG_FLATMEM
unsigned long drgn_test_ARCH_PFN_OFFSET;
#endif

int drgn_test_MEM_ONLINE = MEM_ONLINE;
int drgn_test_MEM_GOING_OFFLINE = MEM_GOING_OFFLINE;
int drgn_test_MEM_OFFLINE = MEM_OFFLINE;
int drgn_test_MEM_GOING_ONLINE = MEM_GOING_ONLINE;
int drgn_test_MEM_CANCEL_ONLINE = MEM_CANCEL_ONLINE;
int drgn_test_MEM_CANCEL_OFFLINE = MEM_CANCEL_OFFLINE;
#ifdef MEM_PREPARE_ONLINE
int drgn_test_MEM_PREPARE_ONLINE = MEM_PREPARE_ONLINE;
#endif
#ifdef MEM_FINISH_OFFLINE
int drgn_test_MEM_FINISH_OFFLINE = MEM_FINISH_OFFLINE;
#endif

static void drgn_test_constants_init(void)
{
	// Some of these aren't actually compile-time constants, so we
	// initialize all of them at runtime.
	drgn_test_THREAD_SIZE = THREAD_SIZE;
#ifdef NR_SECTION_ROOTS
	drgn_test_NR_SECTION_ROOTS = NR_SECTION_ROOTS;
#endif
#ifdef SECTIONS_PER_ROOT
	drgn_test_SECTIONS_PER_ROOT = SECTIONS_PER_ROOT;
#endif
#ifdef SECTION_SIZE_BITS
	drgn_test_SECTION_SIZE_BITS = SECTION_SIZE_BITS;
#endif
#ifdef MAX_PHYSMEM_BITS
	drgn_test_MAX_PHYSMEM_BITS = MAX_PHYSMEM_BITS;
#endif
#ifdef CONFIG_FLATMEM
	drgn_test_ARCH_PFN_OFFSET = ARCH_PFN_OFFSET;
#endif
}

// block

// blk_mode_t, BLK_OPEN_READ, and BLK_OPEN_WRITE were added in Linux kernel
// commit 05bdb9965305 ("block: replace fmode_t with a block-specific type for
// block open flags") (in v6.5).
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
#define blk_mode_t fmode_t
#define BLK_OPEN_READ FMODE_READ
#define BLK_OPEN_WRITE FMODE_WRITE
#endif

// blk_status_t and BLK_STS_OK were added in Linux kernel commit 2a842acab109
// ("block: introduce new block status code type") (in v4.13).
#ifndef BLK_STS_OK
#define blk_status_t int
#define BLK_STS_OK 0
#endif

// blk_mq_alloc_disk() was added in Linux kernel commit b461dfc49eb6 ("blk-mq:
// add the blk_mq_alloc_disk APIs") (in v5.14).
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0)
static struct gendisk *blk_mq_alloc_disk(struct blk_mq_tag_set *set, void *queuedata)
{
       struct request_queue *q;
       struct gendisk *disk;

       // Not blk_mq_init_queue_data() because that was added in Linux kernel
       // commit 2f227bb99934 ("block: add a blk_mq_init_queue_data helper") (in
       // v5.7).
       q = blk_mq_init_queue(set);
       if (IS_ERR(q))
               return ERR_CAST(q);
       q->queuedata = queuedata;

       disk = alloc_disk_node(0, set->numa_node);
       if (!disk) {
               blk_cleanup_queue(q);
               return ERR_PTR(-ENOMEM);
       }
       disk->queue = q;
       return disk;
}
#endif

static int drgn_test_blkdev_major;

struct drgn_test_blkdev {
	struct blk_mq_tag_set tag_set;
	struct gendisk *disk;
	spinlock_t lock;
	int truant;
	struct list_head loafing_requests;
} drgn_test_blkdevs[2];

static void drgn_test_blkdev_complete_rq(struct request *rq)
{
	struct bio *bio;

	if (req_op(rq) == REQ_OP_READ) {
		__rq_for_each_bio(bio, rq)
			zero_fill_bio(bio);
	}
	blk_mq_end_request(rq, BLK_STS_OK);
}

static ssize_t drgn_test_blkdev_truant_show(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct drgn_test_blkdev *data = dev_to_disk(dev)->private_data;
	return sprintf(buf, "%d\n", READ_ONCE(data->truant));
}

static ssize_t drgn_test_blkdev_truant_store(struct device *dev,
					     struct device_attribute *attr,
					     const char *buf, size_t count)
{
	struct drgn_test_blkdev *data = dev_to_disk(dev)->private_data;
	LIST_HEAD(to_complete);
	struct list_head *pos;
	int ret, val;

	ret = kstrtoint(buf, 0, &val);
	if (ret < 0)
		return ret;
	if (val != 0 && val != 1)
		return -EINVAL;

	spin_lock(&data->lock);
	if (!val)
		list_splice_init(&data->loafing_requests, &to_complete);
	data->truant = val;
	spin_unlock(&data->lock);

	list_for_each(pos, &to_complete)
		drgn_test_blkdev_complete_rq(blk_mq_rq_from_pdu(pos));

	return count;
}

static struct device_attribute drgn_test_blkdev_attr_truant =
	__ATTR(truant, 0600, drgn_test_blkdev_truant_show,
	       drgn_test_blkdev_truant_store);

static const struct attribute_group drgn_test_blkdev_attr_group = {
	.attrs = (struct attribute *[]){
		&drgn_test_blkdev_attr_truant.attr,
		NULL,
	},
};

static const struct attribute_group *drgn_test_blkdev_attr_groups[] = {
	&drgn_test_blkdev_attr_group,
	NULL,
};

static blk_status_t drgn_test_queue_rq(struct blk_mq_hw_ctx *hctx,
				       const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct drgn_test_blkdev *data = rq->q->queuedata;

	blk_mq_start_request(rq);

	spin_lock(&data->lock);
	if (data->truant) {
		list_add_tail(blk_mq_rq_to_pdu(rq), &data->loafing_requests);
		spin_unlock(&data->lock);
	} else {
		spin_unlock(&data->lock);
		drgn_test_blkdev_complete_rq(rq);
	}

	return BLK_STS_OK;
}

// For testing flush requests, we want an interface that synchronously queues a
// flush request. Unfortunately, aio IOCB_CMD_FSYNC queues the request
// asynchronously (with schedule_work()). Instead, we expose this via an ioctl.
static int drgn_test_blkdev_ioctl(struct block_device *bdev, blk_mode_t mode,
				  unsigned cmd, unsigned long arg)
{
	struct bio *bio;

	// We co-opt the number for LOOP_SET_FD so that the test code doesn't
	// need to worry about ioctl number encoding.
	if (cmd != 0x4c00)
		return -ENOTTY;

	if (!(mode & (BLK_OPEN_READ | BLK_OPEN_WRITE)))
		return -EBADF;

	// The bdev and opf parameters to bio_alloc() were added in Linux kernel
	// commit 07888c665b40 ("block: pass a block_device and opf to
	// bio_alloc") (in v5.18). Before that, we have to set the block device
	// and operation manually.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
	bio = bio_alloc(bdev, 0, REQ_OP_WRITE | REQ_PREFLUSH, GFP_KERNEL);
	if (!bio)
		return -ENOMEM;
#else
	bio = bio_alloc(GFP_KERNEL, 0);
	if (!bio)
		return -ENOMEM;
	// bio_set_dev() was added in Linux kernel commit 74d46992e0d9 ("block:
	// replace bi_bdev with a gendisk pointer and partitions index") (in
	// v4.14). Before that, we have to set bi_bdev manually.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	bio_set_dev(bio, bdev);
#else
	bio->bi_bdev = bdev;
#endif
	bio->bi_opf = REQ_OP_WRITE | REQ_PREFLUSH;
#endif
	bio->bi_end_io = bio_put;
	submit_bio(bio);
	// We shouldn't be poking at internals like this, but flush requests are
	// added to the requeue list and queued asynchronously. We need them to
	// be queued before we return.
	flush_delayed_work(&bdev->bd_disk->queue->requeue_work);
	return 0;
}

static const struct blk_mq_ops drgn_test_blk_mq_ops = {
	.queue_rq = drgn_test_queue_rq,
};

static const struct block_device_operations drgn_test_blk_fops = {
	.ioctl = drgn_test_blkdev_ioctl,
	.owner = THIS_MODULE,
};

static int drgn_test_blkdev_create(struct drgn_test_blkdev *bdev,
				   int index, int nr_hw_queues, int queue_depth,
				   unsigned int tag_set_flags)
{
	int ret;

	spin_lock_init(&bdev->lock);
	INIT_LIST_HEAD(&bdev->loafing_requests);

	// Before Linux kernel commit f8a5b12247fe ("blk-mq: make mq_ops a const
	// pointer") (in v4.11), struct blk_mq_tag_set::ops wasn't marked const.
	bdev->tag_set.ops =
		(struct blk_mq_ops *)&drgn_test_blk_mq_ops;
	bdev->tag_set.cmd_size = sizeof(struct list_head);
	bdev->tag_set.nr_hw_queues = nr_hw_queues;
	bdev->tag_set.queue_depth = queue_depth;
	bdev->tag_set.numa_node = NUMA_NO_NODE;
	bdev->tag_set.flags = tag_set_flags;
	ret = blk_mq_alloc_tag_set(&bdev->tag_set);
	if (ret) {
		bdev->tag_set.ops = NULL;
		return ret;
	}

	// We need write cache support to test flush requests.
	// BLK_FEAT_WRITE_CACHE was added in Linux kernel commit 1122c0c1cc71
	// ("block: move cache control settings out of queue->flags") (in
	// v6.11). Before that, we have to call blk_queue_write_cache().
	//
	// The lim parameter was added to blk_mq_alloc_disk() in Linux kernel
	// commit 27e32cd23fed ("block: pass a queue_limits argument to
	// blk_mq_alloc_disk") (in v6.9).
	bdev->disk = blk_mq_alloc_disk(&bdev->tag_set,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
				       (&(struct queue_limits){
					       .features = BLK_FEAT_WRITE_CACHE,
				       }),
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
				       NULL,
#endif
				       bdev);
	if (IS_ERR(bdev->disk))
		return PTR_ERR(bdev->disk);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 11, 0)
	blk_queue_write_cache(bdev->disk->queue, true, false);
#endif
	bdev->disk->major = drgn_test_blkdev_major;
	bdev->disk->first_minor = index;
	bdev->disk->minors = 1;
	bdev->disk->fops = &drgn_test_blk_fops;
	sprintf(bdev->disk->disk_name, "drgntestb%d", index);
	set_capacity(bdev->disk, SZ_1G >> SECTOR_SHIFT);
	bdev->disk->private_data = bdev;

	// The groups parameter was added to device_add_disk() in Linux kernel
	// commit fef912bf860e ("block: genhd: add 'groups' argument to
	// device_add_disk") (in v4.20). Before that, we have to call
	// sysfs_create_groups().
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
	// Before Linux kernel commit 83cbce957446 ("block: add error handling
	// for device_add_disk / add_disk") (in v5.15), device_add_disk() didn't
	// return anything.
	ret =
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
	0;
#endif
	device_add_disk(NULL, bdev->disk, drgn_test_blkdev_attr_groups);
	if (ret)
		return ret;
#else
	add_disk(bdev->disk);
	ret = sysfs_create_groups(&disk_to_dev(bdev->disk)->kobj,
				  drgn_test_blkdev_attr_groups);
	if (ret)
		return ret;
#endif

	return 0;
}

static void drgn_test_blkdev_destroy(struct drgn_test_blkdev *bdev)
{
	if (!IS_ERR_OR_NULL(bdev->disk))
		put_disk(bdev->disk);
	if (bdev->tag_set.ops)
		blk_mq_free_tag_set(&bdev->tag_set);
}

static int drgn_test_block_init(void)
{
	int ret;

	drgn_test_blkdev_major = register_blkdev(0, "drgntest");
	if (drgn_test_blkdev_major < 0)
		return drgn_test_blkdev_major;

	ret = drgn_test_blkdev_create(&drgn_test_blkdevs[0], 0, 2, 2, 0);
	if (ret)
		return ret;
	// BLK_MQ_F_TAG_HCTX_SHARED was added in Linux kernel commit
	// 32bc15afed04 ("blk-mq: Facilitate a shared sbitmap per tagset") (in
	// v5.10).
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	ret = drgn_test_blkdev_create(&drgn_test_blkdevs[1], 1, 2, 4,
				      BLK_MQ_F_TAG_HCTX_SHARED);
	if (ret)
		return ret;
#endif

	return 0;
}

static void drgn_test_block_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(drgn_test_blkdevs); i++)
		drgn_test_blkdev_destroy(&drgn_test_blkdevs[i]);
	if (drgn_test_blkdev_major > 0)
		unregister_blkdev(drgn_test_blkdev_major, "drgntest");
}

// list

LIST_HEAD(drgn_test_empty_list);
LIST_HEAD(drgn_test_full_list);
LIST_HEAD(drgn_test_singular_list);
LIST_HEAD(drgn_test_corrupted_list);
// Corrupted list where entry 1 points back to entry 0.
LIST_HEAD(drgn_test_list_cycle1);
// Corrupted list where entry 2 points back to entry 1.
LIST_HEAD(drgn_test_list_cycle2);
// Corrupted list where entry 3 points back to entry 2.
LIST_HEAD(drgn_test_list_cycle3);
// Corrupted list where entry 2 points to itself.
LIST_HEAD(drgn_test_list_self_cycle);
// Corrupted list where entry 0 points to NULL.
LIST_HEAD(drgn_test_list_null);

struct drgn_test_list_entry {
	int value;
	struct list_head node;
};

struct drgn_test_list_entry drgn_test_circular_list = {
	.value = 1,
	.node = LIST_HEAD_INIT(drgn_test_circular_list.node),
};

struct drgn_test_list_anchor {
	long x, y;
	struct list_head list;
} drgn_test_anchored_list = {
	.x = 101,
	.y = 13,
	.list = LIST_HEAD_INIT(drgn_test_anchored_list.list),
};

struct drgn_test_list_entry drgn_test_list_entries[3];
struct drgn_test_list_entry drgn_test_singular_list_entry;
struct drgn_test_list_entry drgn_test_circular_list_entries[2];
struct drgn_test_list_entry drgn_test_corrupted_list_entries[2];
struct drgn_test_list_entry drgn_test_list_cycle1_entries[2];
struct drgn_test_list_entry drgn_test_list_cycle2_entries[3];
struct drgn_test_list_entry drgn_test_list_cycle3_entries[4];
struct drgn_test_list_entry drgn_test_list_self_cycle_entries[3];
struct drgn_test_list_entry drgn_test_list_null_entry;
struct drgn_test_list_entry drgn_test_anchored_list_entries[3];

HLIST_HEAD(drgn_test_empty_hlist);
HLIST_HEAD(drgn_test_full_hlist);

struct drgn_test_hlist_entry {
	int value;
	struct hlist_node node;
};

struct drgn_test_hlist_entry drgn_test_hlist_entries[3];

struct drgn_test_custom_list_entry {
	int value;
	struct drgn_test_custom_list_entry *next;
};

struct drgn_test_custom_list_entry drgn_test_custom_list;
struct drgn_test_custom_list_entry drgn_test_custom_list_entries[2];
// Custom list where entry 4 points back to entry 2.
struct drgn_test_custom_list_entry drgn_test_custom_list_cycle[5];
// Custom list where entry 2 points to itself.
struct drgn_test_custom_list_entry drgn_test_custom_list_self_cycle[3];

// Emulate a race condition between two threads calling list_add() at the same
// time.
static void init_corrupted_list(void)
{
	struct list_head *prev = &drgn_test_corrupted_list;
	struct list_head *next = drgn_test_corrupted_list.next;
	struct list_head *new1 = &drgn_test_corrupted_list_entries[0].node;
	struct list_head *new2 = &drgn_test_corrupted_list_entries[1].node;

	// Thread 1 starts list_add().
	next->prev = new1;

	// Thread 2 races in and does its own list_add().
	next->prev = new2;
	new2->next = next;
	new2->prev = prev;
	WRITE_ONCE(prev->next, new2);

	// Thread 1 finishes list_add().
	new1->next = next;
	new1->prev = prev;
	WRITE_ONCE(prev->next, new1);
}

static void drgn_test_list_init(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(drgn_test_list_entries); i++) {
		drgn_test_list_entries[i].value = i + 1;
		list_add_tail(&drgn_test_list_entries[i].node,
			      &drgn_test_full_list);
	}
	list_add(&drgn_test_singular_list_entry.node, &drgn_test_singular_list);

	for (i = ARRAY_SIZE(drgn_test_hlist_entries); i-- > 0;) {
		hlist_add_head(&drgn_test_hlist_entries[i].node,
			       &drgn_test_full_hlist);
	}

	for (i = 0; i < ARRAY_SIZE(drgn_test_circular_list_entries); i++) {
		drgn_test_circular_list_entries[i].value = i + 2;
		list_add_tail(&drgn_test_circular_list_entries[i].node,
			      &drgn_test_circular_list.node);
	}

	init_corrupted_list();

#define init_list_cycle(n)							\
	do {									\
		for (i = 0; i < ARRAY_SIZE(drgn_test_list_cycle##n##_entries); i++) {\
			list_add_tail(&drgn_test_list_cycle##n##_entries[i].node,\
				      &drgn_test_list_cycle##n);		\
		}								\
		drgn_test_list_cycle##n##_entries[ARRAY_SIZE(drgn_test_list_cycle##n##_entries) - 1].node.next =\
			&drgn_test_list_cycle##n##_entries[ARRAY_SIZE(drgn_test_list_cycle##n##_entries) - 2].node;\
		drgn_test_list_cycle##n##_entries[ARRAY_SIZE(drgn_test_list_cycle##n##_entries) - 2].node.prev =\
			&drgn_test_list_cycle##n##_entries[ARRAY_SIZE(drgn_test_list_cycle##n##_entries) - 1].node;\
	} while (0)

	init_list_cycle(1);
	init_list_cycle(2);
	init_list_cycle(3);
#undef init_list_cycle

	for (i = 0; i < ARRAY_SIZE(drgn_test_list_self_cycle_entries); i++) {
		list_add_tail(&drgn_test_list_self_cycle_entries[i].node,
			      &drgn_test_list_self_cycle);
	}
	INIT_LIST_HEAD(&drgn_test_list_self_cycle_entries[ARRAY_SIZE(drgn_test_list_self_cycle_entries) - 1].node);

	list_add_tail(&drgn_test_list_null_entry.node, &drgn_test_list_null);
	drgn_test_list_null_entry.node.next = NULL;

	for (i = 0; i < ARRAY_SIZE(drgn_test_anchored_list_entries); i++) {
		drgn_test_anchored_list_entries[i].value = i + 1;
		list_add_tail(&drgn_test_anchored_list_entries[i].node,
			      &drgn_test_anchored_list.list);
	}

	drgn_test_custom_list.value = 1;
	for (i = 0; i < ARRAY_SIZE(drgn_test_custom_list_entries); i++) {
		drgn_test_custom_list_entries[i].value = i + 2;
		if (i == 0) {
			drgn_test_custom_list.next = &drgn_test_custom_list_entries[i];
		} else {
			drgn_test_custom_list_entries[i - 1].next =
				&drgn_test_custom_list_entries[i];
		}
	}

	drgn_test_custom_list_cycle[0].value = 1;
	for (i = 1; i < ARRAY_SIZE(drgn_test_custom_list_cycle); i++) {
		drgn_test_custom_list_cycle[i].value = i + 1;
		drgn_test_custom_list_cycle[i - 1].next =
			&drgn_test_custom_list_cycle[i];
	}
	drgn_test_custom_list_cycle[4].next = &drgn_test_custom_list_cycle[2];

	drgn_test_custom_list_self_cycle[0].value = 1;
	for (i = 1; i < ARRAY_SIZE(drgn_test_custom_list_self_cycle); i++) {
		drgn_test_custom_list_self_cycle[i].value = i + 1;
		drgn_test_custom_list_self_cycle[i - 1].next =
			&drgn_test_custom_list_self_cycle[i];
	}
	drgn_test_custom_list_self_cycle[2].next =
		&drgn_test_custom_list_self_cycle[2];
}

// llist

LLIST_HEAD(drgn_test_empty_llist);
LLIST_HEAD(drgn_test_full_llist);
LLIST_HEAD(drgn_test_singular_llist);

struct drgn_test_llist_entry {
	int value;
	struct llist_node node;
};

struct drgn_test_llist_entry drgn_test_llist_entries[3];
struct drgn_test_llist_entry drgn_test_singular_llist_entry;

static void drgn_test_llist_init(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(drgn_test_llist_entries); i++) {
		llist_add(&drgn_test_llist_entries[i].node,
			      &drgn_test_full_llist);
	}

	llist_add(&drgn_test_singular_llist_entry.node, &drgn_test_singular_llist);
}

// plist

PLIST_HEAD(drgn_test_empty_plist);
PLIST_HEAD(drgn_test_full_plist);
struct plist_node drgn_test_empty_plist_node =
	PLIST_NODE_INIT(drgn_test_empty_plist_node, 50);

struct drgn_test_plist_entry {
	char c;
	struct plist_node node;
};

struct drgn_test_plist_entry drgn_test_plist_entries[3];

// Copy of plist_add() (minus debugging code) since it's not exported.
static void drgn_plist_add(struct plist_node *node, struct plist_head *head)
{
	struct plist_node *first, *iter, *prev = NULL;
	struct list_head *node_next = &head->node_list;

	WARN_ON(!plist_node_empty(node));
	WARN_ON(!list_empty(&node->prio_list));

	if (plist_head_empty(head))
		goto ins_node;

	first = iter = plist_first(head);

	do {
		if (node->prio < iter->prio) {
			node_next = &iter->node_list;
			break;
		}

		prev = iter;
		iter = list_entry(iter->prio_list.next,
				struct plist_node, prio_list);
	} while (iter != first);

	if (!prev || prev->prio != node->prio)
		list_add_tail(&node->prio_list, &iter->prio_list);
ins_node:
	list_add_tail(&node->node_list, node_next);
}

static void drgn_test_plist_init(void)
{
	plist_node_init(&drgn_test_plist_entries[0].node, 10);
	drgn_test_plist_entries[0].c = 'H';
	plist_node_init(&drgn_test_plist_entries[1].node, 20);
	drgn_test_plist_entries[1].c = 'I';
	plist_node_init(&drgn_test_plist_entries[2].node, 30);
	drgn_test_plist_entries[2].c = '!';

	drgn_plist_add(&drgn_test_plist_entries[1].node, &drgn_test_full_plist);
	drgn_plist_add(&drgn_test_plist_entries[0].node, &drgn_test_full_plist);
	drgn_plist_add(&drgn_test_plist_entries[2].node, &drgn_test_full_plist);
}

// locking

static DECLARE_COMPLETION(drgn_test_locking_kthread_ready);
struct task_struct *drgn_test_locking_kthread;
struct task_struct *drgn_test_locking_kthread2;
DEFINE_MUTEX(drgn_test_mutex_locked);
DEFINE_MUTEX(drgn_test_mutex_unlocked);
DECLARE_RWSEM(drgn_test_rwsem_read_locked);
DECLARE_RWSEM(drgn_test_rwsem_write_locked);
DECLARE_RWSEM(drgn_test_rwsem_previously_read_locked);
DECLARE_RWSEM(drgn_test_rwsem_previously_write_locked);
DECLARE_RWSEM(drgn_test_rwsem_never_locked);
DECLARE_RWSEM(drgn_test_rwsem_writer_waiting);

static int drgn_test_locking_kthread_fn(void *arg)
{
	mutex_lock(&drgn_test_mutex_locked);

	down_read(&drgn_test_rwsem_read_locked);
	down_write(&drgn_test_rwsem_write_locked);

	down_read(&drgn_test_rwsem_previously_read_locked);
	up_read(&drgn_test_rwsem_previously_read_locked);

	down_write(&drgn_test_rwsem_previously_write_locked);
	up_write(&drgn_test_rwsem_previously_write_locked);

	down_read(&drgn_test_rwsem_writer_waiting);

	complete(&drgn_test_locking_kthread_ready);
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}
		if (kthread_should_park()) {
			__set_current_state(TASK_RUNNING);
			kthread_parkme();
			continue;
		}
		schedule();
		__set_current_state(TASK_RUNNING);
	}

	up_read(&drgn_test_rwsem_writer_waiting);
	up_write(&drgn_test_rwsem_write_locked);
	up_read(&drgn_test_rwsem_read_locked);

	mutex_unlock(&drgn_test_mutex_locked);
	return 0;
}

static int drgn_test_locking_kthread_fn2(void *arg)
{
	down_write(&drgn_test_rwsem_writer_waiting);
	up_write(&drgn_test_rwsem_writer_waiting);
	return 0;
}

static int drgn_test_locking_init(void)
{
	drgn_test_locking_kthread = kthread_create(drgn_test_locking_kthread_fn,
						   NULL,
						   "drgn_test_locking_kthread");
	if (!drgn_test_locking_kthread)
		return -1;
	wake_up_process(drgn_test_locking_kthread);
	wait_for_completion(&drgn_test_locking_kthread_ready);

	drgn_test_locking_kthread2 =
		kthread_create(drgn_test_locking_kthread_fn2, NULL,
			       "drgn_test_locking_kthread2");
	if (!drgn_test_locking_kthread2)
		return -1;
	wake_up_process(drgn_test_locking_kthread2);

	return kthread_park(drgn_test_locking_kthread);
}

static void drgn_test_locking_exit(void)
{
	// This one needs to exit first to unblock the second one.
	if (drgn_test_locking_kthread) {
		kthread_stop(drgn_test_locking_kthread);
		drgn_test_locking_kthread = NULL;
	}
	if (drgn_test_locking_kthread2) {
		kthread_stop(drgn_test_locking_kthread2);
		drgn_test_locking_kthread2 = NULL;
	}
}

// mapletree

const int drgn_test_have_maple_tree = HAVE_MAPLE_TREE;
#if HAVE_MAPLE_TREE
const int drgn_test_maple_range64_slots = MAPLE_RANGE64_SLOTS;
const int drgn_test_maple_arange64_slots = MAPLE_ARANGE64_SLOTS;

#define DRGN_TEST_MAPLE_TREES		\
	X(empty)			\
	X(one)				\
	X(one_range)			\
	X(one_at_zero)			\
	X(one_range_at_zero)		\
	X(zero_entry)			\
	X(zero_entry_at_zero)		\
	X(dense)			\
	X(dense_ranges)			\
	X(sparse)			\
	X(sparse_ranges)		\
	X(three_levels_dense_1)		\
	X(three_levels_dense_2)		\
	X(three_levels_ranges_1)	\
	X(three_levels_ranges_2)

#define X(name)							\
	DEFINE_MTREE(drgn_test_maple_tree_##name);		\
	struct maple_tree drgn_test_maple_tree_arange_##name =	\
	MTREE_INIT(drgn_test_maple_tree_arange_##name,		\
		   MT_FLAGS_ALLOC_RANGE);
DRGN_TEST_MAPLE_TREES
#undef X

static int drgn_test_maple_tree_init(void)
{
	int ret;
	unsigned int arange, i;
	#define X(name) struct maple_tree *name = &drgn_test_maple_tree_##name;
	DRGN_TEST_MAPLE_TREES
	#undef X

	for (arange = 0; arange < 2; arange++) {
		int node_slots = arange ? MAPLE_ARANGE64_SLOTS : MAPLE_RANGE64_SLOTS;

		ret = mtree_insert(one, 666, (void *)0xdeadb00, GFP_KERNEL);
		if (ret)
			return ret;

		ret = mtree_insert_range(one_range, 616, 666,
					 (void *)0xdeadb000, GFP_KERNEL);
		if (ret)
			return ret;

		ret = mtree_insert(one_at_zero, 0, (void *)0x1234, GFP_KERNEL);
		if (ret)
			return ret;

		ret = mtree_insert_range(one_range_at_zero, 0, 0x1337,
					 (void *)0x5678, GFP_KERNEL);
		if (ret)
			return ret;

		ret = mtree_insert(zero_entry, 666, XA_ZERO_ENTRY, GFP_KERNEL);
		if (ret)
			return ret;

		ret = mtree_insert(zero_entry_at_zero, 0, XA_ZERO_ENTRY,
				   GFP_KERNEL);
		if (ret)
			return ret;

		for (i = 0; i < 5; i++) {
			ret = mtree_insert(dense, i,
					   (void *)(uintptr_t)(0xb0ba000 | i),
					   GFP_KERNEL);
			if (ret)
				return ret;
		}

		for (i = 0; i < 5; i++) {
			ret = mtree_insert_range(dense_ranges, i * i,
						 (i + 1) * (i + 1) - 1,
						 (void *)(uintptr_t)(0xb0ba000 | i),
						 GFP_KERNEL);
			if (ret)
				return ret;
		}

		for (i = 0; i < 5; i++) {
			ret = mtree_insert(sparse, (i + 1) * (i + 1),
					   (void *)(uintptr_t)(0xb0ba000 | i),
					   GFP_KERNEL);
			if (ret)
				return ret;
		}

		for (i = 0; i < 5; i++) {
			ret = mtree_insert_range(sparse_ranges,
						 (2 * i + 1) * (2 * i + 1),
						 (2 * i + 2) * (2 * i + 2),
						 (void *)(uintptr_t)(0xb0ba000 | i),
						 GFP_KERNEL);
			if (ret)
				return ret;
		}

		// In theory, a leaf can reference up to MAPLE_RANGE64_SLOTS
		// entries, and a level 1 node can reference up to node_slots *
		// MAPLE_RANGE64_SLOTS entries. In practice, as of Linux 6.6,
		// the maple tree code only fully packs nodes with a maximum of
		// ULONG_MAX. We create and test trees with both the observed
		// and theoretical limits.
		for (i = 0;
		     i < 2 * (node_slots - 1) * (MAPLE_RANGE64_SLOTS - 1) + (MAPLE_RANGE64_SLOTS - 1);
		     i++) {
			ret = mtree_insert(three_levels_dense_1, i,
					   (void *)(uintptr_t)(0xb0ba000 | i),
					   GFP_KERNEL);
			if (ret)
				return ret;
		}

		for (i = 0; i < 2 * node_slots * MAPLE_RANGE64_SLOTS; i++) {
			ret = mtree_insert(three_levels_dense_2, i,
					   (void *)(uintptr_t)(0xb0ba000 | i),
					   GFP_KERNEL);
			if (ret)
				return ret;
		}

		for (i = 0;
		     i < 2 * (node_slots - 1) * (MAPLE_RANGE64_SLOTS - 1) + (MAPLE_RANGE64_SLOTS - 1);
		     i++) {
			ret = mtree_insert_range(three_levels_ranges_1, 2 * i,
						 2 * i + 1,
						 (void *)(uintptr_t)(0xb0ba000 | i),
						 GFP_KERNEL);
			if (ret)
				return ret;
		}
		ret = mtree_insert_range(three_levels_ranges_1, 2 * i,
					 ULONG_MAX,
					 (void *)(uintptr_t)(0xb0ba000 | i),
					 GFP_KERNEL);
		if (ret)
			return ret;

		for (i = 0; i < 2 * node_slots * MAPLE_RANGE64_SLOTS; i++) {
			ret = mtree_insert_range(three_levels_ranges_2, 2 * i,
						 2 * i + 1,
						 (void *)(uintptr_t)(0xb0ba000 | i),
						 GFP_KERNEL);
			if (ret)
				return ret;
		}
		ret = mtree_insert_range(three_levels_ranges_2, 2 * i,
					 ULONG_MAX,
					 (void *)(uintptr_t)(0xb0ba000 | i),
					 GFP_KERNEL);
		if (ret)
			return ret;

		#define X(name) name = &drgn_test_maple_tree_arange_##name;
		DRGN_TEST_MAPLE_TREES
		#undef X
	}
	return 0;
}

static void drgn_test_maple_tree_exit(void)
{
	#define X(name)							\
		mtree_destroy(&drgn_test_maple_tree_##name);		\
		mtree_destroy(&drgn_test_maple_tree_arange_##name);
	DRGN_TEST_MAPLE_TREES
	#undef X
}
#else
static int drgn_test_maple_tree_init(void) { return 0; }
static void drgn_test_maple_tree_exit(void) {}
#endif

// mm

const int drgn_test_vmap_stack_enabled = IS_ENABLED(CONFIG_VMAP_STACK);
const int drgn_test_slab_stack_enabled =
	!IS_ENABLED(CONFIG_VMAP_STACK) && THREAD_SIZE < PAGE_SIZE;
void *drgn_test_va;
phys_addr_t drgn_test_pa;
unsigned long drgn_test_pfn;
struct page *drgn_test_page;
struct page *drgn_test_compound_page;
void *drgn_test_vmalloc_va;
unsigned long drgn_test_vmalloc_pfn;
struct page *drgn_test_vmalloc_page;

#ifdef CONFIG_SPARSEMEM
unsigned long drgn_test_section_nr;
unsigned long drgn_test_section_pfn;
struct mem_section *drgn_test_mem_section;
struct page *drgn_test_section_mem_map;
struct page *drgn_test_section_decoded_mem_map;

unsigned long drgn_test_SECTION_MARKED_PRESENT = SECTION_MARKED_PRESENT;
struct mem_section *drgn_test_present_section = &(struct mem_section){
	.section_mem_map = SECTION_MARKED_PRESENT,
};

unsigned long drgn_test_SECTION_HAS_MEM_MAP = SECTION_HAS_MEM_MAP;
struct mem_section *drgn_test_valid_section = &(struct mem_section){
	.section_mem_map = SECTION_HAS_MEM_MAP,
};

#ifdef SECTION_IS_ONLINE
unsigned long drgn_test_SECTION_IS_ONLINE = SECTION_IS_ONLINE;
struct mem_section *drgn_test_online_section = &(struct mem_section){
	.section_mem_map = SECTION_IS_ONLINE,
};
#endif

#ifdef SECTION_IS_EARLY
unsigned long drgn_test_SECTION_IS_EARLY = SECTION_IS_EARLY;
struct mem_section *drgn_test_early_section = &(struct mem_section){
	.section_mem_map = SECTION_IS_EARLY,
};
#endif

#ifdef SECTION_TAINT_ZONE_DEVICE
unsigned long drgn_test_SECTION_TAINT_ZONE_DEVICE = SECTION_TAINT_ZONE_DEVICE;
#endif

struct {
	unsigned long nr;
	struct mem_section *section;
} *drgn_test_present_sections;
size_t drgn_test_num_present_sections;
#endif

static int drgn_test_mm_init(void)
{
	u32 fill;
	size_t i;
#ifdef CONFIG_SPARSEMEM
	size_t n;
#endif

	drgn_test_page = alloc_page(GFP_KERNEL);
	if (!drgn_test_page)
		return -ENOMEM;
	drgn_test_compound_page = alloc_pages(GFP_KERNEL | __GFP_COMP, 1);
	if (!drgn_test_compound_page)
		return -ENOMEM;
	drgn_test_va = page_address(drgn_test_page);
	// Fill the page with a PRNG sequence.
	fill = drgn_test_prng32_seed("PAGE");
	for (i = 0; i < PAGE_SIZE / sizeof(fill); i++) {
		fill = drgn_test_prng32(fill);
		((u32 *)drgn_test_va)[i] = fill;
	}
	drgn_test_pa = virt_to_phys(drgn_test_va);
	drgn_test_pfn = PHYS_PFN(drgn_test_pa);
	drgn_test_vmalloc_va = vmalloc(PAGE_SIZE);
	if (!drgn_test_vmalloc_va)
		return -ENOMEM;
	drgn_test_vmalloc_pfn = vmalloc_to_pfn(drgn_test_vmalloc_va);
	drgn_test_vmalloc_page = vmalloc_to_page(drgn_test_vmalloc_va);

#ifdef CONFIG_SPARSEMEM
	drgn_test_section_nr = pfn_to_section_nr(drgn_test_pfn);
	drgn_test_section_pfn = section_nr_to_pfn(drgn_test_section_nr);
	drgn_test_mem_section = __nr_to_section(drgn_test_section_nr);
	drgn_test_section_mem_map = __section_mem_map_addr(drgn_test_mem_section);
	// sparse_decode_mem_map() isn't exported, so we do the equivalent
	// ourselves.
	drgn_test_section_decoded_mem_map =
		drgn_test_section_mem_map + drgn_test_section_pfn;

	// __highest_present_section_nr is not exported, so we can't use
	// for_each_present_section_nr().
	for (i = 0, n = 0; i < NR_MEM_SECTIONS; i++) {
		if (present_section_nr(i))
			n++;
	}

	drgn_test_present_sections =
		kmalloc_array(n, sizeof(drgn_test_present_sections[0]),
			      GFP_KERNEL);
	if (!drgn_test_present_sections)
		return -ENOMEM;

	for (i = 0; i < NR_MEM_SECTIONS; i++) {
		if (present_section_nr(i)) {
			drgn_test_present_sections[drgn_test_num_present_sections].nr = i;
			drgn_test_present_sections[drgn_test_num_present_sections].section =
				__nr_to_section(i);
			drgn_test_num_present_sections++;
			if (drgn_test_num_present_sections >= n)
				break;
		}
	}
#endif

	return 0;
}

static void drgn_test_mm_exit(void)
{
	vfree(drgn_test_vmalloc_va);
	if (drgn_test_compound_page)
		__free_pages(drgn_test_compound_page, 1);
	if (drgn_test_page)
		__free_pages(drgn_test_page, 0);
}

// mmzone

int drgn_test_nid;
struct pglist_data *drgn_test_pgdat;

static void drgn_test_mmzone_init(void)
{
	drgn_test_nid = first_online_node;
	drgn_test_pgdat = NODE_DATA(drgn_test_nid);
}

// net

struct net_device *drgn_test_netdev;
void *drgn_test_netdev_priv;
struct sk_buff *drgn_test_skb;
struct skb_shared_info *drgn_test_skb_shinfo;

static int drgn_test_net_init(void)
{
	drgn_test_netdev = dev_get_by_name(&init_net, "lo");
	if (!drgn_test_netdev)
		return -ENODEV;
	// The loopback device doesn't actually have private data, but we just
	// need to compare the pointer.
	drgn_test_netdev_priv = netdev_priv(drgn_test_netdev);
	drgn_test_skb = alloc_skb(64, GFP_KERNEL);
	if (!drgn_test_skb)
		return -ENOMEM;
	drgn_test_skb_shinfo = skb_shinfo(drgn_test_skb);
	return 0;
}

static void drgn_test_net_exit(void)
{
	kfree_skb(drgn_test_skb);
	dev_put(drgn_test_netdev);
}

// page_pool

const int drgn_test_have_page_pool = HAVE_PAGE_POOL;

#if HAVE_PAGE_POOL
struct page_pool *drgn_test_page_pool;
struct page *drgn_test_page_pool_page;
#endif

static int drgn_test_page_pool_init(void)
{
#if HAVE_PAGE_POOL
	struct page_pool_params params = {
		.order = 0,
		.flags = 0,
		.pool_size = 1,
		.nid = NUMA_NO_NODE,
	};
	struct page_pool *pool;

	pool = page_pool_create(&params);
	if (IS_ERR(pool))
		return PTR_ERR(pool);
	drgn_test_page_pool = pool;

	drgn_test_page_pool_page = page_pool_alloc_pages(pool, GFP_KERNEL);
	if (!drgn_test_page_pool_page)
		return -ENOMEM;
#endif
	return 0;
}

static void drgn_test_page_pool_exit(void)
{
#if HAVE_PAGE_POOL
	if (drgn_test_page_pool_page) {
		// page_pool_put_page() changed in Linux kernel commit
		// 458de8a97f10 ("net: page_pool: API cleanup and comments") (in
		// v5.7).
		page_pool_put_page(drgn_test_page_pool,
				   drgn_test_page_pool_page,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
				   0,
#endif
				   true);
	}
	page_pool_destroy(drgn_test_page_pool);
#endif
}

// percpu

DEFINE_PER_CPU(u32, drgn_test_percpu_static);
u32 __percpu *drgn_test_percpu_dynamic;
struct percpu_counter drgn_test_percpu_counter;
struct percpu_counter drgn_test_percpu_counter_negative;

struct drgn_test_percpu_struct {
	int cpu;
	int i;
};

DEFINE_PER_CPU(struct drgn_test_percpu_struct, drgn_test_percpu_structs);

typedef struct drgn_test_percpu_struct drgn_test_percpu_array[3];

DEFINE_PER_CPU(drgn_test_percpu_array, drgn_test_percpu_arrays);

static int drgn_test_percpu_init(void)
{
	int ret;
	int cpu;
	u32 static_seed = drgn_test_prng32_seed("PCPU");
	u32 dynamic_seed = drgn_test_prng32_seed("pcpu");

	drgn_test_percpu_dynamic = alloc_percpu(u32);
	if (!drgn_test_percpu_dynamic)
		return -ENOMEM;
	// Initialize the per-cpu variables with a PRNG sequence.
	for_each_possible_cpu(cpu) {
		int i;

		static_seed = drgn_test_prng32(static_seed);
		per_cpu(drgn_test_percpu_static, cpu) = static_seed;
		dynamic_seed = drgn_test_prng32(dynamic_seed);
		*per_cpu_ptr(drgn_test_percpu_dynamic, cpu) = dynamic_seed;

		per_cpu(drgn_test_percpu_structs, cpu) =
			(struct drgn_test_percpu_struct){
				.cpu = cpu,
			};

		for (i = 0; i < 3; i++) {
			per_cpu(drgn_test_percpu_arrays, cpu)[i] =
				(struct drgn_test_percpu_struct){
					.cpu = cpu,
					.i = i,
				};
		}
	}

	ret = percpu_counter_init(&drgn_test_percpu_counter,
				  10, GFP_KERNEL);
	if (ret)
		return ret;
	percpu_counter_add(&drgn_test_percpu_counter, 3);

	ret = percpu_counter_init(&drgn_test_percpu_counter_negative,
				  33, GFP_KERNEL);
	if (ret)
		return ret;
	percpu_counter_sub(&drgn_test_percpu_counter_negative, 99);

	return 0;
}

static void drgn_test_percpu_exit(void)
{
	percpu_counter_destroy(&drgn_test_percpu_counter_negative);
	percpu_counter_destroy(&drgn_test_percpu_counter);
	free_percpu(drgn_test_percpu_dynamic);
}

// rbtree

struct rb_root drgn_test_empty_rb_root = RB_ROOT;
struct rb_root drgn_test_rb_root = RB_ROOT;

struct drgn_test_rb_entry {
	struct rb_node node;
	int value;
};

struct drgn_test_rb_entry drgn_test_rb_entries[4];

struct rb_node drgn_test_empty_rb_node;

struct drgn_test_rbtree_container_struct {
	struct drgn_test_rb_entry entries[2];
	struct rb_root root;
} drgn_test_rbtree_container;

struct rb_root drgn_test_rbtree_with_equal = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_equal[4];

struct rb_root drgn_test_rbtree_out_of_order = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_out_of_order[4];

struct rb_root drgn_test_rbtree_with_bad_root_parent = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entry_bad_root_parent;

struct rb_root drgn_test_rbtree_with_red_root = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entry_red_root;

struct rb_root drgn_test_rbtree_with_inconsistent_parents = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_inconsistent_parents[2];

struct rb_root drgn_test_rbtree_with_red_violation = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_red_violation[3];

struct rb_root drgn_test_rbtree_with_black_violation = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_black_violation[2];

static void drgn_test_rbtree_insert(struct rb_root *root,
				    struct drgn_test_rb_entry *entry)
{
	struct rb_node **new = &root->rb_node, *parent = NULL;

	while (*new) {
		struct drgn_test_rb_entry *this =
			container_of(*new, struct drgn_test_rb_entry, node);

		parent = *new;
		if (entry->value <= this->value)
			new = &(*new)->rb_left;
		else
			new = &(*new)->rb_right;
	}

	rb_link_node(&entry->node, parent, new);
	rb_insert_color(&entry->node, root);
}

static void drgn_test_rbtree_init(void)
{
	struct rb_node *node;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries); i++) {
		drgn_test_rb_entries[i].value = i;
		drgn_test_rbtree_insert(&drgn_test_rb_root,
					&drgn_test_rb_entries[i]);
	}
	RB_CLEAR_NODE(&drgn_test_empty_rb_node);

	for (i = 0; i < ARRAY_SIZE(drgn_test_rbtree_container.entries); i++) {
		drgn_test_rbtree_container.entries[i].value = i;
		drgn_test_rbtree_insert(&drgn_test_rbtree_container.root,
					&drgn_test_rbtree_container.entries[i]);
	}

	// Red-black tree with entries that compare equal to each other.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_equal); i++) {
		drgn_test_rb_entries_with_equal[i].value = i / 2;
		drgn_test_rbtree_insert(&drgn_test_rbtree_with_equal,
					&drgn_test_rb_entries_with_equal[i]);
	}

	// Bad red-black tree whose entries are out of order.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_out_of_order); i++) {
		drgn_test_rb_entries_out_of_order[i].value = i;
		drgn_test_rbtree_insert(&drgn_test_rbtree_out_of_order,
					&drgn_test_rb_entries_out_of_order[i]);
	}
	drgn_test_rb_entries_out_of_order[0].value = 99;

	// Bad red-black tree with a root node that has a non-NULL parent.
	drgn_test_rbtree_insert(&drgn_test_rbtree_with_bad_root_parent,
				&drgn_test_rb_entry_bad_root_parent);
	rb_set_parent(&drgn_test_rb_entry_bad_root_parent.node,
		      &drgn_test_empty_rb_node);

	// Bad red-black tree with a red root node.
	rb_link_node(&drgn_test_rb_entry_red_root.node, NULL,
		     &drgn_test_rbtree_with_red_root.rb_node);

	// Bad red-black tree with inconsistent rb_parent.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_inconsistent_parents); i++) {
		drgn_test_rb_entries_with_inconsistent_parents[i].value = i;
		drgn_test_rbtree_insert(&drgn_test_rbtree_with_inconsistent_parents,
					&drgn_test_rb_entries_with_inconsistent_parents[i]);
	}
	node = drgn_test_rbtree_with_inconsistent_parents.rb_node;
	rb_set_parent(node->rb_left ? node->rb_left : node->rb_right,
		      &drgn_test_empty_rb_node);

	// Bad red-black tree with red node with red child.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_red_violation); i++)
		drgn_test_rb_entries_with_red_violation[i].value = i;
	drgn_test_rbtree_insert(&drgn_test_rbtree_with_red_violation,
				&drgn_test_rb_entries_with_red_violation[0]);
	rb_link_node(&drgn_test_rb_entries_with_red_violation[1].node,
		     &drgn_test_rb_entries_with_red_violation[0].node,
		     &drgn_test_rb_entries_with_red_violation[0].node.rb_right);
	rb_link_node(&drgn_test_rb_entries_with_red_violation[2].node,
		     &drgn_test_rb_entries_with_red_violation[1].node,
		     &drgn_test_rb_entries_with_red_violation[1].node.rb_right);

	// Bad red-black tree with unequal number of black nodes in paths from
	// root to leaves.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_black_violation); i++)
		drgn_test_rb_entries_with_black_violation[i].value = i;
	drgn_test_rbtree_insert(&drgn_test_rbtree_with_black_violation,
				&drgn_test_rb_entries_with_black_violation[0]);
	rb_link_node(&drgn_test_rb_entries_with_black_violation[1].node,
		     &drgn_test_rb_entries_with_black_violation[0].node,
		     &drgn_test_rb_entries_with_black_violation[0].node.rb_right);
	drgn_test_rb_entries_with_black_violation[1].node.__rb_parent_color |= RB_BLACK;
}

// sbitmap

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
// sbitmap_deferred_clear_bit() was added in Linux kernel commit ea86ea2cdced
// ("sbitmap: ammortize cost of clearing bits") (in v5.0).
#define sbitmap_deferred_clear_bit sbitmap_clear_bit
#endif

struct sbitmap drgn_test_sbitmap;

static int drgn_test_sbitmap_init(void)
{
	int ret;

	ret = sbitmap_init_node(&drgn_test_sbitmap, 128, 4, GFP_KERNEL,
				NUMA_NO_NODE
// The round_robin and alloc_hint parameters were added in Linux kernel commits
// efe1f3a1d583 ("scsi: sbitmap: Maintain allocation round_robin in sbitmap"),
// and c548e62bcf6a ("scsi: sbitmap: Move allocation hint into sbitmap") (both
// in v5.13), respectively.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
				, false , false
#endif
				);
	if (ret)
		return ret;

	sbitmap_set_bit(&drgn_test_sbitmap, 13);
	sbitmap_set_bit(&drgn_test_sbitmap, 23);
	sbitmap_set_bit(&drgn_test_sbitmap, 24);
	sbitmap_set_bit(&drgn_test_sbitmap, 97);
	sbitmap_set_bit(&drgn_test_sbitmap, 98);
	sbitmap_set_bit(&drgn_test_sbitmap, 99);
	sbitmap_set_bit(&drgn_test_sbitmap, 123);

	sbitmap_clear_bit(&drgn_test_sbitmap, 97);
	// Resize to smaller than a set bit to test that the depth is enforced
	// properly.
	sbitmap_resize(&drgn_test_sbitmap, 100);
	sbitmap_deferred_clear_bit(&drgn_test_sbitmap, 98);
	return 0;
}

static void drgn_test_sbitmap_exit(void)
{
	if (drgn_test_sbitmap.map)
		sbitmap_free(&drgn_test_sbitmap);
}

// slab

const int drgn_test_slob = IS_ENABLED(CONFIG_SLOB);
struct kmem_cache *drgn_test_small_kmem_cache;
struct kmem_cache *drgn_test_big_kmem_cache;

struct drgn_test_small_slab_object {
	int padding[11];
	int value;
};

struct drgn_test_big_slab_object {
	unsigned long padding[PAGE_SIZE / 3 * 4 / sizeof(unsigned long) - 1];
	unsigned long value;
};

struct drgn_test_small_slab_object *drgn_test_small_slab_objects[5];
struct drgn_test_big_slab_object *drgn_test_big_slab_objects[5];

static void drgn_test_slab_exit(void)
{
	size_t i;

	if (drgn_test_big_kmem_cache) {
		for (i = 0; i < ARRAY_SIZE(drgn_test_big_slab_objects); i++) {
			if (drgn_test_big_slab_objects[i]) {
				kmem_cache_free(drgn_test_big_kmem_cache,
						drgn_test_big_slab_objects[i]);
			}
		}
		kmem_cache_destroy(drgn_test_big_kmem_cache);
	}
	if (drgn_test_small_kmem_cache) {
		for (i = 0; i < ARRAY_SIZE(drgn_test_small_slab_objects); i++) {
			if (drgn_test_small_slab_objects[i]) {
				kmem_cache_free(drgn_test_small_kmem_cache,
						drgn_test_small_slab_objects[i]);
			}
		}
		kmem_cache_destroy(drgn_test_small_kmem_cache);
	}
}

// Dummy constructor so test slab caches won't get merged.
static void drgn_test_slab_ctor(void *arg)
{
}

static int drgn_test_slab_init(void)
{
	size_t num_tmp_objs;
	size_t i, j;

	// We want objects in the drgn_test_small cache to be spread out over
	// multiple slabs. To accomplish that, we allocate a bunch of temporary
	// objects in the middle of the allocations we intend to keep, then free
	// the temporary objects.
	num_tmp_objs = PAGE_SIZE / sizeof(struct drgn_test_small_slab_object);

	drgn_test_small_kmem_cache =
		kmem_cache_create("drgn_test_small",
				  sizeof(struct drgn_test_small_slab_object),
				  __alignof__(struct drgn_test_small_slab_object),
				  0, drgn_test_slab_ctor);
	if (!drgn_test_small_kmem_cache)
		return -ENOMEM;
	for (i = 0; i < ARRAY_SIZE(drgn_test_small_slab_objects); i++) {
		const bool alloc_tmp_objs =
			i == ARRAY_SIZE(drgn_test_small_slab_objects) / 2;
		void **tmp_objs;
		int error = 0;

		if (alloc_tmp_objs) {
			tmp_objs = kmalloc_array(num_tmp_objs,
						 sizeof(*tmp_objs), GFP_KERNEL);
			if (!tmp_objs)
				return -ENOMEM;
			for (j = 0; j < num_tmp_objs; j++) {
				tmp_objs[j] = kmem_cache_alloc(drgn_test_small_kmem_cache,
							       GFP_KERNEL);
				// We check for allocation failures below to
				// avoid duplicating cleanup code.
			}
		}

		drgn_test_small_slab_objects[i] =
			kmem_cache_alloc(drgn_test_small_kmem_cache,
					 GFP_KERNEL);
		if (!drgn_test_small_slab_objects[i])
			error = -ENOMEM;

		if (alloc_tmp_objs) {
			for (j = 0; j < num_tmp_objs; j++) {
				if (!tmp_objs[j])
					error = -ENOMEM;
				kmem_cache_free(drgn_test_small_kmem_cache,
						tmp_objs[j]);
			}
			kfree(tmp_objs);
		}
		if (error)
			return -ENOMEM;

		drgn_test_small_slab_objects[i]->value = i;
	}
	drgn_test_big_kmem_cache =
		kmem_cache_create("drgn_test_big",
				  sizeof(struct drgn_test_big_slab_object),
				  __alignof__(struct drgn_test_big_slab_object),
				  0, drgn_test_slab_ctor);
	if (!drgn_test_big_kmem_cache)
		return -ENOMEM;
	for (i = 0; i < ARRAY_SIZE(drgn_test_big_slab_objects); i++) {
		drgn_test_big_slab_objects[i] =
			kmem_cache_alloc(drgn_test_big_kmem_cache, GFP_KERNEL);
		if (!drgn_test_big_slab_objects[i])
			return -ENOMEM;
		drgn_test_big_slab_objects[i]->value = i;
	}
	return 0;
}

// timekeeping

ktime_t drgn_test_ktime;
s64 drgn_test_ktime_ns;

static void drgn_test_timekeeping_init(void)
{
	drgn_test_ktime = ktime_get();
	drgn_test_ktime_ns = ktime_to_ns(drgn_test_ktime);
}

// timer

static void drgn_test_timer_fn(struct timer_list *timer)
{
	mod_timer(timer, jiffies + HZ * 60 * 60 * 24);
}

// Before Linux kernel commits 1d27e3e2252b ("timer: Remove expires and data
// arguments from DEFINE_TIMER") and 354b46b1a0ad ("timer: Switch callback
// prototype to take struct timer_list * argument") (in v4.15), the timer
// callback took an unsigned long that had to be passed explicitly.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
DEFINE_TIMER(drgn_test_timer, drgn_test_timer_fn);
#else
static void drgn_test_timer_fn_old(unsigned long timer)
{
	drgn_test_timer_fn((struct timer_list *)timer);
}

DEFINE_TIMER(drgn_test_timer, drgn_test_timer_fn_old, 0,
	     (unsigned long)&drgn_test_timer);
#endif

#define drgn_test_hrtimer_interval ms_to_ktime(1000 * 60 * 60 * 24)

static enum hrtimer_restart drgn_test_hrtimer_fn(struct hrtimer *hrtimer)
{
	hrtimer_forward_now(hrtimer, drgn_test_hrtimer_interval);
	return HRTIMER_RESTART;
}

struct hrtimer drgn_test_hrtimer;
bool drgn_test_hrtimer_started;

static void drgn_test_timer_init(void)
{
	drgn_test_timer_fn(&drgn_test_timer);
	// hrtimer initialization was changed in Linux kernel commit
	// 908a1d775422 ("hrtimers: Introduce hrtimer_setup() to replace
	// hrtimer_init()") (in v6.13).
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
	hrtimer_setup(&drgn_test_hrtimer, drgn_test_hrtimer_fn, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL);
#else
	hrtimer_init(&drgn_test_hrtimer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL);
	drgn_test_hrtimer.function = drgn_test_hrtimer_fn;
#endif
	hrtimer_start(&drgn_test_hrtimer, drgn_test_hrtimer_interval,
		      HRTIMER_MODE_REL);
	drgn_test_hrtimer_started = true;
}

static void drgn_test_timer_exit(void)
{
	// This was renamed in Linux kernel commit 9b13df3fb64e ("timers: Rename
	// del_timer_sync() to timer_delete_sync()") (in v6.2).
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	timer_delete_sync(&drgn_test_timer);
#else
	del_timer_sync(&drgn_test_timer);
#endif
	if (drgn_test_hrtimer_started)
		hrtimer_cancel(&drgn_test_hrtimer);
}

// kthread for stack trace

struct task_struct *drgn_test_kthread;
struct thread_info *drgn_test_kthread_info;

const int drgn_test_have_stacktrace = IS_ENABLED(CONFIG_STACKTRACE);
#ifdef CONFIG_STACKTRACE
unsigned long drgn_test_stack_entries[16];
unsigned int drgn_test_num_stack_entries;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
// stack_trace_save() was added in Linux kernel commit 214d8ca6ee85
// ("stacktrace: Provide common infrastructure") (in v5.2). Wrap the old
// save_stack_trace() interface. save_stack_trace() skips the caller, so we also
// need the extra frame.
static noinline unsigned int
drgn_test_stack_trace_save(unsigned long *store, unsigned int size,
			   unsigned int skipnr)
{
	struct stack_trace trace = {
		.entries = store,
		.max_entries = size,
		.skip = skipnr,
	};
	save_stack_trace(&trace);
	return trace.nr_entries;
}
#elif defined(__arm__) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
// Before Linux kernel commit 9fbed16c3f4f ("ARM: 9259/1: stacktrace: Convert
// stacktrace to generic ARCH_STACKWALK") (in v6.2), stack_trace_save() skips
// the caller on Arm. Wrap it in an extra frame.
static noinline unsigned int
drgn_test_stack_trace_save(unsigned long *store, unsigned int size,
			   unsigned int skipnr)
{
	unsigned int ret = stack_trace_save(store, size, skipnr);
	barrier(); // Prevent tail call optimization.
	return ret;
}
#else
#define drgn_test_stack_trace_save stack_trace_save
#endif
#endif

const int drgn_test_have_stackdepot = IS_ENABLED(CONFIG_STACKDEPOT);
#ifdef CONFIG_STACKDEPOT
depot_stack_handle_t drgn_test_stack_handle;
#endif

// Completion indicating that the kthread has set up its stack frames and is
// ready to be parked.
static DECLARE_COMPLETION(drgn_test_kthread_ready);
struct pt_regs drgn_test_kthread_pt_regs;
static inline void drgn_test_get_pt_regs(struct pt_regs *regs)
{
#if defined(__aarch64__)
	// Copied from crash_setup_regs() in arch/arm64/include/asm/kexec.h as
	// of Linux v6.1.
	u64 tmp1, tmp2;

	__asm__ __volatile__ (
		"stp	 x0,   x1, [%2, #16 *  0]\n"
		"stp	 x2,   x3, [%2, #16 *  1]\n"
		"stp	 x4,   x5, [%2, #16 *  2]\n"
		"stp	 x6,   x7, [%2, #16 *  3]\n"
		"stp	 x8,   x9, [%2, #16 *  4]\n"
		"stp	x10,  x11, [%2, #16 *  5]\n"
		"stp	x12,  x13, [%2, #16 *  6]\n"
		"stp	x14,  x15, [%2, #16 *  7]\n"
		"stp	x16,  x17, [%2, #16 *  8]\n"
		"stp	x18,  x19, [%2, #16 *  9]\n"
		"stp	x20,  x21, [%2, #16 * 10]\n"
		"stp	x22,  x23, [%2, #16 * 11]\n"
		"stp	x24,  x25, [%2, #16 * 12]\n"
		"stp	x26,  x27, [%2, #16 * 13]\n"
		"stp	x28,  x29, [%2, #16 * 14]\n"
		"mov	 %0,  sp\n"
		"stp	x30,  %0,  [%2, #16 * 15]\n"

		"/* faked current PSTATE */\n"
		"mrs	 %0, CurrentEL\n"
		"mrs	 %1, SPSEL\n"
		"orr	 %0, %0, %1\n"
		"mrs	 %1, DAIF\n"
		"orr	 %0, %0, %1\n"
		"mrs	 %1, NZCV\n"
		"orr	 %0, %0, %1\n"
		/* pc */
		"adr	 %1, 1f\n"
	"1:\n"
		"stp	 %1, %0,   [%2, #16 * 16]\n"
		: "=&r" (tmp1), "=&r" (tmp2)
		: "r" (regs)
		: "memory"
	);
#elif defined(__arm__)
	// Copied from crash_setup_regs() in arch/arm/include/asm/kexec.h as of
	// Linux v6.11.
	__asm__ __volatile__ (
		"stmia	%[regs_base], {r0-r12}\n\t"
		"mov	%[_ARM_sp], sp\n\t"
		"str	lr, %[_ARM_lr]\n\t"
		"adr	%[_ARM_pc], 1f\n\t"
		"mrs	%[_ARM_cpsr], cpsr\n\t"
	"1:"
		: [_ARM_pc] "=r" (regs->ARM_pc),
		  [_ARM_cpsr] "=r" (regs->ARM_cpsr),
		  [_ARM_sp] "=r" (regs->ARM_sp),
		  [_ARM_lr] "=o" (regs->ARM_lr)
		: [regs_base] "r" (&regs->ARM_r0)
		: "memory"
	);
#elif defined(__powerpc64__)
	unsigned long link;
	unsigned long ccr;

	asm volatile("std 0,%0" : "=m"(regs->gpr[0]));
	asm volatile("std 1,%0" : "=m"(regs->gpr[1]));
	asm volatile("std 2,%0" : "=m"(regs->gpr[2]));
	asm volatile("std 3,%0" : "=m"(regs->gpr[3]));
	asm volatile("std 4,%0" : "=m"(regs->gpr[4]));
	asm volatile("std 5,%0" : "=m"(regs->gpr[5]));
	asm volatile("std 6,%0" : "=m"(regs->gpr[6]));
	asm volatile("std 7,%0" : "=m"(regs->gpr[7]));
	asm volatile("std 8,%0" : "=m"(regs->gpr[8]));
	asm volatile("std 9,%0" : "=m"(regs->gpr[9]));
	asm volatile("std 10,%0" : "=m"(regs->gpr[10]));
	asm volatile("std 11,%0" : "=m"(regs->gpr[11]));
	asm volatile("std 12,%0" : "=m"(regs->gpr[12]));
	asm volatile("std 13,%0" : "=m"(regs->gpr[13]));
	asm volatile("std 14,%0" : "=m"(regs->gpr[14]));
	asm volatile("std 15,%0" : "=m"(regs->gpr[15]));
	asm volatile("std 16,%0" : "=m"(regs->gpr[16]));
	asm volatile("std 17,%0" : "=m"(regs->gpr[17]));
	asm volatile("std 18,%0" : "=m"(regs->gpr[18]));
	asm volatile("std 19,%0" : "=m"(regs->gpr[19]));
	asm volatile("std 20,%0" : "=m"(regs->gpr[20]));
	asm volatile("std 21,%0" : "=m"(regs->gpr[21]));
	asm volatile("std 22,%0" : "=m"(regs->gpr[22]));
	asm volatile("std 23,%0" : "=m"(regs->gpr[23]));
	asm volatile("std 24,%0" : "=m"(regs->gpr[24]));
	asm volatile("std 25,%0" : "=m"(regs->gpr[25]));
	asm volatile("std 26,%0" : "=m"(regs->gpr[26]));
	asm volatile("std 27,%0" : "=m"(regs->gpr[27]));
	asm volatile("std 28,%0" : "=m"(regs->gpr[28]));
	asm volatile("std 29,%0" : "=m"(regs->gpr[29]));
	asm volatile("std 30,%0" : "=m"(regs->gpr[30]));
	asm volatile("std 31,%0" : "=m"(regs->gpr[31]));
	asm volatile("mflr %0" : "=r"(link));
	asm volatile("std %1,%0" : "=m"(regs->link) : "r"(link));
	asm volatile("mfcr %0" : "=r"(ccr));
	asm volatile("std %1,%0" : "=m"(regs->ccr) : "r"(ccr));
	regs->nip = _THIS_IP_;
#elif defined(__s390x__)
	regs->psw.mask = __extract_psw();
	regs->psw.addr = _THIS_IP_;
	asm volatile("stmg 0,15,%0\n" : "=S" (regs->gprs) : : "memory");
#elif defined(__x86_64__)
	// Copied from crash_setup_regs() in arch/x86/include/asm/kexec.h as of
	// Linux v6.1.
	asm volatile("movq %%rbx,%0" : "=m"(regs->bx));
	asm volatile("movq %%rcx,%0" : "=m"(regs->cx));
	asm volatile("movq %%rdx,%0" : "=m"(regs->dx));
	asm volatile("movq %%rsi,%0" : "=m"(regs->si));
	asm volatile("movq %%rdi,%0" : "=m"(regs->di));
	asm volatile("movq %%rbp,%0" : "=m"(regs->bp));
	asm volatile("movq %%rax,%0" : "=m"(regs->ax));
	asm volatile("movq %%rsp,%0" : "=m"(regs->sp));
	asm volatile("movq %%r8,%0" : "=m"(regs->r8));
	asm volatile("movq %%r9,%0" : "=m"(regs->r9));
	asm volatile("movq %%r10,%0" : "=m"(regs->r10));
	asm volatile("movq %%r11,%0" : "=m"(regs->r11));
	asm volatile("movq %%r12,%0" : "=m"(regs->r12));
	asm volatile("movq %%r13,%0" : "=m"(regs->r13));
	asm volatile("movq %%r14,%0" : "=m"(regs->r14));
	asm volatile("movq %%r15,%0" : "=m"(regs->r15));
	asm volatile("movl %%ss, %%eax;" :"=a"(regs->ss));
	asm volatile("movl %%cs, %%eax;" :"=a"(regs->cs));
	asm volatile("pushfq; popq %0" :"=m"(regs->flags));
	regs->ip = _THIS_IP_;
#endif
}

__attribute__((__noipa__))
static void drgn_test_kthread_fn3(void)
{
	// Create some local variables for the test cases to use. Use volatile
	// to prevent them from being optimized out.
	volatile int a, b, c;
	volatile struct drgn_test_small_slab_object *slab_object;

	a = 1;
	b = 2;
	c = 3;
	slab_object = drgn_test_small_slab_objects[0];

	// Force slab_object onto the stack.
	__asm__ __volatile__ ("" : : "r" (&slab_object) : "memory");

#ifdef CONFIG_STACKTRACE
	drgn_test_num_stack_entries =
		drgn_test_stack_trace_save(drgn_test_stack_entries,
					   ARRAY_SIZE(drgn_test_stack_entries),
					   0);
#endif
#ifdef CONFIG_STACKDEPOT
	stack_depot_init();
	drgn_test_stack_handle = stack_depot_save(drgn_test_stack_entries,
						  drgn_test_num_stack_entries,
						  GFP_KERNEL);
#endif

	complete(&drgn_test_kthread_ready);
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}
		if (kthread_should_park()) {
			__set_current_state(TASK_RUNNING);
			drgn_test_get_pt_regs(&drgn_test_kthread_pt_regs);
			kthread_parkme();
			continue;
		}
		schedule();
		__set_current_state(TASK_RUNNING);
	}

	// Make sure slab_object stays on the stack.
	__asm__ __volatile__ ("" : : "r" (&slab_object) : "memory");
}

__attribute__((__noipa__))
static void drgn_test_kthread_fn2(void)
{
	drgn_test_kthread_fn3();
	barrier(); // Prevent tail call.
}

__attribute__((__noipa__))
static noinline int drgn_test_kthread_fn(void *arg)
{
	drgn_test_kthread_fn2();
	return 0;
}

static void drgn_test_stack_trace_exit(void)
{
	if (drgn_test_kthread) {
		kthread_stop(drgn_test_kthread);
		drgn_test_kthread = NULL;
	}
}

static int drgn_test_stack_trace_init(void)
{
	drgn_test_kthread = kthread_create(drgn_test_kthread_fn,
					   (void *)0xb0ba000,
					   "drgn_test_kthread");
	if (!drgn_test_kthread)
		return -1;
	drgn_test_kthread_info = task_thread_info(drgn_test_kthread);
	wake_up_process(drgn_test_kthread);
	wait_for_completion(&drgn_test_kthread_ready);
	return kthread_park(drgn_test_kthread);
}

// radixtree

RADIX_TREE(drgn_test_radix_tree_empty, GFP_KERNEL);
RADIX_TREE(drgn_test_radix_tree_one, GFP_KERNEL);
RADIX_TREE(drgn_test_radix_tree_one_at_zero, GFP_KERNEL);
RADIX_TREE(drgn_test_radix_tree_sparse, GFP_KERNEL);
#ifdef CONFIG_RADIX_TREE_MULTIORDER
RADIX_TREE(drgn_test_radix_tree_multi_order, GFP_KERNEL);
#endif

static int drgn_test_radix_tree_init(void)
{
	int ret;

	ret = radix_tree_insert(&drgn_test_radix_tree_one, 666,
				(void *)0xdeadb00);
	if (ret)
		return ret;

	ret = radix_tree_insert(&drgn_test_radix_tree_one_at_zero, 0,
				(void *)0x1234);
	if (ret)
		return ret;

	ret = radix_tree_insert(&drgn_test_radix_tree_sparse, 1,
				(void *)0x1234);
	if (ret)
		return ret;

	ret = radix_tree_insert(&drgn_test_radix_tree_sparse, 0x80808080,
				(void *)0x5678);
	if (ret)
		return ret;

	ret = radix_tree_insert(&drgn_test_radix_tree_sparse, 0xffffffff,
				(void *)0x9abc);
	if (ret)
		return ret;

#ifdef CONFIG_RADIX_TREE_MULTIORDER
	ret = __radix_tree_insert(&drgn_test_radix_tree_multi_order, 0x80808000,
				  9, (void *)0x1234);
	if (ret)
		return ret;
#endif

	return 0;
}

static void drgn_test_radix_tree_destroy(struct radix_tree_root *root)
{
	struct radix_tree_iter iter;
	void __rcu **slot;

	radix_tree_for_each_slot(slot, root, &iter, 0)
		radix_tree_delete(root, iter.index);
}

static void drgn_test_radix_tree_exit(void)
{
	drgn_test_radix_tree_destroy(&drgn_test_radix_tree_one);
	drgn_test_radix_tree_destroy(&drgn_test_radix_tree_one_at_zero);
	drgn_test_radix_tree_destroy(&drgn_test_radix_tree_sparse);
#ifdef CONFIG_RADIX_TREE_MULTIORDER
	drgn_test_radix_tree_destroy(&drgn_test_radix_tree_multi_order);
#endif
}

// xarray
const int drgn_test_have_xarray = HAVE_XARRAY;
#if HAVE_XARRAY
DEFINE_XARRAY(drgn_test_xarray_empty);
DEFINE_XARRAY(drgn_test_xarray_one);
DEFINE_XARRAY(drgn_test_xarray_one_at_zero);
DEFINE_XARRAY(drgn_test_xarray_sparse);
DEFINE_XARRAY(drgn_test_xarray_multi_index);
DEFINE_XARRAY(drgn_test_xarray_zero_entry);
DEFINE_XARRAY(drgn_test_xarray_zero_entry_at_zero);
DEFINE_XARRAY(drgn_test_xarray_value);
DEFINE_XARRAY(drgn_test_xarray_pointers);
void *drgn_test_xa_zero_entry;

struct drgn_test_xarray_entry {
	int value;
};

struct drgn_test_xarray_entry drgn_test_xarray_entries[4];

static int drgn_test_xa_store_order(struct xarray *xa, unsigned long index,
				    unsigned order, void *entry, gfp_t gfp)
{
	XA_STATE_ORDER(xas, xa, index, order);

	do {
		xas_lock(&xas);
		xas_store(&xas, entry);
		xas_unlock(&xas);
	} while (xas_nomem(&xas, gfp));
	return xas_error(&xas);
}
#endif

static int drgn_test_xarray_init(void)
{
#if HAVE_XARRAY
	void *entry;
	int ret;
	size_t i;

	drgn_test_xa_zero_entry = XA_ZERO_ENTRY;

	entry = xa_store(&drgn_test_xarray_one, 666, (void *)0xdeadb00,
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);

	entry = xa_store(&drgn_test_xarray_one_at_zero, 0, (void *)0x1234,
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);

	entry = xa_store(&drgn_test_xarray_sparse, 1, (void *)0x1234,
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);
	entry = xa_store(&drgn_test_xarray_sparse, 0x80808080, (void *)0x5678,
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);
	entry = xa_store(&drgn_test_xarray_sparse, 0xffffffffUL, (void *)0x9abc,
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);

	ret = drgn_test_xa_store_order(&drgn_test_xarray_multi_index,
				       0x80808000, 9, (void *)0x1234,
				       GFP_KERNEL);
	if (ret)
		return ret;

	ret = xa_reserve(&drgn_test_xarray_zero_entry, 666, GFP_KERNEL);
	if (ret)
		return ret;

	ret = xa_reserve(&drgn_test_xarray_zero_entry_at_zero, 0, GFP_KERNEL);
	if (ret)
		return ret;

	entry = xa_store(&drgn_test_xarray_value, 0, xa_mk_value(1337),
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);

	for (i = 0; i < ARRAY_SIZE(drgn_test_xarray_entries); i++) {
		drgn_test_xarray_entries[i].value = i;
		entry = xa_store(&drgn_test_xarray_pointers, i,
				 &drgn_test_xarray_entries[i], GFP_KERNEL);
		if (xa_is_err(entry))
			return xa_err(entry);
	}

#endif

	return 0;
}

static void drgn_test_xarray_exit(void)
{
#if HAVE_XARRAY
	xa_destroy(&drgn_test_xarray_one);
	xa_destroy(&drgn_test_xarray_one_at_zero);
	xa_destroy(&drgn_test_xarray_sparse);
	xa_destroy(&drgn_test_xarray_multi_index);
	xa_destroy(&drgn_test_xarray_zero_entry);
	xa_destroy(&drgn_test_xarray_zero_entry_at_zero);
	xa_destroy(&drgn_test_xarray_value);
#endif
}

// idr

DEFINE_IDR(drgn_test_idr_empty);
DEFINE_IDR(drgn_test_idr_one);
DEFINE_IDR(drgn_test_idr_one_at_zero);
DEFINE_IDR(drgn_test_idr_sparse);

static int drgn_test_idr_init(void)
{
	int ret;

	ret = idr_alloc(&drgn_test_idr_one, (void *)0xdeadb00, 66, 67,
			GFP_KERNEL);
	if (ret < 0)
		return ret;

	ret = idr_alloc(&drgn_test_idr_one_at_zero, (void *)0x1234, 0, 1,
			GFP_KERNEL);
	if (ret < 0)
		return ret;

	ret = idr_alloc(&drgn_test_idr_sparse, (void *)0x1234, 1, 2,
			GFP_KERNEL);
	if (ret < 0)
		return ret;

	ret = idr_alloc(&drgn_test_idr_sparse, (void *)0x5678, 0x80, 0x81,
			GFP_KERNEL);
	if (ret < 0)
		return ret;

	ret = idr_alloc(&drgn_test_idr_sparse, (void *)0x9abc, 0xee, 0xef,
			GFP_KERNEL);
	if (ret < 0)
		return ret;

	return 0;
}

static void drgn_test_idr_exit(void)
{
	idr_destroy(&drgn_test_idr_one);
	idr_destroy(&drgn_test_idr_one_at_zero);
	idr_destroy(&drgn_test_idr_sparse);
}

// wait-queue
static struct task_struct *drgn_test_waitq_kthread;
static wait_queue_head_t drgn_test_waitq;
static wait_queue_head_t drgn_test_empty_waitq;

struct drgn_test_waitq_container_struct {
	int x;
	wait_queue_head_t waitq;
} drgn_test_waitq_container;

static int drgn_test_waitq_kthread_fn(void *arg)
{
	wait_event_interruptible(drgn_test_waitq, kthread_should_stop());
	return 0;
}

static int drgn_test_waitq_init(void)
{
	init_waitqueue_head(&drgn_test_waitq);
	init_waitqueue_head(&drgn_test_empty_waitq);
	init_waitqueue_head(&drgn_test_waitq_container.waitq);

	drgn_test_waitq_kthread = kthread_create(drgn_test_waitq_kthread_fn,
						 NULL,
						 "drgn_test_waitq_kthread");
	if (!drgn_test_waitq_kthread)
		return -1;

	wake_up_process(drgn_test_waitq_kthread);
	return 0;
}

static void drgn_test_waitq_exit(void)
{
	if (drgn_test_waitq_kthread) {
		kthread_stop(drgn_test_waitq_kthread);
		drgn_test_waitq_kthread = NULL;
	}
}

// simple-wait-queue
static struct task_struct *drgn_test_swaitq_kthread;
static struct swait_queue_head drgn_test_swaitq;
static struct swait_queue_head drgn_test_empty_swaitq;

static int drgn_test_swaitq_kthread_fn(void *arg)
{
	DECLARE_SWAITQUEUE(swait);
	for (;;) {
		prepare_to_swait_exclusive(&drgn_test_swaitq, &swait, TASK_UNINTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		schedule();
	}
	finish_swait(&drgn_test_swaitq, &swait);
	return 0;
}

static int drgn_test_swaitq_init(void)
{
	init_swait_queue_head(&drgn_test_swaitq);
	init_swait_queue_head(&drgn_test_empty_swaitq);

	drgn_test_swaitq_kthread = kthread_create(drgn_test_swaitq_kthread_fn,
						 NULL,
						 "drgn_test_swaitq_kthread");
	if (!drgn_test_swaitq_kthread)
		return -1;

	wake_up_process(drgn_test_swaitq_kthread);
	return 0;
}

static void drgn_test_swaitq_exit(void)
{
	if (drgn_test_swaitq_kthread) {
		kthread_stop(drgn_test_swaitq_kthread);
		drgn_test_swaitq_kthread = NULL;
	}
}

// completion variable
static struct task_struct *drgn_test_completion_kthread;
static struct completion drgn_test_completion;
static struct completion drgn_test_done_completion;

static int drgn_test_completion_kthread_fn(void *arg)
{
	complete(&drgn_test_done_completion);
	wait_for_completion(&drgn_test_completion);
	return 0;
}

static int drgn_test_completion_init(void)
{
	drgn_test_completion_kthread = kthread_create(drgn_test_completion_kthread_fn,
						 NULL,
						 "drgn_test_completion_kthread");
	if (!drgn_test_completion_kthread)
		return -1;

	init_completion(&drgn_test_completion);
	init_completion(&drgn_test_done_completion);
	wake_up_process(drgn_test_completion_kthread);
	return 0;
}

static void drgn_test_completion_exit(void)
{
	if (drgn_test_completion_kthread) {
		complete(&drgn_test_completion);
		drgn_test_completion_kthread = NULL;
	}
}

// Dummy function symbol.
int drgn_test_function(int x); // Silence -Wmissing-prototypes.
int drgn_test_function(int x)
{
	return x + 1;
}

char drgn_test_data[] = "abc";
const char drgn_test_rodata[] = "def";

// kmodify

#ifdef __x86_64__
enum drgn_kmodify_enum {
	DRGN_KMODIFY_ONE = 1,
	DRGN_KMODIFY_TWO,
	DRGN_KMODIFY_THREE,
};

struct drgn_kmodify_test_struct {
	void *v;
	int *i;
};
struct drgn_kmodify_test_struct *drgn_kmodify_test_ptr =
	&(struct drgn_kmodify_test_struct){};

char drgn_kmodify_test_memory[16];

int drgn_kmodify_test_int;
int *drgn_kmodify_test_int_ptr;

unsigned long drgn_kmodify_test_bitmap[2];
module_param_array_named(kmodify_bitmap, drgn_kmodify_test_bitmap, ulong, NULL,
			 0600);

struct {
	unsigned int expect0_1 : 8;
	unsigned int byte_aligned : 8;
	unsigned int expect1_1 : 1;
	unsigned int bit : 1;
	unsigned int expect1_2 : 1;
	unsigned int expect0_2 : 1;
	unsigned int two_bits : 2;
	unsigned int unaligned : 8;
} drgn_kmodify_test_bit_field = {
	.expect1_1 = 1,
	.expect1_2 = 1,
};

#define DEFINE_KMODIFY_TEST_RETURN(name, return_type, return_value)	\
int drgn_kmodify_test_##name##_called = 0;				\
return_type drgn_kmodify_test_##name(void);				\
return_type drgn_kmodify_test_##name(void)				\
{									\
	drgn_kmodify_test_##name##_called++;				\
	return (return_value);						\
}

#define DEFINE_KMODIFY_TEST_ARGS(name, parameters, condition)	\
int drgn_kmodify_test_##name##_called = 0;			\
void drgn_kmodify_test_##name parameters;			\
void drgn_kmodify_test_##name parameters			\
{								\
	if (condition)						\
		drgn_kmodify_test_##name##_called++;		\
}

DEFINE_KMODIFY_TEST_ARGS(void_return, (void), 1)
DEFINE_KMODIFY_TEST_RETURN(signed_char_return, signed char, -66)
DEFINE_KMODIFY_TEST_RETURN(unsigned_char_return, unsigned char, 200)
DEFINE_KMODIFY_TEST_RETURN(short_return, short, -666)
DEFINE_KMODIFY_TEST_RETURN(unsigned_short_return, unsigned short, 7777)
DEFINE_KMODIFY_TEST_RETURN(int_return, int, -12345)
DEFINE_KMODIFY_TEST_RETURN(unsigned_int_return, unsigned int, 54321U)
DEFINE_KMODIFY_TEST_RETURN(long_return, long, -2468013579L)
DEFINE_KMODIFY_TEST_RETURN(unsigned_long_return, unsigned long, 4000000000UL)
DEFINE_KMODIFY_TEST_RETURN(long_long_return, long long, -9080706050403020100LL)
DEFINE_KMODIFY_TEST_RETURN(unsigned_long_long_return, unsigned long long,
			   12345678909876543210ULL)
DEFINE_KMODIFY_TEST_RETURN(pointer_return, struct drgn_kmodify_test_struct *,
			   drgn_kmodify_test_ptr)
DEFINE_KMODIFY_TEST_RETURN(enum_return, enum drgn_kmodify_enum,
			   DRGN_KMODIFY_TWO)

DEFINE_KMODIFY_TEST_ARGS(
	signed_args,
	(signed char c, short s, int i, long l, long long ll),
	(c == -66 && s == -666 && i == -12345 && l == -2468013579L && ll == -9080706050403020100LL)
)
DEFINE_KMODIFY_TEST_ARGS(
	unsigned_args,
	(unsigned char c, unsigned short s, unsigned int i, unsigned long l, unsigned long long ll),
	(c == 200 && s == 7777 && i == 54321 && l == 4000000000UL && ll == 12345678909876543210ULL)
)

DEFINE_KMODIFY_TEST_ARGS(
	many_args,
	(char c,
	 signed char sc, short ss, int si, long sl, long long sll,
	 unsigned char uc, unsigned short us, unsigned int ui, unsigned long ul, unsigned long long ull),
	(c == 48
	 && sc == -66 && ss == -666 && si == -12345 && sl == -2468013579L && sll == -9080706050403020100LL
	 && uc == 200 && us == 7777 && ui == 54321 && ul == 4000000000UL && ull == 12345678909876543210ULL)
)

DEFINE_KMODIFY_TEST_ARGS(
	enum_args,
	(enum drgn_kmodify_enum a1, enum drgn_kmodify_enum *a2),
	({
		int match = a1 == DRGN_KMODIFY_ONE && *a2 == DRGN_KMODIFY_TWO;
		*a2 = DRGN_KMODIFY_THREE;
		match;
	})
)

DEFINE_KMODIFY_TEST_ARGS(
	pointer_args,
	(struct drgn_kmodify_test_struct *ptr),
	(ptr == drgn_kmodify_test_ptr)
)

char *drgn_kmodify_test_char_str = "Hello";
signed char *drgn_kmodify_test_signed_char_str = ", ";
unsigned char *drgn_kmodify_test_unsigned_char_str = "world";
const char *drgn_kmodify_test_const_char_str = "!";
DEFINE_KMODIFY_TEST_ARGS(
	string_args,
	(char *c, signed char *sc, unsigned char *uc, const char *cc),
	(strcmp(c, drgn_kmodify_test_char_str) == 0 &&
	 strcmp(sc, drgn_kmodify_test_signed_char_str) == 0 &&
	 strcmp(uc, drgn_kmodify_test_unsigned_char_str) == 0 &&
	 strcmp(cc, drgn_kmodify_test_const_char_str) == 0)
)

DEFINE_KMODIFY_TEST_ARGS(
	integer_out_params,
	(signed char *c, short *s, int *i, long *l, long long *ll),
	({
		int match = *c == -66 && *s == -666 && *i == -12345 && *l == -2468013579L && *ll == -9080706050403020100LL;
		*c = 33;
		*s = 333;
		*i = 23456;
		*l = 2222222222L;
		*ll = 9090909090909090909LL;
		match;
	})
)

DEFINE_KMODIFY_TEST_ARGS(
	array_out_params,
	(long arr[3]),
	({
		int match = arr[0] == 1 && arr[1] == 2 && arr[2] == 3;
		arr[0] = 2;
		arr[1] = 3;
		arr[2] = 5;
		match;
	})
)

DEFINE_KMODIFY_TEST_ARGS(
	many_out_params,
	(char *c,
	 signed char *sc, short *ss, int *si, long *sl, long long *sll,
	 unsigned char *uc, unsigned short *us, unsigned int *ui, unsigned long *ul, unsigned long long *ull),
	({
		int match = (*c == 48
			     && *sc == -66 && *ss == -666 && *si == -12345 && *sl == -2468013579L && *sll == -9080706050403020100LL
			     && *uc == 200 && *us == 7777 && *ui == 54321 && *ul == 4000000000UL && *ull == 12345678909876543210ULL);
		*c /= 3;
		*sc /= 3;
		*ss /= 3;
		*si /= 3;
		*sl /= 3;
		*sll /= 3;
		*uc /= 3;
		*us /= 3;
		*ui /= 3;
		*ul /= 3;
		*ull /= 3;
		match;
	})
)
#endif

#ifdef CONFIG_SYSFS

// Crash from an NMI + IRQ handler on architectures where drgn supports
// unwinding through them.
#ifdef __x86_64__
#define DRGN_TEST_NMI_CRASH
#elif defined(__aarch64__)
#define DRGN_TEST_IRQ_CRASH
#endif


// NMI test depends on IRQ
#ifdef DRGN_TEST_NMI_CRASH
#define DRGN_TEST_IRQ_CRASH
#endif

static __noreturn noinline_for_stack void drgn_test_crash_func(void)
{
	panic("drgn_test\n");
}


#ifdef DRGN_TEST_NMI_CRASH
static bool drgn_panic = false;

static noinline_for_stack int drgn_test_nmi_handler(unsigned int cmd, struct pt_regs *regs)
{
	if (drgn_panic) {
		drgn_test_crash_func();
		return NMI_HANDLED; /* lol */
	}

	return NMI_DONE;
}

static noinline_for_stack void drgn_test_crash_irq_work_fn(struct irq_work *work)
{
	drgn_panic = true;
	apic->send_IPI_mask(cpumask_of(smp_processor_id()), NMI_VECTOR);
}
#elif defined(DRGN_TEST_IRQ_CRASH)
static noinline_for_stack void drgn_test_crash_irq_work_fn(struct irq_work *work)
{
	drgn_test_crash_func();
}
#endif

#ifdef DRGN_TEST_IRQ_CRASH
static DEFINE_IRQ_WORK(drgn_test_crash_irq_work, drgn_test_crash_irq_work_fn);
#endif

static ssize_t drgn_test_crash_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	int ret, val;

	ret = kstrtoint(buf, 0, &val);
	if (ret < 0)
		return ret;
	if (val != 1)
		return -EINVAL;

#ifdef DRGN_TEST_IRQ_CRASH
	preempt_disable();
	irq_work_queue(&drgn_test_crash_irq_work);
	// Spin until we get interrupted and crash.
	while (1);
#else
	drgn_test_crash_func();
#endif
}

static int drgn_test_crash_init(void)
{
#ifdef DRGN_TEST_NMI_CRASH
	return register_nmi_handler(NMI_LOCAL, drgn_test_nmi_handler,
	                            0, "drgn_panic");
#else
	return 0;
#endif
}

static struct kobj_attribute drgn_test_crash_attr =
	__ATTR(crash, 0200, NULL, drgn_test_crash_store);

static ssize_t drgn_test_boottime_seconds_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	return sprintf(buf, "%lld\n", ktime_get_boottime_seconds());
}

static struct kobj_attribute drgn_test_boottime_seconds_attr =
	__ATTR(boottime_seconds, 0444, drgn_test_boottime_seconds_show, NULL);

static ssize_t drgn_test_coarse_boottime_ns_show(struct kobject *kobj,
						 struct kobj_attribute *attr,
						 char *buf)
{
	return sprintf(buf, "%llu\n", ktime_get_coarse_boottime_ns());
}

static struct kobj_attribute drgn_test_coarse_boottime_ns_attr =
	__ATTR(coarse_boottime_ns, 0444, drgn_test_coarse_boottime_ns_show,
	       NULL);

static ssize_t drgn_test_clocktai_seconds_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	return sprintf(buf, "%lld\n", ktime_get_clocktai_seconds());
}

static struct kobj_attribute drgn_test_clocktai_seconds_attr =
	__ATTR(clocktai_seconds, 0444, drgn_test_clocktai_seconds_show, NULL);

static ssize_t drgn_test_coarse_clocktai_ns_show(struct kobject *kobj,
						 struct kobj_attribute *attr,
						 char *buf)
{
	return sprintf(buf, "%llu\n", ktime_get_coarse_clocktai_ns());
}

static struct kobj_attribute drgn_test_coarse_clocktai_ns_attr =
	__ATTR(coarse_clocktai_ns, 0444, drgn_test_coarse_clocktai_ns_show,
	       NULL);

static struct attribute_group drgn_test_attr_group = {
	.attrs = (struct attribute *[]){
		&drgn_test_crash_attr.attr,
		&drgn_test_boottime_seconds_attr.attr,
		&drgn_test_coarse_boottime_ns_attr.attr,
		&drgn_test_clocktai_seconds_attr.attr,
		&drgn_test_coarse_clocktai_ns_attr.attr,
		NULL,
	},
};

static struct kobject *drgn_test_kobj;

static int __init drgn_test_sysfs_init(void)
{
	drgn_test_kobj = kobject_create_and_add("drgn_test", kernel_kobj);
	if (!drgn_test_kobj)
		return -ENOMEM;

	return sysfs_create_group(drgn_test_kobj, &drgn_test_attr_group);
}

static void drgn_test_sysfs_exit(void)
{
	kobject_put(drgn_test_kobj);
}
#else
static inline int drgn_test_sysfs_init(void) { return 0; }
static inline void drgn_test_sysfs_exit(void) {}
#endif

// types

union drgn_test_union {
	u32 u;
	s32 s;
};
union drgn_test_union drgn_test_union_var;

typedef union {
	u64 u;
	s64 s;
} drgn_test_anonymous_union;
drgn_test_anonymous_union drgn_test_anonymous_union_var;

static void drgn_test_exit(void)
{
	drgn_test_sysfs_exit();
	drgn_test_slab_exit();
	drgn_test_sbitmap_exit();
	drgn_test_percpu_exit();
	drgn_test_maple_tree_exit();
	drgn_test_mm_exit();
	drgn_test_net_exit();
	drgn_test_page_pool_exit();
	drgn_test_stack_trace_exit();
	drgn_test_timer_exit();
	drgn_test_radix_tree_exit();
	drgn_test_xarray_exit();
	drgn_test_waitq_exit();
	drgn_test_locking_exit();
	drgn_test_idr_exit();
	drgn_test_block_exit();
	drgn_test_swaitq_exit();
	drgn_test_completion_exit();
}

static int __init drgn_test_init(void)
{
	int ret;

	drgn_test_constants_init();
	ret = drgn_test_block_init();
	if (ret)
		goto out;
	drgn_test_list_init();
	drgn_test_llist_init();
	drgn_test_plist_init();
	ret = drgn_test_locking_init();
	if (ret)
		goto out;
	ret = drgn_test_maple_tree_init();
	if (ret)
		goto out;
	ret = drgn_test_mm_init();
	if (ret)
		goto out;
	drgn_test_mmzone_init();
	ret = drgn_test_net_init();
	if (ret)
		goto out;
	ret = drgn_test_page_pool_init();
	if (ret)
		goto out;
	ret = drgn_test_percpu_init();
	if (ret)
		goto out;
	drgn_test_rbtree_init();
	ret = drgn_test_sbitmap_init();
	if (ret)
		goto out;
	ret = drgn_test_slab_init();
	if (ret)
		goto out;
	ret = drgn_test_stack_trace_init();
	if (ret)
		goto out;
	ret = drgn_test_radix_tree_init();
	if (ret)
		goto out;
	drgn_test_timekeeping_init();
	drgn_test_timer_init();
	ret = drgn_test_xarray_init();
	if (ret)
		goto out;

	ret = drgn_test_waitq_init();
	if (ret)
		goto out;
	ret = drgn_test_idr_init();
	if (ret)
		goto out;
	ret = drgn_test_sysfs_init();
	if (ret)
		goto out;
	ret = drgn_test_crash_init();
	if (ret)
		goto out;

	ret = drgn_test_swaitq_init();
	if (ret)
		goto out;

	ret = drgn_test_completion_init();
out:
	if (ret)
		drgn_test_exit();
	return ret;
}

module_init(drgn_test_init);
module_exit(drgn_test_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Module for testing drgn");
