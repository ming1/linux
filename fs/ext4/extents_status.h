/*
 *  fs/ext4/extents_status.h
 *
 * Written by Yongqiang Yang <xiaoqiangnk@gmail.com>
 * Modified by
 *	Allison Henderson <achender@linux.vnet.ibm.com>
 *	Zheng Liu <wenqing.lz@taobao.com>
 *
 */

#ifndef _EXT4_EXTENTS_STATUS_H
#define _EXT4_EXTENTS_STATUS_H

/*
 * Turn on ES_DEBUG__ to get lots of info about extent status operations.
 */
#ifdef ES_DEBUG__
#define es_debug(fmt, ...)	printk(fmt, ##__VA_ARGS__)
#else
#define es_debug(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#endif

enum {
	EXTENT_STATUS_WRITTEN = 0,	/* written extent */
	EXTENT_STATUS_UNWRITTEN = 1,	/* unwritten extent */
	EXTENT_STATUS_DELAYED = 2,	/* delayed extent */
};

/*
 * Here for save memory es_status is stashed into es_pblk because we only have
 * 48 bits physical block and es_status only needs 2 bits.
 */
struct extent_status {
	struct rb_node rb_node;
	ext4_lblk_t es_lblk;		/* first logical block extent covers */
	ext4_lblk_t es_len;		/* length of extent in block */
	ext4_fsblk_t es_pblk : 62;	/* first physical block */
	ext4_fsblk_t es_status : 2;	/* record the status of extent */
};

struct ext4_es_tree {
	struct rb_root root;
	struct extent_status *cache_es;	/* recently accessed extent */
};

extern int __init ext4_init_es(void);
extern void ext4_exit_es(void);
extern void ext4_es_init_tree(struct ext4_es_tree *tree);

extern int ext4_es_insert_extent(struct inode *inode, ext4_lblk_t lblk,
				 ext4_lblk_t len, ext4_fsblk_t pblk,
				 int status);
extern int ext4_es_remove_extent(struct inode *inode, ext4_lblk_t lblk,
				 ext4_lblk_t len);
extern ext4_lblk_t ext4_es_find_extent(struct inode *inode,
				struct extent_status *es);
extern int ext4_es_lookup_extent(struct inode *inode, struct extent_status *es);

static inline int ext4_es_is_written(struct extent_status *es)
{
	return (es->es_status == EXTENT_STATUS_WRITTEN);
}

static inline int ext4_es_is_unwritten(struct extent_status *es)
{
	return (es->es_status == EXTENT_STATUS_UNWRITTEN);
}

static inline int ext4_es_is_delayed(struct extent_status *es)
{
	return (es->es_status == EXTENT_STATUS_DELAYED);
}

static inline ext4_fsblk_t ext4_es_get_pblock(struct extent_status *es,
					      ext4_fsblk_t pb)
{
	return (ext4_es_is_delayed(es) ? ~0 : pb);
}

#endif /* _EXT4_EXTENTS_STATUS_H */
