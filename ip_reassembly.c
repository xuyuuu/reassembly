#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <pthread.h>

#include "common_list.h"
#include "common_utils.h"
#include "ip_reassembly.h"

/*
 * @Return 0/1/-1
 */
static struct yuuu_ipfrags yuuu_ipfrags;


static int yuuu_ipfrag_isfrag(struct yuuu_ipv4_hdr *iphdr)
{
	if(!iphdr)
		return -1;

	__u16 offset = yuuu_cpu_be16(iphdr->frag_off);
	return ((offset & IP_REASSEMBLY_FMMORE_MASK) ||
		(offset & IP_REASSEMBLY_FMOFFSET_MASK));
}

static __u32 yuuu_jhash_3words(__u32 a, __u32 b, __u32 c, __u32 initval)
{
	a += YUUU_JHASH_GOLDEN_RATIO;
	b += YUUU_JHASH_GOLDEN_RATIO;
	c += initval;

	__yuuu_jhash_mix(a, b, c);

	return c;
}

static __u32 yuuu_ipfrag_hashfn(__u16 id, __u32 saddr, __u32 daddr, __u8 prot)
{
	__u64 initval = random();
	return yuuu_jhash_3words((__u32)id << 16 | prot,
			(__u32)saddr, (__u32)daddr,
			initval & (YUUU_FRAGS_HASH_MASK));

}

static struct yuuu_ipfrags_node *yuuu_ipfrags_alloc(struct yuuu_ipfrags *ipfrags, void *keys)
{
	struct yuuu_ipfrags_node *item;

	item = (struct yuuu_ipfrags_node *)malloc(ipfrags->qsize);
	if(!item)
		return NULL;

	ipfrags->constructor(item, keys);
	pthread_mutex_init(&item->lock, NULL);
}

static struct yuuu_ipfrags_node *yuuu_ipfrags_intern(struct yuuu_ipfrags *ipfrags, 
		struct yuuu_ipfrags_node *node, void *keys)
{
	__u32 h;
	struct hlist_node *n;
	struct yuuu_ipfrags_node *tmp;

	pthread_rwlock_wrlock(&ipfrags->lock);
	h = ipfrags->hashfn(node);

	hlist_for_each_entry(tmp, n, &ipfrags->hash[h], list)
	{
		if(ipfrags->match(tmp, keys))
		{
			pthread_rwlock_unlock(&ipfrags->lock);	
			return tmp;
		}
	}

	tmp = node;
	hlist_add_head(&tmp->list, &ipfrags->hash[h]);
	list_add_tail(&tmp->lru_list, &ipfrags->lru_list);
	pthread_rwlock_unlock(&ipfrags->lock);	

	return tmp;
}

static struct yuuu_ipfrags_node *yuuu_ipfrags_add(struct yuuu_ipfrags *ipfrags, void *keys)
{
	struct yuuu_ipfrags_node *item;

	item = yuuu_ipfrags_alloc(ipfrags, keys);
	if(!item)
		return NULL;

	return yuuu_ipfrags_intern(ipfrags, item, keys);
}

static struct yuuu_ipfrags_node *__yuuu_ipfrag_find(struct yuuu_ipfrags *ipfrags, __u32 h, void *keys)
{
	struct yuuu_ipfrags_node *item;
	struct hlist_node *n;

	pthread_rwlock_rdlock(&ipfrags->lock);
	hlist_for_each_entry(item, n, &ipfrags->hash[h], list)
	{
		if(ipfrags->match(item, keys))	
		{
			pthread_rwlock_unlock(&ipfrags->lock);	
			return item;
		}
	}
	pthread_rwlock_unlock(&ipfrags->lock);

	/*add node*/
	return yuuu_ipfrags_add(ipfrags, keys);
}

static int yuuu_ipfrag_find(struct yuuu_ipfrags *ipfrags, struct yuuu_ipv4_hdr *iphdr)
{
	__u32 hash;
	struct yuuu_ipfrags_keys keys;
	struct yuuu_ipfrags_node *res;

	keys.iphdr = iphdr;

	pthread_rwlock_rdlock(&ipfrags->lock);
	hash = yuuu_ipfrag_hashfn(iphdr->id, iphdr->saddr, iphdr->daddr, iphdr->protocol);

	res = __yuuu_ipfrag_find(ipfrags, hash, &keys);
	;
}

static int yuuu_ipfrag_reassembley(struct yuuu_ipfrags *ipfrags, struct yuuu_ipv4_hdr *iphdr)
{
	yuuu_ipfrag_find(ipfrags, iphdr);
	return 0;
}

static int yuuu_ipv4_frag_match(struct yuuu_ipfrags_node *node, void *arg)
{
	struct yuuu_ipfrags_keys *keys= (struct yuuu_ipfrags_keys*)arg;
	struct yuuu_ipfrags_dnode *des;
	des = container_of(node, struct yuuu_ipfrags_dnode, node);

	return (des->id == keys->iphdr->id &&
		des->saddr == keys->iphdr->saddr &&
		des->daddr == keys->iphdr->daddr &&
		des->prot == keys->iphdr->protocol);
}

static void yuuu_ipv4_frag_init(struct yuuu_ipfrags_node *node, void *keys)
{
	struct yuuu_ipfrags_dnode *des = container_of(node, struct yuuu_ipfrags_dnode, node);
	struct yuuu_ipfrags_keys *arg = keys;

	des->prot	= arg->iphdr->protocol;
	des->id		= arg->iphdr->id;
	des->saddr	= arg->iphdr->saddr;
	des->daddr	= arg->iphdr->daddr;
}

static __u32 yuuu_ipv4_frag_hashfn(struct yuuu_ipfrags_node *node)
{
	struct yuuu_ipfrags_dnode *des;
	des = container_of(node, struct yuuu_ipfrags_dnode, node);
	return yuuu_ipfrag_hashfn(des->id, des->saddr, des->daddr, des->prot);
}


static int yuuu_ipfrag_init()
{
	yuuu_ipfrags.qsize		= sizeof(struct yuuu_ipfrags_dnode);
	yuuu_ipfrags.constructor	= yuuu_ipv4_frag_init;
	yuuu_ipfrags.match		= yuuu_ipv4_frag_match;
	yuuu_ipfrags.hashfn		= yuuu_ipv4_frag_hashfn;
}
