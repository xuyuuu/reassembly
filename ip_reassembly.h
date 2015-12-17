#ifndef ip_reassembly_h
#define ip_reassembly_h

struct yuuu_ipv4_hdr
{
#if 1
        __u8 ihl:4,
	 version:4;
#endif

#if 0
	__u8 ihl:4,
	version:4;
#endif
        __u8 tos;
        __u16 tot_len;
        __u16 id;
        __u16 frag_off;
        __u8 ttl;
        __u8 protocol;
        __u16 check;
        __u32 saddr;
        __u32 daddr;
}__attribute__((__packed__));

#define __yuuu_jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

#define IP_REASSEMBLY_MF_SHIFT 13
#define IP_REASSEMBLY_FMMORE_MASK (1 << IP_REASSEMBLY_MF_SHIFT)
#define IP_REASSEMBLY_FMOFFSET_MASK (IP_REASSEMBLY_FMMORE_MASK - 1)

#define YUUU_JHASH_GOLDEN_RATIO 0x9e3779b9

#define YUUU_FRAG_COMPLETE 4
#define YUUU_FRAG_FIRST_IN 2
#define YUUU_FRAG_LAST_IN  1

#define YUUU_FRAGS_HASH_SIZE (1 << 6)
#define YUUU_FRAGS_HASH_MASK (YUUU_FRAGS_HASH_SIZE - 1)

struct yuuu_ipfrags_node;
struct yuuu_ipfrags
{
	struct hlist_head hash[YUUU_FRAGS_HASH_SIZE];
	struct list_head lru_list;
	pthread_rwlock_t lock;

	__u32 qsize;

	__u32 (*hashfn)(struct yuuu_ipfrags_node *);
	int (*match)(struct yuuu_ipfrags_node *node, void *keys);
	void (*constructor)(struct yuuu_ipfrags_node *node, void *keys);
};

struct yuuu_ipfrags_node
{
	struct hlist_node list;
	struct list_head lru_list;
	pthread_mutex_t lock;
};

struct yuuu_ipfrags_dnode
{
	struct yuuu_ipfrags_node node;

	__u32 saddr;
	__u32 daddr;
	__u16 id;
	__u8 prot;
};

struct yuuu_ipfrags_keys
{
	struct yuuu_ipv4_hdr *iphdr;
};


#endif
