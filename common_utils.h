#ifndef common_utils_h
#define common_utils_h

typedef unsigned char   __u8;
typedef unsigned short	__u16;
typedef unsigned int	__u32;
typedef unsigned long	__u64;

#define yuuu_cpu_be16(x) ((__u16)(\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))\

#define yuuu_cpu_be32(x) ((__u32)(\
	(((__u32)(x) & (__u32)0x000000ffUL) << 24) |\
	(((__u32)(x) & (__u32)0x0000ff00UL) << 8) |\
	(((__u32)(x) & (__u32)0x00ff0000UL) >> 8) |\
	(((__u32)(x) & (__u32)0xff000000UL) >> 24)))\

#endif
