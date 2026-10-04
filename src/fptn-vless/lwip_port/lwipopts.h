#pragma once
/*
 * lwIP configuration for fptn-vless: a client-only userspace TCP/IP stack that
 * replaces the OS TUN adapter. IPv4 + TCP + UDP(DNS) + ICMP, no ARP/Ethernet.
 */
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_ICMP 1
#define LWIP_RAW 0
#define LWIP_DNS 1
#define DNS_MAX_SERVERS 2
#define DNS_TABLE_SIZE 32
#define LWIP_ARP 0
#define LWIP_ETHERNET 0
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_IGMP 0
#define LWIP_STATS 0
#define LWIP_NETIF_LOOPBACK 0

/* memory */
#define MEM_ALIGNMENT 8
#define MEM_SIZE (16 * 1024 * 1024)
#define MEMP_NUM_PBUF 512
#define PBUF_POOL_SIZE 4096
#define PBUF_POOL_BUFSIZE 1536
#define MEMP_NUM_TCP_PCB 2048
#define MEMP_NUM_TCP_PCB_LISTEN 8
#define MEMP_NUM_TCP_SEG 8192
#define MEMP_NUM_UDP_PCB 8
#define MEMP_NUM_SYS_TIMEOUT 16

/* tcp (MTU 1420 - 40 bytes of headers - options headroom) */
#define TCP_MSS 1360
#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE 2
#define TCP_WND (128 * 1024)
#define TCP_SND_BUF (64 * 1024)
#define TCP_SND_QUEUELEN ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS))
#define TCP_QUEUE_OOSEQ 1
