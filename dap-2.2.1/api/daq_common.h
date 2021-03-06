/*
** Copyright (C) 2010-2013 Sourcefire, Inc.
** Author: Michael R. Altizer <maltizer@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef _DAQ_COMMON_H
#define _DAQ_COMMON_H

#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>
#ifndef WIN32
#include <sys/time.h>
#else
/* for struct timeavl */
#include <winsock2.h>
#include <windows.h>
#endif

#include "daq_gen.h"

#ifndef DAQ_SO_PUBLIC
#if defined _WIN32 || defined __CYGWIN__
#  if defined DAQ_DLL
#    ifdef __GNUC__
#      define DAQ_SO_PUBLIC __attribute__((dllexport))
#    else
#      define DAQ_SO_PUBLIC __declspec(dllexport)
#    endif
#  else
#    ifdef __GNUC__
#      define DAQ_SO_PUBLIC __attribute__((dllimport))
#    else
#      define DAQ_SO_PUBLIC __declspec(dllimport)
#    endif
#  endif
#  define DLL_LOCAL
#else
#  ifdef HAVE_VISIBILITY
#    define DAQ_SO_PUBLIC  __attribute__ ((visibility("default")))
#    define DAQ_SO_PRIVATE __attribute__ ((visibility("hidden")))
#  else
#    define DAQ_SO_PUBLIC
#    define DAQ_SO_PRIVATE
#  endif
#endif
#endif

#ifdef _WIN32
# ifdef DAQ_DLL
#  define DAQ_LINKAGE DAQ_SO_PUBLIC
# else
#  define DAQ_LINKAGE
# endif
#else
# define DAQ_LINKAGE DAQ_SO_PUBLIC
#endif

#define DAQ_USER_SF_OP_NONE  3  /* SF Operation Empty */
#define DAQ_USER_INT_EXIT	 2  /* Daq interrupted by user */
#define DAQ_HALF_EXIT		 1  /* Daq Initialize interrupted by user */
#define DAQ_SUCCESS          0  /* Success! */
#define DAQ_ERROR           -1  /* Generic error */
#define DAQ_ERROR_NOMEM     -2  /* Out of memory error */
#define DAQ_ERROR_NODEV     -3  /* No such device error */
#define DAQ_ERROR_NOTSUP    -4  /* Functionality is unsupported error */
#define DAQ_ERROR_NOMOD     -5  /* No module specified error */
#define DAQ_ERROR_NOCTX     -6  /* No context specified error */
#define DAQ_ERROR_INVAL     -7  /* Invalid argument/request error */
#define DAQ_ERROR_EXISTS    -8  /* Argument or device already exists */
#define DAQ_ERROR_AGAIN     -9  /* Try again */
#define DAQ_READFILE_EOF    -42 /* Hit the end of the file being read! */

#define DAQ_PKT_FLAG_HW_TCP_CS_GOOD     0x1 /* The DAQ module reports that the checksum for this packet is good. */
#define DAQ_PKT_FLAG_OPAQUE_IS_VALID    0x2 /* The DAQ module actively set the opaque value in the DAQ packet header. */
#define DAQ_PKT_FLAG_NOT_FORWARDING     0x4 /* The DAQ module will not be actively forwarding this packet
                                               regardless of the verdict (e.g, Passive or Inline Tap interfaces). */
#define DAQ_PKT_FLAG_PRE_ROUTING        0x8 /* The packet is being routed via us but packet modifications
                                                (MAC and TTL) have not yet been made. */
#define DAQ_PKT_FLAG_SSL_DETECTED	0x10 /* Packet is ssl client hello */
#define DAQ_PKT_FLAG_SSL_SHELLO	    0x20 /* Packet is ssl server hello */
#define DAQ_PKT_FLAG_SSL_SERVER_KEYX	0x40 /* Packet is ssl server keyx */
#define DAQ_PKT_FLAG_SSL_CLIENT_KEYX	0x80 /* Packet is ssl client keyx */

/* The DAQ packet header structure passed to DAQ Analysis Functions.
 * This should NEVER be modified by user applications. */
#define DAQ_PKTHDR_UNKNOWN  -1  /* Ingress or Egress not known */
#define DAQ_PKTHDR_FLOOD    -2  /* Egress is flooding */
typedef struct _daq_pkthdr
{
    struct timeval ts;      /* Timestamp */
    time_t cts;
    uint32_t caplen;        /* Length of the portion present */
    uint32_t pktlen;        /* Length of this packet (off wire) */
    int32_t ingress_index;  /* Index of the inbound interface. */
    int32_t egress_index;   /* Index of the outbound interface. */
    int32_t ingress_group;  /* Index of the inbound group. */
    int32_t egress_group;   /* Index of the outbound group. */
    uint32_t flags;         /* Flags for the packet (DAQ_PKT_FLAG_*) */
    uint32_t opaque;        /* Opaque context value from the DAQ module or underlying hardware.
                               Directly related to the opaque value in FlowStats. */
    void *priv_ptr;         /* Private data pointer */
    uint32_t flow_id;
    uint16_t address_space_id; /* Unique ID of the address space */
} DAQ_PktHdr_t;

#define DAQ_METAHDR_TYPE_SOF        0
#define DAQ_METAHDR_TYPE_EOF        1
#define DAQ_METAHDR_TYPE_VPN_LOGIN  2
#define DAQ_METAHDR_TYPE_VPN_LOGOUT 3
typedef struct _daq_metahdr
{
    int type;               /* Type */
} DAQ_MetaHdr_t;

typedef struct _daq_modflow
{
    uint32_t    opaque;     /* */
} DAQ_ModFlow_t;

#define DAQ_FLOWSTATS_IPV4      0
#define DAQ_FLOWSTATS_IPV6      1
typedef struct _flow_stats
{
    int32_t ingressZone;
    int32_t egressZone;
    int32_t ingressIntf;
    int32_t egressIntf;
    uint8_t initiatorIp[16];
    uint8_t responderIp[16];
    uint16_t initiatorPort;
    uint16_t responderPort;
    uint8_t protocol;
    uint8_t version;
    uint64_t initiatorPkts;
    uint64_t responderPkts;
    uint64_t initiatorBytes;
    uint64_t responderBytes;
    uint32_t opaque;
    uint16_t vlan_tag;
    struct timeval sof_timestamp;
    struct timeval eof_timestamp;
    uint16_t address_space_id;
} Flow_Stats_t, *Flow_Stats_p;

typedef enum {
    NP_IDFW_VPN_SESSION_TYPE_UNKNOWN = 0,
    NP_IDFW_VPN_SESSION_TYPE_RA_IKEV1 = 1,
    NP_IDFW_VPN_SESSION_TYPE_RA_IKEV2 = 2,
    NP_IDFW_VPN_SESSION_TYPE_RA_SSLVPN = 3,
    NP_IDFW_VPN_SESSION_TYPE_RA_SSLVPN_CLIENTLESS = 4,
    NP_IDFW_VPN_SESSION_TYPE_LAN2LAN_IKEV1 = 5,
    NP_IDFW_VPN_SESSION_TYPE_LAN2LAN_IKEV2 = 6,
    NP_IDFW_VPN_SESSION_TYPE_MAX,
} np_idfw_vpn_session_type_t;

#define DAQ_VPN_INFO_MAX_USER_NAME_LEN  256
typedef struct _daq_vpn_info
{
    uint8_t ip[16];
    uint32_t id;
} DAQ_VPN_Info_t, *DAQ_VPN_Info_p;

typedef struct _daq_vpn_login_info
{
    DAQ_VPN_Info_t info;
    uint32_t os;
    uint32_t type;
    char user[DAQ_VPN_INFO_MAX_USER_NAME_LEN + 1];
} DAQ_VPN_Login_Info_t, *DAQ_VPN_Login_Info_p;

typedef enum {
    DAQ_VERDICT_PASS,       /* Pass the packet. */
    DAQ_VERDICT_BLOCK,      /* Block the packet. */
    DAQ_VERDICT_REPLACE,    /* Pass a packet that has been modified in-place. (No resizing allowed!) */
    DAQ_VERDICT_WHITELIST,  /* Pass the packet and fastpath all future packets in the same flow systemwide. */
    DAQ_VERDICT_BLACKLIST,  /* Block the packet and block all future packets in the same flow systemwide. */
    DAQ_VERDICT_IGNORE,     /* Pass the packet and fastpath all future packets in the same flow for this application. */
    DAQ_VERDICT_RETRY,     /* Hold the packet briefly and resend it to Snort while Snort waits for external response. Drop any new packets received on that flow while holding before sending them to Snort. */
    MAX_DAQ_VERDICT
} DAQ_Verdict;

typedef struct __xstatsinfo
{
    uint8_t cIfup;
    uint32_t link_speed;
    uint64_t uRxPrcnt;
    uint64_t uRxPrbyte;
    uint64_t uTxPrcnt;
    uint64_t uTxPrbyte;
} xstatsinfo;

typedef DAQ_Verdict (*DAQ_Analysis_Func_t)(void *user, const DAQ_PktHdr_t *hdr, const uint8_t *data);
typedef int (*DAQ_Meta_Func_t)(void *user, const DAQ_MetaHdr_t *hdr, const uint8_t *data);
typedef int (*DAQ_Set_SF_Config)(void *args);
typedef int (*DAQ_SF_Init_Func_t)(void *mbuf_cfl, uint16_t rsock, uint16_t nsock);
typedef int (*DAQ_SF_Merge_Func_t)(void *mbuf_cfl, void *mbuf, unsigned sock_id, uint8_t dp_type, uint8_t db_sync);
typedef int (*DAQ_SF_Init_SSN_Func_t)(void);
typedef int (*DAQ_SF_Cfl_SSN_Func_t)(void *mbuf_cfl);
typedef int (*DAQ_SF_Cfl_DBIns_Func_t)(void *mbuf_cfl);
typedef int (*DAQ_SP_Init_Func_t)(void);
typedef int (*DAQ_SP_Scale_Func_t)(xstatsinfo *xtinfo, uint8_t pid);

//StatsFlow DataPlane struct
typedef struct __DataplaneAddrs
{
    int sock_id;
    void *dp_main;
    void *dp_extra;
} DataplaneAddrs;

/* daq_dpdk_mbuf_ring collections ****************************/
typedef enum _SUR_DAQ_MBUF_TYPE
{
    MPOOL_STATSFLOW = 0,
    MPOOL_SF_STACK,
    MPOOL_SF_SSN,
    MPOOL_SF_CFL_IPT_HA,
    MPOOL_SF_CFL_IPTET,
    MPOOL_SF_CFL_PP_HA,
    MPOOL_SF_CFL_PROTP,
    MPOOL_SF_CFL,
    MPOOL_SF_PPL,   /*packet pay load*/
    MPOOL_DETECT_MCH,
    MPOOL_META,
    MPOOL_META_PAYLOAD,
    MPOOL_DIGGER,
    MPOOL_PORT_BITMAP,
    MPOOL_MATCHED_PKT,
    MPOOL_GEO,
    MPOOL_AP_MSG,
    MPOOL_AP_SQ_OP,//Squirrel Output
    AP_MPOOL_COUNT
} AP_DAQ_MPOOL_TYPE;

typedef enum _SUR_DAQ_RING_TYPE
{
    RING_STATSFLOW = 0,
    RING_SF_STACK,
    //RING_SF_ALY,
    RING_META,
    RING_META_PAYLOAD,
    RING_DIGGER,
    RING_MSG_MASTER,        //ap->master(daq)
    RING_AP_MSG_DG,         //master->digger
    RING_AP_MSG_SQ,         //master->squirrel
    RING_AP_MSG_PT,         //master->portrait
    RING_AP_SQ_OP,          //squirrel->portrait
    RING_AP_SQ_OP_RET,      //portrait->quirrel
    AP_RING_COUNT
} AP_DAQ_RING_TYPE;

typedef enum __DAQ_MBUF_ATTRIBUTE
{
    MR_SINGLETON = 0,
    MR_PRIMARY_ONLY,
//    MPOOL_SECONDARY_ONLY,
    MR_ALL_QUEUES,
    MR_GENERAL,
    MR_PRIMARY_NUMA_NODES,
} DAQ_MPOOL_RING_ATTRIBUTE;
/*
typedef enum __DAQ_RING_ATTRIBUTE
{
    RING_SINGLETON,
    RING_PRIMARY_ONLY,
    RING_SECONDARY_ONLY,
    RING_ALL_QUEUES,
    RING_GENERAL,
} DAQ_RING_ATTRIBUTE;*/

typedef struct __daq_dpdk_mbuf_collect
{
    uint8_t type;
    uint8_t attri;
    char name[62];
    uint32_t poolsize;
    uint32_t datalen;
    uint32_t poolcache;
    uint32_t private_dlen;      //mostly "0"
    uint64_t flag_rein;
    uint64_t pool_sche;
} daq_dpdk_mpool_collect;

typedef struct __daq_dpdk_ring_collect
{
    uint8_t type;
    uint8_t attri;
    char name[62];
    uint32_t queue_size;
    unsigned flags;
    uint64_t flag_sp;
} daq_dpdk_ring_collect;

#define MINV_MAX_MPOOL_CNT      16
#define MINV_MAX_RING_CNT      16
typedef struct __mn_dpl_config
{
    uint16_t npool;
    uint16_t nring;
    daq_dpdk_mpool_collect mpools[MINV_MAX_MPOOL_CNT];
    daq_dpdk_ring_collect rings[MINV_MAX_RING_CNT];
} mn_dpl_config;

//StatsFlow DataPlane Load Info
#define DAQ_CFL_LT_SERVICE_NUM      4   //CFL;SSN;DB-INS;STACK-PROTO-SCALE
typedef struct __DataplaneLoadInfo
{
    uint16_t rsock;
    uint16_t nsock;
    uint16_t npool;
    uint16_t nring;
    char *ap_name;
    daq_dpdk_mpool_collect *mpools;
    daq_dpdk_ring_collect *rings;
    DAQ_SF_Init_Func_t sf_init;
    DAQ_SF_Merge_Func_t sf_confluence;
    DAQ_SF_Init_SSN_Func_t sf_ssn_init;
    DAQ_SF_Cfl_SSN_Func_t sf_cfl_ssn;
    DAQ_SF_Cfl_DBIns_Func_t sf_cfl_dbins;   /*database inspection*/
    DAQ_SP_Init_Func_t sp_init;
    DAQ_SP_Scale_Func_t sp_scale;
} ApDpLoadInfo;

typedef enum __daq_sf_req_type
{
    DAQ_SF_DP_SWAP = 0,
    DAQ_SF_DP_SWAP_RTN,
    DAQ_SF_STACK_DP_SWAP,
    DAQ_SF_STACK_DP_SWAP_RTN,
    DAQ_SF_SET_CONFIG,
    DAQ_SF_SET_CONFIG_RTN,
    DAQ_SF_DIST_DP,
    DAQ_SF_SSN_ANALYST,
    DAQ_SF_REQ_INVALID,
    DAQ_SF_REQ_INVALID_RTN
} daq_sf_req_type;

typedef enum {
    DAQ_MODE_PASSIVE,
    DAQ_MODE_INLINE,
    DAQ_MODE_READ_FILE,
    MAX_DAQ_MODE
} DAQ_Mode;

#define DAQ_FILTER_CONFIG_DATA_SIZE      128

typedef struct __DAQ_Filter_Config
{
    uint32_t uOperation; //Operation as defined in module.h
    uint32_t config_size;
    char content[DAQ_FILTER_CONFIG_DATA_SIZE];
}DAQ_Filter_Config;

#define DAQ_CFG_PROMISC     0x01
#define DAQ_CFG_DAEMON      0x02
#define DAQ_CFG_SYSLOG      0x04
#define DAQ_CFG_MINERVA     0x08

typedef struct _daq_dict_entry DAQ_Dict;

typedef struct _daq_config
{
    char *name;         /* Name of the interface(s) or file to be opened */
    int snaplen;        /* Maximum packet capture length */
    unsigned timeout;   /* Read timeout for acquire loop in milliseconds (0 = unlimited) */
    DAQ_Mode mode;      /* Module mode (DAQ_MODE_*) */
    uint32_t flags;     /* Other configuration flags (DAQ_CFG_*) */
    uint64_t lcore_utl_flag;    /*App's lcore utilization*/
    DAQ_Dict *values;   /* Dictionary of arbitrary key[:value] string pairs. */
    char *extra;        /* Miscellaneous configuration data to be passed to the DAQ module */
    ApDpLoadInfo *ap_dpl;	/* stats_flow data-plane load info */
} DAQ_Config_t;

typedef enum {
    DAQ_STATE_UNINITIALIZED,
    DAQ_STATE_INITIALIZED,
    DAQ_STATE_STARTED,
    DAQ_STATE_STOPPED,
    DAQ_STATE_UNKNOWN,
    MAX_DAQ_STATE
} DAQ_State;

typedef struct _daq_stats
{
    uint64_t hw_packets_received;       /* Packets received by the hardware */
    uint64_t hw_packets_dropped;        /* Packets dropped by the hardware */
    uint64_t packets_received;          /* Packets received by this instance */
    uint64_t packets_filtered;          /* Packets filtered by this instance's BPF */
    uint64_t packets_injected;          /* Packets injected by this instance */
    uint64_t verdicts[MAX_DAQ_VERDICT]; /* Counters of packets handled per-verdict. */
} DAQ_Stats_t;

#define DAQ_DP_TUNNEL_TYPE_NON_TUNNEL 0
#define DAQ_DP_TUNNEL_TYPE_GTP_TUNNEL 1
#define DAQ_DP_TUNNEL_TYPE_OTHER_TUNNEL 2

typedef struct _DAQ_DP_key_t {
    uint32_t af;                /* AF_INET or AF_INET6 */
    union {
        struct in_addr src_ip4;
        struct in6_addr src_ip6;
    } sa;
    union {
        struct in_addr dst_ip4;
        struct in6_addr dst_ip6;
    } da;
    uint8_t protocol;           /* TCP or UDP (IPPROTO_TCP or IPPROTO_UDP )*/
    uint16_t src_port;          /* TCP/UDP source port */
    uint16_t dst_port;          /* TCP/UDP destination port */
    uint16_t address_space_id;  /* Address Space ID */
    uint16_t tunnel_type;       /* Tunnel type */
    uint16_t vlan_id;           /* VLAN ID */
    uint16_t vlan_cnots;
} DAQ_DP_key_t;

/* DAQ module type flags */
#define DAQ_TYPE_FILE_CAPABLE   0x01    /* can read from a file */
#define DAQ_TYPE_INTF_CAPABLE   0x02    /* can open live interfaces */
#define DAQ_TYPE_INLINE_CAPABLE 0x04    /* can form an inline bridge */
#define DAQ_TYPE_MULTI_INSTANCE 0x08    /* can be instantiated multiple times */
#define DAQ_TYPE_NO_UNPRIV      0x10    /* can not run unprivileged */

/* DAQ module capability flags */
#define DAQ_CAPA_NONE           0x000   /* no capabilities */
#define DAQ_CAPA_BLOCK          0x001   /* can block packets */
#define DAQ_CAPA_REPLACE        0x002   /* can replace/modify packet data (up to the original data size) */
#define DAQ_CAPA_INJECT         0x004   /* can inject packets */
#define DAQ_CAPA_WHITELIST      0x008   /* can whitelist flows */
#define DAQ_CAPA_BLACKLIST      0x010   /* can blacklist flows */
#define DAQ_CAPA_UNPRIV_START   0x020   /* can call start() without root privileges */
#define DAQ_CAPA_BREAKLOOP      0x040   /* can call breakloop() to break acquisition loop */
#define DAQ_CAPA_BPF            0x080   /* can call set_filter() to establish a BPF */
#define DAQ_CAPA_DEVICE_INDEX   0x100   /* can consistently fill the device_index field in DAQ_PktHdr */
#define DAQ_CAPA_INJECT_RAW     0x200   /* injection of raw packets (no layer-2 headers) */
#define DAQ_CAPA_RETRY          0x400   /* resend packet to Snort after brief delay. */

typedef struct _daq_module DAQ_Module_t;

#endif /* _DAQ_COMMON_H */
