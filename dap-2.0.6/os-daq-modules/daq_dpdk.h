#ifndef __DAQ_DPDK_H__
#define __DAQ_DPDK_H__



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <species.h>

#include <daq_api.h>
#include <sfbpf.h>
#include <sfbpf_dlt.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_cycles.h>



#define DAQ_DPDK_VERSION 2

//MBUF configuration
#define NUM_MBUFS           8192//0x10000
#define MBUF_CACHE_SIZE     512
#define BURST_SIZE          256

#define MAX_ARGS            64

#define MAX_NIC_PORT_NUM    4
#define MAX_QUEUE_NUM       16
#define USI_MAX_CORE_NUM    64

#define MAX_DP_AP_NUM       16      //MAX Applications

#define RX_RING_NUM 1
#define TX_RING_NUM 1

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096

#define DPDKINST_STARTED       0x1

#define DAQ_DPDK_SECONDARY_EPFD_RETRY       5

#define DAQ_DPDK_SECONDARY_INIT_DELAY       15   //Seconds
#define DAQ_DPDK_SECONDARY_EPFD_DELAY       5

//#define RX_CNT_TRACK
//#define RX_CSUM_TRACK

//IPC
#define DAQ_DPDK_RING_MSG_TOLERATE              8
#define DAQ_DPDK_RING_MSG_QUEUE_SIZE            DAQ_DPDK_RING_MSG_TOLERATE
#define DAQ_DPDK_RING_MSG_DATA_LEN              8192     //Message maximum data size, change this accordingly
#define DAQ_DPDK_RING_MSG_POOL_SIZE             1024
#define DAQ_DPDK_RING_MSG_POOL_CACHE            32
#define DAQ_DPDK_RING_MSG_HB_LOST_MAX           50      // 50<<0x01, 100 seconds

#define DAQ_DPDK_RING_PKTMBUF_QUEUE_SIZE        (0x10000)

#ifdef BUILD_SP_SEALION
    #define DAQ_DPDK_POWER_CTL
#endif
#define DAQ_DPDK_WITH_MINERVA
//#define DAQ_DPDK_POWER_FREQ_CTL

//#define DAQ_DPDK_PKT_FORWARD

typedef enum _DAQ_DPDK_MBUF_TYPE
{
#ifdef DAQ_DPDK_PKT_FORWARD
    MPOOL_PKT_TX = 0,
#endif
    MPOOL_PKT_RX,
    MPOOL_IPCRSEQ,
    DAQ_MPOOL_COUNT
} DAQ_DPDK_MPOOL_TYPE;

typedef enum _DAQ_DPDK_RING_TYPE
{
    RING_INTER_HB = 0,
    RING_MASTER_STATS,
    RING_IPC_PCREQ,
    RING_IPC_PCRSP,
#ifdef DAQ_DPDK_PKT_FORWARD
    RING_FW_PKT,
#endif
    DAQ_RING_COUNT
} DAQ_DPDK_RING_TYPE;

typedef struct _EtherHdr
{
    uint8_t ether_dst[6];
    uint8_t ether_src[6];
    uint16_t ether_type;

} EtherHdr;

typedef struct _DAQ_MASTER_STATS
{
    uint64_t st_seq;
    uint64_t daq_mpool_fail_cnt[DAQ_MPOOL_COUNT];
    uint64_t ap_mpool_fail_cnt[AP_MPOOL_COUNT];
} DAQ_MASTER_STATS;

typedef enum __dpdk_port_work_mode
{
	DPDK_PORT_RX,
	DPDK_PORT_TX,
	DPDK_PORT_RXTX,
}dpdk_port_work_mode;

typedef struct __Dpdk_Power_Heuristic
{
    int intr_en;
    uint64_t prev_tsc_power;
}Dpdk_Power_Heuristic;

typedef struct _dpdk_instance
{
    struct _dpdk_instance *next;
    struct _dpdk_instance *peer;
    uint8_t rx_queue_s;
    uint8_t tx_queue_s;
    uint8_t rx_queue_e;
    uint8_t tx_queue_e;
    uint8_t rx_queue_h;
    uint8_t tx_queue_h;
    uint8_t n_rx_queue;
    uint8_t n_tx_queue;
    uint32_t flags;
    uint32_t port_mode;
    int port;
    int fw_port;
    int index;
    int tx_start;
    int tx_end;
    int sigfd;
    int epfd;
    unsigned lcore_ids[MAX_QUEUE_NUM];
    volatile int break_loop;
    pthread_t tid;

    struct rte_mempool *daq_mpools[DAQ_MPOOL_COUNT][MAX_QUEUE_NUM];
    struct rte_ring *daq_rings[DAQ_RING_COUNT][MAX_QUEUE_NUM];

    struct rte_mempool *ap_mpools[AP_MPOOL_COUNT][MAX_QUEUE_NUM];
    struct rte_ring *ap_rings[AP_RING_COUNT][MAX_QUEUE_NUM];

    struct rte_mbuf *tx_burst[BURST_SIZE * RX_RING_NUM];

    void *sf_mbuf_ssn;
} DpdkInstance;

typedef struct _dpdk_context
{
    char *device;
    char *filter;
    uint8_t cfl_unity;
    uint8_t n_port;
    uint8_t naf_port;
    uint16_t n_port_queue;
    uint64_t lcore_utilize_flag;
    DpdkInstance *instances[MAX_NIC_PORT_NUM];
    DpdkInstance *rx_ins;
    Dpdk_Power_Heuristic *power_heurs;
    ApDpLoadInfo *ap_dpl;
    struct rte_mempool *daq_mpool[DAQ_MPOOL_COUNT];
    struct rte_ring *daq_ring[DAQ_RING_COUNT];
    struct rte_mempool *ap_mpool[DAQ_DP_MP_NUMA_NODE_NUM][AP_MPOOL_COUNT];
    struct rte_ring *ap_ring[AP_RING_COUNT];
    DAQ_MASTER_STATS m_stats;
    uint64_t st_seq_queues[MAX_NIC_PORT_NUM][MAX_QUEUE_NUM];
    uint64_t st_seq_aps[MAX_DP_AP_NUM];
    uint8_t msg_ring_aps[MAX_DP_AP_NUM];
    uint64_t pq_stack_dbm;
    void *mbuf_cfl_dp;
    int snaplen;
    int timeout;
    int debug;
    int epfds[MAX_NIC_PORT_NUM][MAX_QUEUE_NUM];
    int socfds[MAX_NIC_PORT_NUM][MAX_QUEUE_NUM];
    enum rte_proc_type_t proc_type;
    int mulp_sync_count;
    int intf_count;
    volatile int break_loop;
    int cflags;
    struct sfbpf_program fcode;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
    uint64_t mbuf_stats;
} Dpdk_Context_t;

typedef uint8_t  portid_t;
#define RTE_PORT_ALL            (~(portid_t)0x0)
#define RSS_HASH_KEY_LENGTH 64

struct rss_type_info {
    char str[32];
    uint64_t rss_type;
};

typedef struct __pktcnt_msg
{
    int rtn;
    daq_sf_req_type msg_type;
    void *msg_ptr;
}pktcnt_msg;

#define STD_BUF  1024

extern char log_buf[STD_BUF+1];
extern int daq_dpdk_log_daemon;

static inline void DAQ_RTE_LOG(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);

    if ( daq_dpdk_log_daemon ) {
        vsnprintf(log_buf, STD_BUF, format, ap);
        log_buf[STD_BUF] = '\0';
        syslog(LOG_DAEMON | LOG_NOTICE, "%s", log_buf);
    }
    else {
        vfprintf(stderr, format, ap);
    }

    va_end(ap);
}

#ifdef LOG_DEEP
#define DAQ_RTE_LOG_DEEP(fmt, ...)        DAQ_RTE_LOG(fmt, ##__VA_ARGS__)
#else
#define DAQ_RTE_LOG_DEEP(fmt, ...)
#endif

#endif  /*End of __DAQ_DPDK_H__*/
