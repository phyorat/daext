/*
** Copyright (C) 2016
**     University of Science and Technology of China.  All rights reserved.
** Author: Tiwei Bie <btw () mail ustc edu cn>
**         Jiaxin Liu <jiaxin10 () mail ustc edu cn>
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
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <daq_api.h>
#include <sfbpf.h>
#include <sfbpf_dlt.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>

#define DAQ_DPDK_VERSION 2

#define NUM_MBUFS           8192//0x10000
#define MBUF_CACHE_SIZE     512
#define BURST_SIZE          256

#define MAX_ARGS            64

#define MAX_QUEUE_NUM       16

#define RX_RING_NUM 1
#define TX_RING_NUM 1

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096

//#define RX_CNT_TRACK

static uint8_t rss_intel_key[40] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

static const struct rte_eth_conf port_conf_default = {
        .rxmode = {
            .mq_mode    = ETH_MQ_RX_RSS,
            .split_hdr_size = 0,
            .header_split   = 0, /**< Header Split disabled */
            .hw_ip_checksum = 1, /**< IP checksum offload enabled */
            .hw_vlan_filter = 0, /**< VLAN filtering disabled */
            .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
            .hw_strip_crc   = 0, /**< CRC stripped by hardware */
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = rss_intel_key,
                .rss_hf = ETH_RSS_PROTO_MASK,
            },
        },
        .txmode = {
            .mq_mode = ETH_MQ_TX_NONE,
        },
};

typedef struct _dpdk_instance
{
    struct _dpdk_instance *next;
    struct _dpdk_instance *peer;
#define DPDKINST_STARTED       0x1
    uint32_t flags;
    enum rte_proc_type_t proc_type;
    int rx_rings;
    int tx_rings;
    int rx_queue_s;
    int tx_queue_s;
    int rx_queue_e;
    int tx_queue_e;
    int port;
    int index;
    int tx_start;
    int tx_end;
    struct rte_mempool *mbuf_pool;
    struct rte_mempool *mbuf_pools[MAX_QUEUE_NUM];
    struct rte_mbuf *tx_burst[BURST_SIZE * RX_RING_NUM];
} DpdkInstance;

typedef struct _dpdk_context
{
    char *device;
    char *filter;
    int snaplen;
    int timeout;
    int debug;
    DpdkInstance *instances;
    int intf_count;
    struct sfbpf_program fcode;
    volatile int break_loop;
    int promisc_flag;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
} Dpdk_Context_t;

static void dpdk_daq_reset_stats(void *handle);

#ifdef RX_CNT_TRACK
static void
nic_stats_display(uint8_t port_id)
{
    struct rte_eth_stats stats;
    uint8_t i;

    static const char *nic_stats_border = "########################";

    rte_eth_stats_get(port_id, &stats);
    printf("\n  %s NIC statistics for port %-2d %s\n",
           nic_stats_border, port_id, nic_stats_border);

    printf("  RX-packets: %-10"PRIu64"  RX-errors:  %-10"PRIu64
           "  RX-bytes:  %-10"PRIu64"\n", stats.ipackets, stats.ierrors,
           stats.ibytes);
    printf("  RX-nombuf:  %-10"PRIu64"\n", stats.rx_nombuf);
    printf("  TX-packets: %-10"PRIu64"  TX-errors:  %-10"PRIu64
           "  TX-bytes:  %-10"PRIu64"\n", stats.opackets, stats.oerrors,
           stats.obytes);

    printf("\n");
    for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
        printf("  Stats reg %2d RX-packets: %-10"PRIu64
               "  RX-errors: %-10"PRIu64
               "  RX-bytes: %-10"PRIu64"\n",
               i, stats.q_ipackets[i], stats.q_errors[i], stats.q_ibytes[i]);
    }

    printf("\n");
    for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
        printf("  Stats reg %2d TX-packets: %-10"PRIu64
               "  TX-bytes: %-10"PRIu64"\n",
               i, stats.q_opackets[i], stats.q_obytes[i]);
    }

    printf("  %s############################%s\n",
           nic_stats_border, nic_stats_border);
}

static void
nic_xstats_display(uint8_t port_id)
{
    struct rte_eth_xstat_name *xstats_names;
    struct rte_eth_xstat *xstats;
    int len, ret, i;
    static const char *nic_stats_border = "########################";

    len = rte_eth_xstats_get_names(port_id, NULL, 0);
    if (len < 0) {
        printf("Cannot get xstats count\n");
        return;
    }
    xstats = malloc(sizeof(xstats[0]) * len);
    if (xstats == NULL) {
        printf("Cannot allocate memory for xstats\n");
        return;
    }

    xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * len);
    if (xstats_names == NULL) {
        printf("Cannot allocate memory for xstat names\n");
        free(xstats);
        return;
    }
    if (len != rte_eth_xstats_get_names(
            port_id, xstats_names, len)) {
        printf("Cannot get xstat names\n");
        goto err;
    }

    printf("###### NIC extended statistics for port %-2d #########\n",
               port_id);
    printf("%s############################\n",
               nic_stats_border);
    ret = rte_eth_xstats_get(port_id, xstats, len);
    if (ret < 0 || ret > len) {
        printf("Cannot get xstats\n");
        goto err;
    }

    //len = len>23 ? 23:len;

    for (i = 0; i < len; i++)
        printf("%s: %"PRIu64"\n",
            xstats_names[i].name,
            xstats[i].value);

    printf("%s############################\n",
               nic_stats_border);
err:
    free(xstats);
    free(xstats_names);
}
#endif

struct rss_type_info {
    char str[32];
    uint64_t rss_type;
};

typedef uint8_t  portid_t;
#define RTE_PORT_ALL            (~(portid_t)0x0)

static const struct rss_type_info rss_type_table[] = {
    { "ipv4", ETH_RSS_IPV4 },
    { "ipv4-frag", ETH_RSS_FRAG_IPV4 },
    { "ipv4-tcp", ETH_RSS_NONFRAG_IPV4_TCP },
    { "ipv4-udp", ETH_RSS_NONFRAG_IPV4_UDP },
    { "ipv4-sctp", ETH_RSS_NONFRAG_IPV4_SCTP },
    { "ipv4-other", ETH_RSS_NONFRAG_IPV4_OTHER },
    { "ipv6", ETH_RSS_IPV6 },
    { "ipv6-frag", ETH_RSS_FRAG_IPV6 },
    { "ipv6-tcp", ETH_RSS_NONFRAG_IPV6_TCP },
    { "ipv6-udp", ETH_RSS_NONFRAG_IPV6_UDP },
    { "ipv6-sctp", ETH_RSS_NONFRAG_IPV6_SCTP },
    { "ipv6-other", ETH_RSS_NONFRAG_IPV6_OTHER },
    { "l2-payload", ETH_RSS_L2_PAYLOAD },
    { "ipv6-ex", ETH_RSS_IPV6_EX },
    { "ipv6-tcp-ex", ETH_RSS_IPV6_TCP_EX },
    { "ipv6-udp-ex", ETH_RSS_IPV6_UDP_EX },
    { "port", ETH_RSS_PORT },
    { "vxlan", ETH_RSS_VXLAN },
    { "geneve", ETH_RSS_GENEVE },
    { "nvgre", ETH_RSS_NVGRE },
};

void
port_rss_hash_conf_show(portid_t port_id, const char rss_info[], int show_rss_key)
{
#define RSS_HASH_KEY_LENGTH 64
    struct rte_eth_rss_conf rss_conf;
    uint8_t rss_key[RSS_HASH_KEY_LENGTH];
    uint64_t rss_hf;
    uint8_t i;
    int diag;
    struct rte_eth_dev_info dev_info;
    uint8_t hash_key_size;

    if (0)//port_id_is_invalid(port_id, ENABLED_WARN))
        return;

    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);
    if (dev_info.hash_key_size > 0 &&
            dev_info.hash_key_size <= sizeof(rss_key))
        hash_key_size = dev_info.hash_key_size;
    else {
        RTE_LOG(ERR, EAL, "dev_info did not provide a valid hash key size\n");
        return;
    }

    rss_conf.rss_hf = 0;
    for (i = 0; i < RTE_DIM(rss_type_table); i++) {
        if (!strcmp(rss_info, rss_type_table[i].str))
            rss_conf.rss_hf = rss_type_table[i].rss_type;
    }

    /* Get RSS hash key if asked to display it */
    rss_conf.rss_key = (show_rss_key) ? rss_key : NULL;
    rss_conf.rss_key_len = hash_key_size;
    diag = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
    if (diag != 0) {
        switch (diag) {
        case -ENODEV:
            RTE_LOG(ERR, EAL, "port index %d invalid\n", port_id);
            break;
        case -ENOTSUP:
            RTE_LOG(ERR, EAL, "operation not supported by device\n");
            break;
        default:
            RTE_LOG(ERR, EAL, "operation failed - diag=%d\n", diag);
            break;
        }
        return;
    }
    rss_hf = rss_conf.rss_hf;
    if (rss_hf == 0) {
        RTE_LOG(ERR, EAL, "RSS disabled\n");
        return;
    }
    RTE_LOG(INFO, EAL, "RSS functions:\n ");
    for (i = 0; i < RTE_DIM(rss_type_table); i++) {
        if (rss_hf & rss_type_table[i].rss_type)
            printf("%s ", rss_type_table[i].str);
    }
    printf("\n");
    if (!show_rss_key)
        return;
    RTE_LOG(INFO, EAL, "RSS key:\n");
    for (i = 0; i < hash_key_size; i++)
        printf("%02X", rss_key[i]);
    printf("\n\n");
}

static int start_instance(Dpdk_Context_t *dpdkc, DpdkInstance *instance)
{
    unsigned sock_id;
    int rx_rings = RX_RING_NUM, tx_rings = TX_RING_NUM;
    struct rte_eth_conf port_conf = port_conf_default;
    int port, queue, ret;
    struct rte_eth_dev_info info;

    port = instance->port;
    rx_rings = instance->rx_rings;
    tx_rings = instance->tx_rings;

    RTE_LOG(INFO, EAL, "%s: RX-- q_start %d, q_end %d, q_all %d, ring_sizes %d\n",
    		__func__, instance->rx_queue_s, instance->rx_queue_e,
    		instance->rx_rings, RX_RING_SIZE);
    RTE_LOG(INFO, EAL, "%s: TX-- q_start %d, q_end %d, q_all %d, ring_sizes %d\n",
    		__func__, instance->tx_queue_s, instance->tx_queue_e,
    		instance->tx_rings, RX_RING_SIZE);

    if ( RTE_PROC_SECONDARY == instance->proc_type ) {
    	RTE_LOG(INFO, EAL, "%s: Secondary process, No Configuration of RTE_ETH\n", __func__);
    	return DAQ_SUCCESS;
    }

    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret != 0)
    {
        DPE(dpdkc->errbuf, "%s: Couldn't configure port %d\n", __FUNCTION__, port);
        return DAQ_ERROR;
    }

    rte_eth_dev_info_get(port, &info);
    info.default_rxconf.rx_drop_en = 1;
    info.default_rxconf.rx_thresh.pthresh = 16;
    info.default_rxconf.rx_thresh.hthresh = 16;
    RTE_LOG(INFO, EAL, "%s: RX-- Initialing port %d with config: rx_thresh.pthresh %d, "
            "rx_thresh.hthresh %d, rx_thresh.wthresh %d, "
            "rx_free_thresh %d, rx_deferred_start %d\n", __func__, port,
            info.default_rxconf.rx_thresh.pthresh,
            info.default_rxconf.rx_thresh.hthresh,
            info.default_rxconf.rx_thresh.wthresh,
            info.default_rxconf.rx_free_thresh,
            info.default_rxconf.rx_deferred_start);
    for (queue = 0; queue < rx_rings; queue++)
    {
        sock_id = rte_lcore_to_socket_id(4+queue);
        RTE_LOG(INFO, EAL, "%s: queue %d, ring_size %d, sock_id %d\n",
                __func__, queue, RX_RING_SIZE, sock_id);
        ret = rte_eth_rx_queue_setup(port, queue, RX_RING_SIZE,
                sock_id,//rte_eth_dev_socket_id(port),
                &info.default_rxconf,
                instance->mbuf_pools[queue]);
        if (ret != 0)
        {
            DPE(dpdkc->errbuf, "%s: Couldn't setup rx queue %d for port %d\n", __FUNCTION__, queue, port);
            return DAQ_ERROR;
        }
    }

    for (queue = 0; queue < tx_rings; queue++)
    {
        ret = rte_eth_tx_queue_setup(port, queue, TX_RING_SIZE,
                rte_eth_dev_socket_id(port),
                NULL);
        if (ret != 0)
        {
            DPE(dpdkc->errbuf, "%s: Couldn't setup tx queue %d for port %d\n", __FUNCTION__, queue, port);
            return DAQ_ERROR;
        }
    }

    ret = rte_eth_dev_start(instance->port);
    if (ret != 0)
    {
        DPE(dpdkc->errbuf, "%s: Couldn't start device for port %d\n", __FUNCTION__, port);
        return DAQ_ERROR;
    }

    port_rss_hash_conf_show(instance->port, "ipv4", 1);

    instance->flags |= DPDKINST_STARTED;

    if (dpdkc->promisc_flag)
        rte_eth_promiscuous_enable(instance->port);

    return DAQ_SUCCESS;
}

static void destroy_instance(DpdkInstance *instance)
{
    int i;

    if (instance)
    {
        if (instance->flags & DPDKINST_STARTED)
        {
            for (i = instance->tx_start; i < instance->tx_end; i++)
                rte_pktmbuf_free(instance->tx_burst[i]);

            rte_eth_dev_stop(instance->port);
            instance->flags &= ~DPDKINST_STARTED;
        }

        free(instance);
    }
}

static DpdkInstance *create_instance(const char *device, DpdkInstance *parent, char *errbuf, size_t errlen)
{
    unsigned sock_id = rte_socket_id();
    DpdkInstance *instance;
    int port, i, queue = 0, q_step = 1, queue_cnt = 1;
    char poolname[64];
    int qn_strlen;
    static int index = 0;

    instance = calloc(1, sizeof(DpdkInstance));
    if (!instance)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate a new instance structure.", __FUNCTION__);
        goto err;
    }

    instance->index = index;
    index++;

    if (strncmp(device, "dpdk", 4) != 0 || sscanf(&device[4], "%d", &port) != 1)
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!", __FUNCTION__, device);
        goto err;
    }

    instance->port = port;

    if ( strlen(device) > 8 )
    {
        if ( '#' == *(device+5) && 0 < sscanf(device+6, "%d", &queue_cnt) ) {
            RTE_LOG(INFO, EAL, "%s: Use Rx Queue on Port %d, Total %d...\n", __FUNCTION__, port, queue_cnt);
        }
        else {
            snprintf(errbuf, errlen, "%s: Invalid interface queue_cnt specification: '%s'!", __FUNCTION__, device);
            goto err;
        }

        if ( queue_cnt > 9 )
            qn_strlen = 8;
        else
            qn_strlen = 7;

        if ( '@' == *(device+qn_strlen) && 0 < sscanf(device+qn_strlen+1, "%d", &queue) ) {
            RTE_LOG(INFO, EAL, "%s: Use Rx Queue %d on Port %d, Total %d...\n", __FUNCTION__, queue, port, queue_cnt);
            q_step = 1;
        }
        else {
            snprintf(errbuf, errlen, "%s: Invalid interface queue_idx specification: '%s'!", __FUNCTION__, device);
            goto err;
        }
    }

    instance->rx_queue_s = queue;
    instance->rx_queue_e = queue+q_step;
    instance->rx_rings = queue_cnt;

    instance->tx_queue_s = 0;//queue;
    instance->tx_queue_e = 0;//queue+q_step;
    instance->tx_rings = 0;//queue_cnt;

    instance->proc_type = rte_eal_process_type();

    if ( RTE_PROC_SECONDARY == instance->proc_type ) {
    	RTE_LOG(INFO, EAL, "%s: Secondary Process\n", __func__);

        snprintf(poolname, sizeof(poolname), "MBUF_POOL_S%dQ%d", sock_id, queue);//%d", port);

        RTE_LOG(INFO, EAL, "%s: MBUFS 0x%x, CACHE_SIZE 0x%x, sock_mp %s\n",
                __func__, NUM_MBUFS, MBUF_CACHE_SIZE, poolname);
    	instance->mbuf_pool = rte_mempool_lookup(poolname);

        if ( NULL == instance->mbuf_pool ) {
            snprintf(errbuf, errlen, "%s: Couldn't create mbuf pool!\n", __FUNCTION__);
            goto err;
        }

    	//rte_ring_lookup();
    }
    else {
    	RTE_LOG(INFO, EAL, "%s: Primary Process\n", __func__);
    	for (i=0; i<queue_cnt; i++) {
    	    sock_id = rte_lcore_to_socket_id(4+i);
    	    snprintf(poolname, sizeof(poolname), "MBUF_POOL_S%dQ%d", sock_id, i);//%d", port);

    	    RTE_LOG(INFO, EAL, "%s: MBUFS 0x%x, CACHE_SIZE 0x%x, sock_mp %s\n",
    	            __func__, NUM_MBUFS, MBUF_CACHE_SIZE, poolname);
    	    instance->mbuf_pools[i] = rte_pktmbuf_pool_create(poolname, NUM_MBUFS,
    	            MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, sock_id);//rte_socket_id());

    	    if ( NULL == instance->mbuf_pools[i] ) {
    	        snprintf(errbuf, errlen, "%s: Couldn't create mbuf pool!\n", __FUNCTION__);
    	        goto err;
    	    }

    	    if ( i == queue )
    	        instance->mbuf_pool = instance->mbuf_pools[i];
    	}
    }

    return instance;

err:
    destroy_instance(instance);
    return NULL;
}

static int create_bridge(Dpdk_Context_t *dpdkc, const int port1, const int port2)
{
    DpdkInstance *instance, *peer1, *peer2;

    peer1 = peer2 = NULL;
    for (instance = dpdkc->instances; instance; instance = instance->next)
    {
        if (instance->port == port1)
            peer1 = instance;
        else if (instance->port == port2)
            peer2 = instance;
    }

    if (!peer1 || !peer2)
        return DAQ_ERROR_NODEV;

    peer1->peer = peer2;
    peer2->peer = peer1;

    return DAQ_SUCCESS;
}

static int dpdk_close(Dpdk_Context_t *dpdkc)
{
    DpdkInstance *instance;

    if (!dpdkc)
        return -1;

    /* Free all of the device instances. */
    while ((instance = dpdkc->instances) != NULL)
    {
        dpdkc->instances = instance->next;
        destroy_instance(instance);
    }

    sfbpf_freecode(&dpdkc->fcode);

    dpdkc->state = DAQ_STATE_STOPPED;

    return 0;
}

static int parse_args(char *inputstring, char **argv)
{
    char **ap;

    for (ap = argv; (*ap = strsep(&inputstring, " \t")) != NULL;)
    {
        if (**ap != '\0')
            if (++ap >= &argv[MAX_ARGS])
                break;
    }
    return ap - argv;
}

static int dpdk_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    Dpdk_Context_t *dpdkc;
    DpdkInstance *instance;
    DAQ_Dict *entry;
    char intf[IFNAMSIZ];
    int num_intfs = 0;
    int port1, port2, ports;
    size_t len;
    char *dev;
    int ret, rval = DAQ_ERROR;
    char *dpdk_args = NULL;
    char argv0[] = "fake";
    char *argv[MAX_ARGS + 1];
    int argc;

    dpdkc = calloc(1, sizeof(Dpdk_Context_t));
    if (!dpdkc)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new DPDK context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dpdkc->device = strdup(config->name);
    if (!dpdkc->device)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dpdkc->snaplen = config->snaplen;
    dpdkc->timeout = (config->timeout > 0) ? (int) config->timeout : -1;
    dpdkc->promisc_flag = (config->flags & DAQ_CFG_PROMISC);

    /* Import the DPDK arguments */
    for (entry = config->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, "dpdk_args"))
            dpdk_args = entry->value;
    }

    if (!dpdk_args)
    {
        snprintf(errbuf, errlen, "%s: Missing EAL arguments!", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    argv[0] = argv0;
    argc = parse_args(dpdk_args, &argv[1]) + 1;
    optind = 1;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        snprintf(errbuf, errlen, "%s: Invalid EAL arguments!\n", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    ports = rte_eth_dev_count();
    if (ports == 0)
    {
        snprintf(errbuf, errlen, "%s: No Ethernet ports!\n", __FUNCTION__);
        rval = DAQ_ERROR_NODEV;
        goto err;
    }

    dev = dpdkc->device;
    if ( *dev == ':' )
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification1: '%s'!", __FUNCTION__, dpdkc->device);
        goto err;
    }

    if (((len = strlen(dev)) > 0 && *(dev + len - 1) == ':'))
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification2: '%s'!", __FUNCTION__, dpdkc->device);
        goto err;
    }

    if ((config->mode == DAQ_MODE_PASSIVE && strstr(dev, "::")))
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification3: '%s'!", __FUNCTION__, dpdkc->device);
        goto err;
    }

    while (*dev != '\0')
    {
        len = strcspn(dev, ":");
        if (len >= sizeof(intf))
        {
            snprintf(errbuf, errlen, "%s: Interface name too long! (%zu)", __FUNCTION__, len);
            goto err;
        }
        if (len != 0)
        {
            dpdkc->intf_count++;
            if (dpdkc->intf_count > ports)
            {
                snprintf(errbuf, errlen, "%s: Using more than %d interfaces is not valid!",
                         __FUNCTION__, ports);
                goto err;
            }
            snprintf(intf, len + 1, "%s", dev);
            instance = create_instance(intf, dpdkc->instances, errbuf, errlen);
            if (!instance)
                goto err;

            instance->next = dpdkc->instances;
            dpdkc->instances = instance;
            num_intfs++;
            if (config->mode != DAQ_MODE_PASSIVE)
            {
                if (num_intfs == 2)
                {
                    port1 = dpdkc->instances->next->port;
                    port2 = dpdkc->instances->port;

                    if (create_bridge(dpdkc, port1, port2) != DAQ_SUCCESS)
                    {
                        snprintf(errbuf, errlen, "%s: Couldn't create the bridge between dpdk%d and dpdk%d!",
                                 __FUNCTION__, port1, port2);
                        goto err;
                    }
                    num_intfs = 0;
                }
                else if (num_intfs > 2)
                    break;
            }
        }
        else
            len = 1;
        dev += len;
    }

    /* If there are any leftover unbridged interfaces and we're not in Passive mode, error out. */
    if (!dpdkc->instances || (config->mode != DAQ_MODE_PASSIVE && num_intfs != 0))
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!",
                __FUNCTION__, dpdkc->device);
        goto err;
    }

    /* Initialize other default configuration values. */
    dpdkc->debug = 0;

    /* Import the configuration dictionary requests. */
    for (entry = config->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, "debug"))
            dpdkc->debug = 1;
    }

    dpdkc->state = DAQ_STATE_INITIALIZED;

    *ctxt_ptr = dpdkc;
    return DAQ_SUCCESS;

err:
    if (dpdkc)
    {
        dpdk_close(dpdkc);
        if (dpdkc->device)
            free(dpdkc->device);
        free(dpdkc);
    }
    return rval;
}

static int dpdk_daq_set_filter(void *handle, const char *filter)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    struct sfbpf_program fcode;

    if (dpdkc->filter)
        free(dpdkc->filter);

    dpdkc->filter = strdup(filter);
    if (!dpdkc->filter)
    {
        DPE(dpdkc->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(dpdkc->snaplen, DLT_EN10MB, &fcode, dpdkc->filter, 1, 0) < 0)
    {
        DPE(dpdkc->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&dpdkc->fcode);
    dpdkc->fcode.bf_len = fcode.bf_len;
    dpdkc->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

static int dpdk_daq_start(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;

    for (instance = dpdkc->instances; instance; instance = instance->next)
    {
        if (start_instance(dpdkc, instance) != DAQ_SUCCESS)
            return DAQ_ERROR;
    }

    dpdk_daq_reset_stats(handle);

    dpdkc->state = DAQ_STATE_STARTED;

    return DAQ_SUCCESS;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
    DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};

static int dpdk_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    const uint8_t *data;
    uint16_t len;
    int c = 0, burst_size;
    int i;
    int queue;
    struct timeval ts;
#ifdef RX_CNT_TRACK
    static uint64_t queue_cnt = 0;
    static uint64_t show_cnt = 0;
#endif

    daqhdr.egress_index = DAQ_PKTHDR_UNKNOWN;
    daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
    daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
    daqhdr.flags = 0;
    daqhdr.opaque = 0;
    daqhdr.priv_ptr = NULL;
    daqhdr.address_space_id = 0;

    while (c < cnt || cnt <= 0)
    {
        struct rte_mbuf *bufs[BURST_SIZE];

        for (instance = dpdkc->instances; instance; instance = instance->next) {
            /* Has breakloop() been called? */
            if ( unlikely( dpdkc->break_loop ) ) {
                dpdkc->break_loop = 0;
                return 0;
            }

            for (queue = instance->rx_queue_s; queue < instance->rx_queue_e; queue++) {
                gettimeofday(&ts, NULL);

                burst_size = BURST_SIZE;

                const uint16_t nb_rx =
                    rte_eth_rx_burst(instance->port, queue,
                            bufs, burst_size);
#ifdef RX_CNT_TRACK
                if ( unlikely(show_cnt++ & 0x1000000) ) {
                    //nic_xstats_display(instance->port);
                    //nic_stats_display(instance->port);
                    show_cnt = 0;
                    printf("Queue %d Rx Counts: %"PRIu64"\n", queue, queue_cnt);
                }
#endif

                if (unlikely(nb_rx == 0))
                    continue;

#ifdef RX_CNT_TRACK
                queue_cnt += nb_rx;
#endif

                for (i = 0; i < nb_rx; i++) {
                    verdict = DAQ_VERDICT_PASS;

                    data = rte_pktmbuf_mtod(bufs[i], void *);
                    len = rte_pktmbuf_data_len(bufs[i]);

                    dpdkc->stats.hw_packets_received++;
                    daqhdr.ts = ts;
                    daqhdr.caplen = len;
                    daqhdr.pktlen = len;
                    daqhdr.ingress_index = instance->index;

#ifdef RX_CNT_TRACK_HASH
                    printf("p_toeplitz_hash 0x%x\n", bufs[i]->hash.rss);
#endif

                    if ( likely(NULL!=callback) ) {
                        verdict = callback(user, &daqhdr, data);
                        if (verdict >= MAX_DAQ_VERDICT)
                            verdict = DAQ_VERDICT_PASS;
                        dpdkc->stats.verdicts[verdict]++;
                        verdict = verdict_translation_table[verdict];
                    }
                    dpdkc->stats.packets_received++;
                    c++;

                    rte_pktmbuf_free(bufs[i]);
                }
            }
        }

        return 0;
    }

    return 0;
}

static int dpdk_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;

    struct rte_mbuf *m;

    /* Find the instance that the packet was received on. */
    for (instance = dpdkc->instances; instance; instance = instance->next)
    {
        if (instance->index == hdr->ingress_index)
            break;
    }

    if (!instance)
    {
        DPE(dpdkc->errbuf, "%s: Unrecognized ingress interface specified: %u",
                __FUNCTION__, hdr->ingress_index);
        return DAQ_ERROR_NODEV;
    }

    if (!reverse && !(instance = instance->peer))
    {
        DPE(dpdkc->errbuf, "%s: Specified ingress interface (%u) has no peer for forward injection.",
                __FUNCTION__, hdr->ingress_index);
        return DAQ_ERROR_NODEV;
    }

    m = rte_pktmbuf_alloc(instance->mbuf_pool);
    if (!m)
    {
        DPE(dpdkc->errbuf, "%s: Couldn't allocate memory for packet.",
                __FUNCTION__);
        return DAQ_ERROR_NOMEM;
    }

    rte_memcpy(rte_pktmbuf_mtod(m, void *), packet_data, len);

    const uint16_t nb_tx = rte_eth_tx_burst(instance->port, 0, &m, 1);

    if (unlikely(nb_tx == 0))
    {
        DPE(dpdkc->errbuf, "%s: Couldn't send packet. Try again.", __FUNCTION__);
        rte_pktmbuf_free(m);
        return DAQ_ERROR_AGAIN;
    }

    return DAQ_SUCCESS;
}

static int dpdk_daq_breakloop(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    dpdkc->break_loop = 1;

    return DAQ_SUCCESS;

}

static int dpdk_daq_stop(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    dpdk_close(dpdkc);

    return DAQ_SUCCESS;
}

static void dpdk_daq_shutdown(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    dpdk_close(dpdkc);
    if (dpdkc->device)
        free(dpdkc->device);
    if (dpdkc->filter)
        free(dpdkc->filter);
    free(dpdkc);
}

static DAQ_State dpdk_daq_check_status(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    return dpdkc->state;
}

static int dpdk_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    rte_memcpy(stats, &dpdkc->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static void dpdk_daq_reset_stats(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    memset(&dpdkc->stats, 0, sizeof(DAQ_Stats_t));
}

static int dpdk_daq_get_snaplen(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    return dpdkc->snaplen;
}

static uint32_t dpdk_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
        DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF |
        DAQ_CAPA_DEVICE_INDEX;
}

static int dpdk_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *dpdk_daq_get_errbuf(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    return dpdkc->errbuf;
}

static void dpdk_daq_set_errbuf(void *handle, const char *string)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    if (!string)
        return;

    DPE(dpdkc->errbuf, "%s", string);
}

static int dpdk_daq_get_device_index(void *handle, const char *device)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;
    int port;

    if (strncmp(device, "dpdk", 4) != 0 || sscanf(&device[4], "%d", &port) != 1)
        return DAQ_ERROR_NODEV;

    for (instance = dpdkc->instances; instance; instance = instance->next)
    {
        if (instance->port == port)
            return instance->index;
    }

    return DAQ_ERROR_NODEV;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t dpdk_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_API_VERSION,
    /* .module_version = */ DAQ_DPDK_VERSION,
    /* .name = */ "dpdk",
    /* .type = */ DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .initialize = */ dpdk_daq_initialize,
    /* .set_filter = */ dpdk_daq_set_filter,
    /* .start = */ dpdk_daq_start,
    /* .acquire = */ dpdk_daq_acquire,
    /* .inject = */ dpdk_daq_inject,
    /* .breakloop = */ dpdk_daq_breakloop,
    /* .stop = */ dpdk_daq_stop,
    /* .shutdown = */ dpdk_daq_shutdown,
    /* .check_status = */ dpdk_daq_check_status,
    /* .get_stats = */ dpdk_daq_get_stats,
    /* .reset_stats = */ dpdk_daq_reset_stats,
    /* .get_snaplen = */ dpdk_daq_get_snaplen,
    /* .get_capabilities = */ dpdk_daq_get_capabilities,
    /* .get_datalink_type = */ dpdk_daq_get_datalink_type,
    /* .get_errbuf = */ dpdk_daq_get_errbuf,
    /* .set_errbuf = */ dpdk_daq_set_errbuf,
    /* .get_device_index = */ dpdk_daq_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL
};

