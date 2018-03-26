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

#include "daq_dpdk.h"
#include "daq_dpdk_statsop.h"
#include "daq_dpdk_epfd_ipc.h"
#ifdef DAQ_DPDK_POWER_CTL
#include "daq_dpdk_power.h"
#endif

static DpdkInstance *create_instance(Dpdk_Context_t *dpdkc, const char *device, char *errbuf, size_t errlen);
//static int create_bridge(Dpdk_Context_t *dpdkc, const int port1, const int port2);

char log_buf[STD_BUF+1];
int daq_dpdk_log_daemon = 0;
int daq_dpdk_cassini = 0;
int gBreak_loop = 0;

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
#ifdef DAQ_DPDK_POWER_CTL
        .intr_conf = {
            .lsc = 1,
            .rxq = 1,
        },
#else
        .intr_conf = {
            .lsc = 0,
            .rxq = 1,
        },
#endif
};

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

DpdkInstance *Send_Instance = NULL;
DAQ_PktHdr_t daqhdr;

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
    DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};

daq_dpdk_mpool_collect dk_mbuf_coll [] =
{
#ifdef DAQ_DPDK_PKT_FORWARD
        {MPOOL_PKT_TX,       MR_ALL_QUEUES, "MPOOL_PKT_TX_S%dP%dQ%d",           NUM_MBUFS, RTE_MBUF_DEFAULT_BUF_SIZE, MBUF_CACHE_SIZE, 0, DAQ_DPDK_INN, 0},
#endif
        {MPOOL_PKT_RX,       MR_ALL_QUEUES, "MPOOL_PKT_RX_S%dP%dQ%d",           NUM_MBUFS, RTE_MBUF_DEFAULT_BUF_SIZE, MBUF_CACHE_SIZE, 0, DAQ_DPDK_INN, 0},
        {MPOOL_IPCRSEQ,      MR_ALL_QUEUES, "MPOOL_IPCRSEQ_S%dP%dQ%d",
                DAQ_DPDK_RING_MSG_POOL_SIZE, DAQ_DPDK_RING_MSG_DATA_LEN, DAQ_DPDK_RING_MSG_POOL_CACHE, 0, DAQ_DPDK_INN, 0},
};

daq_dpdk_ring_collect dk_ring_coll [] =
{
        {RING_INTER_HB,      MR_ALL_QUEUES, "RING_INTER_HB_S%dP%dQ%d",          DAQ_DPDK_RING_MSG_QUEUE_SIZE, RING_F_SP_ENQ | RING_F_SC_DEQ, DAQ_DPDK_INN},
        {RING_MASTER_STATS,  MR_ALL_QUEUES, "RING_MASTER_ST_S%dP%dQ%d",         DAQ_DPDK_RING_MSG_QUEUE_SIZE, RING_F_SP_ENQ | RING_F_SC_DEQ, DAQ_DPDK_INN},
        {RING_IPC_PCREQ,     MR_ALL_QUEUES, "RING_IPC_PCREQ_S%dP%dQ%d",         DAQ_DPDK_RING_MSG_QUEUE_SIZE, RING_F_SP_ENQ | RING_F_SC_DEQ, DAQ_DPDK_INN},
        {RING_IPC_PCRSP,     MR_ALL_QUEUES, "RING_IPC_PCRSP_S%dP%dQ%d",         DAQ_DPDK_RING_MSG_QUEUE_SIZE, RING_F_SP_ENQ | RING_F_SC_DEQ, DAQ_DPDK_INN},
#ifdef DAQ_DPDK_PKT_FORWARD
        {RING_FW_PKT,        MR_ALL_QUEUES, "RING_FW_PKT_S%dP%dQ%d",            DAQ_DPDK_RING_PKTMBUF_QUEUE_SIZE, RING_F_SP_ENQ | RING_F_SC_DEQ, DAQ_DPDK_INN},
#endif
};

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

    printf("\n");
    for (i = 0; i < len; i++) {
        if ( !strcmp("rx_good_packets", xstats_names[i].name)
                || !strcmp("rx_good_bytes", xstats_names[i].name) ) {
            printf("port %d--%s: %"PRIu64"\n", port_id, xstats_names[i].name, xstats[i].value);
        }
    }

    printf("%s############################\n",
               nic_stats_border);
err:
    free(xstats);
    free(xstats_names);
}
#endif

void
port_rss_hash_conf_show(portid_t port_id, const char rss_info[], int show_rss_key)
{
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
    DAQ_RTE_LOG("RSS functions:\n ");
    for (i = 0; i < RTE_DIM(rss_type_table); i++) {
        if (rss_hf & rss_type_table[i].rss_type)
            DAQ_RTE_LOG("%s ", rss_type_table[i].str);
    }
    DAQ_RTE_LOG("\n");
    if (!show_rss_key)
        return;
    DAQ_RTE_LOG("RSS key:\n");
    for (i = 0; i < hash_key_size; i++)
        DAQ_RTE_LOG("%02X", rss_key[i]);
    DAQ_RTE_LOG("\n\n");
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

static int parse_interface(const DAQ_Config_t *config, Dpdk_Context_t *dpdkc, char *errbuf, size_t errlen)
{
    size_t len;
    //int num_intfs = 0;
    //int port1, port2;
    char intf[IFNAMSIZ];
	char *dev;
    DpdkInstance *instance;

    dev = dpdkc->device;
    if ( *dev == ':' ) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification1: '%s'!", __FUNCTION__, dpdkc->device);
        return -1;
    }

    if (((len = strlen(dev)) > 0 && *(dev + len - 1) == ':')) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification2: '%s'!", __FUNCTION__, dpdkc->device);
        return -1;
    }

    if ((config->mode == DAQ_MODE_PASSIVE && strstr(dev, "::"))) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification3: '%s'!", __FUNCTION__, dpdkc->device);
        return -1;
    }

    dpdkc->n_port = 0;
    dpdkc->n_port_queue = 0;
    while (*dev != '\0') {
        len = strcspn(dev, ":");
        if (len >= sizeof(intf)) {
            snprintf(errbuf, errlen, "%s: Interface name too long! (%zu)", __FUNCTION__, len);
            return -1;
        }

        if (len != 0) {
            dpdkc->intf_count++;
            snprintf(intf, len + 1, "%s", dev);
            instance = create_instance(dpdkc, intf, errbuf, errlen);
            if (!instance)
            	return -1;

            /*instance->next = dpdkc->instances;
            dpdkc->instances = instance;*/
            dpdkc->instances[dpdkc->naf_port] = instance;
            if ( (instance->fw_port<0) || !(config->flags&DAQ_CFG_MINERVA) )
                dpdkc->n_port++;
            dpdkc->naf_port++;

            /*num_intfs++;
            if (config->mode != DAQ_MODE_PASSIVE) {
                if (num_intfs == 2) {
                    port1 = dpdkc->instances->next->port;
                    port2 = dpdkc->instances->port;

                    if (create_bridge(dpdkc, port1, port2) != DAQ_SUCCESS) {
                        snprintf(errbuf, errlen, "%s: Couldn't create the bridge between dpdk%d and dpdk%d!",
                                 __FUNCTION__, port1, port2);
                        return -1;
                    }
                    num_intfs = 0;
                }
                else if (num_intfs > 2)
                    break;
            }*/
        }
        else {
            len = 1;
        }

        dev += len;
    }

    /* If there are any leftover unbridged interfaces and we're not in Passive mode, error out. */
    if (/*!dpdkc->instances || */(config->mode != DAQ_MODE_PASSIVE && /*num_intfs*/dpdkc->n_port != 0)) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!",
                __FUNCTION__, dpdkc->device);
        return -1;
    }

    return 0;
}

#ifdef DAQ_DPDK_POWER_CTL
static int epfd_wait_get(Dpdk_Context_t *dpdkc)
{
    int epfd_retry = DAQ_DPDK_SECONDARY_EPFD_RETRY;

    //epfd
    while ( epfd_retry -- ) {
        dpdkc->rx_ins->epfd = epfd_client(dpdkc);
        if ( dpdkc->rx_ins->epfd >= 0 ) {
            break;
        }
        sleep(1);
    }
    if ( dpdkc->rx_ins->epfd < 0 ) {
        return DAQ_ERROR;
    }

    DAQ_RTE_LOG("%s: got epfd-%d\n", __func__, dpdkc->rx_ins->epfd);

    return 0;
}
#endif

static void destroy_instance(Dpdk_Context_t *dpdkc)
{
    uint8_t p_idx;
    int i;
    DpdkInstance *instance;

    for ( p_idx=0; p_idx<dpdkc->naf_port; p_idx++ ) {
        instance = dpdkc->instances[p_idx];
        if (instance) {
            if (instance->flags & DPDKINST_STARTED) {
                for (i = instance->tx_start; i < instance->tx_end; i++)
                    rte_pktmbuf_free(instance->tx_burst[i]);

                if ( RTE_PROC_PRIMARY == dpdkc->proc_type )
                    rte_eth_dev_stop(instance->port);
                instance->flags &= ~DPDKINST_STARTED;
            }

            free(instance);
            dpdkc->instances[p_idx] = NULL;
        }
    }
}

static int destroy_dpdkc(Dpdk_Context_t *dpdkc)
{
//    DpdkInstance *instance;

    if (!dpdkc)
        return -1;

    if ( RTE_PROC_PRIMARY == dpdkc->proc_type ) {
        RTE_LOG(INFO, EAL, "%s: Remove all epfd ipc fd\n", __func__);
        epfd_unlink_all(dpdkc);
    }

    /* Free all of the device instances. */
    //while ((instance = dpdkc->instances) != NULL)
        //dpdkc->instances = instance->next;
        //destroy_instance(instance);
    destroy_instance(dpdkc);

    sfbpf_freecode(&dpdkc->fcode);

    dpdkc->state = DAQ_STATE_STOPPED;

    return 0;
}

static DpdkInstance *create_instance(Dpdk_Context_t *dpdkc, const char *device, char *errbuf, size_t errlen)
{
    uint8_t intf_len = strlen(device);
    const char *p_intf;
    DpdkInstance *instance;
    int port = 0, queue = 0, q_step = 1, queue_cnt = 1;
    static int index = 0;

    if ( intf_len < 4 ) {
        snprintf(errbuf, errlen, "%s: Invalid device specification: '%s'!", __FUNCTION__, device);
        return NULL;
    }

    instance = calloc(1, sizeof(DpdkInstance));
    if ( NULL == instance) {
        snprintf(errbuf, errlen, "%s: Couldn't allocate a new instance structure.", __FUNCTION__);
        return NULL;
    }

    memset(instance, 0, sizeof(DpdkInstance));
    instance->index = index;
    index++;

    instance->fw_port = -1;

    //port
    p_intf = device;
    if ( !memcmp(p_intf, "psi", 3) ) {
        p_intf += 3;
        port = *p_intf - '0';
        if ( port >= MAX_NIC_PORT_NUM ) {
            snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!", __FUNCTION__, device);
            goto err;
        }

        p_intf += 1;
    }
    else if ( !memcmp(p_intf, "psd", 3) ) {
        p_intf += 3;
        port = *p_intf - '0';
        if ( port >= MAX_NIC_PORT_NUM ) {
            snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!", __FUNCTION__, device);
            goto err;
        }

        instance->fw_port = port;

        p_intf += 1;
    }

    //Queue Number And Queue Index
    if ( (intf_len>=6) && ('#' == *p_intf) ) {
        p_intf += 1;
        queue_cnt = atoi(p_intf);
        if ( queue_cnt > MAX_QUEUE_NUM ) {
            snprintf(errbuf, errlen, "%s: Invalid interface queue_cnt specification: '%s'!", __FUNCTION__, device);
            goto err;
        }

        if ( queue_cnt > 9 )
            p_intf += 2;
        else
            p_intf += 1;
    }

    if ( (intf_len>=8) && ('@' == *p_intf) ) {
        p_intf += 1;
        queue = atoi(p_intf);
        if ( queue >= queue_cnt ) {
            snprintf(errbuf, errlen, "%s: Invalid interface queue_idx specification: '%s'!", __FUNCTION__, device);
            goto err;
        }

        q_step = 1;
    }

    p_intf++;
    if ( (intf_len>=10) && ('&' == *p_intf) ) {
        p_intf += 1;
        instance->fw_port = atoi(p_intf);
        if ( instance->fw_port >= MAX_NIC_PORT_NUM ) {
            snprintf(errbuf, errlen, "%s: Invalid interface port(fw) : %d!", __FUNCTION__, instance->fw_port);
            goto err;
        }
    }

    printf("%s: Use Rx Queue %d on Port %d, Total %d...\n", __FUNCTION__, queue, port, queue_cnt);

    instance->port = port;
    instance->rx_queue_s = queue;
    instance->rx_queue_e = queue+q_step;
    instance->rx_queue_h = q_step;
    instance->n_rx_queue = queue_cnt;
    instance->tx_queue_s = 0;//queue;
    instance->tx_queue_e = 0;//queue+q_step;
    instance->tx_queue_h = 0;
    instance->n_tx_queue = 0;//queue_cnt;
    instance->port_mode = DPDK_PORT_RX;
    dpdkc->n_port_queue += queue_cnt;

    if (  0 == instance->index ) {
        dpdkc->rx_ins = instance;
    }
    else if ( instance->fw_port >=0 ) { //minerva
        /*instance->rx_queue_s = 0;
        instance->rx_queue_e = 0;
        instance->rx_queue_h = 0;
        instance->n_rx_queue = 0;*/

        instance->tx_queue_s = queue;
        instance->tx_queue_e = queue+queue_cnt;
        instance->tx_queue_h = queue_cnt;
        instance->n_tx_queue = queue_cnt;

        instance->port_mode = DPDK_PORT_TX;
        //Send_Instance = instance;
    }

    instance->tid = pthread_self();

    return instance;

err:
    //destroy_instance(instance);
    free(instance);
    return NULL;
}
/*
static int create_bridge(Dpdk_Context_t *dpdkc, const int port1, const int port2)
{
    uint8_t p_idx;
    DpdkInstance *instance, *peer1, *peer2;

    peer1 = peer2 = NULL;
    //for (instance = dpdkc->instances; instance; instance = instance->next) {
    for ( p_idx=0; p_idx<dpdkc->n_port; p_idx++ ) {
        instance = dpdkc->instances[p_idx];
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
*/

/*static int mbuf_lcore_getname(char *buf, int buflen,
        DpdkInstance *instance, unsigned sock_id, uint8_t qid, uint8_t type)
{
    switch (type) {
    case PKT_MBUF_POOL:
        if ( DPDK_PORT_TX == instance->port_mode ) {
            snprintf(buf, buflen, "MBUF_TX_POOL_S%dP%dQ%d",
                    sock_id, instance->port, qid);
        }
        else if ( DPDK_PORT_RX == instance->port_mode ) {
            snprintf(buf, buflen, "MBUF_RX_POOL_S%dP%dQ%d",
                    sock_id, instance->port, qid);
        }
        else {
            return -1;
        }
        break;
    case IPC_MSG_RING:
        snprintf(buf, buflen, "IPC_RING_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    case IPC_MSG_MBUF_POOL:
        snprintf(buf, buflen, "IPC_MPOOL_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    case IPC_MSG_RING_PC_RSP:
        snprintf(buf, buflen, "IPC_RING_PCRSP_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    case IPC_MSG_RING_PC_REQ:
        snprintf(buf, buflen, "IPC_RING_PCREQ_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    case IPC_RING_PKT_MBUF:
        snprintf(buf, buflen, "IPC_RING_PKTMBUF_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    case STATS_FLOW_MSG_RING:
        snprintf(buf, buflen, "SF_RING_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    case STATS_FLOW_MBUF_POOL:
        snprintf(buf, buflen, "SF_MBUF_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    case STATS_FLOW_MBUF_POOL_SSN:
        snprintf(buf, buflen, "SFSSN_MBUF_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    case STATS_FLOW_MBUF_CFL_POOL:
        snprintf(buf, buflen, "SF_MBUF_CFL_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    default:
        break;
    }

    return 0;
}

static int mbuf_ring_instance_sta(uint8_t attri, Dpdk_Context_t *dpdkc)
{
    if ( (MPOOL_PRIMARY_ONLY==attri
            || MPOOL_SINGLETON==attri) && !(dpdkc->cflags&DAQ_CFG_MINERVA) )
        return 0;
    else if ( (MPOOL_SECONDARY_ONLY==attri) && (dpdkc->cflags&DAQ_CFG_MINERVA) )
        return 0;

    return 1;
}*/

static void
mbuf_obj_init(struct rte_mempool *mp, __attribute__((unused)) void *arg,
        void *obj, unsigned i)
{
    memset(obj, 0, mp->elt_size);
}

static void *mpool_lcore_create(daq_dpdk_mpool_collect *dmcoll, signed sockidx,
        unsigned core_id, uint8_t port, uint8_t q_idx, uint8_t if_mp_pkt, char *errbuf, size_t errlen)
{
    unsigned sock_id;
    char namebuf[64];
    struct rte_mempool *dst_mpool;

    if ( -1 == sockidx ) {
        sock_id = rte_lcore_to_socket_id(core_id);
    }
    else {
        sock_id = sockidx;
    }

    snprintf(namebuf, sizeof(namebuf), dmcoll->name,
            sock_id, port, q_idx);
    if ( if_mp_pkt ) {
        dst_mpool = rte_pktmbuf_pool_create(namebuf, dmcoll->poolsize,
                dmcoll->poolcache, dmcoll->private_dlen, dmcoll->datalen, sock_id);
    }
    else {
        dst_mpool = rte_mempool_create(namebuf,
                dmcoll->poolsize,dmcoll->datalen,dmcoll->poolcache,dmcoll->private_dlen,
                NULL, NULL, NULL, NULL, sock_id, 0);
    }

    DAQ_RTE_LOG("%s: mpool(%s)--MBUFS 0x%x(0x%x), CACHE_SIZE 0x%x\n",
            __func__, namebuf, dmcoll->poolsize, dmcoll->datalen, dmcoll->poolcache);

    if ( NULL == dst_mpool )
        snprintf(errbuf, errlen, "%s: Couldn't create %s!\n", __FUNCTION__, namebuf);
    else if ( !if_mp_pkt )
        rte_mempool_obj_iter(dst_mpool, mbuf_obj_init, NULL);

    /*                DAQ_RTE_LOG("%s: MBUFS count indeed 0x%x\n", __func__,
                            rte_mempool_free_count(instance->mbuf_pools[i]));

    if ( i == instance->rx_queue_s ) {
        instance->daq_mpool[mr_idx] = instance->daq_mpools[mr_idx][i];
    }*/

    return dst_mpool;
}

static int mpool_lcore_scroll(Dpdk_Context_t *dpdkc, daq_dpdk_mpool_collect *dmcoll,
        uint8_t is_daq_lo, char *errbuf, size_t errlen)
{
    uint8_t core_idx = 0, p_idx, q_idx, if_pkt_mp;
    uint16_t i;
    struct rte_mempool **dst_mpool;
    DpdkInstance *instance;

    switch ( dmcoll->attri ) {
    case MR_ALL_QUEUES:
    case MR_GENERAL:
        for ( p_idx=0; p_idx<dpdkc->naf_port; p_idx++) {//= dpdkc->instances; instance; instance = instance->next) {
            instance = dpdkc->instances[p_idx];
            for (q_idx=0; q_idx<instance->n_rx_queue; q_idx++) {
                if_pkt_mp = 0;
                if ( is_daq_lo ) {
                    dst_mpool = &instance->daq_mpools[dmcoll->type][q_idx];
                    if ( MPOOL_PKT_RX == dmcoll->type )
                        if_pkt_mp = 1;
                }
                else {
                    if ( instance->fw_port >=0 )
                        continue;
                    dst_mpool = &instance->ap_mpools[dmcoll->type][q_idx];
                }

                //Get Core(Utilize) ID -> Get Socket ID
                do {
                    if ( core_idx >= USI_MAX_CORE_NUM ) {
                        DAQ_RTE_LOG("%s: No valid core assigned.\n", __func__);
                        return -1;
                    }

                    if ( dpdkc->lcore_utilize_flag & (0x01L<<core_idx) )
                        break;
                } while ( core_idx++ );

                //Create mpool
                *dst_mpool = (struct rte_mempool*)mpool_lcore_create(dmcoll, -1,
                        core_idx, instance->port, q_idx, if_pkt_mp,
                        errbuf, errlen);
                if ( NULL == *dst_mpool )
                    return -1;

                instance->lcore_ids[q_idx] = rte_lcore_to_socket_id(core_idx);

                //Go to Next Core ID
                core_idx++;

                dpdkc->mbuf_stats += (((uint64_t)dmcoll->poolsize) * ((uint64_t)dmcoll->datalen));
            }
            /*if ( MPOOL_PRIMARY_ONLY == dmcoll->attri )
                break;*/
        }
        break;
    case MR_PRIMARY_NUMA_NODES:
        //dmcoll->pool_sche = (dmcoll->pool_sche/dpdkc->ap_dpl->nsock);
        //dmcoll->datalen = dmcoll->datalen * dmcoll->pool_sche;
        dmcoll->poolsize = dmcoll->poolsize * (dpdkc->ap_dpl->nsock/dpdkc->ap_dpl->rsock);
        for (i=0; i<dpdkc->ap_dpl->rsock; i++) {
            if ( is_daq_lo )
                dst_mpool = &dpdkc->daq_mpool[dmcoll->type];
            else
                dst_mpool = &dpdkc->ap_mpool[i][dmcoll->type];

            *dst_mpool = (struct rte_mempool*)mpool_lcore_create(dmcoll, i,
                    0, 0, 0, 0,
                    errbuf, errlen);
            if ( NULL == *dst_mpool )
                return -1;

            dpdkc->mbuf_stats += (((uint64_t)dmcoll->poolsize) * ((uint64_t)dmcoll->datalen));
        }
        break;
    default:
        if ( is_daq_lo )
            dst_mpool = &dpdkc->daq_mpool[dmcoll->type];
        else
            dst_mpool = &dpdkc->ap_mpool[0][dmcoll->type];

        *dst_mpool = (struct rte_mempool*)mpool_lcore_create(dmcoll, -1,
                0, 0, 0, 0,
                errbuf, errlen);
        if ( NULL == *dst_mpool )
            return -1;

        dpdkc->mbuf_stats += (((uint64_t)dmcoll->poolsize) * ((uint64_t)dmcoll->datalen));
        break;
    }

    return 0;
}

static int mpool_lcore_lookup(Dpdk_Context_t *dpdkc, daq_dpdk_mpool_collect *dmcoll,
        uint8_t is_daq_lo, char *errbuf, size_t errlen)
{
//    uint8_t p_idx, q_idx;
    unsigned sock_id;
    char namebuf[64];
    struct rte_mempool **dst_mpool;
    DpdkInstance *instance;

    if ( MR_PRIMARY_ONLY == dmcoll->attri
            || MR_PRIMARY_NUMA_NODES == dmcoll->attri ) {
        DAQ_RTE_LOG("%s: this is mpool for primary only(idx-%d)\n", __func__, dmcoll->type);
        return 0;
    }

//    for ( p_idx=0; p_idx<dpdkc->n_port; p_idx++) {
        instance = dpdkc->instances[0];
//        for (q_idx=0; q_idx<instance->n_rx_queue; q_idx++) {
            if ( is_daq_lo )
                dst_mpool = &dpdkc->daq_mpool[dmcoll->type];
            else
                dst_mpool = &dpdkc->ap_mpool[0][dmcoll->type];

            sock_id = rte_socket_id();//rte_lcore_to_socket_id(q_idx);
            snprintf(namebuf, sizeof(namebuf), dmcoll->name,
                    sock_id, instance->port, instance->rx_queue_s);
            *dst_mpool = rte_mempool_lookup(namebuf);
            if ( NULL == *dst_mpool ) {
                snprintf(errbuf, errlen, "%s: Couldn't find %s!\n", __FUNCTION__, namebuf);
                return -1;
            }

            DAQ_RTE_LOG("%s: mpool(%s)--MBUFS 0x%x, CACHE_SIZE 0x%x, avil_cnt %d\n",
                    __func__, namebuf, dmcoll->poolsize, dmcoll->poolcache,
                    rte_mempool_avail_count(*dst_mpool));
//        }
//    }

    return 0;
}

static int mpool_lcore_recreate(Dpdk_Context_t *dpdkc, daq_dpdk_mpool_collect *dmcoll,
        uint8_t p_idx, uint8_t q_idx,
        uint8_t is_daq_lo, char *errbuf, size_t errlen)
{
    uint8_t core_idx = 0, pi, qi;
    uint8_t if_pkt_mp = 0;
    int ret = 1;
    struct rte_mempool **dst_mpool;
    DpdkInstance *instance;

    switch (dmcoll->attri) {
    case MR_ALL_QUEUES:
        if ( p_idx < dpdkc->n_port ) {//= dpdkc->instances; instance; instance = instance->next) {
            instance = dpdkc->instances[p_idx];
            if ( q_idx < instance->n_rx_queue ) {
                if ( is_daq_lo ) {
                    dst_mpool = &instance->daq_mpools[dmcoll->type][q_idx];
                    if ( MPOOL_PKT_RX == dmcoll->type )
                        if_pkt_mp = 1;
                }
                else {
                    dst_mpool = &instance->ap_mpools[dmcoll->type][q_idx];
                }

                DAQ_RTE_LOG("%s: free mpool-%d-[%d]-flag_rein-%x and recreate it.\n", __func__,
                        is_daq_lo, dmcoll->type, dmcoll->flag_rein);

                //Free previous pool
                if ( NULL != *dst_mpool ) {
                    rte_mempool_free(*dst_mpool);
                }

                //Get Core(Utilize) ID -> Get Socket ID
                for (pi=0; pi<=p_idx; pi++) {
                    instance = dpdkc->instances[pi];
                    for (qi=0; qi<instance->n_rx_queue; qi++) {
                        do {
                            if ( core_idx >= USI_MAX_CORE_NUM ) {
                                DAQ_RTE_LOG("%s: No valid core assigned.\n", __func__);
                                return -1;
                            }

                            if ( dpdkc->lcore_utilize_flag & (0x01L<<core_idx) )
                                break;
                        } while ( core_idx++ );

                        if ( (pi==p_idx) && (qi==q_idx) )
                            break;
                    }
                }

                DAQ_RTE_LOG("%s: re-init with core %d, port %d, queue %d\n", __func__,
                        core_idx, instance->port, q_idx);

                //Create new one
                *dst_mpool = (struct rte_mempool*)mpool_lcore_create(dmcoll, -1,
                        core_idx, instance->port, q_idx, if_pkt_mp,
                        errbuf, errlen);
                if ( NULL == *dst_mpool )
                    ret = -1;
                else
                    ret = 0;
            }
        }
        break;
    case MR_SINGLETON:
        dst_mpool = &dpdkc->ap_mpool[0][dmcoll->type];

        DAQ_RTE_LOG("%s: free mpool(%s)-flag_rein-%x and recreate it.\n", __func__,
                dmcoll->name, dmcoll->type, dmcoll->flag_rein);

        //Free previous pool
        if ( NULL != *dst_mpool ) {
            rte_mempool_free(*dst_mpool);
        }

        DAQ_RTE_LOG("%s: re-init with core %d\n", __func__,
                core_idx);

        //Create new one
        *dst_mpool = (struct rte_mempool*)mpool_lcore_create(dmcoll, -1,
                core_idx, 0, 0, if_pkt_mp,
                errbuf, errlen);
        if ( NULL == *dst_mpool )
            ret = -1;
        else
            ret = 0;
        break;
    default:
        ret = 0;
        break;
    }

    return ret;
}

static int mpool_lcore_check_full(Dpdk_Context_t *dpdkc, daq_dpdk_mpool_collect *dmcoll,
        uint8_t p_idx, uint8_t q_idx, uint8_t is_daq_lo)
{
    int ret = 0;
    struct rte_mempool **dst_mpool;
    DpdkInstance *instance;

    if ( MR_ALL_QUEUES == dmcoll->attri ) {
        //if ( p_idx < dpdkc->n_port ) {//= dpdkc->instances; instance; instance = instance->next) {
            instance = dpdkc->instances[0];//[p_idx];
            if ( q_idx < instance->n_rx_queue ) {
                if ( is_daq_lo ) {
                    dst_mpool = &dpdkc->daq_mpool[dmcoll->type];
                }
                else {
                    dst_mpool = &dpdkc->ap_mpool[0][dmcoll->type];
                }

                if ( NULL != *dst_mpool ) {
                    ret = rte_mempool_full(*dst_mpool);
                    DAQ_RTE_LOG("%s: port %d, queue %d, mpool-%d-[%d] full? ret %d, ac %d\n", __func__,
                            p_idx, q_idx, is_daq_lo, dmcoll->type, ret, rte_mempool_avail_count(*dst_mpool));
                }
            }
        //}
    }
    else {
        ret = 1;
    }

    return ret;
}

static void *mring_lcore_create(daq_dpdk_ring_collect *drcoll,
        unsigned core_id, uint8_t port, uint8_t q_idx, char *errbuf, size_t errlen)
{
    unsigned sock_id;
    char namebuf[64];
    struct rte_ring *dst_ring;

    sock_id = rte_lcore_to_socket_id(core_id);
    snprintf(namebuf, sizeof(namebuf), drcoll->name,
            sock_id, port, q_idx);
    dst_ring = rte_ring_create(namebuf,
            drcoll->queue_size, sock_id, drcoll->flags);

    DAQ_RTE_LOG("%s: ring(%s)--QUEUE 0x%x, FLAG 0x%x\n",
            __func__, namebuf, drcoll->queue_size, drcoll->flags);

    if ( NULL == dst_ring )
        snprintf(errbuf, errlen, "%s: Couldn't create %s!\n", __FUNCTION__, namebuf);

/*    if ( i == instance->rx_queue_s ) {
        instance->ap_ring[mr_idx] = instance->ap_rings[mr_idx][i];
    }*/

    return dst_ring;
}

static int mring_lcore_scroll(Dpdk_Context_t *dpdkc, daq_dpdk_ring_collect *drcoll,
        uint8_t is_daq_lo, char *errbuf, size_t errlen)
{
    uint8_t core_idx = 0, p_idx, q_idx;
    struct rte_ring **dst_ring;
    DpdkInstance *instance;

    if ( MR_ALL_QUEUES != drcoll->attri ) {
        if ( is_daq_lo )
            dst_ring = &dpdkc->daq_ring[drcoll->type];
        else
            dst_ring = &dpdkc->ap_ring[drcoll->type];

        *dst_ring = (struct rte_ring*)mring_lcore_create(drcoll,
                0, 0, 0, errbuf, errlen);
        if ( NULL == *dst_ring )
            return -1;
    }

    if ( MR_ALL_QUEUES == drcoll->attri
            || MR_GENERAL == drcoll->attri ) {
        for ( p_idx=0; p_idx<dpdkc->n_port; p_idx++) {//= dpdkc->instances; instance; instance = instance->next) {
            instance = dpdkc->instances[p_idx];
            for (q_idx=0; q_idx<instance->n_rx_queue; q_idx++) {
                if ( is_daq_lo )
                    dst_ring = &instance->daq_rings[drcoll->type][q_idx];
                else
                    dst_ring = &instance->ap_rings[drcoll->type][q_idx];

                //Get Core(Utilize) ID -> Get Socket ID
                do {
                    if ( core_idx >= USI_MAX_CORE_NUM ) {
                        DAQ_RTE_LOG("%s: No valid core assigned.\n", __func__);
                        return -1;
                    }

                    if ( dpdkc->lcore_utilize_flag & (0x01L<<core_idx) )
                        break;
                } while ( core_idx++ );

                *dst_ring = (struct rte_ring*)mring_lcore_create(drcoll,
                        core_idx, instance->port, q_idx, errbuf, errlen);
                if ( NULL == *dst_ring )
                    return -1;

                core_idx++;
            }
        }
    }

    return 0;
}

static int mring_lcore_lookup(Dpdk_Context_t *dpdkc, daq_dpdk_ring_collect *drcoll,
        uint8_t is_daq_lo, char *errbuf, size_t errlen)
{
//    uint8_t p_idx, q_idx;
    unsigned sock_id;
    char namebuf[64];
    struct rte_ring **dst_ring;
    DpdkInstance *instance;

    if ( MR_PRIMARY_ONLY == drcoll->attri
            || MR_PRIMARY_NUMA_NODES == drcoll->attri )
        return 0;

//    for ( p_idx=0; p_idx<dpdkc->n_port; p_idx++) {
        instance = dpdkc->instances[0];
//        for (q_idx=0; q_idx<instance->n_rx_queue; q_idx++) {
            if ( is_daq_lo )
                dst_ring = &dpdkc->daq_ring[drcoll->type];
            else
                dst_ring = &dpdkc->ap_ring[drcoll->type];

            sock_id = rte_socket_id();//rte_lcore_to_socket_id(instance->rx_queue_s);
            snprintf(namebuf, sizeof(namebuf), drcoll->name,
                    sock_id, instance->port, instance->rx_queue_s);
            *dst_ring = rte_ring_lookup(namebuf);
            if ( NULL == *dst_ring ) {
                snprintf(errbuf, errlen, "%s: Couldn't find %s!\n", __FUNCTION__, namebuf);
                return -1;
            }

            DAQ_RTE_LOG("%s: ring(%s)--QUEUE 0x%x, FLAG 0x%x\n",
                    __func__, namebuf, drcoll->queue_size, drcoll->flags);
//        }
//    }

    return 0;
}

int mpool_lcore_queue_reinit(Dpdk_Context_t *dpdkc, uint64_t flag_rein_u,
        uint8_t port_idx, uint8_t queue_idx)
{
    uint8_t mr_idx;
    int m_ret;
    daq_dpdk_mpool_collect *dmcoll;
    char errbuf[256];
    size_t errlen = sizeof(errbuf);

    DAQ_RTE_LOG("%s: port_idx %d, queue %d\n", __func__, port_idx, queue_idx);

    //DAQ mpools
    for ( mr_idx=0; mr_idx<DAQ_MPOOL_COUNT; mr_idx++ ) {
        dmcoll = &dk_mbuf_coll[mr_idx];
        if ( !(flag_rein_u & dmcoll->flag_rein) )
            continue;

        m_ret = mpool_lcore_recreate(dpdkc, dmcoll,
                port_idx, queue_idx,
                1, errbuf, errlen);
        if ( m_ret ) {
            return m_ret;
        }
    }

    //AP mpools
    for ( mr_idx=0; mr_idx<dpdkc->ap_dpl->npool; mr_idx++ ) {
        dmcoll = &dpdkc->ap_dpl->mpools[mr_idx];
        if ( !(flag_rein_u & dmcoll->flag_rein) )
            continue;

        m_ret = mpool_lcore_recreate(dpdkc, dmcoll,
                port_idx, queue_idx,
                0, errbuf, errlen);
        if ( m_ret ) {
            return m_ret;
        }
    }

    return 0;
}

/*
 * Check if mpools for specific queue are all available
 * return:
 * 1: available
 * 0: not available
 * */
static int mpool_lcore_queue_check_validity(Dpdk_Context_t *dpdkc, uint64_t flag_rein_u,
        uint8_t port_idx, uint8_t queue_idx)
{
    uint8_t mr_idx;
    int m_ret;
    daq_dpdk_mpool_collect *dmcoll;

    //DAQ mpools
    for ( mr_idx=0; mr_idx<DAQ_MPOOL_COUNT; mr_idx++ ) {
        //Not for m-pool for pkt_rx_queue
        dmcoll = &dk_mbuf_coll[mr_idx];
        m_ret = mpool_lcore_check_full(dpdkc, dmcoll,
                port_idx, queue_idx, 1);

        if ( !(flag_rein_u & dmcoll->flag_rein) )
            continue;

        if ( !m_ret ) {
            DAQ_RTE_LOG("%s: daq-mpool[%d] not full\n", __func__, dmcoll->type);
            return 0;
        }
    }

    //AP mpools
    for ( mr_idx=0; mr_idx<dpdkc->ap_dpl->npool; mr_idx++ ) {
        dmcoll = &dpdkc->ap_dpl->mpools[mr_idx];
        if ( !(flag_rein_u & dmcoll->flag_rein) )
            continue;

        m_ret = mpool_lcore_check_full(dpdkc, dmcoll,
                port_idx, queue_idx, 0);
        if ( !m_ret ) {
            DAQ_RTE_LOG("%s: ap-mpool[%d] not full\n", __func__, dmcoll->type);
            return 0;
        }
    }

    return 1;
}

static int mbuf_lcore_init(Dpdk_Context_t *dpdkc, char *errbuf, size_t errlen)
{
	uint8_t mr_idx;//, p_idx, q_idx;
	int m_ret;
//    unsigned sock_id = rte_socket_id();
//    DpdkInstance *instance;
    daq_dpdk_mpool_collect *dmcoll;
    daq_dpdk_ring_collect *drcoll;
//    struct rte_mempool **dst_mpool;
//    struct rte_ring **dst_ring;
//    char namebuf[64];

    //for (instance = dpdkc->instances; instance; instance = instance->next) {
        //instance->lcore_id = rte_lcore_id();

        if ( RTE_PROC_SECONDARY == dpdkc->proc_type ) {
            DAQ_RTE_LOG("%s: Secondary Process\n", __func__);

            //DAQ mpools
            for ( mr_idx=0; mr_idx<DAQ_MPOOL_COUNT; mr_idx++ ) {
                dmcoll = &dk_mbuf_coll[mr_idx];
                m_ret = mpool_lcore_lookup(dpdkc, dmcoll, 1, errbuf, errlen);
                if ( m_ret ) {
                    DAQ_RTE_LOG(errbuf);
                    return m_ret;
                }
            }

            //AP mpools
            for ( mr_idx=0; mr_idx<dpdkc->ap_dpl->npool; mr_idx++ ) {
                dmcoll = &dpdkc->ap_dpl->mpools[mr_idx];
                m_ret = mpool_lcore_lookup(dpdkc, dmcoll, 0, errbuf, errlen);
                if ( m_ret ) {
                    DAQ_RTE_LOG(errbuf);
                    return m_ret;
                }
            }
/*                if ( MR_PRIMARY_ONLY == dmcoll->attri )
                    continue;

                snprintf(namebuf, sizeof(namebuf), dmcoll->name,
                        sock_id, instance->port, instance->rx_queue_s);
                instance->ap_mpool[mr_idx] = rte_mempool_lookup(namebuf);
                if ( NULL == instance->ap_mpool[mr_idx] ) {
                    snprintf(errbuf, errlen, "%s: Couldn't find %s!\n", __FUNCTION__, namebuf);
                    return -1;
                }

                DAQ_RTE_LOG("%s: mpool(%s)--MBUFS 0x%x, CACHE_SIZE 0x%x\n",
                        __func__, namebuf, dmcoll->poolsize, dmcoll->poolcache);
            }*/

            //DAQ rings
            for ( mr_idx=0; mr_idx<DAQ_RING_COUNT; mr_idx++ ) {
                drcoll = &dk_ring_coll[mr_idx];
                m_ret = mring_lcore_lookup(dpdkc, drcoll, 1, errbuf, errlen);
                if ( m_ret ) {
                    DAQ_RTE_LOG(errbuf);
                    return m_ret;
                }
/*                if ( MR_PRIMARY_ONLY == drcoll->attri )
                    continue;

                snprintf(namebuf, sizeof(namebuf), drcoll->name,
                        sock_id, instance->port, instance->rx_queue_s);
                instance->daq_ring[mr_idx] = rte_ring_lookup(namebuf);
                if ( NULL == instance->daq_ring[mr_idx] ) {
                    snprintf(errbuf, errlen, "%s: Couldn't find %s!\n", __FUNCTION__, namebuf);
                    return -1;
                }

                DAQ_RTE_LOG("%s: ring(%s)--QUEUE 0x%x, FLAG 0x%x\n",
                        __func__, namebuf, drcoll->queue_size, drcoll->flags);*/
            }

            //AP rings
            for ( mr_idx=0; mr_idx<dpdkc->ap_dpl->nring; mr_idx++ ) {
                drcoll = &dpdkc->ap_dpl->rings[mr_idx];
                m_ret = mring_lcore_lookup(dpdkc, drcoll, 0, errbuf, errlen);
                if ( m_ret ) {
                    DAQ_RTE_LOG(errbuf);
                    return m_ret;
                }
/*                if ( MR_PRIMARY_ONLY == drcoll->attri )
                    continue;

                snprintf(namebuf, sizeof(namebuf), drcoll->name,
                        sock_id, instance->port, instance->rx_queue_s);
                instance->ap_ring[mr_idx] = rte_ring_lookup(namebuf);
                if ( NULL == instance->ap_ring[mr_idx] ) {
                    snprintf(errbuf, errlen, "%s: Couldn't find %s!\n", __FUNCTION__, namebuf);
                    return -1;
                }

                DAQ_RTE_LOG("%s: ring(%s)--QUEUE 0x%x, FLAG 0x%x\n",
                        __func__, namebuf, drcoll->queue_size, drcoll->flags);*/
            }
        }
        else {
            DAQ_RTE_LOG("%s: Primary Process\n", __func__);

            //DAQ mpools
            for ( mr_idx=0; mr_idx<DAQ_MPOOL_COUNT; mr_idx++ ) {
                dmcoll = &dk_mbuf_coll[mr_idx];
                m_ret = mpool_lcore_scroll(dpdkc, dmcoll, 1, errbuf, errlen);
                if ( m_ret ) {
                    DAQ_RTE_LOG(errbuf);
                    return m_ret;
                }
            }

            //AP mpools
            for ( mr_idx=0; mr_idx<dpdkc->ap_dpl->npool; mr_idx++ ) {
                dmcoll = &dpdkc->ap_dpl->mpools[mr_idx];
                m_ret = mpool_lcore_scroll(dpdkc, dmcoll, 0, errbuf, errlen);
                if ( m_ret ) {
                    DAQ_RTE_LOG(errbuf);
                    return m_ret;
                }
            }

            DAQ_RTE_LOG("%s: mbuf_stats accumulation: %lu\n", __func__, dpdkc->mbuf_stats);

            /*    for (i=0; i<instance->n_rx_queue; i++) {
                    //if ( !mbuf_ring_instance_sta(dmcoll->attri, dpdkc) )
                    if ( MPOOL_PRIMARY_ONLY == dmcoll->attri )
                        dst_mpool = &instance->daq_mpool[mr_idx];
                    else
                        dst_mpool = &instance->daq_mpools[mr_idx][i];

                    sock_id = rte_lcore_to_socket_id(i);
                    snprintf(namebuf, sizeof(namebuf), dmcoll->name,
                            sock_id, instance->port, i);
                    *dst_mpool = rte_mempool_create(namebuf,
                            dmcoll->poolsize,dmcoll->datalen,dmcoll->poolcache,dmcoll->private_dlen,
                            NULL, NULL, NULL, NULL, sock_id, 0);

                    DAQ_RTE_LOG("%s: mpool(%s)--MBUFS 0x%x(0x%x), CACHE_SIZE 0x%x\n",
                            __func__, namebuf, dmcoll->poolsize, dmcoll->datalen, dmcoll->poolcache);

                    if ( NULL == *dst_mpool ) {
                        snprintf(errbuf, errlen, "%s: Couldn't create %s!\n", __FUNCTION__, namebuf);
                        return -1;
                    }
*/
                    /*if ( i == instance->rx_queue_s ) {
                        instance->ap_mpool[mr_idx] = instance->ap_mpools[mr_idx][i];
                    }*/
 //               }
 //           }

            //DAQ rings
            for ( mr_idx=0; mr_idx<DAQ_RING_COUNT; mr_idx++ ) {
                drcoll = &dk_ring_coll[mr_idx];
                m_ret = mring_lcore_scroll(dpdkc, drcoll, 1, errbuf, errlen);
                if ( m_ret ) {
                    DAQ_RTE_LOG(errbuf);
                    return m_ret;
                }
            }
/*                for (i=0; i<instance->n_rx_queue; i++) {
                    if ( !mbuf_ring_instance_sta(drcoll->attri, dpdkc) )
                        continue;

                    sock_id = rte_lcore_to_socket_id(i);
                    snprintf(namebuf, sizeof(namebuf), drcoll->name,
                            sock_id, instance->port, i);
                    instance->daq_rings[mr_idx][i] = rte_ring_create(namebuf,
                            drcoll->queue_size, sock_id, drcoll->flags);
                    if ( NULL == instance->daq_rings[mr_idx][i] ) {
                        snprintf(errbuf, errlen, "%s: Couldn't create %s!\n", __FUNCTION__, namebuf);
                        return -1;
                    }

                    DAQ_RTE_LOG("%s: ring(%s)--QUEUE 0x%x, FLAG 0x%x\n",
                            __func__, namebuf, drcoll->queue_size, drcoll->flags);

                    if ( i == instance->rx_queue_s ) {
                        instance->daq_ring[mr_idx] = instance->daq_rings[mr_idx][i];
                    }
                }
            }*/

                //AP rings
            for ( mr_idx=0; mr_idx<dpdkc->ap_dpl->nring; mr_idx++ ) {
                drcoll = &dpdkc->ap_dpl->rings[mr_idx];
                m_ret = mring_lcore_scroll(dpdkc, drcoll, 0, errbuf, errlen);
                if ( m_ret ) {
                    DAQ_RTE_LOG(errbuf);
                    return m_ret;
                }
/*              if ( !mbuf_ring_instance_sta(drcoll->attri, dpdkc) )
                    continue;*/
            }
        }
    //}

    return 0;
}

static int start_instance(Dpdk_Context_t *dpdkc, DpdkInstance *instance)
{
    unsigned sock_id;
    int rx_rings = RX_RING_NUM, tx_rings = TX_RING_NUM;
    int port, queue, ret;
    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_eth_dev_info info;

    port = instance->port;
    rx_rings = instance->n_rx_queue;
    tx_rings = instance->n_tx_queue;

    DAQ_RTE_LOG("%s: port %d, RX-- q_start %d, q_end %d, q_all %d, ring_sizes %d\n",
    		__func__, port, instance->rx_queue_s, instance->rx_queue_e,
    		rx_rings, RX_RING_SIZE);
    DAQ_RTE_LOG("%s: port %d, TX-- q_start %d, q_end %d, q_all %d, ring_sizes %d\n",
    		__func__, port, instance->tx_queue_s, instance->tx_queue_e,
    		tx_rings, RX_RING_SIZE);

    if ( RTE_PROC_SECONDARY == dpdkc->proc_type ) {
        DAQ_RTE_LOG("%s: Secondary process, No Configuration of RTE_ETH\n",
                __func__);
        return DAQ_SUCCESS;
    }

    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret != 0) {
        DPE(dpdkc->errbuf, "%s: Couldn't configure port %d\n", __FUNCTION__, port);
        return DAQ_ERROR;
    }

    rte_eth_dev_info_get(port, &info);
    info.default_rxconf.rx_drop_en = 1;
    info.default_rxconf.rx_thresh.pthresh = 16;
    info.default_rxconf.rx_thresh.hthresh = 16;
    DAQ_RTE_LOG("%s: RX-- Initialing port %d with config: rx_thresh.pthresh %d, "
            "rx_thresh.hthresh %d, rx_thresh.wthresh %d, "
            "rx_free_thresh %d, rx_deferred_start %d\n", __func__, port,
            info.default_rxconf.rx_thresh.pthresh,
            info.default_rxconf.rx_thresh.hthresh,
            info.default_rxconf.rx_thresh.wthresh,
            info.default_rxconf.rx_free_thresh,
            info.default_rxconf.rx_deferred_start);
    for (queue = 0; queue < rx_rings; queue++) {
        sock_id = rte_lcore_to_socket_id(queue);
        DAQ_RTE_LOG("%s: queue %d, ring_size %d, sock_id %d, mbuf 0x%lx\n",
                __func__, queue, RX_RING_SIZE, sock_id, (unsigned long)instance->daq_mpools[MPOOL_PKT_RX][queue]);
        ret = rte_eth_rx_queue_setup(port, queue, RX_RING_SIZE,
                rte_eth_dev_socket_id(port),
                &info.default_rxconf,
                instance->daq_mpools[MPOOL_PKT_RX][queue]);
        if (ret != 0) {
            DPE(dpdkc->errbuf, "%s: Couldn't setup rx queue %d for port %d\n", __FUNCTION__, queue, port);
            return DAQ_ERROR;
        }
    }

    for (queue = 0; queue < tx_rings; queue++) {
        ret = rte_eth_tx_queue_setup(port, queue, TX_RING_SIZE,
                rte_eth_dev_socket_id(port),
                NULL);
        DAQ_RTE_LOG("%s: setup tx port %u queue %u\n", __func__, port, queue);
        if (ret != 0) {
            DPE(dpdkc->errbuf, "%s: Couldn't setup tx queue %d for port %d\n", __FUNCTION__, queue, port);
            return DAQ_ERROR;
        }
    }

    ret = rte_eth_dev_start(instance->port);
    if (ret != 0) {
        DPE(dpdkc->errbuf, "%s: Couldn't start device for port %d\n", __FUNCTION__, port);
        return DAQ_ERROR;
    }

    //port_rss_hash_conf_show(instance->port, "ipv4", 1);

    instance->flags |= DPDKINST_STARTED;

    if ( dpdkc->cflags & DAQ_CFG_PROMISC )
        rte_eth_promiscuous_enable(instance->port);

    return DAQ_SUCCESS;
}

int dpdk_daq_wait_dpl_cfg(ApDpLoadInfo *ap_dpl)
{
    struct rte_mempool *mp_dpl_cfg;
    struct rte_ring *mr_dpl_cfg;
    mn_dpl_config *dpl_psur;

    mp_dpl_cfg = rte_mempool_create("MN_MBUF_DPL_CONF", 1, sizeof(mn_dpl_config), 0, 0,
                                NULL, NULL, NULL, NULL, /*sock_id,default 0*/0, 0);
    if ( NULL == mp_dpl_cfg ) {
        DAQ_RTE_LOG("%s: mbuf for dataplane config failed\n", __func__);
        return -1;
    }

    mr_dpl_cfg = rte_ring_create("MN_RING_DPL_CONF", 2, /*sock_id,default 0*/0, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if ( NULL == mr_dpl_cfg ) {
        rte_mempool_free(mp_dpl_cfg);
        DAQ_RTE_LOG("%s: ring for dataplane config failed\n", __func__);
        return -1;
    }

    do {
        if ( !rte_ring_dequeue(mr_dpl_cfg, (void**)&dpl_psur) ) {
            DAQ_RTE_LOG("%s: got dpl_cfg\n", __func__);
            break;
        }

        DAQ_RTE_LOG("waiting for dpl_cfg\n");
        sleep(1);
    } while (!gBreak_loop);

    if ( gBreak_loop )
        return -1;

    ap_dpl->npool = dpl_psur->npool;
    ap_dpl->nring = dpl_psur->nring;
    ap_dpl->mpools = dpl_psur->mpools;
    ap_dpl->rings = dpl_psur->rings;

    DAQ_RTE_LOG("%s: npool %d, nring %d\n", __func__,
            ap_dpl->npool, ap_dpl->nring);

    //rte_mempool_put(mp_dpl_cfg, (void*)dpl_psur);
    //rte_mempool_free(mp_dpl_cfg);
    //rte_ring_free(mr_dpl_cfg);

    return 0;
}

int dpdk_daq_send_dpl_cfg(ApDpLoadInfo *src_dpl)
{
    int ret;
    struct rte_mempool *mp_dpl_cfg;
    struct rte_ring *mr_dpl_cfg;
    mn_dpl_config *dst_dpl;

    mp_dpl_cfg = rte_mempool_lookup("MN_MBUF_DPL_CONF");
    if ( NULL == mp_dpl_cfg )
        return -1;

    mr_dpl_cfg = rte_ring_lookup("MN_RING_DPL_CONF");
    if ( NULL == mr_dpl_cfg )
        return -1;

    //rte_mempool_get(dst_dpl =
    if (rte_mempool_get(mp_dpl_cfg, (void**)&dst_dpl) < 0) {
        DAQ_RTE_LOG("%s: Failed to get sf_mbuf\n", __func__);
        return -1;
    }

    dst_dpl->npool = src_dpl->npool;
    dst_dpl->nring = src_dpl->nring;
    rte_memcpy(dst_dpl->mpools, src_dpl->mpools, sizeof(daq_dpdk_mpool_collect)*src_dpl->npool);
    rte_memcpy(dst_dpl->rings, src_dpl->rings, sizeof(daq_dpdk_ring_collect)*src_dpl->nring);

    ret = rte_ring_enqueue(mr_dpl_cfg, dst_dpl);
    if ( -ENOBUFS == ret ) {
        DAQ_RTE_LOG("%s: ring full for msg dpl-cfg\n", __func__);
        rte_mempool_put(mp_dpl_cfg, dst_dpl);
        return 1;
    }
    else if ( -EDQUOT == ret ) {
        DAQ_RTE_LOG("%s: Quota exceeded msg dpl-cfg\n", __func__);
        return 1;
    }

    DAQ_RTE_LOG("%s: sent dpl-cfg\n", __func__);

    return 0;
}

static int dpdk_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    Dpdk_Context_t *dpdkc;
    DAQ_Dict *entry;
    int ports;
    int ret, rval = DAQ_ERROR;
    char *dpdk_args = NULL;
    char *dpdk_c_args = NULL;
    char *argv[MAX_ARGS + 1];
    uint64_t *msg_seq_s, *msg_seq_e;
    uint64_t lcore_mask;
    unsigned di_lcore_id;
    int argc;
    //char argv0[] = "daq";
    char dpdk_args_cap[512];

    //RTE LOG LEVEL
    if ( config->flags & DAQ_CFG_SYSLOG ) {
        daq_dpdk_log_daemon = 1;
    }

    dpdkc = calloc(1, sizeof(Dpdk_Context_t));
    if (!dpdkc) {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new DPDK context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    memset(dpdkc, 0, sizeof(Dpdk_Context_t));

    dpdkc->device = strdup(config->name);
    if (!dpdkc->device) {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dpdkc->snaplen = config->snaplen;
    dpdkc->timeout = (config->timeout > 0) ? (int) config->timeout : -1;
    dpdkc->cflags = config->flags;
    dpdkc->ap_dpl = config->ap_dpl;
    dpdkc->lcore_utilize_flag = config->lcore_utl_flag;

    dpdkc->proc_type = RTE_PROC_INVALID;

#ifdef DAQ_DPDK_POWER_CTL
    dpdkc->power_heurs = &power_track;
#endif

    //mpool_ring datalen
    /*dk_mbuf_coll[MPOOL_STATSFLOW].datalen = config->sf_dpl->dplen;
    dk_mbuf_coll[MPOOL_SF_SSN].datalen = config->sf_dpl->dplen_ssn;
    dk_mbuf_coll[MPOOL_SF_CFL].datalen = config->sf_dpl->conflu_dplen;*/

    /* Interface */
    if ( parse_interface(config, dpdkc, errbuf, errlen) ) {
        goto err;
    }

    /* Import the DPDK arguments */
    for (entry = config->values; entry; entry = entry->next) {
        if ( !strcmp(entry->key, "dpdk_args") )
            dpdk_args = entry->value;
        else if ( !strcmp(entry->key, "dpdk_c_args") )
            dpdk_c_args = entry->value;
        else if ( !strcmp(entry->key, "dpdk_csn") )
            daq_dpdk_cassini = 1;
    }

    if (!dpdk_args || !dpdk_c_args) {
        snprintf(errbuf, errlen, "%s: Missing EAL arguments!", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    snprintf(dpdk_args_cap, sizeof(dpdk_args_cap), "-c %s %s", dpdk_c_args, dpdk_args);
    printf("%s: dpdk_args -- %s\n", __func__, dpdk_args_cap);
    argv[0] = dpdkc->ap_dpl->ap_name;//argv0;
    argc = parse_args(dpdk_args_cap, &argv[1]) + 1;
    optind = 1;

    snprintf(errbuf, errlen, "%s", "ready to rte_eal_init\n");

    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        snprintf(errbuf, errlen, "%s: Invalid EAL arguments!\n", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    ports = rte_eth_dev_count();
    if (ports == 0) {
        snprintf(errbuf, errlen, "%s: No Ethernet ports!\n", __FUNCTION__);
        rval = DAQ_ERROR_NODEV;
        goto err;
    }

    DAQ_RTE_LOG("%s: data-plane port count %u\n", __func__, ports);

    if (dpdkc->intf_count > ports) {
        snprintf(errbuf, errlen, "%s: Using more than %d interfaces is not valid!",
                 __FUNCTION__, ports);
        goto err;
    }

    //DPDK proc-type
    dpdkc->proc_type = rte_eal_process_type();

    //Identify Primary and Secondary
    if ( config->flags & DAQ_CFG_MINERVA ) {
        /*if ( dpdk_daq_wait_dpl_cfg(dpdkc->ap_dpl) ) {
            snprintf(errbuf, errlen, "%s: Get dpl_config failed!", __FUNCTION__);
            goto err;
        }*/
        //epfd ipc communication
        epfd_unlink_all(dpdkc);

        //Init master-stats sequence
        msg_seq_s = (uint64_t*)dpdkc->st_seq_queues;
        msg_seq_e = msg_seq_s + (sizeof(dpdkc->st_seq_queues)/sizeof(uint64_t));
        while ( msg_seq_s < msg_seq_e ) {
            *msg_seq_s = MSG_SEQ_INIT_START;
            msg_seq_s ++;
        }
        msg_seq_s = (uint64_t*)dpdkc->st_seq_aps;
        msg_seq_e = msg_seq_s + (sizeof(dpdkc->st_seq_aps)/sizeof(uint64_t));
        while ( msg_seq_s < msg_seq_e ) {
            *msg_seq_s = MSG_SEQ_INIT_START;
            msg_seq_s ++;
        }

        //Init ap rings index
        dpdkc->msg_ring_aps[0] = RING_AP_MSG_SQ;
        //dpdkc->msg_ring_aps[1] = RING_AP_MSG_PT;
        dpdkc->msg_ring_aps[1] = 0xff;

        //CORE MASK check
        lcore_mask = strtoul(dpdk_c_args, NULL, 16);
        di_lcore_id = rte_lcore_id();
        DAQ_RTE_LOG("%s: lcore-mask-0x%lx, cur lcore %d\n", __func__, lcore_mask, di_lcore_id);
        if ( !(lcore_mask&(0x01<<(di_lcore_id+(DAQ_CFL_LT_SERVICE_NUM-1)))) ) {
            DAQ_RTE_LOG("%s: sf_confluence use unity one lcore\n", __func__);
            dpdkc->cfl_unity = 1;
        }
    }
    else {//if ( dpdkc->rx_ins->rx_queue_s > 0 ) {
        /*if ( daq_dpdk_cassini )
            dpdk_daq_send_dpl_cfg(dpdkc->ap_dpl);*/

#ifdef DAQ_DPDK_POWER_CTL
        sleep(DAQ_DPDK_SECONDARY_EPFD_DELAY);
        if ( epfd_wait_get(dpdkc) ) {
            snprintf(errbuf, errlen, "%s: Get epfd from primary lcore failed!", __FUNCTION__);
            goto err;
        }
#else
        sleep(DAQ_DPDK_SECONDARY_INIT_DELAY+
                (((dpdkc->rx_ins->port)*(dpdkc->rx_ins->n_rx_queue)+dpdkc->rx_ins->rx_queue_s)<<1));
#endif
    }

    RTE_LOG(INFO, EAL, "%s: lcore utilize 0x%lx, Processing port %d queue %d\n",
    		__func__, dpdkc->lcore_utilize_flag, dpdkc->rx_ins->port, dpdkc->rx_ins->rx_queue_s);

    //RTE LOG LEVEL
    if ( config->flags & DAQ_CFG_SYSLOG ) {
#ifdef BUILD_DPDK_VER_17111
        rte_log_set_global_level(RTE_LOG_NOTICE);
#else
        rte_set_log_level(RTE_LOG_NOTICE);
#endif
    }

    //DPDK mbuf initialize
    if ( mbuf_lcore_init(dpdkc, errbuf, errlen) ){
        goto err;
    }

    if ( !(config->flags & DAQ_CFG_MINERVA) ) {
        //DPDK mbuf check validation
        if ( !mpool_lcore_queue_check_validity(dpdkc,
                DAQ_DPDK_INN_REIN|DAQ_DPDK_DP_SF_REIN|DAQ_DPDK_DP_SUR_REIN,
                dpdkc->rx_ins->port, dpdkc->rx_ins->rx_queue_s) ) {
            daq_dpdk_secondary_msg_handling(dpdkc, 1);

            //DPDK mbuf initialize(again)
            if ( mbuf_lcore_init(dpdkc, errbuf, errlen) ){
                goto err;
            }
        }
    }

    /* Initialize other default configuration values. */
    dpdkc->debug = 0;

    /* Import the configuration dictionary requests. */
    for (entry = config->values; entry; entry = entry->next) {
        if (!strcmp(entry->key, "debug"))
            dpdkc->debug = 1;
    }

    dpdkc->state = DAQ_STATE_INITIALIZED;

    //DAQ HEADER Struct
    daqhdr.cts = 0;
    daqhdr.egress_index = DAQ_PKTHDR_UNKNOWN;
    daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
    daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
    daqhdr.flags = 0;
    daqhdr.opaque = 0;
    daqhdr.priv_ptr = NULL;
    daqhdr.address_space_id = 0;

    *ctxt_ptr = dpdkc;
    return DAQ_SUCCESS;

err:
    if (dpdkc) {
    	destroy_dpdkc(dpdkc);
        if (dpdkc->device)
            free(dpdkc->device);
        free(dpdkc);
    }
    return rval;
}

static void dpdk_daq_reset_stats(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    memset(&dpdkc->stats, 0, sizeof(DAQ_Stats_t));
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

//Response Pkt Count Filter
static int dpdk_daq_pc_filter_rsp(void *handle, const void *sf_data, int datalen,
        DAQ_Set_SF_Config sfconf_cb, daq_sf_req_type *targ_type)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance = dpdkc->rx_ins;
    void *msg;
    //struct rte_mempool *msg_mpool = instance->daq_mpool[MPOOL_IPCRSEQ];
    struct rte_mempool *msg_mpool = dpdkc->daq_mpool[MPOOL_IPCRSEQ];
    struct rte_ring *rsp_ring = dpdkc->daq_ring[RING_IPC_PCRSP];
    pktcnt_msg *pc_msg;
    pktcnt_msg pc_msg_rsp;
    int ret, ret_type;

    ret_type = DAQ_USER_SF_OP_NONE;

    //Get retrieve data msg
    if (rte_ring_dequeue(/*instance*/dpdkc->daq_ring[RING_IPC_PCREQ], &msg) < 0) {
        return ret_type;
    }

    pc_msg = (pktcnt_msg*)msg;

    DAQ_RTE_LOG_DEEP("%s: Get pc req(%d) in queue[%d] process...\n",
            __func__, pc_msg->msg_type, instance->rx_queue_s);

    switch (pc_msg->msg_type) {
    case DAQ_SF_DP_SWAP:
        //Transfer Data
        if ( unlikely(NULL!=pc_msg->msg_ptr && NULL!=sf_data) )
            rte_memcpy(pc_msg->msg_ptr, sf_data, datalen);
        pc_msg_rsp.rtn = DAQ_SUCCESS;
        pc_msg_rsp.msg_type = DAQ_SF_DP_SWAP_RTN;
        ret_type = DAQ_SUCCESS;
        *targ_type = DAQ_SF_DP_SWAP_RTN;
        break;
    case DAQ_SF_STACK_DP_SWAP:
        pc_msg_rsp.rtn = DAQ_SUCCESS;
        pc_msg_rsp.msg_type = DAQ_SF_STACK_DP_SWAP_RTN;
        ret_type = DAQ_SUCCESS;
        *targ_type = DAQ_SF_STACK_DP_SWAP_RTN;
        break;
    case DAQ_SF_SET_CONFIG:
        //Save Config
        rsp_ring = dpdkc->ap_ring[RING_MSG_SUR];
        pc_msg_rsp.rtn = sfconf_cb(pc_msg->msg_ptr);
        pc_msg_rsp.msg_type = DAQ_SF_SET_CONFIG_RTN;
        ret_type = DAQ_SUCCESS;
        *targ_type = DAQ_SF_SET_CONFIG_RTN;
        break;
    default:
        pc_msg_rsp.rtn = DAQ_SUCCESS;
        pc_msg_rsp.msg_type = DAQ_SF_REQ_INVALID_RTN;
        break;
    }

    rte_mempool_put(msg_mpool, msg);

    //Send data
    if ( DAQ_SF_DP_SWAP_RTN == pc_msg_rsp.msg_type
            || DAQ_SF_STACK_DP_SWAP_RTN == pc_msg_rsp.msg_type
            || DAQ_SF_SET_CONFIG_RTN == pc_msg_rsp.msg_type ) {
        DAQ_RTE_LOG_DEEP("%s: pc req done in queue[%d] process, send rsp--(%d)\n",
                __func__, instance->rx_queue_s, pc_msg_rsp.msg_type);

        //Send confirm msg to handler
        if (rte_mempool_get(msg_mpool, &msg) < 0)
            rte_panic("Failed to get message buffer\n");
        rte_memcpy(msg, &pc_msg_rsp, sizeof(pc_msg_rsp));

        ret = rte_ring_enqueue(rsp_ring, msg);
        if ( -ENOBUFS == ret ) {
            DAQ_RTE_LOG("%s: ring full for msg in queue[%d] process\n", __func__, instance->rx_queue_s);
            rte_mempool_put(msg_mpool, msg);
        }
        else if ( -EDQUOT == ret ) {
            DAQ_RTE_LOG("%s: Quota exceeded msg in queue[%d] process\n", __func__, instance->rx_queue_s);
        }
    }

    return ret_type;
}

//Request Pkt Count Filter
static int dpdk_daq_pc_filter_req(void *handle, void *dst_data, daq_sf_req_type req_type)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance = dpdkc->rx_ins;
    void *msg;
    //struct rte_mempool *msg_mpool = instance->daq_mpool[MPOOL_IPCRSEQ];
    struct rte_mempool *msg_mpool = dpdkc->daq_mpool[MPOOL_IPCRSEQ];
    pktcnt_msg *pc_msg;
    DAQ_Filter_Config *df_cfg;
    int ret;

    if ( DAQ_STATE_STARTED != dpdkc->state )
        return DAQ_USER_SF_OP_NONE;

    //Preparing Message
    if (rte_mempool_get(msg_mpool, &msg) < 0)
        rte_panic("Failed to get message buffer\n");

    pc_msg = (pktcnt_msg*)msg;

    switch ( req_type ) {
    case DAQ_SF_DP_SWAP:
    case DAQ_SF_STACK_DP_SWAP:
        pc_msg->msg_type = req_type;
        pc_msg->msg_ptr = dst_data;
        break;
    case DAQ_SF_SET_CONFIG:
        pc_msg->msg_type = req_type;
        pc_msg->msg_ptr = msg + sizeof(pktcnt_msg);

        df_cfg = (DAQ_Filter_Config*)dst_data;
        rte_memcpy(pc_msg->msg_ptr, dst_data,
                (long)offsetof(DAQ_Filter_Config, content)+df_cfg->config_size);//, sizeof(DAQ_Filter_Config));
        DAQ_RTE_LOG_DEEP("%s: save filter config, len %d\n", __func__,
                (long)offsetof(DAQ_Filter_Config, content)+df_cfg->config_size);
        break;
    default:
        return DAQ_USER_SF_OP_NONE;
        break;
    }

    DAQ_RTE_LOG_DEEP("%s: send pc req(%d) in queue[%d] process\n",
            __func__, pc_msg->msg_type, instance->rx_queue_s);

    ret = rte_ring_enqueue(/*instance*/dpdkc->daq_ring[RING_IPC_PCREQ], msg);
    if ( -ENOBUFS == ret ) {
        DAQ_RTE_LOG("%s: ring full for msg in queue[%d] process\n", __func__, instance->rx_queue_s);
        rte_mempool_put(msg_mpool, msg);
    }
    else if ( -EDQUOT == ret ) {
        DAQ_RTE_LOG("%s: Quota exceeded msg in queue[%d] process\n", __func__, instance->rx_queue_s);
    }

    //Signal to main thread
#ifdef DAQ_DPDK_POWER_CTL
    pthread_kill(instance->tid, SIGCONT);
#endif

    ret = 0;
    if ( DAQ_SF_DP_SWAP == req_type
            || DAQ_SF_STACK_DP_SWAP == req_type ) {
        //Wait data back
        do {
            if (rte_ring_dequeue(/*instance*/dpdkc->daq_ring[RING_IPC_PCRSP], &msg) < 0){
                usleep(100);
            }
            else{
                DAQ_RTE_LOG_DEEP("%s: get pc rsp--(%d) in queue[%d] process\n",
                        __func__, ((pktcnt_msg*)msg)->msg_type, instance->rx_queue_s);
                ret = ((pktcnt_msg*)msg)->rtn;
                rte_mempool_put(msg_mpool, msg);
                break;
            }
        } while(1);
    }

    return ret;
}

//Request Pkt Count Filter
static int dpdk_daq_multicast_req(void *handle, void *dst_data, daq_sf_req_type req_type)
{
    uint8_t p_idx, q_idx;
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;
    void *msg;
    pktcnt_msg *pc_msg;
    DAQ_Filter_Config *df_cfg;
    int ret;

    if ( DAQ_STATE_STARTED != dpdkc->state )
        return DAQ_USER_SF_OP_NONE;

    for ( p_idx=0; p_idx<dpdkc->n_port; p_idx++) {
        instance = dpdkc->instances[p_idx];
        for (q_idx=0; q_idx<instance->n_rx_queue; q_idx++) {
            //Preparing Message
            if (rte_mempool_get(instance->daq_mpools[MPOOL_IPCRSEQ][q_idx], &msg) < 0)
                rte_panic("Failed to get message buffer\n");

            pc_msg = (pktcnt_msg*)msg;
            pc_msg->msg_type = req_type;
            pc_msg->msg_ptr = msg + sizeof(pktcnt_msg);

            df_cfg = (DAQ_Filter_Config*)dst_data;
            rte_memcpy(pc_msg->msg_ptr, dst_data,
                    (long)offsetof(DAQ_Filter_Config, content)+df_cfg->config_size);//, sizeof(DAQ_Filter_Config));
            DAQ_RTE_LOG_DEEP("%s: save filter config, len %d\n", __func__,
                    (long)offsetof(DAQ_Filter_Config, content)+df_cfg->config_size);

            DAQ_RTE_LOG_DEEP("%s: send pc req(%d) in queue[%d] process\n",
                    __func__, pc_msg->msg_type, instance->rx_queue_s);

            ret = rte_ring_enqueue(instance->daq_rings[RING_IPC_PCREQ][q_idx], msg);
            if ( -ENOBUFS == ret ) {
                DAQ_RTE_LOG("%s: ring full for msg in queue[%d] process\n", __func__, q_idx);
                rte_mempool_put(instance->daq_mpools[MPOOL_IPCRSEQ][q_idx], msg);
            }
            else if ( -EDQUOT == ret ) {
                DAQ_RTE_LOG("%s: Quota exceeded msg in queue[%d] process\n", __func__, q_idx);
            }
        }
    }

    ret = 0;
    //Wait data back
    for ( p_idx=0; p_idx<dpdkc->n_port; p_idx++) {
        instance = dpdkc->instances[p_idx];
        for (q_idx=0; q_idx<instance->n_rx_queue; q_idx++) {
            do {
                if (rte_ring_dequeue(instance->ap_rings[RING_MSG_SUR][q_idx], &msg) < 0){
                    usleep(100);
                }
                else{
                    DAQ_RTE_LOG_DEEP("%s: get pc rsp--(%d) in queue[%d] process\n",
                            __func__, ((pktcnt_msg*)msg)->msg_type, q_idx);
                    ret = ((pktcnt_msg*)msg)->rtn;
                    rte_mempool_put(instance->daq_mpools[MPOOL_IPCRSEQ][q_idx], msg);
                    break;
                }
            } while(1);
        }
    }

    return ret;
}

static int dpdk_daq_sf_get_mbuf(void *handle, void **mbuf)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
//	DpdkInstance *instance = dpdkc->rx_ins;

    //DAQ_RTE_LOG("%s: pre get mbuf\n", __func__);

    if (rte_mempool_get(/*instance*/dpdkc->ap_mpool[0][MPOOL_STATSFLOW], mbuf) < 0) {
        DAQ_RTE_LOG("%s: Failed to get sf_mbuf\n", __func__);
        *mbuf = NULL;
        return 1;
    }

    //DAQ_RTE_LOG("%s: got mbuf 0x%lx\n", __func__, (unsigned long)*mbuf);

    return 0;
}

static int dpdk_daq_sf_put_mbuf(void *handle, void *mbuf, uint8_t pool_idx)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
//    DpdkInstance *instance = dpdkc->rx_ins;

    rte_mempool_put(/*instance*/dpdkc->ap_mpool[0][pool_idx], mbuf);

    return 0;
}

static int dpdk_daq_sf_get_mbufs(void *handle, void *mbufs, uint8_t pool_idx)
{
    uint16_t sock_id = 0;
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance = dpdkc->rx_ins;
    DataplaneAddrs *dpbufs = (DataplaneAddrs*)mbufs;

    DAQ_RTE_LOG_DEEP("%s: pre get mbuf[%d]\n", __func__, pool_idx);

    if ( pool_idx >= AP_MPOOL_COUNT )
        return 1;

    if ( dpbufs->sock_id >=0 )
        sock_id = dpbufs->sock_id;

    switch (pool_idx) {
    case MPOOL_STATSFLOW:
        if ( rte_mempool_get(/*instance*/dpdkc->ap_mpool[sock_id][MPOOL_STATSFLOW], &dpbufs->dp_main) < 0 ) {
            DAQ_RTE_LOG("%s: Failed to get sf_mbuf[%d]\n", __func__, MPOOL_STATSFLOW);
            return 1;
        }

        if ( NULL == instance->sf_mbuf_ssn ) {
            if ( rte_mempool_get(/*instance*/dpdkc->ap_mpool[sock_id][MPOOL_SF_SSN], &instance->sf_mbuf_ssn ) < 0) {
                DAQ_RTE_LOG("%s: Failed to get sfssn_mbuf\n", __func__);
                return 1;
            }
            DAQ_RTE_LOG("%s: got mbuf_ssn 0x%lx\n", __func__, (unsigned long)instance->sf_mbuf_ssn);
        }

        dpbufs->dp_extra = instance->sf_mbuf_ssn;
        break;
    default:
        if ( rte_mempool_get(/*instance*/dpdkc->ap_mpool[sock_id][pool_idx], &dpbufs->dp_main) < 0 ) {
            DAQ_RTE_LOG_DEEP("%s: Failed to get mbuf[%d], mpool empty?(%d)\n", __func__,
                    pool_idx, rte_mempool_empty(dpdkc->ap_mpool[pool_idx]));
            dpdkc->m_stats.ap_mpool_fail_cnt[pool_idx] ++;
            return 1;
        }
        break;
    }


    return 0;
}

static int dpdk_daq_sf_send_mbuf(void *handle, void *mbuf, uint8_t ring_idx, uint8_t pool_idx)
        //uint8_t buf_len, uint8_t buf_type)
{
    int ret;
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
//    DpdkInstance *instance = dpdkc->rx_ins;
    //struct rte_mempool *msg_mpool = instance->daq_mpool[MPOOL_IPCRSEQ];
    //void *msg;

    if ( ring_idx >= AP_RING_COUNT
            || pool_idx >= AP_MPOOL_COUNT )
        return 1;

/*    if ( MPOOL_STATSFLOW == pool_idx
            && DAQ_SF_SSN_ANALYST == buf_type ) {
        if (rte_mempool_get(msg_mpool, &msg) < 0)
            rte_panic("Failed to get message buffer\n");

        rte_memcpy(msg, mbuf, buf_len);
        rte_mempool_put(msg_mpool, msg);

        ret = rte_ring_enqueue(instance->daq_ring[RING_SF_ALY], msg);
        if ( -ENOBUFS == ret ) {
            DAQ_RTE_LOG("%s: ring[%d] full for msg in queue[%d] process\n", __func__,
                    RING_SF_ALY, instance->rx_queue_s);
            rte_mempool_put(msg_mpool, msg);
            return 1;
        }
        else if ( -EDQUOT == ret ) {
            DAQ_RTE_LOG("%s: ring[%d] Quota exceeded msg in queue[%d] process\n", __func__,
                    RING_SF_ALY, instance->rx_queue_s);
            return 1;
        }

        return 0;
    }

    if ( DAQ_SF_DIST_DP == buf_type ) {
    }*/

    ret = rte_ring_enqueue(/*instance*/dpdkc->ap_ring[ring_idx], mbuf);
    if ( -ENOBUFS == ret ) {
        DAQ_RTE_LOG_DEEP("%s: ring[%d] ring full for msg in queue[%d] process\n", __func__,
                ring_idx, instance->rx_queue_s);
        rte_mempool_put(/*instance*/dpdkc->ap_mpool[0][pool_idx], mbuf);
        return 1;
    }
    else if ( -EDQUOT == ret ) {
        DAQ_RTE_LOG_DEEP("%s: ring[%d] Quota exceeded msg in queue[%d] process\n", __func__,
                ring_idx, instance->rx_queue_s);
        return 1;
    }

    DAQ_RTE_LOG_DEEP("%s: send mbuf(%d) 0x%lx\n", __func__,
            buf_type, (unsigned long)mbuf);

    return 0;
}

int dpdk_daq_sf_multicast(void *handle, void *mdata, uint32_t md_len, uint8_t ring_idx, uint8_t pool_idx)
{
    uint8_t p_idx, q_idx;
    int ret;
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    void *mbuf;
    DpdkInstance *instance;

    if ( ring_idx >= AP_RING_COUNT
            || pool_idx >= AP_MPOOL_COUNT )
        return 1;

    for ( p_idx=0; p_idx<dpdkc->n_port; p_idx++) {
        instance = dpdkc->instances[p_idx];
        for (q_idx=0; q_idx<instance->n_rx_queue; q_idx++) {
            if (rte_mempool_get(instance->ap_mpools[pool_idx][q_idx], &mbuf) < 0) {
                DAQ_RTE_LOG("%s: Failed to get sf_multicast_mbuf[%u][%u]\n", __func__,
                        p_idx, q_idx);
                return 1;
            }

            rte_memcpy(mbuf, mdata, md_len);

            ret = rte_ring_enqueue(instance->ap_rings[ring_idx][q_idx], mbuf);
            if ( -ENOBUFS == ret ) {
                DAQ_RTE_LOG_DEEP("%s: ring[%d] ring full for msg in queue[%d] process\n", __func__,
                        ring_idx, q_idx);
                rte_mempool_put(instance->ap_mpools[pool_idx][q_idx], mbuf);
                return 1;
            }
            else if ( -EDQUOT == ret ) {
                DAQ_RTE_LOG_DEEP("%s: ring[%d] Quota exceeded msg in queue[%d] process\n", __func__,
                        ring_idx, q_idx);
                return 1;
            }
        }
    }

    DAQ_RTE_LOG_DEEP("%s: multicast mbuf(%d).\n", __func__, pool_idx);
    return 0;
}

static void *dpdk_daq_rte_memcpy(void *mbuf_dst, const void *mbuf_src, uint32_t buf_len)
        //uint8_t buf_len, uint8_t buf_type)
{
    return rte_memcpy(mbuf_dst, mbuf_src, buf_len);
}

static int dpdk_daq_start(void *handle)
{
    uint8_t p_idx;
    int ret;
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;

    if ( dpdkc->cflags & DAQ_CFG_MINERVA ) {
        RTE_LOG(INFO, EAL, "%s: Minerva is here\n", __func__);
        //return DAQ_SUCCESS;
    }

    //for (instance = dpdkc->instances; instance; instance = instance->next) {
    for ( p_idx=0; p_idx<dpdkc->naf_port; p_idx++ ) {
        instance = dpdkc->instances[p_idx];
        if (start_instance(dpdkc, instance) != DAQ_SUCCESS)
            return DAQ_ERROR;
    }

    //if ( NULL!=dpdkc->rx_ins && RTE_PROC_PRIMARY==dpdkc->proc_type ) {
    if ( dpdkc->cflags & DAQ_CFG_MINERVA ) {
        //port stats lcore available
        if ( rte_lcore_count()>0 ) {
            unsigned slaveid, valid_id = rte_lcore_id();//dpdkc->rx_ins->lcore_id;

/*            if ( dpdkc->ap_dpl->sp_init ) {
                slaveid = rte_get_next_lcore(valid_id, 0, 0);
                if ( RTE_MAX_LCORE != slaveid ) {
                    valid_id = slaveid;
                    ret = rte_eal_remote_launch(sys_ifinfo, dpdkc, slaveid);
                    if (ret != 0) {
                        RTE_LOG(ERR, EAL, "Failed to start lcore %d, return %d",
                                slaveid, ret);
                    }
                    else {
                        DAQ_RTE_LOG("sys_info_if_stats lunched on lcore %d\n", slaveid);
                    }
                }
            }*/

            if ( dpdkc->ap_dpl->sf_init ) {
                slaveid = rte_get_next_lcore(valid_id, 0, 0);
                if ( RTE_MAX_LCORE != slaveid ) {
                    valid_id = slaveid;
                    ret = rte_eal_remote_launch(sf_confluence, dpdkc, slaveid);
                    if (ret != 0) {
                        RTE_LOG(ERR, EAL, "Failed to start lcore %d, return %d",
                                slaveid, ret);
                    }
                    else {
                        DAQ_RTE_LOG("sf_confluence lunched on lcore %d\n", slaveid);
                    }
                }
            }

            if ( dpdkc->ap_dpl->sf_ssn_init && !dpdkc->cfl_unity ) {
                slaveid = rte_get_next_lcore(valid_id, 0, 0);
                if ( RTE_MAX_LCORE != slaveid ) {
                    valid_id = slaveid;
                    ret = rte_eal_remote_launch(sf_confluence_ssn, dpdkc, slaveid);
                    if (ret != 0) {
                        RTE_LOG(ERR, EAL, "Failed to start lcore %d, return %d",
                                slaveid, ret);
                    }
                    else {
                        DAQ_RTE_LOG("sf_confluence_ssn lunched on lcore %d\n", slaveid);
                    }
                }
            }

            if ( dpdkc->ap_dpl->sf_cfl_dbins ) {
                slaveid = rte_get_next_lcore(valid_id, 0, 0);
                if ( RTE_MAX_LCORE != slaveid ) {
                    valid_id = slaveid;
                    ret = rte_eal_remote_launch(sf_confluence_dbins, dpdkc, slaveid);
                    if (ret != 0) {
                        RTE_LOG(ERR, EAL, "Failed to start lcore %d, return %d",
                                slaveid, ret);
                    }
                    else {
                        DAQ_RTE_LOG("sf_confluence_dbins lunched on lcore %d\n", slaveid);
                    }
                }
            }
        }

#ifdef DAQ_DPDK_POWER_CTL
        if ( RTE_PROC_SECONDARY == dpdkc->proc_type ) {
        }
        else {
            //DAQ Power/EPFD Heuristic Initialize
            if ( (ret=daq_dpdk_power_heuristic_init(dpdkc)) ) {
            	if ( 4 == ret )
            		return DAQ_HALF_EXIT;
            	return DAQ_ERROR;
            }
        }

        //Signal FD
        signalfd_register(dpdkc->rx_ins);
#endif
    }

    dpdk_daq_reset_stats(handle);

    dpdkc->state = DAQ_STATE_STARTED;

    DAQ_RTE_LOG("%s: port %d queue %d started!\n",
    		__func__, dpdkc->rx_ins->port, dpdkc->rx_ins->rx_queue_s);

    if ( dpdkc->cflags & DAQ_CFG_MINERVA ) {
        sys_ifinfo_init(dpdkc);
    }

    return DAQ_SUCCESS;
}

static int dpdk_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;
    DAQ_Verdict verdict;
    const uint8_t *data;
    uint16_t len;
    int c = 0;//, burst_size;
    int i;
#ifdef DAQ_DPDK_PKT_FORWARD
//    int ret;
//    uint8_t ether_dst[6] = {0xc8, 0x1f, 0x66, 0xdb, 0xcb, 0xd8};
//    EtherHdr *eh_hdr;
    struct rte_mbuf *m_send;
    static uint64_t fw_cnt = 0;
    uint16_t nb_tx;
#endif
    uint32_t queue;
    struct timeval ts;
#ifdef RX_CNT_TRACK
    static uint64_t queue_cnt = 0;
    static uint64_t show_cnt = 0;
    struct rte_eth_link rte_link;
#endif

    if ( dpdkc->cflags & DAQ_CFG_MINERVA ) {
        sys_ifinfo(dpdkc);
        return 0;
    }

//    while (c < cnt || cnt <= 0)
    {
        struct rte_mbuf *bufs[BURST_SIZE];

        //for (instance = dpdkc->instances; instance; instance = instance->next) {
        instance = dpdkc->rx_ins;

#ifdef DAQ_DPDK_POWER_CTL
            daq_dpdk_power_preheuris(instance->lcore_ids[instance->rx_queue_s]);
#endif

            /* Has breakloop() been called? */
            if ( unlikely( dpdkc->break_loop ) ) {
                RTE_LOG(INFO, EAL, "Exiting from Dpdk Context\n");
                dpdkc->break_loop = 0;
                return 0;
            }

            if ( unlikely( instance->break_loop ) ) {
                RTE_LOG(INFO, EAL, "Exiting from Instance\n");
                instance->break_loop = 0;
                return DAQ_READFILE_EOF;//DAQ_USER_INT_EXIT;
            }

            for (queue = instance->rx_queue_s; queue < instance->rx_queue_e; queue++) {
                //gettimeofday(&ts, NULL);
                ts.tv_sec = time(NULL);//daqhdr.cts
                ts.tv_usec = 0;

                //burst_size = BURST_SIZE;

                const uint16_t nb_rx =
                    rte_eth_rx_burst(instance->port, queue,
                            bufs, BURST_SIZE);

#ifdef RX_CNT_TRACK
                if ( unlikely(show_cnt++ & 0x1000000) ) {
                    nic_xstats_display(instance->port);
                    //nic_stats_display(instance->port);
                    show_cnt = 0;
                    rte_eth_link_get_nowait(instance->port, &rte_link);
                    printf("Queue %d Rx Counts: %"PRIu64", link state %d\n",
                            queue, queue_cnt, rte_link.link_status);
                }
#endif

#ifdef DAQ_DPDK_POWER_CTL
                //tag queue state, busy/little/idle
                daq_dpdk_power_heuris(dpdkc->rx_ins, queue, nb_rx);
#endif

                if (unlikely(nb_rx == 0))
                    continue;

#ifdef RX_CNT_TRACK
                queue_cnt += nb_rx;
#endif

                rte_prefetch0(rte_pktmbuf_mtod(bufs[0], void *));

                for (i = 0; i < nb_rx; i++) {
                    verdict = DAQ_VERDICT_PASS;

                    if ((bufs[i]->ol_flags & PKT_RX_IP_CKSUM_BAD) != 0) {
#ifdef RX_CSUM_TRACK
                        printf("%s: ip cksum error\n", __func__);
#endif
                        rte_pktmbuf_free(bufs[i]);
                        continue;
                    }
                    else if ((bufs[i]->ol_flags & PKT_RX_L4_CKSUM_BAD) != 0){
#ifdef RX_CSUM_TRACK
                        printf("%s: tcp cksum error\n", __func__);
#endif
                        rte_pktmbuf_free(bufs[i]);
                        continue;
                    }

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

                    if (likely(i < nb_rx - 1)) {
                        rte_prefetch0(rte_pktmbuf_mtod(bufs[i+1], void *));
                    }

                    if ( likely(NULL!=callback) ) {
                        verdict = callback(user, &daqhdr, data);
                        if (verdict >= MAX_DAQ_VERDICT)
                            verdict = DAQ_VERDICT_PASS;
                        dpdkc->stats.verdicts[verdict]++;
                        verdict = verdict_translation_table[verdict];
                    }
                    dpdkc->stats.packets_received++;
                    c++;

#ifdef DAQ_DPDK_PKT_FORWARD
                    //dst_mac:c8:1f:66:db:cb:d8
                    //if ( unlikely(NULL != Send_Instance) ) {
                    if ( unlikely(instance->fw_port >= 0) ) {
                        /*eh_hdr = (EtherHdr *)data;
                        if ( memcmp(eh_hdr->ether_dst, ether_dst, 6) ) {
                            printf("%s: try allocate memory for packet.\n",
                                    __FUNCTION__);
                            m_send = rte_pktmbuf_alloc(dpdkc->daq_mpool[MPOOL_PKT_TX]);
                            if (!m_send) {
                                printf("%s: Couldn't allocate memory for packet.\n",
                                        __FUNCTION__);
                            }
                            else {
                                printf("%s: Could allocate memory for packet.\n",
                                        __FUNCTION__);
                                rte_memcpy(rte_pktmbuf_mtod(m_send, void *), data, len);
                                m_send->pkt_len  = len;
                                m_send->data_len = len;
                                nb_tx = rte_eth_tx_burst(instance->fw_port, 0, &m_send, 1);
                                if (unlikely(nb_tx == 0)) {
                                    printf("%s: Couldn't send packet. Try again.\n", __FUNCTION__);
                                    rte_pktmbuf_free(m_send);
                                }
                                else {
                                    fw_cnt++;
                                    printf("%s: dirty pkt, fw_port %u, fw_cnt %"PRIu64"\n", __func__, instance->fw_port, fw_cnt);
                                }
                            }*/

                            fw_cnt++;
                            //if ( 0xffff == (fw_cnt & 0xffff) )
                                printf("%s: dirty pkt, fw_port %u, fw_cnt %"PRIu64"\n", __func__, instance->fw_port, fw_cnt);
                            //rte_eth_tx_burst(Send_Instance->port, 0, &bufs[i], 1);
                            nb_tx = rte_eth_tx_burst(instance->fw_port, 0, &bufs[i], 1);
                            if (unlikely(nb_tx == 0)) {
                                printf("%s: Couldn't send packet. Try again.", __FUNCTION__);
                                rte_pktmbuf_free(bufs[i]);
                            }
                        //}
                    }

/*                    ret = rte_ring_enqueue(instance->msg_ring_pkt_forw, bufs[i]);
                    if ( -ENOBUFS == ret ) {
                        DAQ_RTE_LOG_DEEP("%s: Ring full for pkt-mbuf in queue[%d] process\n", __func__,
                                instance->rx_queue_s);
                        rte_pktmbuf_free(bufs[i]);
                    }
                    else if ( -EDQUOT == ret ) {
                        DAQ_RTE_LOG("%s: Quota exceeded pkt-mbuf in queue[%d] process\n", __func__,
                                instance->rx_queue_s);
                        rte_pktmbuf_free(bufs[i]);
                    }*/
#else
                    rte_pktmbuf_free(bufs[i]);
#endif
                }
            }
        //}

#ifdef DAQ_DPDK_POWER_CTL
        daq_dpdk_power_heurissum(dpdkc->rx_ins);
#endif

        if ( likely(RTE_PROC_SECONDARY == dpdkc->proc_type) ) {
            if ( unlikely( ts.tv_sec > (daqhdr.cts+1) ) ) {
                daqhdr.cts = ts.tv_sec;
                if ( unlikely(daq_dpdk_secondary_msg_handling(dpdkc, 0)) ) {
                    if ( dpdkc->mulp_sync_count++ > DAQ_DPDK_RING_MSG_HB_LOST_MAX ) {
                        DAQ_RTE_LOG("%s: primary msg lost touch, exit daq_aquire!\n",
                                __func__);
                        return DAQ_READFILE_EOF;
                    }
                }
                else {
                    dpdkc->mulp_sync_count = 0;
                }

                DAQ_RTE_LOG_DEEP("%s: check primary msg: cts %lu, loss count %d\n", __func__,
                        daqhdr.cts, dpdkc->mulp_sync_count);
            }
        }

        return 0;
    }

    return 0;
}

static int dpdk_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    uint8_t p_idx;
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance = NULL;

    struct rte_mbuf *m;

    /* Find the instance that the packet was received on. */
    //for (instance = dpdkc->instances; instance; instance = instance->next)
    for ( p_idx=0; p_idx<dpdkc->naf_port; p_idx++ )
    {
        if (dpdkc->instances[p_idx]->index == hdr->ingress_index) {
            instance = dpdkc->instances[p_idx];
            break;
        }
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

    m = rte_pktmbuf_alloc(dpdkc->daq_mpool[MPOOL_PKT_RX]);
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

    if ( NULL != dpdkc )
        dpdkc->break_loop = 1;

    gBreak_loop = 1;

    return DAQ_SUCCESS;
}

static int dpdk_daq_breakloop_ext(void)
{
    gBreak_loop = 1;

    return DAQ_SUCCESS;
}

static int dpdk_daq_stop(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    destroy_dpdkc(dpdkc);

    return DAQ_SUCCESS;
}

static void dpdk_daq_shutdown(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    destroy_dpdkc(dpdkc);
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
    uint8_t p_idx;
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;
    int port;

    if (strncmp(device, "dpdk", 4) != 0 || sscanf(&device[4], "%d", &port) != 1)
        return DAQ_ERROR_NODEV;

    //for (instance = dpdkc->instances; instance; instance = instance->next)
    for ( p_idx=0; p_idx<dpdkc->naf_port; p_idx++ )
    {
        instance = dpdkc->instances[p_idx];
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
    /* .rsp_pc_filter = */ dpdk_daq_pc_filter_rsp,
    /* .req_pc_filter = */ dpdk_daq_pc_filter_req,
    /* .sf_mc_msg = */ dpdk_daq_multicast_req,
    /* .sf_get_mbuf = */ dpdk_daq_sf_get_mbuf,
    /* .sf_put_mbuf = */ dpdk_daq_sf_put_mbuf,
    /* .sf_get_mbufs = */ dpdk_daq_sf_get_mbufs,
    /* .sf_send_mbuf = */ dpdk_daq_sf_send_mbuf,
    /* .dp_rte_memcpy = */ dpdk_daq_rte_memcpy,
    /* .start = */ dpdk_daq_start,
    /* .acquire = */ dpdk_daq_acquire,
    /* .inject = */ dpdk_daq_inject,
    /* .breakloop = */ dpdk_daq_breakloop,
    /* .breakloop_ext = */ dpdk_daq_breakloop_ext,
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

