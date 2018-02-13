/*
 *
 *
 * */
#include <signal.h>
#include <assert.h>

#include "daq_gen.h"
#include "daq_dpdk.h"
#include "daq_dpdk_epfd_ipc.h"
#include "daq_dpdk_statsop.h"


extern int mpool_lcore_queue_reinit(Dpdk_Context_t *dpdkc, uint64_t flag_rein_u,
        uint8_t port_idx, uint8_t queue_idx);

static void nic_xstats_get(uint8_t port_id, xstatsinfo *pinf)
{
    struct rte_eth_xstat_name *xstats_names;
    struct rte_eth_xstat *xstats;
    int len, ret, i;

    len = rte_eth_xstats_get_names(port_id, NULL, 0);
    if (len < 0) {
        syslog(LOG_ERR, "%s: Cannot get xstats count: port %d\n", __func__, port_id);
        return;
    }

    xstats = rte_malloc("pkt stats", sizeof(xstats[0]) * len, 0);
    if (xstats == NULL) {
        syslog(LOG_ERR, "%s: Cannot allocate memory for xstats\n", __func__);
        return;
    }

    xstats_names = rte_malloc("pkt stats", sizeof(struct rte_eth_xstat_name) * len, 0);
    if (xstats_names == NULL) {
        syslog(LOG_ERR, "%s: Cannot allocate memory for xstat names\n", __func__);
        free(xstats);
        return;
    }

    if (len != rte_eth_xstats_get_names(
            port_id, xstats_names, len)) {
        syslog(LOG_ERR, "%s: Cannot get xstat names\n", __func__);
        goto err;
    }

    ret = rte_eth_xstats_get(port_id, xstats, len);
    if (ret < 0 || ret > len) {
        syslog(LOG_ERR, "%s: Cannot get xstats\n", __func__);
        goto err;
    }

    for (i = 0; i < len; i++) {
        if ( !strcmp("rx_good_packets", xstats_names[i].name) ) {
            pinf->uRxPrcnt = xstats[i].value;
        }
        else if ( !strcmp("rx_good_bytes", xstats_names[i].name) ) {
            pinf->uRxPrbyte = xstats[i].value;
        }
        else if ( !strcmp("tx_good_packets", xstats_names[i].name) ) {
            pinf->uTxPrcnt = xstats[i].value;
        }
        else if ( !strcmp("tx_good_bytes", xstats_names[i].name) ) {
            pinf->uTxPrbyte = xstats[i].value;
        }
        else {
            //DAQ_RTE_LOG("port %d--%s: %"PRIu64"\n", port_id, xstats_names[i].name, xstats[i].value);
        }
    }

err:
    rte_free(xstats);
    rte_free(xstats_names);
}

static void daq_dpdk_master_send(Dpdk_Context_t *dpdkc, DpdkInstance *instance, uint8_t qid)
{
    int ret;
    void *msg = NULL;
    DAQ_MASTER_STATS *m_st;
    struct rte_mempool *msg_mpool = instance->daq_mpools[MPOOL_IPCRSEQ][qid];
    struct rte_ring *msg_ring = instance->daq_rings[RING_INTER_HB][qid];

    if ( rte_ring_full(msg_ring) ) {
        DAQ_RTE_LOG_DEEP("%s: ring full for msg to port(%d) queue(%d) process\n", __func__,
                instance->port, qid);
        return;
    }

    if (rte_mempool_get(msg_mpool, &msg) < 0)
        rte_panic("Failed to get message buffer\n");

    m_st = (DAQ_MASTER_STATS*)msg;
    m_st->st_seq = dpdkc->st_seq_queues[instance->port][qid] ++;

    DAQ_RTE_LOG_DEEP("%s: heartbeat sent(seq %d) to thread of port %d queue %d\n", __func__,
            m_st->st_seq, instance->port, qid);

    ret = rte_ring_enqueue(msg_ring, msg);
    if ( -ENOBUFS == ret ) {
        DAQ_RTE_LOG_DEEP("%s: ring full for msg to port(%d) queue(%d) process\n", __func__,
                instance->port, qid);
        rte_mempool_put(msg_mpool, msg);
    }
    else if ( -EDQUOT == ret ) {
        DAQ_RTE_LOG("%s: Quota exceeded msg to port(%d) queue(%d) process\n", __func__,
                instance->port, qid);
    }
}

static int daq_dpdk_master_rsv_stats(Dpdk_Context_t *dpdkc, DpdkInstance *instance, uint8_t qid)
{
    int ret, i;
    uint64_t msg_seq_this;
    void *msg = NULL;
    DAQ_MASTER_STATS *m_st;
    struct rte_mempool *msg_mpool = instance->daq_mpools[MPOOL_IPCRSEQ][qid];

    ret = rte_ring_dequeue(instance->daq_rings[RING_MASTER_STATS][qid], &msg);
    if ( ret < 0 ) {
        return -1;
    }

    m_st = (DAQ_MASTER_STATS*)msg;
    msg_seq_this = m_st->st_seq;
    for ( i=0; i<DAQ_MPOOL_COUNT; i++) {
        dpdkc->m_stats.daq_mpool_fail_cnt[i] += m_st->daq_mpool_fail_cnt[i];
    }
    for ( i=0; i<AP_MPOOL_COUNT; i++) {
        dpdkc->m_stats.ap_mpool_fail_cnt[i] += m_st->ap_mpool_fail_cnt[i];
    }

    DAQ_RTE_LOG_DEEP("%s: master stats(seq %d) received from port %d queue %d\n", __func__,
            msg_seq_this, instance->port, qid);

    rte_mempool_put(msg_mpool, msg);

    if ( msg_seq_this < MSG_SEQ_INIT_START ) {
        //Reset msg sequence number
        switch ( msg_seq_this ) {
        case MSG_MP_RESET:
            DAQ_RTE_LOG("%s: master stats(seq %d), reset mpools for port %d queue %d\n", __func__,
                    msg_seq_this, instance->port, qid);
            //Wait IPC mpool clear/full
            do {
                if ( rte_mempool_full(msg_mpool) )
                    break;

                usleep(1000);
            } while(1);

            //Reset mpools
            mpool_lcore_queue_reinit(dpdkc,
                    DAQ_DPDK_INN_REIN|DAQ_DPDK_DP_SF_REIN|DAQ_DPDK_DP_SUR_REIN,
                    instance->index, qid);

            //Send response msg
            dpdkc->st_seq_queues[instance->port][qid] = MSG_SEQ_READY;
            daq_dpdk_master_send(dpdkc, instance, qid);
            break;
        default:
            break;
        }
    }

    return 0;
}

void daq_dpdk_apmsg_send(Dpdk_Context_t *dpdkc, uint8_t apid, uint8_t rings)
{
    int ret;
    void *msg = NULL;
    daq_dp_ap_msg *m_st;
    uint8_t i;
    uint8_t *msg_ring_apid = dpdkc->msg_ring_aps + apid;
    struct rte_mempool *msg_mpool = dpdkc->ap_mpool[0][MPOOL_AP_MSG];
    struct rte_ring *msg_ring;

    for (i=0; i<rings; i++, msg_ring_apid++) {
        if ( 0xff==*msg_ring_apid || AP_RING_COUNT<*msg_ring_apid )
            break;

        msg_ring = dpdkc->ap_ring[*msg_ring_apid];

        if ( rte_ring_full(msg_ring) ) {
            DAQ_RTE_LOG_DEEP("%s: ring full for msg to ap[%d] process\n", __func__,
                    *msg_ring_apid);
            return;
        }

        if (rte_mempool_get(msg_mpool, &msg) < 0) {
            DAQ_RTE_LOG("%s: Failed to get message buffer\n", __func__);
            return;
        }

        m_st = (daq_dp_ap_msg*)msg;
        m_st->st_idx = i;
        m_st->ap_rid = *msg_ring_apid;
        m_st->st_seq = dpdkc->st_seq_aps[i] ++;

        DAQ_RTE_LOG_DEEP("%s: heartbeat sent(seq %d) to ap[%d]\n", __func__,
                m_st->st_seq, *msg_ring_apid);

        ret = rte_ring_enqueue(msg_ring, msg);
        if ( -ENOBUFS == ret ) {
            DAQ_RTE_LOG_DEEP("%s: ring full for msg to ap[%d] process\n", __func__,
                    *msg_ring_apid);
            rte_mempool_put(msg_mpool, msg);
        }
        else if ( -EDQUOT == ret ) {
            DAQ_RTE_LOG("%s: Quota exceeded msg to ap[%d] process\n", __func__,
                    *msg_ring_apid);
        }
    }
}

int daq_dpdk_apmsg_handler(Dpdk_Context_t *dpdkc)
{
    int ret;
    uint64_t msg_seq_this;
    void *msg = NULL;
    daq_dp_ap_msg *m_st;
    struct rte_mempool *msg_mpool = dpdkc->ap_mpool[0][MPOOL_AP_MSG];

    do {
        ret = rte_ring_dequeue(dpdkc->ap_ring[RING_MSG_MASTER], &msg);
        if ( ret < 0 ) {
            break;
        }

        m_st = (daq_dp_ap_msg*)msg;
        msg_seq_this = m_st->st_seq;

        DAQ_RTE_LOG_DEEP("%s: dp stats(seq %d) received from ap[%d]\n", __func__,
                msg_seq_this, m_st->ap_rid);

        rte_mempool_put(msg_mpool, msg);

        if ( msg_seq_this < MSG_SEQ_INIT_START ) {
            //Reset msg sequence number
            switch ( msg_seq_this ) {
            case MSG_MP_RESET:
                DAQ_RTE_LOG("%s: dp stats(seq %d), reset mpools for ap[%d]\n", __func__,
                        msg_seq_this, m_st->ap_rid);
                //Wait IPC mpool clear/full
                /*do {
                    if ( rte_mempool_full(msg_mpool) )
                        break;

                    usleep(1000);
                } while(1);*/

                //Reset mpools
                mpool_lcore_queue_reinit(dpdkc, m_st->res_flag, 0, 0);

                //Send response msg
                dpdkc->st_seq_aps[m_st->st_idx] = MSG_SEQ_READY;
                daq_dpdk_apmsg_send(dpdkc, m_st->st_idx, 1);
                break;
            default:
                break;
            }
        }
    }while(1);

    return 0;
}

int sf_confluence(void *args)
{
    uint8_t pid, qid, skip_round = 0;
    uint8_t mbuf_cnt;
    uint16_t mbuf_sum;
    uint32_t cfl_idle_cnt;
    int err;
    sigset_t sigset;

    Dpdk_Context_t *dpdkc = (Dpdk_Context_t*)args;
    DpdkInstance *instance;
    void *mbuf_dp;
    void *mbuf_cfl_dp;

    //block signal
    err = sigemptyset(&sigset);
    assert(err == 0);
    err = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    assert(err == 0);

    //Get mbuf for flow confluence
    if (rte_mempool_get(/*instance*/dpdkc->ap_mpool[0][MPOOL_SF_CFL], &mbuf_cfl_dp) < 0) {
        rte_panic("Failed to get sf_cfl_mbuf\n");
        return 1;
    }

    memset(mbuf_cfl_dp, 0, dpdkc->ap_dpl->mpools[MPOOL_SF_CFL].datalen);
    dpdkc->ap_dpl->sf_init(mbuf_cfl_dp, dpdkc->ap_dpl->rsock, dpdkc->ap_dpl->nsock);
    dpdkc->mbuf_cfl_dp = mbuf_cfl_dp;

    if ( dpdkc->cfl_unity ) {
        dpdkc->ap_dpl->sf_ssn_init();
    }

    mbuf_sum = 0;
    while (1) {
        //Stats Flow
        mbuf_cnt = 0;
        for (pid=0; pid<dpdkc->n_port; pid++) {
            instance = dpdkc->instances[pid];
            for (qid=0; qid<instance->n_rx_queue; qid++) {
                //Stats_Flow: Merge and Insert
                if ( !rte_ring_dequeue(instance->ap_rings[RING_STATSFLOW][qid], &mbuf_dp) ) {
                    //Merge
                    DAQ_RTE_LOG_DEEP("%s: got mbuf(iptet) from queue %d\n", __func__, qid);
                    dpdkc->ap_dpl->sf_confluence(mbuf_cfl_dp,
                            mbuf_dp,
                            instance->lcore_ids[qid],
                            MPOOL_STATSFLOW, 0);

                    //Clear
                    memset(mbuf_dp, 0, dpdkc->ap_dpl->mpools[MPOOL_STATSFLOW].datalen);
                    //Release
                    rte_mempool_put(instance->ap_mpools[MPOOL_STATSFLOW][qid], mbuf_dp);

                    mbuf_cnt++;
                }

                /*//Stack
                if ( !rte_ring_dequeue(instance->ap_rings[RING_SF_STACK][qid], &mbuf_dp) ) {
                    //Merge
                    DAQ_RTE_LOG_DEEP("%s: got mbuf(stack) from queue %d\n", __func__, qid);
                    dpdkc->ap_dpl->sf_confluence(mbuf_cfl_dp, mbuf_dp, MPOOL_SF_STACK, dn_sync);

                    //Clear
                    memset(mbuf_dp, 0, dpdkc->ap_dpl->mpools[MPOOL_SF_STACK].datalen);
                    //Release
                    rte_mempool_put(instance->ap_mpools[MPOOL_SF_STACK][qid], mbuf_dp);
                }*/
            }
        }

        if ( 0 == mbuf_cnt ) {
            if ( mbuf_sum > 0 ) {
                if ( cfl_idle_cnt++ > 5000 ) {      //should be 5 seconds
                    DAQ_RTE_LOG("%s: Cfl mbuf count(%d) cleared for burn-in\n", __func__, mbuf_sum);
                    //I/O operation
                    if ( !skip_round )
                        skip_round = dpdkc->ap_dpl->sf_confluence(mbuf_cfl_dp, NULL, 0, MPOOL_STATSFLOW, 1);
                    else
                        skip_round--;
                    mbuf_sum = 0;
                }
            }
        }
        else {
            if ( 0 == mbuf_sum )
                cfl_idle_cnt = 0;    //Start burn-in flag

            mbuf_sum += mbuf_cnt;
            if ( mbuf_sum == dpdkc->n_port_queue ) {
                DAQ_RTE_LOG_DEEP("%s: Cfl mbuf count(%d) cleared for one round\n", __func__, mbuf_sum);
                //I/O operation
                if ( !skip_round )
                    skip_round = dpdkc->ap_dpl->sf_confluence(mbuf_cfl_dp, NULL, 0, MPOOL_STATSFLOW, 1);
                else
                    skip_round--;
                mbuf_sum = 0;

                //SSN
                if ( dpdkc->cfl_unity ) {
                    dpdkc->ap_dpl->sf_cfl_ssn(dpdkc->mbuf_cfl_dp);
                }

                //Stats of mpool-get-fail count
                DAQ_RTE_LOG("%s: mpool_failed stats -- [%d]-%lu, [%d]-%lu, [%d]-%lu\n", __func__,
                        MPOOL_META, dpdkc->m_stats.ap_mpool_fail_cnt[MPOOL_META],
                        MPOOL_META_PAYLOAD, dpdkc->m_stats.ap_mpool_fail_cnt[MPOOL_META_PAYLOAD],
                        MPOOL_DIGGER, dpdkc->m_stats.ap_mpool_fail_cnt[MPOOL_DIGGER]);
            }
        }

        usleep(1000);
        //DAQ_RTE_LOG("%s: loop done\n", __func__);
    }

    return 0;
}

int sf_confluence_ssn(void *args)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t*)args;

    DAQ_RTE_LOG("%s: waiting for confluence data-plane ready.\n", __func__);
    while ( NULL == dpdkc->mbuf_cfl_dp ) {
        sleep(1);
    }

    dpdkc->ap_dpl->sf_ssn_init();

    while (1) {
        if ( NULL == dpdkc->mbuf_cfl_dp ) {
            sleep(1);
            continue;
        }

        //SSN
        dpdkc->ap_dpl->sf_cfl_ssn(dpdkc->mbuf_cfl_dp);

        sleep(1);
        //DAQ_RTE_LOG("%s: loop done\n", __func__);
    }

    return 0;
}

int sf_confluence_dbins(void *args)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t*)args;

    while ( NULL == dpdkc->mbuf_cfl_dp ) {
        sleep(1);
    }

    dpdkc->ap_dpl->sf_cfl_dbins(dpdkc->mbuf_cfl_dp);

    return 0;
}

static int sf_confluence_stackstats(Dpdk_Context_t *dpdkc)
{
    uint8_t pid, qid;
    uint16_t cfl_scaled = 0;
    uint16_t st_dbc = 0;
    uint64_t st_dbm = 0, st_std_dbm = 0;
    DpdkInstance *instance;
    void *mbuf_dp;

    if ( NULL == dpdkc->mbuf_cfl_dp )
        return 0;

    for (pid=0; pid<dpdkc->n_port; pid++) {
        instance = dpdkc->instances[pid];
        for (qid=0; qid<instance->n_rx_queue; qid++) {
            st_dbc++;
            st_std_dbm |= (0x01<<st_dbc);

            //Stack
            if ( !rte_ring_dequeue(instance->ap_rings[RING_SF_STACK][qid], &mbuf_dp) ) {
                st_dbm |= (0x01<<st_dbc);

                //Duplicate port-queue
                if ( dpdkc->pq_stack_dbm & st_dbm ) {
                    //Sync to DB
                    dpdkc->ap_dpl->sf_confluence(dpdkc->mbuf_cfl_dp, NULL, 0, MPOOL_SF_STACK, 1);
                    dpdkc->pq_stack_dbm = 0;
                    cfl_scaled = 1;

                    //Start map from this queue
                    st_dbm = (0x01<<st_dbc);
                }

                //Merge
                DAQ_RTE_LOG_DEEP("%s: got mbuf(stack) from queue %d\n", __func__, qid);
                dpdkc->ap_dpl->sf_confluence(dpdkc->mbuf_cfl_dp, mbuf_dp, 0, MPOOL_SF_STACK, 0);

                //if ( (pid+1)==dpdkc->n_port && (qid+1)==instance->n_rx_queue )
                    //cfl_scaled = 1;

                //Clear
                memset(mbuf_dp, 0, dpdkc->ap_dpl->mpools[MPOOL_SF_STACK].datalen);
                //Release
                rte_mempool_put(instance->ap_mpools[MPOOL_SF_STACK][qid], mbuf_dp);
            }
        }
    }

    //if ( cfl_scaled ) {
    dpdkc->pq_stack_dbm |= st_dbm;
    if ( dpdkc->pq_stack_dbm == st_std_dbm ) {
        //Sync to DB
        dpdkc->ap_dpl->sf_confluence(dpdkc->mbuf_cfl_dp, NULL, 0, MPOOL_SF_STACK, 1);
        dpdkc->pq_stack_dbm = 0;
        cfl_scaled = 1;
    }

    return cfl_scaled;
}

int sys_ifinfo_init(Dpdk_Context_t *dpdkc)
{
    int err;
    sigset_t sigset;

    //block signal
    err = sigemptyset(&sigset);
    assert(err == 0);
    err = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    assert(err == 0);

    while ( dpdkc->ap_dpl->sp_init() ) {
        DAQ_RTE_LOG("%s: sp_init failed, try again\n", __func__);
        sleep(1);
    }

    DAQ_RTE_LOG("%s: sp_init OK\n", __func__);

    return 0;
}

int sys_ifinfo(void *args)
{
    uint8_t pid, qid, pt_scale = 0;
    //uint32_t sp_timetick, sp_timetick_pre = 0;
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t*)args;
    DpdkInstance *instance;// = dpdkc->rx_ins;
    xstatsinfo xsta_info;
    struct rte_eth_link rte_link;

    do {
        //Stack stats data, one scale time-line
        if ( sf_confluence_stackstats(dpdkc) )
            pt_scale = 1;

        //sp_timetick = time(NULL);
        if ( pt_scale ) {//sp_timetick > sp_timetick_pre ) {
            //sp_timetick_pre = sp_timetick;
            /*DAQ_RTE_LOG("%s: scale port num %d, pt_scale %d, tv %d\n", __func__,
                    dpdkc->n_port, pt_scale, time(NULL));*/

            //Get data from NIC
            for ( pid=0; pid<dpdkc->n_port; pid++ ) {
                instance = dpdkc->instances[pid];
                nic_xstats_get(instance->port, &xsta_info);
                memset(&rte_link, 0, sizeof(rte_link));
                rte_eth_link_get_nowait(instance->port, &rte_link);
                if ( ETH_LINK_UP == rte_link.link_status ) {
                    xsta_info.cIfup = 1;
                    xsta_info.link_speed = rte_link.link_speed;
                }
                else {
                    xsta_info.cIfup = 0;
                    xsta_info.link_speed = 0;
                }

                //port stats, port 0
                dpdkc->ap_dpl->sp_scale(&xsta_info, instance->port);

                //IPC for primary process monitoring
                for (qid=0; qid<instance->n_rx_queue; qid++) {
                    daq_dpdk_master_send(dpdkc, instance, qid);
                }
            }
            daq_dpdk_apmsg_send(dpdkc, 0, MAX_DP_AP_NUM);
        }

        //Stats Gap
#ifdef DAQ_DPDK_POWER_CTL
        if ( dpdkc->power_heurs->intr_en ) {
            epfd_server_loop(dpdkc);
        }
        else {
            sleep(1);
        }
#else
        usleep(1000);
#endif
    } while (0);

    for ( pid=0; pid<dpdkc->n_port; pid++ ) {
        instance = dpdkc->instances[pid];
        for (qid=0; qid<instance->n_rx_queue; qid++) {
            daq_dpdk_master_rsv_stats(dpdkc, instance, qid);
        }
    }
    daq_dpdk_apmsg_handler(dpdkc);

    return 0;
}
