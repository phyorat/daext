#ifndef __DAQ_DPDK_STATSOP_H__
#define __DAQ_DPDK_STATSOP_H__


extern daq_dpdk_mpool_collect dk_mbuf_coll[];
extern daq_dpdk_ring_collect dk_ring_coll[];

static inline int daq_dpdk_secondary_msg_handling(Dpdk_Context_t *dpdkc, uint8_t msg_push)//DpdkInstance *instance)
{
    int ret;
    void *msg;
    DAQ_MASTER_STATS *m_st;
    struct rte_mempool *msg_mpool = dpdkc->daq_mpool[MPOOL_IPCRSEQ];
    struct rte_ring *msg_ring_rsv = dpdkc->daq_ring[RING_INTER_HB];
    struct rte_ring *msg_ring_snd = dpdkc->daq_ring[RING_MASTER_STATS];

    if ( likely(!msg_push) ) {
        if (rte_ring_dequeue(/*instance*/msg_ring_rsv, &msg) < 0){
            return -1;
        }
    }
    else {
        unsigned sock_id;
        char namebuf[64];

        if ( NULL == msg_mpool ) {
            sock_id = rte_lcore_to_socket_id(dpdkc->rx_ins->rx_queue_s);
            snprintf(namebuf, sizeof(namebuf), dk_mbuf_coll[MPOOL_IPCRSEQ].name,
                    sock_id, dpdkc->rx_ins->port, dpdkc->rx_ins->rx_queue_s);
            DAQ_RTE_LOG("%s: looking mpool %s!\n", __FUNCTION__, namebuf);
            msg_mpool = rte_mempool_lookup(namebuf);
            if ( NULL == msg_mpool ) {
                DAQ_RTE_LOG("%s: Couldn't find %s!\n", __FUNCTION__, namebuf);
                return -1;
            }
        }

        if ( NULL == msg_ring_rsv ) {
            sock_id = rte_lcore_to_socket_id(dpdkc->rx_ins->rx_queue_s);
            snprintf(namebuf, sizeof(namebuf), dk_ring_coll[RING_INTER_HB].name,
                    sock_id, dpdkc->rx_ins->port, dpdkc->rx_ins->rx_queue_s);
            DAQ_RTE_LOG("%s: looking ring %s!\n", __FUNCTION__, namebuf);
            msg_ring_rsv = rte_ring_lookup(namebuf);
            if ( NULL == msg_ring_rsv ) {
                DAQ_RTE_LOG("%s: Couldn't find %s!\n", __FUNCTION__, namebuf);
                return -1;
            }
        }

        if ( NULL == msg_ring_snd ) {
            sock_id = rte_lcore_to_socket_id(dpdkc->rx_ins->rx_queue_s);
            snprintf(namebuf, sizeof(namebuf), dk_ring_coll[RING_MASTER_STATS].name,
                    sock_id, dpdkc->rx_ins->port, dpdkc->rx_ins->rx_queue_s);
            DAQ_RTE_LOG("%s: looking ring %s!\n", __FUNCTION__, namebuf);
            msg_ring_snd = rte_ring_lookup(namebuf);
            if ( NULL == msg_ring_snd ) {
                DAQ_RTE_LOG("%s: Couldn't find %s!\n", __FUNCTION__, namebuf);
                return -1;
            }
        }

        if (rte_mempool_get(msg_mpool, &msg) < 0) {
            DAQ_RTE_LOG("Failed to get message buffer\n");
            return -1;
        }

        memset(msg, 0, dk_mbuf_coll[MPOOL_IPCRSEQ].datalen);
        DAQ_RTE_LOG("%s: push msg to master\n", __func__);
    }

    //Parse message
    m_st = (DAQ_MASTER_STATS*)msg;
    if ( unlikely(msg_push) )
        dpdkc->m_stats.st_seq = MSG_MP_RESET;
    else
        dpdkc->m_stats.st_seq = m_st->st_seq;
    rte_memcpy(m_st, &dpdkc->m_stats, sizeof(DAQ_MASTER_STATS));
    memset(&dpdkc->m_stats, 0, sizeof(dpdkc->m_stats));

    DAQ_RTE_LOG_DEEP("%s: slave stats(seq %d) send of port %d queue %d\n", __func__,
            m_st->st_seq, dpdkc->rx_ins->port, dpdkc->rx_ins->rx_queue_s);

    //Send to master
    ret = rte_ring_enqueue(/*instance*/msg_ring_snd, msg);
    if ( -ENOBUFS == ret ) {
        DAQ_RTE_LOG_DEEP("%s: ring full for msg to master process\n", __func__);
        rte_mempool_put(msg_mpool, msg);
    }
    else if ( -EDQUOT == ret ) {
        DAQ_RTE_LOG("%s: Quota exceeded msg to master process\n", __func__);
    }

    if ( unlikely(msg_push) ) {
        //Wait for msg back from master
        do {
            if ( 0 == rte_ring_dequeue(/*instance*/msg_ring_rsv, &msg) ) {
                m_st = (DAQ_MASTER_STATS*)msg;
                dpdkc->m_stats.st_seq = m_st->st_seq;
                rte_mempool_put(msg_mpool, msg);

                if ( MSG_SEQ_READY == dpdkc->m_stats.st_seq )
                    break;
                else
                    continue;
            }

            DAQ_RTE_LOG("%s: waiting for master (re)init mpools.\n", __func__);
            sleep(1);
        } while(1);
    }

    return 0;
}

int sf_confluence(void *args);
int sf_confluence_ssn(void *args);
int sf_confluence_dbins(void *args);
int sys_ifinfo_init(Dpdk_Context_t *dpdkc);
int sys_ifinfo(void *args);

#endif  /*__DAQ_DPDK_STATSOP_H__*/
