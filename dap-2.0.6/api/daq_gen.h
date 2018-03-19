#ifndef __DAQ_GEN_H__
#define __DAQ_GEN_H__

#include <stdint.h>

#define DAQ_DP_MP_NUMA_NODE_NUM             2       /* Co-relate to numa node,
                                                    ** adjust MAX_IPTET_CONFLUENCE_NODE_SZ
                                                    ** according to working memory size.*/

//MPOOL
#define DAQ_DP_MP_SF_FLW              "MPOOL_STATS_FLOW_S%dP%dQ%d"
#define DAQ_DP_MP_SF_STK              "MPOOL_SF_STACK_S%dP%dQ%d"
#define DAQ_DP_MP_SF_SSN              "MPOOL_SF_SSN_S%dP%dQ%d"
#define DAQ_DP_MP_SFCFL_IPTHA         "MPOOL_SFCFL_IPTHA_S%dP%dQ%d"
#define DAQ_DP_MP_SFCFL_IPT           "MPOOL_SFCFL_IPT_S%dP%dQ%d"
#define DAQ_DP_MP_SFCFL_PPHA          "MPOOL_SFCFL_PPHA_S%dP%dQ%d"
#define DAQ_DP_MP_SFCFL_PP            "MPOOL_SFCFL_PP_S%dP%dQ%d"
#define DAQ_DP_MP_SF_CFL              "MPOOL_SF_CFL_S%dP%dQ%d"
#define DAQ_DP_MP_SF_PPL              "MPOOL_SF_PPL_SPQ"

#define DAQ_DP_MP_DG_MTA              "meta-mpool_s%dp%dq%d"
#define DAQ_DP_MP_DG_MPL              "meta-pl-mpool_s%dp%dq%d"
#define DAQ_DP_MP_DG_INT              "digger-mempool"
#define DAQ_DP_MP_DG_GEO              "mpool-geo"

#define DAQ_DP_MP_SUR_PBM             "MPOOL_PBM_S%dP%dQ%d"
#define DAQ_DP_MP_SUR_MCP             "MPOOL_MCP_S%dP%dQ%d"

#define DAQ_DP_MP_MSG_AP              "MPOOL_MSG_AP"

#define DAQ_DP_MP_EVN_PT              "portrait-mpool"

//RING
#define DAQ_DP_RING_SF_FLW            "RING_STATS_FLOW_S%dP%dQ%d"
#define DAQ_DP_RING_SF_STK            "RING_SF_STACK_S%dP%dQ%d"

#define DAQ_DP_RING_DG_MTA            "meta-ring_s%dp%dq%d"
#define DAQ_DP_RING_DG_MPL            "meta-pl-ring_s%dp%dq%d"
#define DAQ_DP_RING_DG_INT            "digger-ring"

#define DAQ_DP_RING_MASTER            "master-msg"
#define DAQ_DP_RING_MSG_SV            "surveyor-msg_s%dp%dq%d"
#define DAQ_DP_RING_MSG_DG            "digger-msg"
#define DAQ_DP_RING_MSG_SQ            "squirrel-msg"
#define DAQ_DP_RING_MSG_PT            "portrait-msg"

#define DAQ_DP_RING_SQ_SND            "portrait-ring"
#define DAQ_DP_RING_SQ_RSV            "portrait-ring-back"


typedef enum _DAQ_DPDK_INTER_MSG_SEQ
{
    MSG_MP_RESET,
    MSG_SEQ_READY,
    MSG_SEQ_INIT_START,        //Message Sequence Initial Number
} DAQ_DPDK_INTER_MSG_SEQ;

typedef enum __daq_dpdk_sf_mpr_type
{
    DAQ_DPDK_INN               = (0x01L<<0),
    DAQ_DPDK_INN_REIN          = (0x01L<<1),
    DAQ_DPDK_DP_SF             = (0x01L<<2),
    DAQ_DPDK_DP_SF_REIN        = (0x01L<<3),
    DAQ_DPDK_DP_SUR            = (0x01L<<4),
    DAQ_DPDK_DP_SUR_REIN       = (0x01L<<5),
    DAQ_DPDK_DP_AP             = (0x01L<<6),
    DAQ_DPDK_DP_DIGGER         = (0x01L<<7),
    DAQ_DPDK_DP_DIGGER_REIN    = (0x01L<<8),
    DAQ_DPDK_DP_SQ             = (0x01L<<9),
    DAQ_DPDK_DP_SQ_REIN        = (0x01L<<10),
} daq_dpdk_sf_mpr_type;

typedef struct __daq_dp_ap_msg
{
    uint8_t st_idx;
    uint8_t ap_rid;
    uint64_t st_seq;
    uint64_t res_flag;
} daq_dp_ap_msg;

#endif /*end of __DAQ_GEN_H__*/
