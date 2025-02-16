/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2020 MediaTek Inc.
 */

#ifndef _NAN_SCHEDULER_H_
#define _NAN_SCHEDULER_H_

#if CFG_SUPPORT_NAN

#define NAN_SEND_PKT_TIME_SLOT 16
#define NAN_SEND_PKT_TIME_GUARD_TIME 2

#define NAN_MAX_NDC_RECORD (NAN_MAX_CONN_CFG + 1) /* one for default NDC */

#define NAN_MAX_POTENTIAL_CHNL_LIST 10

/* the number of availability attribute per NAN station */
#define NAN_NUM_AVAIL_DB 2
/* the number of availability entry per NAN availability attribute */
#define NAN_NUM_AVAIL_TIMELINE 10
/* the number of BAND_CHNL entry per NAN availability entry attribute */
#define NAN_NUM_BAND_CHNL_ENTRY 5

#define NAN_NUM_PEER_SCH_DESC 50

#define NAN_TIMELINE_MGMT_SIZE          1  /* need to align with FW */
#define NAN_TIMELINE_MGMT_CHNL_LIST_NUM 10 /* need to align with FW */

#define NAN_CRB_NEGO_MAX_TRANSACTION 20

#define NAN_DW_INTERVAL 512
#define NAN_SLOT_INTERVAL 16

#define NAN_SLOTS_PER_DW_INTERVAL (NAN_DW_INTERVAL / NAN_SLOT_INTERVAL)

#define NAN_TOTAL_DW 16
#define NAN_TOTAL_SLOT_WINDOWS (NAN_TOTAL_DW * NAN_SLOTS_PER_DW_INTERVAL)

#define NAN_TIME_BITMAP_CONTROL_SIZE 2
#define NAN_TIME_BITMAP_LENGTH_SIZE 1
#define NAN_TIME_BITMAP_MAX_SIZE 64
#define NAN_TIME_BITMAP_FIELD_MAX_LENGTH                                       \
	(NAN_TIME_BITMAP_CONTROL_SIZE + NAN_TIME_BITMAP_LENGTH_SIZE +          \
	 NAN_TIME_BITMAP_MAX_SIZE)

#define NAN_DEFAULT_MAP_ID 1

#define NAN_MAX_CONN_CFG 8 /* the max supported concurrent NAN data path */

#define NAN_INVALID_QOS_MAX_LATENCY 65535
#define NAN_INVALID_QOS_MIN_SLOTS 0
#define NAN_QOS_MAX_LATENCY_LOW_BOUND 1
#define NAN_QOS_MAX_LATENCY_UP_BOUND 30
#define NAN_QOS_MIN_SLOTS_LOW_BOUND 1
#define NAN_QOS_MIN_SLOTS_UP_BOUND 30
#define NAN_DEFAULT_NDL_QUOTA_LOW_BOUND 3
#define NAN_DEFAULT_NDL_QUOTA_UP_BOUND 30
#define NAN_DEFAULT_RANG_QUOTA_LOW_BOUND 1
#define NAN_DEFAULT_RANG_QUOTA_UP_BOUND 3

#define NAN_INVALID_MAP_ID 0xFF

enum _NAN_CHNL_BW_MAP {
	NAN_CHNL_BW_20 = 0,
	NAN_CHNL_BW_40,
	NAN_CHNL_BW_80,
	NAN_CHNL_BW_160,
	NAN_CHNL_BW_NUM
};

struct NAN_EVT_NDL_FLOW_CTRL {
	uint16_t au2FlowCtrl[NAN_MAX_CONN_CFG];
};

struct NAN_FLOW_CTRL {
	u_int8_t fgAllow;
	uint32_t u4Time;
};

union _NAN_BAND_CHNL_CTRL {
	struct {
		uint32_t u4Type : 1;
		uint32_t u4Rsvd : 31;
	} rInfo;

	struct {
		uint32_t u4Type : 1;
		uint32_t u4Rsvd : 23;
		uint32_t u4BandIdMask : 8;
	} rBand;

	struct {
		uint32_t u4Type : 1;
		uint32_t u4Rsvd : 7;
		uint32_t u4OperatingClass : 8;
		uint32_t u4PrimaryChnl : 8;
		uint32_t u4AuxCenterChnl : 8;
	} rChannel;

	uint32_t u4RawData;
};

struct NAN_EVT_NDL_FLOW_CTRL_V2 {
	uint32_t au4RemainingTime[NAN_MAX_CONN_CFG];
	union _NAN_BAND_CHNL_CTRL arBandChnlInfo[NAN_MAX_CONN_CFG];
};

enum _ENUM_NAN_NEGO_TYPE_T {
	ENUM_NAN_NEGO_DATA_LINK,
	ENUM_NAN_NEGO_RANGING,
	ENUM_NAN_NEGO_NUM
};

enum _ENUM_NAN_NEGO_ROLE_T {
	ENUM_NAN_NEGO_ROLE_INITIATOR,
	ENUM_NAN_NEGO_ROLE_RESPONDER,
	ENUM_NAN_NEGO_ROLE_NUM
};

struct _NAN_SCHEDULE_TIMELINE_T {
	uint8_t ucMapId;
	uint8_t aucRsvd[3];

	uint32_t au4AvailMap[NAN_TOTAL_DW];
};

enum _ENUM_NAN_DEVCAP_FIELD_T {
	ENUM_NAN_DEVCAP_CAPABILITY_SET,
	ENUM_NAN_DEVCAP_TX_ANT_NUM,
	ENUM_NAN_DEVCAP_RX_ANT_NUM
};

struct _NAN_PHY_SETTING_T {
	uint8_t ucPhyTypeSet;
	uint8_t ucNonHTBasicPhyType;
	unsigned char fgUseShortPreamble;
	unsigned char fgUseShortSlotTime;

	uint16_t u2OperationalRateSet;
	uint16_t u2BSSBasicRateSet;

	uint16_t u2VhtBasicMcsSet;
	unsigned char fgErpProtectMode;
	uint8_t ucHtOpInfo1;

	uint16_t u2HtOpInfo2;
	uint16_t u2HtOpInfo3;

	enum ENUM_HT_PROTECT_MODE eHtProtectMode;
	enum ENUM_GF_MODE eGfOperationMode;
	enum ENUM_RIFS_MODE eRifsOperationMode;

	/* ENUM_CHNL_EXT_T eBssSCO; */
};

struct _NAN_SCHED_EVENT_NAN_ATTR_T {
	uint8_t aucNmiAddr[MAC_ADDR_LEN];
	uint8_t aucRsvd[2];
	uint8_t aucNanAttr[1000];
};

struct _NAN_DEVICE_CAPABILITY_T {
	unsigned char fgValid;
	uint8_t ucMapId;
	uint8_t ucSupportedBand;
	uint8_t ucOperationMode;
	uint8_t ucDw24g;
	uint8_t ucDw5g;
	uint8_t ucOvrDw24gMapId;
	uint8_t ucOvrDw5gMapId;
	uint8_t ucNumTxAnt;
	uint8_t ucNumRxAnt;
	uint8_t ucCapabilitySet;

	uint16_t u2MaxChnlSwitchTime;
};

struct _NAN_NDC_CTRL_T {
	unsigned char fgValid;
	uint8_t aucNdcId[NAN_NDC_ATTRIBUTE_ID_LENGTH];
	uint8_t aucRsvd[1];
	struct _NAN_SCHEDULE_TIMELINE_T arTimeline[NAN_NUM_AVAIL_DB];
};

union _NAN_AVAIL_ENTRY_CTRL {
	struct {
		uint16_t u2Type : 3;
		uint16_t u2Preference : 2;
		uint16_t u2Util : 3;
		uint16_t u2RxNss : 4;
		uint16_t u2TimeMapAvail : 1;
		uint16_t u2Rsvd : 3;
	} rField;

	uint16_t u2RawData;
};

struct _NAN_AVAILABILITY_TIMELINE_T {
	unsigned char fgActive;

	union _NAN_AVAIL_ENTRY_CTRL rEntryCtrl;

	uint8_t ucNumBandChnlCtrl;
	union _NAN_BAND_CHNL_CTRL arBandChnlCtrl[NAN_NUM_BAND_CHNL_ENTRY];

	uint32_t au4AvailMap[NAN_TOTAL_DW];
};

struct _NAN_AVAILABILITY_DB_T {
	uint8_t ucMapId;

	struct _NAN_AVAILABILITY_TIMELINE_T
		arAvailEntryList[NAN_NUM_AVAIL_TIMELINE];
};

struct _NAN_PEER_SCH_DESC_T {
	struct LINK_ENTRY rLinkEntry;

	uint8_t aucNmiAddr[MAC_ADDR_LEN];

	OS_SYSTIME rUpdateTime;

	unsigned char fgUsed;   /* indicate the SCH DESC is used by a SCH REC */
	uint32_t u4SchIdx; /* valid only when fgUsed is TRUE */

	uint32_t u4AvailAttrToken;
	struct _NAN_AVAILABILITY_DB_T arAvailAttr[NAN_NUM_AVAIL_DB];

	uint32_t u4DevCapAttrToken;
	struct _NAN_DEVICE_CAPABILITY_T arDevCapability[NAN_NUM_AVAIL_DB + 1];

	uint32_t u4QosMinSlots;
	uint32_t u4QosMaxLatency;

	/* for peer proposal cache during schedule negotiation */
	struct _NAN_NDC_CTRL_T rSelectedNdcCtrl;

	unsigned char fgImmuNdlTimelineValid;
	struct _NAN_SCHEDULE_TIMELINE_T arImmuNdlTimeline[NAN_NUM_AVAIL_DB];

	unsigned char fgRangingTimelineValid;
	struct _NAN_SCHEDULE_TIMELINE_T arRangingTimeline[NAN_NUM_AVAIL_DB];
};

struct _NAN_CHANNEL_TIMELINE_T {
	unsigned char fgValid;
	uint8_t aucRsvd[3];

	union _NAN_BAND_CHNL_CTRL rChnlInfo;

	int32_t i4Num; /* track the number of slot in availability map */
	uint32_t au4AvailMap[NAN_TOTAL_DW];
};

struct _NAN_TIMELINE_MGMT_T {
	uint8_t ucMapId;

	/* for committed availability type */
	struct _NAN_CHANNEL_TIMELINE_T
		arChnlList[NAN_TIMELINE_MGMT_CHNL_LIST_NUM];

	/* for conditional availability type */
	unsigned char fgChkCondAvailability;
	struct _NAN_CHANNEL_TIMELINE_T
		arCondChnlList[NAN_TIMELINE_MGMT_CHNL_LIST_NUM];

	/* for custom committed FAW */
	struct _NAN_CHANNEL_TIMELINE_T
		arCustChnlList[NAN_TIMELINE_MGMT_CHNL_LIST_NUM];
};

/* NAN Scheduler Control Block */
struct _NAN_SCHEDULER_T {
	unsigned char fgInit;

	unsigned char fgEn2g;
	unsigned char fgEn5gH;
	unsigned char fgEn5gL;

	uint8_t ucNanAvailAttrSeqId; /* shared by all availability attr */
	uint16_t u2NanAvailAttrControlField;     /* tracking changed flags */
	uint16_t u2NanCurrAvailAttrControlField; /* tracking changed flags */

	struct _NAN_NDC_CTRL_T arNdcCtrl[NAN_MAX_NDC_RECORD];

	struct LINK rPeerSchDescList;
	struct LINK rFreePeerSchDescList;
	struct _NAN_PEER_SCH_DESC_T arPeerSchDescArray[NAN_NUM_PEER_SCH_DESC];

	unsigned char fgAttrDevCapValid;
	struct _NAN_ATTR_DEVICE_CAPABILITY_T rAttrDevCap;

	uint32_t u4NumOfPotentialChnlList;
	struct _NAN_CHNL_ENTRY_T
		arPotentialChnlList[NAN_MAX_POTENTIAL_CHNL_LIST];

	struct TIMER rAvailAttrCtrlResetTimer;

	uint8_t ucCommitDwInterval;
};

uint32_t nanSchedNegoApplyCustChnlList(struct ADAPTER *prAdapter);

uint32_t nanSchedInit(struct ADAPTER *prAdapter);
uint32_t nanSchedUninit(struct ADAPTER *prAdapter);

void nanSchedDropResources(struct ADAPTER *prAdapter, uint8_t *pucNmiAddr,
			   enum _ENUM_NAN_NEGO_TYPE_T eType);

void nanSchedNegoInitDb(struct ADAPTER *prAdapter, uint32_t u4SchIdx,
			enum _ENUM_NAN_NEGO_TYPE_T eType,
			enum _ENUM_NAN_NEGO_ROLE_T eRole);
void nanSchedNegoDispatchTimeout(struct ADAPTER *prAdapter,
		uintptr_t ulParam);
uint32_t nanSchedNegoGenLocalCrbProposal(struct ADAPTER *prAdapter);
uint32_t nanSchedNegoChkRmtCrbProposal(struct ADAPTER *prAdapter,
				       uint32_t *pu4RejectCode);

unsigned char nanSchedNegoIsRmtCrbConflict(
	struct ADAPTER *prAdapter,
	struct _NAN_SCHEDULE_TIMELINE_T arTimeline[NAN_NUM_AVAIL_DB],
	unsigned char *pfgEmptyMapSet, uint32_t au4EmptyMap[NAN_TOTAL_DW]);

unsigned char nanSchedNegoInProgress(struct ADAPTER *prAdapter);
void nanSchedNegoStop(struct ADAPTER *prAdapter);
uint32_t nanSchedNegoStart(
	struct ADAPTER *prAdapter, uint8_t *pucNmiAddr,
	enum _ENUM_NAN_NEGO_TYPE_T eType, enum _ENUM_NAN_NEGO_ROLE_T eRole,
	void (*pfCallback)(struct ADAPTER *prAdapter, uint8_t *pucNmiAddr,
			   enum _ENUM_NAN_NEGO_TYPE_T eType,
			   enum _ENUM_NAN_NEGO_ROLE_T eRole, void *pvToken),
	void *pvToken);

uint32_t nanSchedNegoGetImmuNdlScheduleList(struct ADAPTER *prAdapter,
					    uint8_t **ppucScheduleList,
					    uint32_t *pu4ScheduleListLength);
uint32_t nanSchedNegoGetRangingScheduleList(struct ADAPTER *prAdapter,
					    uint8_t **ppucScheduleList,
					    uint32_t *pu4ScheduleListLength);
uint32_t nanSchedNegoGetQosAttr(struct ADAPTER *prAdapter,
		uint8_t **ppucQosAttr, uint32_t *pu4QosLength);
uint32_t nanSchedNegoGetSelectedNdcAttr(struct ADAPTER *prAdapter,
					uint8_t **ppucNdcAttr,
					uint32_t *pu4NdcAttrLength);
uint32_t nanSchedNegoAddQos(struct ADAPTER *prAdapter, uint32_t u4MinSlots,
			    uint32_t u4MaxLatency);

uint32_t nanSchedGetAvailabilityAttr(struct ADAPTER *prAdapter,
				     uint8_t **ppucAvailabilityAttr,
				     uint32_t *pu4AvailabilityAttrLength);
uint32_t nanSchedGetNdcAttr(struct ADAPTER *prAdapter, uint8_t **ppucNdcAttr,
			    uint32_t *pu4NdcAttrLength);

uint32_t nanSchedGetDevCapabilityAttr(struct ADAPTER *prAdapter,
				      uint8_t **ppucDevCapAttr,
				      uint32_t *pu4DevCapAttrLength);

uint32_t nanSchedGetUnalignedScheduleAttr(struct ADAPTER *prAdapter,
					  uint8_t **ppucUnalignedScheduleAttr,
					  uint32_t *pu4UnalignedScheduleLength);

uint32_t nanSchedGetExtWlanInfraAttr(struct ADAPTER *prAdapter,
				     uint8_t **ppucExtWlanInfraAttr,
				     uint32_t *pu4ExtWlanInfraLength);

uint32_t nanSchedGetPublicAvailAttr(struct ADAPTER *prAdapter,
				    uint8_t **ppucPublicAvailAttr,
				    uint32_t *pu4PublicAvailLength);

uint32_t nanSchedPeerUpdateUawAttr(struct ADAPTER *prAdapter,
				   uint8_t *pucNmiAddr, uint8_t *pucUawAttr);
uint32_t nanSchedPeerUpdateQosAttr(struct ADAPTER *prAdapter,
				   uint8_t *pucNmiAddr, uint8_t *pucQosAttr);
uint32_t nanSchedPeerUpdateNdcAttr(struct ADAPTER *prAdapter,
				   uint8_t *pucNmiAddr, uint8_t *pucNdcAttr);
uint32_t nanSchedPeerUpdateAvailabilityAttr(struct ADAPTER *prAdapter,
					    uint8_t *pucNmiAddr,
					    uint8_t *pucAvailabilityAttr);
uint32_t nanSchedPeerUpdateImmuNdlScheduleList(
	struct ADAPTER *prAdapter, uint8_t *pucNmiAddr,
	struct _NAN_SCHEDULE_ENTRY_T *prScheduleEntryList,
	uint32_t u4ScheduleEntryListLength);
uint32_t nanSchedPeerUpdateRangingScheduleList(
	struct ADAPTER *prAdapter, uint8_t *pucNmiAddr,
	struct _NAN_SCHEDULE_ENTRY_T *prScheduleEntryList,
	uint32_t u4ScheduleEntryListLength);
uint32_t nanSchedPeerUpdateDevCapabilityAttr(struct ADAPTER *prAdapter,
					     uint8_t *pucNmiAddr,
					     uint8_t *pucDevCapabilityAttr);

void nanSchedPeerUpdateCommonFAW(struct ADAPTER *prAdapter, uint32_t u4SchIdx);

uint32_t nanGetPeerDevCapability(struct ADAPTER *prAdapter,
				 enum _ENUM_NAN_DEVCAP_FIELD_T eField,
				 uint8_t *pucNmiAddr, uint8_t ucMapID,
				 uint32_t *pu4RetValue);

uint8_t nanGetPeerMinBw(struct ADAPTER *prAdapter, uint8_t *pucNmiAddr,
				enum ENUM_BAND eBand);

uint8_t nanGetPeerMaxBw(struct ADAPTER *prAdapter, uint8_t *pucNmiAddr);

uint32_t nanSchedDbgDumpPeerAvailability(struct ADAPTER *prAdapter,
					 uint8_t *pucNmiAddr);

enum _ENUM_NAN_WINDOW_T nanWindowType(struct ADAPTER *prAdapter,
				      uint16_t u2SlotIdx);
uint32_t nanUtilCheckBitOneCnt(struct ADAPTER *prAdapter, uint8_t *pucBitMask,
			      uint32_t u4Size);
void nanUtilDump(struct ADAPTER *prAdapter,
		uint8_t *pucMsg, uint8_t *pucContent, uint32_t u4Length);
uint32_t nanUtilCalAttributeToken(struct _NAN_ATTR_HDR_T *prNanAttr);

unsigned char nanGetFeatureNDPE(struct ADAPTER *prAdapter);
unsigned char nanGetFeaturePeerNDPE(struct ADAPTER *prAdapter,
		uint8_t *pucNmiAddr);

union _NAN_BAND_CHNL_CTRL nanQueryChnlInfoBySlot(struct ADAPTER *prAdapter,
		uint16_t u2SlotIdx,
		uint32_t **ppau4AvailMap,
		unsigned char fgCommitOrCond);
uint8_t nanQueryPrimaryChnlBySlot(struct ADAPTER *prAdapter,
		uint16_t u2SlotIdx, unsigned char fgCommitOrCond);
union _NAN_BAND_CHNL_CTRL nanQueryPeerChnlInfoBySlot(struct ADAPTER *prAdapter,
		uint32_t u4SchIdx,
		uint32_t u4AvailDatabaseIdx,
		uint16_t u2SlotIdx,
		unsigned char fgCommitOrCond);
uint8_t nanQueryPeerPrimaryChnlBySlot(struct ADAPTER *prAdapter,
		uint32_t u4SchIdx,
		uint32_t u4AvailDatabaseIdx,
		uint16_t u2SlotIdx, unsigned char fgCommitOrCond);
uint32_t nanGetPeerPrimaryChnlBySlot(struct ADAPTER *prAdapter,
		uint32_t u4SchIdx, uint32_t u4AvailDbIdx,
		uint16_t u2SlotIdx, unsigned char fgChkRmtCondSlot);

uint32_t nanSchedConfigPhyParams(struct ADAPTER *prAdapter);
uint32_t nanSchedCmdUpdateSchedVer(struct ADAPTER *prAdapter);
uint32_t nanSchedConfigGetAllowedBw(struct ADAPTER *prAdapter,
		uint8_t ucChannel);

uint32_t
nanSchedCmdUpdatePhySettigns(struct ADAPTER *prAdapter,
			     struct _NAN_PHY_SETTING_T *pr2P4GPhySettings,
			     struct _NAN_PHY_SETTING_T *pr5GPhySettings);
uint32_t nanSchedCmdManagePeerSchRecord(struct ADAPTER *prAdapter,
			uint32_t u4SchIdx, unsigned char fgActivate);
uint32_t nanSchedCmdUpdatePeerCapability(struct ADAPTER *prAdapter,
					 uint32_t u4SchIdx);
uint32_t nanSchedCmdUpdateCRB(struct ADAPTER *prAdapter, uint32_t u4SchIdx);
uint32_t nanSchedCmdUpdateAvailability(struct ADAPTER *prAdapter);
uint32_t nanSchedCmdUpdatePotentialChnlList(struct ADAPTER *prAdapter);
uint32_t nanSchedCmdUpdateAvailabilityCtrl(struct ADAPTER *prAdapter);
#ifdef CFG_SUPPORT_UNIFIED_COMMAND
uint32_t nanSchedulerUniEventDispatch(struct ADAPTER *prAdapter,
				   uint32_t u4SubEvent, uint8_t *pucBuf);
#else
uint32_t nanSchedulerEventDispatch(struct ADAPTER *prAdapter,
				   uint32_t u4SubEvent, uint8_t *pucBuf);
#endif

uint32_t nanSchedEventClearFAWBitmap(struct ADAPTER *prAdapter,
		uint8_t *pcuEvtBuf);

uint32_t nanSchedSwDbg4(struct ADAPTER *prAdapter, uint32_t u4Data);

uint32_t nanSchedCmdMapStaRecord(struct ADAPTER *prAdapter,
				 uint8_t *pucNmiAddr,
				 enum NAN_BSS_ROLE_INDEX eRoleIdx,
				 uint8_t ucStaRecIdx,
				 uint8_t ucNdpCxtId,
				 uint8_t ucWlanIndex,
				 uint8_t *pucNdiAddr);

unsigned char
nanSchedPeerSchRecordIsValid(struct ADAPTER *prAdapter, uint32_t u4SchIdx);
uint32_t
nanSchedQueryStaRecIdx(struct ADAPTER *prAdapter, uint32_t u4SchIdx,
		       uint32_t u4Idx);

void nanSchedPeerPrepareNegoState(struct ADAPTER *prAdapter,
				  uint8_t *pucNmiAddr);
void nanSchedPeerCompleteNegoState(struct ADAPTER *prAdapter,
				   uint8_t *pucNmiAddr);

uint32_t nanSchedNegoCustFawResetCmd(struct ADAPTER *prAdapter);
uint32_t nanSchedNegoCustFawApplyCmd(struct ADAPTER *prAdapter);
uint32_t nanSchedNegoCustFawConfigCmd(struct ADAPTER *prAdapter, uint8_t ucChnl,
				      uint32_t u4SlotBitmap);

void nanSchedReleaseUnusedCommitSlot(struct ADAPTER *prAdapter);
enum ENUM_BAND
nanSchedGetSchRecBandByMac(struct ADAPTER *prAdapter, uint8_t *pucNmiAddr);

#if CFG_SUPPORT_NAN_ADVANCE_DATA_CONTROL
struct NAN_FLOW_CTRL *nanSchedGetPeerSchRecFlowCtrl(struct ADAPTER *prAdapter,
						    uint32_t u2SchId);
#endif

struct _NAN_TIMELINE_MGMT_T *
nanGetTimelineMgmt(struct ADAPTER *prAdapter);
struct _NAN_PEER_SCH_DESC_T *
nanSchedSearchPeerSchDescByNmi(struct ADAPTER *prAdapter, uint8_t *pucNmiAddr);
struct _NAN_SCHEDULER_T *
nanGetScheduler(struct ADAPTER *prAdapter);

extern union _NAN_BAND_CHNL_CTRL g_rNullChnl;

#if (CFG_NAN_SCHEDULER_VERSION == 1)
uint32_t
nanSchedInitDefChnlMap(struct ADAPTER *prAdapter);

uint32_t
nanSchedClearDefChnlMap(struct ADAPTER *prAdapter);

uint32_t
nanSchedUpdateDefChnlInfo(struct ADAPTER *prAdapter);

union _NAN_BAND_CHNL_CTRL
nanQueryNonNanChnlInfoBySlot(struct ADAPTER *prAdapter,
	uint16_t u2SlotIdx, enum ENUM_BAND eBand);

uint32_t
nanSchedUpdateNonNanTimelineByAis(struct ADAPTER *prAdapter);

uint32_t
nanSchedSyncNonNanChnlToNan(struct ADAPTER *prAdapter);

uint32_t
nanSchedCommitNonNanChnlList(struct ADAPTER *prAdapter);

#endif/* (CFG_NAN_SCHEDULER_VERSION == 1) */

#if (CFG_SUPPORT_NAN_NDP_DUAL_BAND == 0)
uint32_t
nanSchedRemoveDiffBandChnlList(
	struct ADAPTER *prAdapter);
#endif /* (CFG_SUPPORT_NAN_NDP_DUAL_BAND == 0) */

#endif
#endif /* _NAN_SCHEDULER_H_ */
