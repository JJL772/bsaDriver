#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <time.h>

#include <new>
#include <arpa/inet.h>
#include <sstream>


#include <sys/types.h>
#include <sys/stat.h>

#include <cantProceed.h>
#include <ellLib.h>
#include <epicsTypes.h>
#include <epicsTime.h>
#include <epicsThread.h>
#include <epicsString.h>
#include <epicsTimer.h>
#include <epicsMutex.h>
#include <epicsEvent.h>
#include <iocsh.h>

#include <drvSup.h>
#include <epicsExport.h>

#include <bldStream.h>
#include <serviceAsynDriver.h>
#include <bsaAsynDriver.h>

#include <yamlLoader.h>

#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/log.h>
#include <pvxs/iochooks.h>
#include <pvxs/nt.h>


static const char *driverName = "serviceAsynDriver";

static ELLLIST *pDrvEllList = NULL;

typedef struct {
    ELLNODE         node;
    char            *named_root;
    char            *port_name;
    char            *reg_path;
    serviceAsynDriver  *pServiceDrv;
    ELLLIST         *pServiceEllList;
} pDrvList_t;


static void init_drvList(void)
{
    if(!pDrvEllList) {
        pDrvEllList = (ELLLIST *) mallocMustSucceed(sizeof(ELLLIST), "serviceAsynDriver(init_drvList)");
        ellInit(pDrvEllList);
    }
    return;
}

static pDrvList_t *find_drvLast(void)
{
    init_drvList();

    if(ellCount(pDrvEllList)) return (pDrvList_t *) ellLast(pDrvEllList);
    else                      return (pDrvList_t *) NULL;

}

static pDrvList_t *find_drvByPort(const char *port_name)
{
    init_drvList();
    pDrvList_t *p = (pDrvList_t *) ellFirst(pDrvEllList);

    while(p) {
        if(p->port_name && strlen(p->port_name) && !strcmp(p->port_name, port_name)) break;
        p = (pDrvList_t *) ellNext(&p->node);
    }

    return p;
}

static int prep_drvAnonimous(void)
{
    init_drvList();
    pDrvList_t *p = (pDrvList_t *) mallocMustSucceed(sizeof(pDrvList_t), "serviceAsynDriver(prep_drvAnonimous)");

    p->named_root = NULL;
    p->port_name  = NULL;
    p->reg_path   = NULL;
    p->pServiceDrv   = NULL;
    p->pServiceEllList  = NULL;

    ellAdd(pDrvEllList, &p->node);
    return ellCount(pDrvEllList);
}


static int serviceAdd(const char *channelKey, serviceDataType_t type, double *slope, double *offset, bool doNotTouch)
{
    pDrvList_t * pl = find_drvLast();

    if(pl){
        if(pl->pServiceDrv || (pl->port_name && strlen(pl->port_name))) pl = NULL;  /* the driver node has been configured,
                                                                                    need to make another one */
    }

    while(!pl) {
        prep_drvAnonimous();
        pl = find_drvLast();
    }

    while(!pl->pServiceEllList) {   /* initialize the linked list once */
        pl->pServiceEllList = (ELLLIST *) mallocMustSucceed(sizeof(ELLLIST), "serviceAsynDriver (serviceAdd)");
        ellInit(pl->pServiceEllList);
    }

    channelList_t *p = (channelList_t *) mallocMustSucceed(sizeof(channelList_t), "serviceAsynDriver (serviceAdd)");
    strcpy(p->channel_key, channelKey);
    p->index = 0;
    p->p_channelMask = -1;
    p->p_channelSevr = -1;
    for(unsigned int i = 0; i < NUM_EDEF_MAX; i++) {
        p->p_channel[i] = -1;              /* initialize paramters with invalid */
        p->pkey_channel[i][0] = '\0';     /* initialize with a null string */
        p->pkey_channelPID[i][0] = '\0';  /* initialize with a null string */ 
    }

    p->type    = type;
    p->pslope  = slope;
    p->poffset = offset;
    p->doNotTouch = doNotTouch;
    ellAdd(pl->pServiceEllList, &p->node);
    return 0;
}


static int associateBsaChannels(const char *port_name)
{
    ELLLIST *pBsaEllList = find_bsaChannelList(port_name);

    if(!pBsaEllList) return -1;
    bsaList_t * p = (bsaList_t *) ellFirst(pBsaEllList);

    while(p) {
        serviceAdd(p->bsa_name, serviceDataType_t(p->type), &p->slope, &p->offset, &p->doNotTouch);
        p = (bsaList_t *) ellNext(&p->node);
    }
    printf("Associate %d of channels from bsa port(%s) \n", ellCount(find_drvLast()->pServiceEllList), port_name);

    return 0;
}

static int bldChannelName(const char *channel_key, const char *channel_name)
{

  /* Implement EPICS driver initialization here */
    init_drvList();

    if(!pDrvEllList) {
        printf("BSSS/BLD Driver never been configured\n");
        return 0;
    }

    pDrvList_t *p = (pDrvList_t *) ellFirst(pDrvEllList);

    while(p) {
        if(p->pServiceDrv->getServiceType() == bld) break;
        p = (pDrvList_t *) ellNext(&p->node);
    }    

    /* Found BLD driver. Create PVA */
    if (p != NULL)
        p->pServiceDrv->addBldChannelName(channel_key, channel_name);
    else {
        printf("Error: No BLD driver found. Must instantiate driver first.\n");
        return -1;
    }

    return 0;
}


static void bsss_callback(void *pUsr, void *buf, unsigned size)
{
    ((serviceAsynDriver *)pUsr)->bsssCallback(buf, size);
}

static void bld_callback(void *pUsr, void *buf, unsigned size)
{
    ((serviceAsynDriver *)pUsr)->bldCallback(buf, size);
}


serviceAsynDriver::serviceAsynDriver(const char *portName, const char *reg_path, const int num_dyn_param, ELLLIST *pServiceEllList,  serviceType_t type, const char *named_root, const char* pva_basename)
    : asynPortDriver(portName,
                                        1,  /* number of elements of this device */
#if (ASYN_VERSION <<8 | ASYN_REVISION) < (4<<8 | 32)
                                         NUM_SERVICE_DET_PARAMS +  num_dyn_param ,    /* number of asyn params to be cleared for each device */
#endif /* asyn version check, under 4.32 */
                                         asynInt32Mask | asynInt64Mask | asynFloat64Mask | asynOctetMask | asynDrvUserMask |
                                         asynInt32ArrayMask | asynInt64ArrayMask | asynFloat64ArrayMask,    /* Interface mask */
                                         asynInt32Mask | asynInt64Mask | asynFloat64Mask | asynOctetMask | asynEnumMask |
                                         asynInt32ArrayMask | asynInt64ArrayMask | asynFloat64ArrayMask,       /* Interrupt mask */
                                         1,    /* asynFlags. This driver does block and it is non multi-device, so flag is 1. */
                                         1,    /* Auto connect */
                                         0,    /* Default priority */
                                         0),    /* Default stack size */
                                         channelMask(0)

{
    

    if(!pServiceEllList || !ellCount(pServiceEllList)) return;   /* if there is no service data channels in the list, nothing to do */
    this->pServiceEllList = pServiceEllList;

    Path root_ = (named_root && strlen(named_root))? cpswGetNamedRoot(named_root): cpswGetRoot();
    if(!root_) {
        printf("%s driver: could not find root path\n", type == bsss? "BSSS" : "BLD");
        return;
    }

    Path reg_ = root_->findByName(reg_path);
    if(!reg_) {
        printf("%s driver: could not find registers at path %s\n", type == bsss? "BSSS" : "BLD", reg_path);
        return;
    }
    switch (type) {
        case bld:  this->pService = new Bld::BldYaml(reg_); break;
        case bsss: this->pService = new Bsss::BsssYaml(reg_); break;
    }
    serviceType = type;
    
    channelSevr = 0;

    int i = 0;
    channelList_t *p = (channelList_t *) ellFirst(pServiceEllList);
    while(p) {
        p->index = i++;
        p = (channelList_t *) ellNext(&p->node);
    }



    SetupAsynParams(type);


    switch (type) {
        case bld:      
            for(unsigned int i = 0; i < this->pService->getEdefNum(); i++)
            {
                socketAPIInitByInterfaceName(ntohl( inet_addr( DEFAULT_MCAST_IP ) ), 
                                    DEFAULT_MCAST_PORT, 
                                    MAX_BUFF_SIZE, 
                                    UCTTL, 
                                    NULL, 
                                    &pVoidsocketAPI[i]);
                if ( pVoidsocketAPI[i] == NULL ) 
                    printf("Failed instantiating new socketAPI for service %u\n", i);
            }
            bldPacketPayload = (uint32_t *) mallocMustSucceed(MAX_BUFF_SIZE, "bldPacketPayload");
        
            pvaBaseName = epicsStrDup(pva_basename);    

            registerBldCallback(named_root, bld_callback, (void *) this); 
            break;
        case bsss: 
            registerBsssCallback(named_root, bsss_callback, (void *) this); 
            break;
    }        
}


void serviceAsynDriver::addBldChannelName(const char * key, const char * name)
{
    bool found = false;
    for (channelList_t *plist = (channelList_t *) ellFirst(pServiceEllList);
        plist!=NULL;
        plist = (channelList_t *) ellNext(&plist->node))
    {
        if (strcmp(plist->channel_key, key) == 0)
        {
            strcpy(plist->channel_name, name);
            found = true;
        }
    }    
    if (found == false)
        printf("Error: BsaKey not found.\n");
}


void serviceAsynDriver::updatePVA()
{
    std::string pvaName(pvaBaseName);
    pvaName = pvaName + ":BLD:PAYLOAD";

    server.removePV(pvaName);
    pv.close();

    this->initPVA();
}

void serviceAsynDriver::initPVA()
{

    channelList_t *plist;
    uint32_t mask;

    pvxs::shared_array<const std::string> _labels;  
    pvxs::TypeDef                         _def;
    pvxs::Value                           _initial;
    char * name;

    std::string pvaName(pvaBaseName);
    pvaName = pvaName + ":BLD:PAYLOAD";

    server = pvxs::ioc::server();

    auto labels = std::vector<std::string>();
    auto value  = pvxs::TypeDef(pvxs::TypeCode::Struct, {});

    pv = pvxs::server::SharedPV::buildReadonly();

    for (plist = (channelList_t *) ellFirst(pServiceEllList), mask = 0x1;
        plist!=NULL;
        plist = (channelList_t *) ellNext(&plist->node), mask <<= 1)
    {
        if ((mask & channelMask) == 0)
            continue;

        if (plist->channel_name == NULL)
            name = plist->channel_key;
        else
            name = plist->channel_name;

        if (plist->type != float32_service)
            value += {pvxs::Member(pvxs::TypeCode::UInt32A, name)};    
        else
            value += {pvxs::Member(pvxs::TypeCode::Float32, name)};    
        labels.push_back(name);        
    }

    _labels = pvxs::shared_array<const std::string>(labels.begin(), labels.end());
    _def = pvxs::TypeDef(pvxs::TypeCode::Struct, "epics:nt/NTScalar:1.0", {
                         value.as("BldPayload")
                         });
    
    _initial              = _def.create();


    pv.open(_initial);
    server.addPV(pvaName, pv);
}

serviceAsynDriver::~serviceAsynDriver()
{
}

void serviceAsynDriver::SetupAsynParams(serviceType_t type)
{
    char param_name[100];
    char prefix[10];

    switch (type) {
        case bld:  sprintf(prefix, BLD_STR);  break;
        case bsss: sprintf(prefix, BSSS_STR); break;
    }

    // Service Status Monitoring
    sprintf(param_name, CURRPACKETSIZE_STR, prefix);   createParam(param_name, asynParamInt32, &p_currPacketSize);
    sprintf(param_name, CURRPACKETSTATUS_STR, prefix); createParam(param_name, asynParamInt32, &p_currPacketStatus);
    sprintf(param_name, CURRPULSEIDL_STR, prefix);     createParam(param_name, asynParamInt32, &p_currPulseIdL);
    sprintf(param_name, CURRTIMESTAMPL_STR, prefix);   createParam(param_name, asynParamInt32, &p_currTimeStampL);
    sprintf(param_name, CURRDELTA_STR, prefix);        createParam(param_name, asynParamInt32, &p_currDelta);
    sprintf(param_name, PACKETCOUNT_STR, prefix);      createParam(param_name, asynParamInt32, &p_packetCount);
    sprintf(param_name, PAUSED_STR, prefix);           createParam(param_name, asynParamInt32, &p_paused);
    sprintf(param_name, DIAGNCLOCKRATE_STR, prefix);   createParam(param_name, asynParamInt32, &p_diagnClockRate);
    sprintf(param_name, DIAGNSTROBERATE_STR, prefix);  createParam(param_name, asynParamInt32, &p_diagnStrobeRate);
    sprintf(param_name, EVENTSEL0RATE_STR, prefix);    createParam(param_name, asynParamInt32, &p_eventSel0Rate);

    // Service Status Control
    sprintf(param_name, PACKETSIZE_STR, prefix);       createParam(param_name, asynParamInt32, &p_packetSize);
    sprintf(param_name, ENABLE_STR, prefix);           createParam(param_name, asynParamInt32, &p_enable);

    channelList_t *p = (channelList_t *) ellFirst(pServiceEllList);
    while(p) {
        sprintf(param_name, CHANNELMASK_STR, prefix, p->channel_key); createParam(param_name, asynParamInt32, &(p->p_channelMask)); 
        sprintf(param_name, CHANNELSEVR_STR, prefix, p->channel_key); createParam(param_name, asynParamInt32, &(p->p_channelSevr));
        p = (channelList_t *) ellNext(&p->node);
    }

    // Service Rate Controls
    for(unsigned int i = 0; i < this->pService->getEdefNum(); i++) {
        sprintf(param_name, EDEFENABLE_STR, prefix, i);createParam(param_name, asynParamInt32, &p_edefEnable[i]);
        sprintf(param_name, RATEMODE_STR, prefix, i);  createParam(param_name, asynParamInt32, &p_rateMode[i]);
        sprintf(param_name, FIXEDRATE_STR, prefix, i); createParam(param_name, asynParamInt32, &p_fixedRate[i]);
        sprintf(param_name, ACRATE_STR, prefix, i);    createParam(param_name, asynParamInt32, &p_acRate[i]);
        sprintf(param_name, TSLOTMASK_STR, prefix, i); createParam(param_name, asynParamInt32, &p_tSlotMask[i]);
        sprintf(param_name, EXPSEQNUM_STR, prefix, i); createParam(param_name, asynParamInt32, &p_expSeqNum[i]);
        sprintf(param_name, EXPSEQBIT_STR, prefix, i); createParam(param_name, asynParamInt32, &p_expSeqBit[i]);
        sprintf(param_name, DESTMODE_STR, prefix, i);  createParam(param_name, asynParamInt32, &p_destMode[i]);
        sprintf(param_name, DESTMASK_STR, prefix, i);  createParam(param_name, asynParamInt32, &p_destMask[i]);
        sprintf(param_name, RATELIMIT_STR, prefix, i); createParam(param_name, asynParamInt32, &p_rateLimit[i]);

        /* BLD multicast port and addresses */
        if (type == bld) {
            sprintf(param_name, BLDMULTICASTADDR_STR, i); createParam(param_name, asynParamOctet, &p_multicastAddr[i]);
            sprintf(param_name, BLDMULTICASTPORT_STR, i); createParam(param_name, asynParamInt32, &p_multicastPort[i]);
        }
    }

    /* PVs only existant in BSSS driver */
    if (type == bsss)
    {
        // set up dyanamic paramters
        for(unsigned int i = 0; i < this->pService->getEdefNum(); i++) {
            channelList_t *p  = (channelList_t *) ellFirst(this->pServiceEllList);
            while(p) {
                sprintf(param_name, BSSSPV_STR,  p->channel_key, i); createParam(param_name, asynParamFloat64, &p->p_channel[i]);    strcpy(p->pkey_channel[i],    param_name);
                sprintf(param_name, BSSSPID_STR, p->channel_key, i); createParam(param_name, asynParamInt64,   &p->p_channelPID[i]); strcpy(p->pkey_channelPID[i], param_name);
                p = (channelList_t *) ellNext(&p->node);
            }
        }
    }

}


void serviceAsynDriver::SetRate(int chn)
{
    uint32_t rateMode, fixedRate, acRate, tSlotMask, expSeqNum, expSeqBit;

    getIntegerParam(p_rateMode[chn], (epicsInt32*) &rateMode);
    switch(rateMode) {
        case 0: /* fixed rate mode */
            getIntegerParam(p_fixedRate[chn], (epicsInt32*) &fixedRate);
            pService->setFixedRate(chn, fixedRate);
            break;
        case 1: /* AC rate mode */
            getIntegerParam(p_acRate[chn], (epicsInt32*) &acRate);
            getIntegerParam(p_tSlotMask[chn], (epicsInt32*) &tSlotMask);
            pService->setACRate(chn, tSlotMask, acRate);
            break;
        case 2: /* Seq rate mode */
            getIntegerParam(p_expSeqNum[chn], (epicsInt32*) &expSeqNum);
            getIntegerParam(p_expSeqBit[chn], (epicsInt32*) &expSeqBit);
            pService->setSeqRate(chn, expSeqNum, expSeqBit);
            break;
        default:  /* nothing todo */
            break;
    }
}

void serviceAsynDriver::SetDest(int chn)
{
    uint32_t destMode, destMask;

    getIntegerParam(p_destMode[chn], (epicsInt32*) &destMode);
    getIntegerParam(p_destMask[chn], (epicsInt32*) &destMask);

    switch(destMode) {
        case 2:  /* Inclusion */
            pService->setDestInclusion(chn, destMask);
            break;
        case 1:  /* Exclusion */
            pService->setDestExclusion(chn, destMask);
            break;
        case 0:  /* Disable */
            pService->setDestDisable(chn);
            break;
        default:  /* nothing to do */
            break;
    }
}

void serviceAsynDriver::SetChannelSevr(int chn, int sevr)
{
    uint64_t mask = 0x3 << (chn*2);

    channelSevr &= ~mask;
    channelSevr |= (uint64_t(sevr) << (chn*2)) & mask;

}

int serviceAsynDriver::GetChannelSevr(int chn)
{
   return int((channelSevr >> (chn *2)) & 0x3);
}

void serviceAsynDriver::MonitorStatus(void)
{
    uint32_t v;

    pService->getCurrPacketSize(&v);    setIntegerParam(p_currPacketSize, (epicsInt32) v);
    pService->getCurrPacketState(&v);   setIntegerParam(p_currPacketStatus, (epicsInt32) v);
    pService->getCurrPulseIdL(&v);      setIntegerParam(p_currPulseIdL, (epicsInt32) v);
    pService->getCurrTimeStampL(&v);    setIntegerParam(p_currTimeStampL, (epicsInt32) v);
    pService->getCurrDelta(&v);         setIntegerParam(p_currDelta, (epicsInt32) v);
    pService->getPacketCount(&v);       setIntegerParam(p_packetCount, (epicsInt32) v);
    pService->getPaused(&v);            setIntegerParam(p_paused, (epicsInt32) v);
    pService->getDiagnClockRate(&v);    setIntegerParam(p_diagnClockRate, (epicsInt32) v);
    pService->getDiagnStrobeRate(&v);   setIntegerParam(p_diagnStrobeRate, (epicsInt32) v);
    pService->getEventSel0Rate(&v);     setIntegerParam(p_eventSel0Rate, (epicsInt32) v);

    callParamCallbacks();
}


asynStatus serviceAsynDriver::writeOctet (asynUser *pasynUser, const char *value,
                                    size_t nChars, size_t *nActual)
{
    int function = pasynUser->reason;
    asynStatus status = asynSuccess;
    const char *functionName = "writeOctet";

    for(unsigned int edef = 0; edef < this->pService->getEdefNum(); edef++) {
        if(function == p_multicastAddr[edef]) {
            socketAPISetAddr(ntohl( inet_addr( value )), pVoidsocketAPI[edef]);
            break;
        }
    }

    if (status)
        asynPrint(pasynUser, ASYN_TRACE_ERROR,
                  "%s:%s: status=%d, function=%d, value=%s",
                  driverName, functionName, status, function, value);
    else
    {
        asynPrint(pasynUser, ASYN_TRACEIO_DRIVER,
              "%s:%s: function=%d, value=%s\n",
              driverName, functionName, function, value);
        callParamCallbacks();
    }
    *nActual = nChars;
    return status;
}

asynStatus serviceAsynDriver::writeInt32(asynUser *pasynUser, epicsInt32 value)
{
    int function = pasynUser->reason;
    asynStatus status = asynSuccess;
    const char *functionName = "writeInt32";

    /* set the parameter in the parameter library */
    status = (asynStatus) setIntegerParam(function, value);

    channelList_t *p = (channelList_t *) ellFirst(pServiceEllList);
    while(p) {
       if(function == p->p_channelMask) {
           pService->setChannelMask(p->index, uint32_t(value));
           if (serviceType == bld)
           {
                if (value == 0)
                    channelMask = channelMask & ~(0x1U << p->index);
                else
                    channelMask = channelMask | (0x1U << p->index);
                updatePVA();
           }
           goto done;
       }
       if(function == p->p_channelSevr) {
           SetChannelSevr(p->index, value);
           goto done;
       }
        p = (channelList_t *) ellNext(&p->node);
    }


    if(function == p_packetSize) {
        pService->setPacketSize((uint32_t) value);
        goto done;
    }
    else if(function == p_enable) {
        pService->enablePacket((uint32_t) value);
        goto done;
    }


    for(unsigned int i = 0; i < this->pService->getEdefNum(); i++) {
        if(function == p_rateMode[i]  ||
           function == p_fixedRate[i] ||
           function == p_acRate[i]    ||
           function == p_tSlotMask[i] ||
           function == p_expSeqNum[i] ||
           function == p_expSeqBit[i]) {
            SetRate(i);
            goto done;
        }

        else if(function == p_destMode[i] ||
                function == p_destMask[i]) {
            SetDest(i);
            goto done;
        }
        else if(function == p_edefEnable[i]) {
            pService->setEdefEnable(i, (uint32_t) value);
            goto done;
        }
        else if(function == p_rateLimit[i]) {
            pService->setRateLimit(i, (uint32_t) value);
            goto done;
        } else if(function == p_multicastPort[i]) {
            socketAPISetPort( value, pVoidsocketAPI[i]);
            goto done;
        }
    }

    done:
    callParamCallbacks();
    return status;
}


void serviceAsynDriver::bsssCallback(void *p, unsigned size)
{
     uint32_t *buf         = (uint32_t *) p;
     uint32_t *p_uint32    = buf + IDX_DATA;
     int32_t  *p_int32     = (int32_t *) (buf + IDX_DATA);
     float    *p_float32   = (float*)(buf + IDX_DATA);
     double   val;
     uint32_t channel_mask = buf[IDX_CHN_MASK];
     uint32_t service_mask = buf[IDX_SVC_MASK];
     uint64_t sevr_mask    = *(uint64_t*) (buf+IDX_SEVR_MASK(size));
     uint64_t pulse_id     = ((uint64_t)(buf[IDX_PIDU])) << 32 | buf[IDX_PIDL];

     epicsTimeStamp _ts;
     _ts.nsec = buf[IDX_NSEC];
     _ts.secPastEpoch  = buf[IDX_SEC];
     setTimeStamp(&_ts);    // timestamp update for asyn port and related PVs


     channelList_t *plist = (channelList_t *) ellFirst(pServiceEllList);
     int data_chn = 0;
     int index = 0;
     while(plist) {
         if(!(channel_mask & (uint32_t(0x1) << data_chn))) goto skip;   // skipping the channel, if the channel is not in the mask

         for(unsigned int i = 0, svc_mask = 0x1; i < this->pService->getEdefNum(); i++, svc_mask <<= 1) {
             if(service_mask & svc_mask) {
                 setInteger64Param(plist->p_channelPID[i], pulse_id);  // pulse id update if service mask is set

                 setDoubleParam(plist->p_channel[i], INFINITY);   // make asyn PV update even posting the same value with previous

                 if(int((sevr_mask >> (data_chn*2)) & 0x3) <= GetChannelSevr(data_chn) ) {  // data update for valid mask
                     switch(plist->type){
                         case int32_service:
                             val = (double) (p_int32[index]);
                             break;
                         case uint32_service:
                             val = (double) (p_uint32[index]);
                             break;
                         case float32_service:
                             val = (double) (p_float32[index]);
                             break;
                         case uint64_service:
                         default:
                              val = NAN;   // uint64 never defined
                             break;
                     }
                 } else val = NAN;  // put NAN for invalid mask

                 if(!isnan(val)) val = val * (*plist->pslope) + (*plist->poffset);
                 setDoubleParam(plist->p_channel[i], val);
             }
         }
         index++;

         skip:

         plist = (channelList_t *) ellNext(&plist->node);  // evolve to next data channel
         data_chn++;      // evolve data channel number to next channel
     }
     

     callParamCallbacks();

}

serviceType_t serviceAsynDriver::getServiceType()
{
    return serviceType;
}
void serviceAsynDriver::bldCallback(void *p, unsigned size)
{
    
    uint32_t *buf         = (uint32_t *) p;
    uint32_t *p_uint32    = buf + IDX_DATA;
    int32_t  *p_int32     = (int32_t *) (buf + IDX_DATA);
    float    *p_float32   = (float*)(buf + IDX_DATA);
    float    *bldPacketPayloadfloat = (float    *) bldPacketPayload;
    bldAxiStreamHeader_t *header = (bldAxiStreamHeader_t *) p;
    bldAxiStreamComplementaryHeader_t * compHeader;
    double   val;
    int data_chn, index;
    uint64_t sevr_mask;
    channelList_t *plist;
    static uint32_t versionSize = 0;
    uint32_t multicastIndex = MULTICAST_IDX_DATA;
    uint32_t severityMaskAddrL = MULTICAST_IDX_SEVRL;
    uint32_t severityMaskAddrH = MULTICAST_IDX_SEVRH;

    /* Matt: versionSize increments whenever channel mask changes */
    if (this->channelMask != header->channelMask)
        versionSize++;

    bldPacketPayload[IDX_NSEC] = buf[IDX_NSEC];
    bldPacketPayload[IDX_SEC]  = buf[IDX_SEC];
    bldPacketPayload[IDX_PIDL] = buf[IDX_PIDL];
    bldPacketPayload[IDX_PIDU] = buf[IDX_PIDU];
    bldPacketPayload[IDX_PIDU] = versionSize;
    
    uint32_t consumedSize = sizeof(bldAxiStreamHeader_t);
    do{
    
        for (plist = (channelList_t *) ellFirst(pServiceEllList), index = 0, data_chn = 0;
            plist!=NULL;
            plist = (channelList_t *) ellNext(&plist->node), data_chn++) 
        {
            if(!(header->channelMask & (uint32_t(0x1) << data_chn)))
                continue;   // skipping the channel, if the channel is not in the mask

            switch(plist->type){
                case int32_service:
                    val = (double) (p_int32[index]);
                    break;
                case uint32_service:
                    val = (double) (p_uint32[index]);
                    break;
                case float32_service:
                    val = (double) (p_float32[index]);
                    break;
                case uint64_service:
                default:
                    val = NAN;   // uint64 never defined
                    break;
            }
            
            if(!isnan(val)) 
                val = val * (*plist->pslope) + (*plist->poffset);

            /* If fixed, apply correct format */
            if (plist->doNotTouch == 1)
                bldPacketPayload[multicastIndex++] = p_uint32[index]; /* formatted to int32/uint32 (untouched) */
            else
                bldPacketPayloadfloat[multicastIndex++] = val; /* formatted to IEEE 754 */

            index++; /* Increment index only if not skipping */
            consumedSize += 4;
        }

        sevr_mask    = *(uint64_t*) (buf + index + IDX_DATA);
        bldPacketPayload[severityMaskAddrL] = *(buf + index + IDX_DATA);
        bldPacketPayload[severityMaskAddrH] = *(buf + index + IDX_DATA + 1);

        consumedSize += sizeof(sevr_mask);

        if (consumedSize >= size)
            break;

        /* If reaches here is because there is more event data */
        compHeader = (bldAxiStreamComplementaryHeader_t *) (buf + (consumedSize/4));

        bldPacketPayload[multicastIndex++] = *(buf + (consumedSize/4));
        severityMaskAddrL = multicastIndex++;
        severityMaskAddrH = multicastIndex++;

        p_uint32    = (uint32_t *) (compHeader + sizeof(bldAxiStreamComplementaryHeader_t));
        p_int32     = (int32_t *) (compHeader + sizeof(bldAxiStreamComplementaryHeader_t));
        p_float32   = (float*) (compHeader + sizeof(bldAxiStreamComplementaryHeader_t));

        consumedSize += sizeof(bldAxiStreamComplementaryHeader_t);
    } while (consumedSize < size);

    for (uint32_t mask = 0xF & (header->serviceMask >> 24), it = 0; mask != 0x0; mask >>= 1, it++)
    {
        if ( (mask & 0x1) != 0 )
        {
                socketAPISendRawData(pVoidsocketAPI[it], 
                                                    multicastIndex*sizeof(int), 
                                                    (char*) bldPacketPayload);
        }
    }
}

extern "C" {

static int  serviceMonitorPoll(void)
{
    while(1) {
        pDrvList_t *p = (pDrvList_t *) ellFirst(pDrvEllList);
        while(p) {
            if(p->pServiceDrv) p->pServiceDrv->MonitorStatus();
            p = (pDrvList_t *) ellNext(&p->node);
        }
        epicsThreadSleep(1.);
    }

    return 0;
}


int serviceAsynDriverConfigure(const char *portName, const char *reg_path, const char *named_root, serviceType_t type, const char* pva_basename)
{
    pDrvList_t *pl = find_drvByPort(portName);
    if(!pl) {
        pl = find_drvLast();
        if(pl) {
            if(!pl->port_name && !pl->named_root && !pl->pServiceDrv) pl->port_name = epicsStrDup(portName);
            else pl = NULL;
        }
    }
    if(!pl) {
        printf("%s list never been configured for port (%s)\n", type == bsss? "BSSS":"BLD", portName);
        return -1;
    }

    pl->named_root = (named_root && strlen(named_root))?epicsStrDup(named_root): cpswGetRootName();

    if(!pl->pServiceEllList) return -1;

    int i = 0;
    channelList_t *p = (channelList_t *) ellFirst(pl->pServiceEllList);
    while(p) {
        i += (int) (&p->p_lastParam - &p->p_firstParam -1);
        p = (channelList_t *) ellNext(&p->node);

    }    /* calculate number of dyanmic parameters */
    if (type == bld && pva_basename == NULL)
    {
        printf("BLD driver pva_basename is NULL. Please add basename.\n");
        return -1;
    }

    pl->port_name = epicsStrDup(portName);
    pl->reg_path  = epicsStrDup(reg_path);
    pl->pServiceDrv  = new serviceAsynDriver(portName, reg_path, i, pl->pServiceEllList, type, pl->named_root, pva_basename);

    return 0;
}


static const iocshArg initArg0 = { "portName",                                           iocshArgString };
static const iocshArg initArg1 = { "register path (which should be described in yaml):", iocshArgString };
static const iocshArg initArg2 = { "named_root (optional)",                              iocshArgString };
static const iocshArg * const initArgs[] = { &initArg0,
                                             &initArg1,
                                             &initArg2 };
static const iocshFuncDef bsssInitFuncDef = { "bsssAsynDriverConfigure", 3, initArgs };
static void bsssInitCallFunc(const iocshArgBuf *args)
{
 
    serviceAsynDriverConfigure(args[0].sval,  /* port name */
                               args[1].sval,  /* register path */
                              (args[2].sval && strlen(args[2].sval))? args[2].sval: NULL, /* named_root */
                               bsss,
                               NULL );  /* BSSS call */
}

static const iocshArg initBldArg0 = { "portName",                                           iocshArgString };
static const iocshArg initBldArg1 = { "register path (which should be described in yaml)",  iocshArgString };
static const iocshArg initBldArg2 = { "Payload PVA basename",                               iocshArgString };
static const iocshArg initBldArg3 = { "named_root (optional)",                              iocshArgString };
static const iocshArg * const initBldArgs[] = { &initBldArg0,
                                                &initBldArg1,
                                                &initBldArg2,
                                                &initBldArg3 };
static const iocshFuncDef bldInitFuncDef = { "bldAsynDriverConfigure", 4, initBldArgs };
static void bldInitCallFunc(const iocshArgBuf *args)
{
 
    serviceAsynDriverConfigure(args[0].sval,  /* port name */
                               args[1].sval,  /* register path */
                               (args[3].sval && strlen(args[3].sval))? args[3].sval: NULL, /* named_root */
                               bld,
                               args[2].sval  /* bld PVA basename */
                               );  /* BLD call */ 
}


static const iocshArg associateArg0 = { "bsa port", iocshArgString };
static const iocshArg * const associateArgs [] = { &associateArg0 };
static const iocshFuncDef bsssAssociateFuncDef = { "bsssAssociateBsaChannels", 1, associateArgs };
static const iocshFuncDef bldAssociateFuncDef =  { "bldAssociateBsaChannels", 1, associateArgs };

static void associateCallFunc(const iocshArgBuf *args)
{
    associateBsaChannels(args[0].sval);
}

static const iocshArg bldChannelNameArg0 = { "bsaKey",      iocshArgString };
static const iocshArg bldChannelNameArg1 = { "channelName", iocshArgString };
static const iocshArg * const bldChannelNameArgs [] = { &bldChannelNameArg0,
                                                        &bldChannelNameArg1};
static const iocshFuncDef bldChannelNameFuncDef = { "bldChannelName", 2, bldChannelNameArgs };
static void bldChannelNameCallFunc(const iocshArgBuf *args)
{
    bldChannelName(args[0].sval, args[1].sval);
}

void serviceAsynDriverRegister(void)
{
    iocshRegister(&bsssInitFuncDef,        bsssInitCallFunc);
    iocshRegister(&bldInitFuncDef,         bldInitCallFunc);
    iocshRegister(&bsssAssociateFuncDef,   associateCallFunc);
    iocshRegister(&bldAssociateFuncDef,    associateCallFunc);
    iocshRegister(&bldChannelNameFuncDef,  bldChannelNameCallFunc);    
}

epicsExportRegistrar(serviceAsynDriverRegister);




/* EPICS driver support for serviceAsynDriver */

static int serviceAsynDriverReport(int interest);
static int serviceAsynDriverInitialize(void);

static struct drvet serviceAsynDriver = {
    2,
    (DRVSUPFUN) serviceAsynDriverReport,
    (DRVSUPFUN) serviceAsynDriverInitialize
};

epicsExportAddress(drvet, serviceAsynDriver);

static int serviceAsynDriverReport(int interest)
{
    pDrvList_t *p = (pDrvList_t *) ellFirst(pDrvEllList);

    while(p) {
        printf("named_root: %s, port: %s, driver instace: %p, number of channels: %d\n",
              (p->named_root && strlen(p->named_root))?p->named_root: "Unknown",
              (p->port_name && strlen(p->port_name))? p->port_name: "Unknown",
              p->pServiceDrv,
              (p->pServiceEllList)? ellCount(p->pServiceEllList): -1);
        p = (pDrvList_t *) ellNext(&p->node);
    }

    return 0;
}

static int serviceAsynDriverInitialize(void)
{

   /* Implement EPICS driver initialization here */
    init_drvList();

    if(!pDrvEllList) {
        printf("BSSS/BLD Driver never been configured\n");
        return 0;
    }

    printf("BSSS/BLD driver: %d of service driver instance(s) has (have) been configured\n", ellCount(pDrvEllList));

    pDrvList_t *p = (pDrvList_t *) ellFirst(pDrvEllList);

    epicsThreadCreate("serviceDrvPoll", epicsThreadPriorityMedium,
                      epicsThreadGetStackSize(epicsThreadStackMedium),
                      (EPICSTHREADFUNC) serviceMonitorPoll, 0);

    while(p) {
        if(p->pServiceDrv->getServiceType() == bld) break;
        p = (pDrvList_t *) ellNext(&p->node);
    }    

    /* Found BLD driver. Create PVA */
    if (p != NULL)
        p->pServiceDrv->initPVA();

    return 0;
}


} /* extern "C" */
