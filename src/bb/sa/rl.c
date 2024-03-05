#include "PR/os_internal.h"
#include "bcp.h"


typedef struct /* size=0x8 */ {
    /* 0x0000 */ u8 type;
    /* 0x0004 */ u32 size;
} OSBbStatBuf;

typedef u32 BbId;
typedef u32 BbContentId;
typedef u32 BbAesKey[4];
typedef u32 BbAesIv[4];
typedef u32 BbEccPrivateKey[8];
typedef u32 BbEccPublicKey[16];
typedef u32 BbRsaPublicKey2048[64];
typedef u32 BbRsaPublicKey4096[128];
typedef u32 BbRsaExponent;
typedef u32 BbRsaSig2048[64];
typedef u32 BbRsaSig4096[128];
typedef u32 BbEccSig[16];
typedef u32 BbOwnerId;
typedef u32 BbRandomMix[8];
typedef u16 BbTicketId;
typedef union /* size=0x200 */ {
    /* 0x0000 */ BbRsaSig2048 rsa2048;
    /* 0x0000 */ BbRsaSig4096 rsa4096;
    /* 0x0000 */ BbEccSig ecc;
} BbGenericSig;
typedef u32 BbShaHash[5];
typedef u8 BbServerName[64];
typedef u8 BbName[64];
typedef u8 BbServerSuffix[64];
typedef BbServerSuffix BbCrlEntry;
typedef struct /* size=0x1AC */ {
    /* 0x0000 */ u32 unusedPadding;
    /* 0x0004 */ u32 caCrlVersion;
    /* 0x0008 */ u32 cpCrlVersion;
    /* 0x000C */ u32 size;
    /* 0x0010 */ u32 descFlags;
    /* 0x0014 */ BbAesIv commonCmdIv;
    /* 0x0024 */ BbShaHash hash;
    /* 0x0038 */ BbAesIv iv;
    /* 0x0048 */ u32 execFlags;
    /* 0x004C */ u32 hwAccessRights;
    /* 0x0050 */ u32 secureKernelRights;
    /* 0x0054 */ u32 bbid;
    /* 0x0058 */ BbServerName issuer;
    /* 0x0098 */ BbContentId id;
    /* 0x009C */ BbAesKey key;
    /* 0x00AC */ BbRsaSig2048 contentMetaDataSign;
} BbContentMetaDataHead;
typedef struct /* size=0x29AC */ {
    /* 0x0000 */ u8 contentDesc[10240];
    /* 0x2800 */ BbContentMetaDataHead head;
} BbContentMetaData;
typedef struct /* size=0x1A0 */ {
    /* 0x0000 */ BbId bbId;
    /* 0x0004 */ BbTicketId tid;
    /* 0x0006 */ u16 code;
    /* 0x0008 */ u16 limit;
    /* 0x000A */ u16 reserved;
    /* 0x000C */ u32 tsCrlVersion;
    /* 0x0010 */ BbAesIv cmdIv;
    /* 0x0020 */ BbEccPublicKey serverKey;
    /* 0x0060 */ BbServerName issuer;
    /* 0x00A0 */ BbRsaSig2048 ticketSign;
} BbTicketHead;
typedef struct /* size=0x2B4C */ {
    /* 0x0000 */ BbContentMetaData cmd;
    /* 0x29AC */ BbTicketHead head;
} BbTicket;

typedef struct /* size=0x8C */ {
    /* 0x0000 */ u32 certType;
    /* 0x0004 */ u32 sigType;
    /* 0x0008 */ u32 date;
    /* 0x000C */ BbServerName issuer;
    /* 0x004C */ union /* size=0x40 */ {
    /*        */   BbServerSuffix server;
    /*        */   BbName bbid;
    /*        */ } name;
} BbCertId, BbCertBase;

typedef struct /* size=0x2CC */ {
    /* 0x0000 */ BbCertId certId;
    /* 0x008C */ u32 publicKey[16];
    /* 0x00CC */ BbGenericSig signature;
} BbEccCert;

typedef struct /* size=0x390 */ {
    /* 0x0000 */ BbCertId certId;
    /* 0x008C */ BbRsaPublicKey2048 publicKey;
    /* 0x018C */ BbRsaExponent exponent;
    /* 0x0190 */ BbGenericSig signature;
} BbRsaCert;

typedef enum {
    CRL_UNUSED0 = 0,
    CRL_UNUSED1 = 1,
    CRL_UNUSED2 = 2
} BbCrlUnusedEnumType;

typedef struct /* size=0x258 */ {
    /* 0x0000 */ BbGenericSig signature;
    /* 0x0200 */ u32 type;
    /* 0x0204 */ u32 sigType;
    /* 0x0208 */ BbCrlUnusedEnumType unusedPadding;
    /* 0x020C */ u32 versionNumber;
    /* 0x0210 */ u32 date;
    /* 0x0214 */ BbServerName issuer;
    /* 0x0254 */ u32 numberRevoked;
} BbCrlHead;

typedef struct /* size=0x1C */ {
    /* 0x0000 */ BbCrlHead* head;
    /* 0x0004 */ BbServerSuffix* list;
    /* 0x0008 */ BbCertBase* certChain[5];
} BbCrlBundle;
typedef struct /* size=0x2C */ {
    /* 0x0000 */ BbTicket* ticket;
    /* 0x0004 */ BbCertBase* ticketChain[5];
    /* 0x0018 */ BbCertBase* cmdChain[5];
} BbTicketBundle;
typedef struct /* size=0x54 */ {
    /* 0x0000 */ BbCrlBundle tsrl;
    /* 0x001C */ BbCrlBundle carl;
    /* 0x0038 */ BbCrlBundle cprl;
} BbAppLaunchCrls;

typedef struct /* size=0x2C */ {
    /* 0x0000 */ u32 eepromAddress;
    /* 0x0004 */ u32 eepromSize;
    /* 0x0008 */ u32 flashAddress;
    /* 0x000C */ u32 flashSize;
    /* 0x0010 */ u32 sramAddress;
    /* 0x0014 */ u32 sramSize;
    /* 0x0018 */ u32 pakAddress[4];
    /* 0x0028 */ u32 pakSize;
} OSBbStateVector;

typedef struct /* size=0x44 */ {
    /* 0x0000 */ OSBbStateVector state;
    /* 0x002C */ u32 romBase;
    /* 0x0030 */ s32 tvType;
    /* 0x0034 */ u32 memSize;
    /* 0x0038 */ u32 errataSize;
    /* 0x003C */ u32 errataAddress;
    /* 0x0040 */ u32 magic;
} OSBbLaunchMetaData;

// static char* getServerNameStr(char* in);
// static int fillCrlBundle(BbCrlHead* rl, BbCrlBundle* rlBundle);
// int osBbSaRlInit();
// int osBbSaRlBundle(BbAppLaunchCrls* rls);

static int gNumRls = 0;
static u8 gRlBuf[16384];

static char* getServerNameStr(char* in) {
    int indx = strlen(in) - 1;

    while (indx > 0) {
        if(in[indx--] == '-') {
            return in + (indx + 2);
        }
    }
    return 0;
}

static s32 fillCrlBundle(BbCrlHead *rl, BbCrlBundle *rlBundle) {
    char* serverName;
    char* issuer;

    issuer = rl->issuer;
    rlBundle->head = rl;
    rlBundle->list = &rl[1];
    serverName = getServerNameStr(issuer);
    if (serverName == NULL) {
        if (strcmp("Root", issuer) != 0) {
            return -1;
        }
        rlBundle->certChain[0] = NULL;
    } else if (osBbSaCertCreateChain(serverName, rlBundle->certChain) < 0) {
        return -1;
    }
    
    return 0;
}

extern char gSaRlFname[];

s32 osBbSaRlInit(void) {
    OSBbStatBuf fsStat;
    s32 fsret;
    s32 fd;

    fd = osBbFOpen(gSaRlFname, "r");
    if (fd < 0) {
        return 1;
    }

    if (osBbFStat(fd, &fsStat, 0, 0) != 0) {
        return -1;
    }

    if (fsStat.size <= 0x4000) {
        if (osBbFRead(fd, 0, gRlBuf, fsStat.size) < 0) {
            osBbFClose(fd);
            return -1;
        }

        osBbFClose(fd);
        if (*(u32*)gRlBuf >= 4) {
            return -1;
        }
        gNumRls = *(u32*)gRlBuf;
        return 0;
    }

    return -1;
}

s32 osBbSaRlBundle(BbAppLaunchCrls *rls) {
    int i;
    int ret;
    BbCrlHead* rl;

    memset(rls, 0, sizeof(BbAppLaunchCrls));
    rl = (BbCrlHead*)&gRlBuf[4];

    if (gNumRls == 0) {
        ret = osBbSaRlInit();
        if (ret == -1) {
            return -1;
        }

        if (ret == 1) {
            return 0;
        }

        if (ret != 0) {
            return -1;
        }
    }

    for(i = 0; i < gNumRls; i++, rl = (u8*)rl + (rl->numberRevoked*64 + sizeof(BbCrlHead))) {
        if(i >= 3) {
            return 0;
        }

        switch(rl->type) {
            case 0:
                if (fillCrlBundle(rl, &rls->tsrl) != 0) {
                    return -1;
                }
                break;
            case 1:
                if (fillCrlBundle(rl, &rls->cprl) != 0) {
                    return -1;
                }
                break;
            case 2:
                if (fillCrlBundle(rl, &rls->carl) != 0) {
                    return -1;
                }
                break;
            default:
                return -1;
        }
    }
    return 0;
}