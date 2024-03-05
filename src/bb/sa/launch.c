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

// void osBbSaCidToAppName(BbContentId cid, char*, char*);
// void osBbSaCidToAppName(BbContentId cid, char *ext, char *name);
// s32 osBbSaBundleTicket(BbTicket *ticket, BbTicketBundle *ticketBundle, BbAppLaunchCrls *appRls);
// s32 osBbSaGamePrelaunch(BbTicket *ticket);

extern char gSaAppExt[];
extern char gSaRecExt[];
extern char gSaRecryptKeyFname[];

static u8 gLaunchBuf[0x4000];

static struct /* size=0xA0 */ {
    /* 0x0000 */ s32 sfd;
    /* 0x0004 */ s32 dfd;
    /* 0x0008 */ BbTicketBundle ticketBundle;
    /* 0x0034 */ BbAppLaunchCrls appRls;
    /* 0x0088 */ u32 recoveryBTgt;
    /* 0x008C */ u32 destBProc;
    /* 0x0090 */ char launchAppName[16];
} gRecryptState;

int getAppExtensionsPresent(BbContentId cid) {
  char appName[16];
  s32 fd;
  int ret = 0;

  // check for {cid}.app
  osBbSaCidToAppName(cid, gSaAppExt, appName);
  fd = osBbFOpen(appName, "r");
  if (fd >= 0) {
    ret = 1;
    osBbFClose(fd);
  }

  // check for {cid}.rec
  osBbSaCidToAppName(cid, gSaRecExt, appName);
  fd = osBbFOpen(appName, "r");
  if (fd >= 0) {
    OSBbStatBuf fsStat;
    osBbFStat(fd, &fsStat, 0, 0);
    if (fsStat.size == 0) {
      osBbFClose(fd);
      osBbFDelete(appName);
    } else {
      ret |= 2;
      osBbFClose(fd);
    }
  }

  return ret;
}

s32 readKeylist(u8 *keylist) {
  s32 fd;
  s32 ret = 0;

  fd = osBbFOpen(gSaRecryptKeyFname, "r");
  if (fd < 0) {
    return -6;
  }
  if (osBbFRead(fd, NULL, keylist, 0x4000) < 0) {
    ret = -1;
  }
  osBbFClose(fd);
  return ret;
}

s32 saveKeylist(u8 *keylist) {
  s32 fd;
  int ret = 0;
  char tmpFile[13] = "_recrypt.sys";

  osBbFDelete(tmpFile);
  fd = osBbFCreate(tmpFile, 1, 0x4000);
  if (fd < 0) {
    return -1;
  }
  
  if (osBbFWrite(fd, 0, keylist, 0x4000) < 0) {
   ret = -1;
  }

  osBbFClose(fd);
  osBbFRename(tmpFile, gSaRecryptKeyFname);
  return ret;
}

#define GET_NYBBLE(d, i) (((d) >> (i)) & 0xF)
void osBbSaCidToAppName(BbContentId cid, char *ext, char *name) {
    int i, j = 0;

    for(i = 28; i >= 0; i-=4) {
        name[j++] = (GET_NYBBLE(cid, i) < 10U) ? (GET_NYBBLE(cid, i) + 0x30) : (GET_NYBBLE(cid, i) + 0x57);
    }

    name[j++] = '.';
    name[j++] = ext[0];
    name[j++] = ext[1];
    name[j++] = ext[2];
    name[j++] = '\0';
}

s32 osBbSaBundleTicket(BbTicket *ticket, BbTicketBundle *ticketBundle, BbAppLaunchCrls *appRls) {
    ticketBundle->ticket = ticket;
    if (osBbSaCertCreateChain(ticket->head.issuer, ticketBundle->ticketChain) >= 0) {
        if ((osBbSaCertCreateChain(ticket->cmd.head.issuer, ticketBundle->cmdChain) >= 0) && (osBbSaRlBundle(appRls) == 0)) {
            return 0;
        }
        return -3;
    }
    return -3;
}

static s32 prelaunchRecryptNotReq(BbContentMetaDataHead* pCmdh, u8* keylist) {
    if (skLaunchSetup(&gRecryptState.ticketBundle, &gRecryptState.appRls, keylist) == 0) {
        osBbSaCidToAppName(pCmdh->id, gSaAppExt, gRecryptState.launchAppName);
        return 0;
    }
    return -3;
}

static s32 prelaunchFullRecrypt(BbContentMetaDataHead *pCmdh, u8 *keylist) {
  OSBbStatBuf fsStat;
  char appName[16];

  saveKeylist(keylist);
  osBbSaCidToAppName(pCmdh->id, gSaAppExt, appName);
  gRecryptState.sfd = osBbFOpen(appName, "r");
  if (gRecryptState.sfd >= 0) {
    osBbSaCidToAppName(pCmdh->id, gSaRecExt, appName);
    gRecryptState.dfd = osBbFCreate(appName, 1, 0);
    if ((gRecryptState.dfd >= 0) && (osBbFStat(gRecryptState.sfd, &fsStat, NULL, 0) >= 0)) {
      if (fsStat.size >= pCmdh->size) {
        gRecryptState.recoveryBTgt = 0;
        gRecryptState.destBProc = 0;
        return 1;
      }
      return -1;
    }
  }
  return -1;
}

s32 osBbSaGamePrelaunch(BbTicket *ticket) {
  BbTicketId tid = ticket->head.tid;
  u8* keylist = gLaunchBuf;
  BbContentMetaDataHead* pCmdh = &ticket->cmd.head;
  OSBbStatBuf fsStat;
  char appName[16];
  int i;
  int ret;
  u16 limit = ticket->head.limit;
  u16 cc[26];
  u16 window;

  /* demo */
  if ((s16)tid < 0) {
    skGetConsumption(&window, cc);

    for(i = 0; i < 26; i++) {
      if ((tid & 0x7FFF) == (window + i)) {
        if ((cc[i] != limit) || (ticket->head.code >= 3)) {
          break;
        }
        return -4;
      }
    }
  }

  memset(keylist, 0, 0x4000);
  if (readKeylist(keylist) == -1) {
    return -1;
  }

  if (osBbSaBundleTicket(ticket, &gRecryptState.ticketBundle, &gRecryptState.appRls) != 0) {
    return -3;
  }

  osBbSaCidToAppName(pCmdh->id, gSaRecExt, gRecryptState.launchAppName);
  
  i = getAppExtensionsPresent(pCmdh->id);
  switch(i) {
    case 0: // no file present
      return -1;
      break;
    case 1: // app present
      ret = skRecryptBegin(&gRecryptState.ticketBundle, &gRecryptState.appRls, keylist);
      switch (ret) {
        case 1:
          return prelaunchRecryptNotReq(pCmdh, keylist);
          break;
        case 2:
          return prelaunchFullRecrypt(pCmdh, keylist);
          break;
        case 3:
          if (skRecryptData(0, 0) != 0) {
              return -3;
          }
          /* falls through */
        case 4:
          return prelaunchFullRecrypt(pCmdh, keylist);
        default:
          return -3;
      }
    case 2: // app not present, rec present
      ret = skLaunchSetup(&gRecryptState.ticketBundle, &gRecryptState.appRls, keylist);
      switch(ret) {
        case 0:
          return 0;
        case 3:
          if (skRecryptBegin(&gRecryptState.ticketBundle, &gRecryptState.appRls, keylist) == 3) {
            osBbSaCidToAppName(pCmdh->id, gSaRecExt, appName);
            gRecryptState.dfd = osBbFOpen(appName, "rw");
            if ((gRecryptState.dfd >= 0) && (osBbFStat(gRecryptState.dfd, &fsStat, 0, 0) >= 0)) {
              gRecryptState.destBProc = 0;
              gRecryptState.recoveryBTgt = fsStat.size;
              return 1;
            } else {
              return -1;
            }
          } else {
              return -3;
          }
          break;
        case 4:
          if (readKeylist(keylist) != -1) {
            if (skRecryptListValid(keylist) != -1) {
              return -3;
            } else {
              return -5;
            }
          } else {
              return -5;
          }
          break;
        default:
          return -3;
          break;
      }
    default: //??
      ret = skRecryptBegin(&gRecryptState.ticketBundle, &gRecryptState.appRls, keylist);
      switch(ret) {
        case 1:
          osBbFDelete(gRecryptState.launchAppName);
          return prelaunchRecryptNotReq(pCmdh, keylist);
        case 4:
          if ((readKeylist(keylist) == -1) || (skRecryptListValid(keylist) == -1)) {
              return -5;
          }
          /* falls through */
        case 2:
          osBbFDelete(gRecryptState.launchAppName);
          return prelaunchFullRecrypt(pCmdh, keylist);
        case 3:
          osBbSaCidToAppName(pCmdh->id, gSaAppExt, appName);

          if (((gRecryptState.sfd = osBbFOpen(appName, "r")) < 0)){
              return -1;
          }

          osBbSaCidToAppName(pCmdh->id, gSaRecExt, appName);

          if(((gRecryptState.dfd = osBbFOpen(appName, "rw")) < 0)) {
              return -1;
          }

          if((osBbFStat(gRecryptState.dfd, &fsStat, 0, 0) < 0)) {
              return -1;
          }

          if ((gRecryptState.recoveryBTgt = fsStat.size) == 0) {
              return -1;
          } 

          gRecryptState.destBProc = 0;
          return 1;
          
        default:
          return -3;
      }
  }
}

s32 osBbSaGamePersonalize(u8 *chunkBuffer) {
  u32 chunkSize;
  u32 contentSize;
  int ret;

    chunkSize = 0x20000;
    contentSize = gRecryptState.ticketBundle.ticket->cmd.head.size;
    if (contentSize < (gRecryptState.destBProc + 0x20000)) {
        chunkSize = contentSize - gRecryptState.destBProc;
    }

    if (gRecryptState.recoveryBTgt != 0) {
        if (osBbFRead(gRecryptState.dfd, gRecryptState.destBProc, chunkBuffer, chunkSize) < 0) {
            ret = -1;
            goto cleanup;
        }

        if (skRecryptComputeState(chunkBuffer, chunkSize) != 0) {
            ret = -3;
            goto cleanup;
        }

        gRecryptState.destBProc += chunkSize;
        if (gRecryptState.destBProc < contentSize) {
          if (gRecryptState.destBProc == gRecryptState.recoveryBTgt) {
            gRecryptState.recoveryBTgt = 0;
            if (osBbFRead(gRecryptState.sfd, 0U, chunkBuffer, chunkSize) < 0) {
                ret = -1;
                goto cleanup;
            }

            if (skRecryptData(chunkBuffer, chunkSize) != 0) {
                ret = -3;
                goto cleanup;
            }
          }
        }

    } else {
      if (osBbFRead(gRecryptState.sfd, gRecryptState.destBProc ? 0x20000 : 0, chunkBuffer, chunkSize) < 0) {
          ret = -1;
          goto cleanup;
      }
      if (skRecryptData(chunkBuffer, chunkSize) != 0) {
          ret = -3;
          goto cleanup;
      }
      if (osBbFShuffle(gRecryptState.sfd, gRecryptState.dfd, gRecryptState.destBProc != 0, chunkBuffer, chunkSize) < 0) {
          ret = -1;
          goto cleanup;
      }
      gRecryptState.destBProc += chunkSize;
    }

    if (gRecryptState.destBProc >= contentSize) {
      char appName[16];
      u8* keylist = gLaunchBuf;
      osBbSaCidToAppName(gRecryptState.ticketBundle.ticket->cmd.head.id, gSaAppExt, appName);
      osBbFClose(gRecryptState.sfd);
      osBbFClose(gRecryptState.dfd);
      osBbFDelete(appName);
      if (skRecryptEnd(keylist) != 0) {
          osBbSaCidToAppName(gRecryptState.ticketBundle.ticket->cmd.head.id, gSaRecExt, appName);
          osBbFDelete(appName);
          return -3;
      }
        saveKeylist(keylist);
        if (skLaunchSetup(&gRecryptState.ticketBundle, &gRecryptState.appRls, keylist) != 0) {
            return -3;
        }
        return 0; 
    }
    return 1;

cleanup:
    osBbFClose(gRecryptState.sfd);
    osBbFClose(gRecryptState.dfd);
    return ret;
}

s32 osBbSaGameLoadState(OSBbStateVector *sv, u32 *bindings, u16 tid) {
    return osBbLoadState(gRecryptState.launchAppName, tid, sv, bindings);
}

s32 osBbSaGameLaunch(OSBbLaunchMetaData* md) {
  OSBbStatBuf fsStat;
  s32 fd;
  s32 listSize;
  s32 loadAll;
  u32 addr;

  fd = osBbFOpen(gRecryptState.launchAppName, "r");
  if (fd < 0) {
    return -1;
  }

  memset(gLaunchBuf, 0, 0x4000);
  if((osBbFStat(fd, &fsStat, gLaunchBuf, 0x2000) != 0)) {
    return -1;
  }

  listSize = fsStat.size / 0x4000;
  loadAll = (gRecryptState.ticketBundle.ticket->cmd.head.execFlags & 2) == 0;
  osWritebackDCacheAll();
  addr = osBbLoadApp(md, gLaunchBuf, listSize, loadAll);

  if (addr != NULL) {
    s32 mask = __osDisableInt();
    skLaunch(addr);
    __osRestoreInt(mask);
  }
  return -3;
}
