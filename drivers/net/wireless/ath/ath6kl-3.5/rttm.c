/*
 * Copyright (c) 2004-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/ip.h>
#include "core.h"
#include "debug.h"
#include "wlan_location_defs.h"
#include "rttm.h"
#include "ath_netlink.h"
void DumpRttResp(void * data);
S_RTTM_CONTEXT *g_pRttmContext;

int rttm_init(void* ar)
{
   S_RTTM_CONTEXT *prttm=NULL;
   prttm=kmalloc(sizeof(S_RTTM_CONTEXT),GFP_KERNEL);
   if(NULL==prttm)
    return -ENOMEM;
   memset(prttm,0,sizeof(S_RTTM_CONTEXT));
   if(NULL==prttm->cirbuf)
    return -ENOMEM;
   prttm->pvreadptr = prttm->cirbuf;
   prttm->pvbufptr = prttm->cirbuf;
   prttm->ar =ar;
   DEV_SETRTT_HDL(prttm);
   //Initialize NL For RTT
   if(0!=ath_netlink_init())
   {
       ath6kl_err("RTT Init Failed to Initialize NetLink Interface \n");
       return -ENODEV;
   }
   return 0;
}

int rttm_getbuf(void **buf,u32 *len)
{
   S_RTTM_CONTEXT *prttm=NULL;
   prttm=DEV_GETRTT_HDL();
   if(prttm->nCirResp==0)
    return -EINVAL;
   if(0==((S_RTT_PRIV_HDR *)prttm->pvreadptr)->done)
   {
     return -EINVAL;
   }
   prttm->pvreadptr+=sizeof(S_RTT_PRIV_HDR);
   if(((struct nsp_mresphdr *)prttm->pvreadptr)->response_type == 1)
   {
   *len = MRES_LEN + ((struct nsp_mresphdr *)prttm->pvreadptr)->no_of_responses*CIR_RES_LEN ;
   }
   else
   {
   *len = MRES_LEN + sizeof(struct nsp_rtt_resp) ;
   }
   *buf = prttm->pvreadptr;
   prttm->pvreadptr+=*len;
   if(prttm->pvreadptr >= prttm->cirbuf + RTTM_CIR_BUF_SIZE)
    prttm->pvreadptr = prttm->cirbuf;
    prttm->nCirResp--;
   prttm->pvreadptr = prttm->cirbuf;
   prttm->pvbufptr = prttm->cirbuf;
   prttm->nCirResp =0;
   prttm->burst = 0;
   prttm->burstsize = 0;
    return 0;
}

int rttm_recv(void *buf,u32 len)
{
   S_RTTM_CONTEXT *prttm=NULL;
   prttm=DEV_GETRTT_HDL();
   if(prttm->burst==0)
   {
     
     //Begin Burst
     prttm->burst=1;
     if(((struct nsp_mresphdr *)buf)->response_type == 1)
     {
     prttm->burstsize =MRES_LEN + (((struct nsp_mresphdr *)buf)->no_of_responses*CIR_RES_LEN) ;
     }
     else
     {
     prttm->burstsize =MRES_LEN + sizeof(struct nsp_rtt_resp) ;
     }
    if(prttm->burstsize  > (RTTM_CIR_BUF_SIZE - (prttm->pvbufptr - prttm->cirbuf)))
    {
        prttm->pvbufptr = prttm->cirbuf;
        prttm->pvreadptr = prttm->cirbuf;
    }
     prttm->privptr = prttm->pvbufptr;
    ((S_RTT_PRIV_HDR *)(prttm->privptr))->done = 0x0;
     prttm->pvbufptr+=sizeof(S_RTT_PRIV_HDR);
   }
   memcpy(prttm->pvbufptr,buf,len);
   prttm->pvbufptr+=len;
   prttm->burstsize-=len;
   if(0==prttm->burstsize)
   {
     prttm->burst = 0;
    //DumpRttResp(prttm->privptr+sizeof(S_RTT_PRIV_HDR));
    ((S_RTT_PRIV_HDR *)(prttm->privptr))->done = 0x1;
    
    prttm->nCirResp++;
    {
      //Pass up Recv RTT Resp by NL
      void *data=NULL;
      u32 datalen=0;
      rttm_getbuf(&data,&datalen);
      if(data && datalen)
      {
      ath_netlink_send(data,datalen);
      }
      
    }
   }
   return 0;
}

void rttm_free()
{
   S_RTTM_CONTEXT *prttm=NULL;
   prttm=DEV_GETRTT_HDL();
   if(prttm)
   kfree(prttm);
   ath_netlink_free();
}

void DumpRttResp(void * data)
{
     int i=0,j=0;
     struct nsp_mresphdr *presphdr = (struct nsp_mresphdr *)data;
     struct nsp_cir_resp *pcirresp = (struct nsp_cir_resp *)((u8 *)data + sizeof(struct nsp_mresphdr));
     int explen = (presphdr->no_of_responses * sizeof(struct nsp_cir_resp))+ sizeof(struct nsp_mresphdr);
          ath6kl_dbg(ATH6KL_DBG_RTT,"RTT Response  Size Expected : %d ",explen);
     if(presphdr)
      ath6kl_dbg(ATH6KL_DBG_RTT,"NSP Response ReqId : %x RespType : %x NoResp : %x Result : %x \n",presphdr->request_id,presphdr->response_type,presphdr->no_of_responses,presphdr->result);
      pcirresp->no_of_chains = 2;
      for(i=0;i<presphdr->no_of_responses;i++)
      {
          ath6kl_dbg(ATH6KL_DBG_RTT,"TOD : %x\n",pcirresp->tod);
          ath6kl_dbg(ATH6KL_DBG_RTT,"TOA : %x\n",pcirresp->toa);
          ath6kl_dbg(ATH6KL_DBG_RTT,"TotalChains : %x\n",pcirresp->no_of_chains);
          ath6kl_dbg(ATH6KL_DBG_RTT,"RSSI0 : %x RSSI1 : %x ",pcirresp->rssi[0],pcirresp->rssi[1]);
          ath6kl_dbg(ATH6KL_DBG_RTT,"SendRate : %x\n",pcirresp->sendrate);
          ath6kl_dbg(ATH6KL_DBG_RTT,"RecvRate : %x\n",pcirresp->recvrate);
          ath6kl_dbg(ATH6KL_DBG_RTT,"ChannelDump : \n");
          for(j=0;j<RTTM_CDUMP_SIZE(pcirresp->no_of_chains,pcirresp->isht40);j++)
          {
               u8 k=0;
               k++; 
               ath6kl_dbg(ATH6KL_DBG_RTT,"%x ",pcirresp->channel_dump[j]);
               if(k>15)
                   ath6kl_dbg(ATH6KL_DBG_RTT,("\n"));
          }
           pcirresp++;
       }
}


int rttm_issue_request(void *buf)
{
   S_RTTM_CONTEXT *prttm=NULL;
   struct nsp_mrqst stmrqst;
   struct nsp_rtt_config strttcfg;
   struct nsp_header hdr;
   u32 ftype;
   struct ath6kl *ar=NULL;
   prttm=DEV_GETRTT_HDL();

   ar = prttm->ar;
  memcpy(&hdr,buf,NSP_HDR_LEN);
  ftype = hdr.frame_type;
   if(ftype == NSP_MRQST)
   {
     memcpy(&stmrqst ,buf + NSP_HDR_LEN,sizeof(struct nsp_mrqst));
     if (wmi_rtt_req_meas(ar->wmi,&stmrqst))
	return -EIO;
   }
   else if(ftype == NSP_RTTCONFIG)
   {
     memcpy(&strttcfg ,buf + NSP_HDR_LEN,sizeof(struct nsp_rtt_config));
     if (wmi_rtt_config(ar->wmi,&strttcfg))
        return -EIO;
   }

  return 0;
} 

