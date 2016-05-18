/*
 * Copyright (c) 2016, Hasso-Plattner-Institut.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/llsec/adaptivesec/akes-nbr.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "net/linkaddr.h"
#include "net/llsec/llsec.h"
#include "sys/etimer.h"

#define PAYLOAD_LEN 1

#ifdef SECRDC_CONF_SENDER_ENERGY
#define DEBUG 0
#else /* SECRDC_CONF_SENDER_ENERGY */
#define DEBUG 1
#endif /* SECRDC_CONF_SENDER_ENERGY */
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

PROCESS(sender_process, "sender_process");
AUTOSTART_PROCESSES(&sender_process);

/*---------------------------------------------------------------------------*/
static void
on_sent(void *ptr, int status, int transmissions)
{
  static int tx_ok;
  static int tx_collision;
  static int tx_noack;
  static int tx_deferred;
  static int tx_err;
  static int tx_err_fatal;

  switch(status) {
  case MAC_TX_OK:
    tx_ok++;
    break;
  case MAC_TX_COLLISION:
    tx_collision++;
    break;
  case MAC_TX_NOACK:
    tx_noack++;
    break;
  case MAC_TX_DEFERRED:
    tx_deferred++;
    break;
  case MAC_TX_ERR:
    tx_err++;
    break;
  case MAC_TX_ERR_FATAL:
    tx_err_fatal++;
    break;
  }
  PRINTF("OK %i / COLLISION %i / NOACK %i / DEFERRED %i / ERR %i / ERR_FATAL %i\n",
      tx_ok,
      tx_collision,
      tx_noack,
      tx_deferred,
      tx_err,
      tx_err_fatal);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sender_process, ev, data)
{
  static const linkaddr_t addr = {{ 0x00 , 0x12 , 0x4B , 0x00 , 0x06 , 0x0D , 0x85 , 0xDC }};
  struct akes_nbr *nbr;
  static struct etimer periodic_timer;

  PROCESS_BEGIN();

  memset(adaptivesec_group_key, 0, AKES_NBR_KEY_LEN);
  packetbuf_clear();
  packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &addr);
  nbr = akes_nbr_new(AKES_NBR_PERMANENT)->permanent;
  nbr->expiration_time = clock_seconds() + (60 * 60 * 24);
  memset(nbr->group_key, 0, AKES_NBR_KEY_LEN);

#ifdef SECRDC_CONF_SENDER_ENERGY
  etimer_set(&periodic_timer, NETSTACK_RDC.channel_check_interval() * 8);
#else /* SECRDC_CONF_SENDER_ENERGY */
  etimer_set(&periodic_timer, NETSTACK_RDC.channel_check_interval());
#endif /* SECRDC_CONF_SENDER_ENERGY */
#ifndef SECRDC_CONF_INFINITE_STROBE
  while(1)
#endif /* SECRDC_CONF_INFINITE_STROBE */
  {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    etimer_reset(&periodic_timer);

    packetbuf_clear();
#if 1
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &addr);
#endif
    memset(packetbuf_dataptr(), 0xFF, PAYLOAD_LEN);
    packetbuf_set_datalen(PAYLOAD_LEN);
#ifdef SECRDC_CONF_SENDER_ENERGY
    NETSTACK_LLSEC.send(NULL, NULL);
#else /* SECRDC_CONF_SENDER_ENERGY */
    NETSTACK_LLSEC.send(on_sent, NULL);
#endif /* SECRDC_CONF_SENDER_ENERGY */
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
