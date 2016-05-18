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
#include "net/netstack.h"

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

PROCESS(receiver_process, "receiver_process");
AUTOSTART_PROCESSES(&receiver_process);
static rtimer_clock_t sfd;

/*---------------------------------------------------------------------------*/
static void
on_sfd(void)
{
  sfd = RTIMER_NOW();
}
/*---------------------------------------------------------------------------*/
extern void cc2538_rf_flushrx(void);
static void
on_rxpktdone(void)
{
  PRINTF("%lu;%lu\n", sfd, RTIMER_NOW());
  cc2538_rf_flushrx();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(receiver_process, ev, data)
{
  PROCESS_BEGIN();

  NETSTACK_RADIO.set_value(RADIO_PARAM_RX_MODE, RADIO_RX_MODE_POLL_MODE);
  NETSTACK_RADIO.set_object(RADIO_PARAM_SFD_CALLBACK, on_sfd, 0);
  NETSTACK_RADIO.set_object(RADIO_PARAM_RXPKTDONE_CALLBACK, on_rxpktdone, 0);
  NETSTACK_RADIO.on();

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
