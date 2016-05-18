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
#include "net/packetbuf.h"

PROCESS(receiver_process, "receiver_process");
AUTOSTART_PROCESSES(&receiver_process);

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(receiver_process, ev, data)
{
  static const linkaddr_t addr = {{ 0x00 , 0x12 , 0x4B , 0x00 , 0x06 , 0x0D , 0x84 , 0x6C }};
  struct akes_nbr *nbr;

  PROCESS_BEGIN();

  memset(adaptivesec_group_key, 0, AKES_NBR_KEY_LEN);
  packetbuf_clear();
  packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &addr);
  nbr = akes_nbr_new(AKES_NBR_PERMANENT)->permanent;
  nbr->expiration_time = clock_seconds() + (60 * 60 * 24);
  memset(nbr->group_key, 0, AKES_NBR_KEY_LEN);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
