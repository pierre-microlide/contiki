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

#ifndef PROJECT_RECEIVER_CONF_H_
#define PROJECT_RECEIVER_CONF_H_

/* configure RDC layer */
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC secrdc_driver
#undef SECRDC_CONF_ENABLED
#define SECRDC_CONF_ENABLED 1
#undef SECRDC_CONF_WITH_DOZING
#define SECRDC_CONF_WITH_DOZING 1
#undef SECRDC_CONF_WITH_SECURE_PHASE_LOCK
#define SECRDC_CONF_WITH_SECURE_PHASE_LOCK 1
#undef SECRDC_CONF_WITH_ORIGINAL_PHASE_LOCK
#define SECRDC_CONF_WITH_ORIGINAL_PHASE_LOCK 1
#undef SECRDC_CONF_RANDOMIZE

/* configure MAC layer */
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC nullmac_driver

/* configure LLSEC layer */
#undef ADAPTIVESEC_CONF_UNICAST_SEC_LVL
#define ADAPTIVESEC_CONF_UNICAST_SEC_LVL 2
#undef ADAPTIVESEC_CONF_BROADCAST_SEC_LVL
#define ADAPTIVESEC_CONF_BROADCAST_SEC_LVL 2
#undef LLSEC802154_CONF_USES_AUX_HEADER
#define LLSEC802154_CONF_USES_AUX_HEADER 0
#undef AKES_CONF_QUIET
#define AKES_CONF_QUIET 1
#include "net/llsec/adaptivesec/noncoresec-autoconf.h"
#if 0
#include "net/llsec/adaptivesec/potr-autoconf.h"
#endif

/* configure ContikiMAC FRAMER */
#if 1
#undef NETSTACK_CONF_FRAMER
#define NETSTACK_CONF_FRAMER contikimac_framer
#undef CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER
#define CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER adaptivesec_framer
#undef ADAPTIVESEC_CONF_DECORATED_FRAMER
#define ADAPTIVESEC_CONF_DECORATED_FRAMER framer_802154
#else
#undef NETSTACK_CONF_FRAMER
#define NETSTACK_CONF_FRAMER contikimac_framer
#undef CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER
#define CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER adaptivesec_framer
#undef ADAPTIVESEC_CONF_DECORATED_FRAMER
#define ADAPTIVESEC_CONF_DECORATED_FRAMER potr_framer
#undef POTR_CONF_WITH_CONTIKIMAC_FRAMER
#define POTR_CONF_WITH_CONTIKIMAC_FRAMER 1
#endif
#undef CONTIKIMAC_FRAMER_CONF_SHORTEST_PACKET_SIZE
#define CONTIKIMAC_FRAMER_CONF_SHORTEST_PACKET_SIZE 98

/* configure NETWORK layer */
#undef NETSTACK_CONF_NETWORK
#define NETSTACK_CONF_NETWORK nullnet_driver

#endif /* PROJECT_RECEIVER_CONF_H_ */
