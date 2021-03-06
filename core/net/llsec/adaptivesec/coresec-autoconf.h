/*
 * Copyright (c) 2015, Hasso-Plattner-Institut.
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

/**
 * \file
 *         Autoconfigures the adaptivesec_driver.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#undef NETSTACK_CONF_LLSEC
#define NETSTACK_CONF_LLSEC                   adaptivesec_driver
#undef NETSTACK_CONF_FRAMER
#define NETSTACK_CONF_FRAMER                  adaptivesec_framer
#undef ADAPTIVESEC_CONF_STRATEGY
#define ADAPTIVESEC_CONF_STRATEGY             coresec_strategy
#undef AKES_NBR_CONF_WITH_PAIRWISE_KEYS
#define AKES_NBR_CONF_WITH_PAIRWISE_KEYS      1
#undef AKES_NBR_CONF_WITH_INDICES
#define AKES_NBR_CONF_WITH_INDICES            1

#ifndef ADAPTIVESEC_CONF_UNICAST_SEC_LVL
#define ADAPTIVESEC_CONF_UNICAST_SEC_LVL      6
#endif /* ADAPTIVESEC_CONF_UNICAST_SEC_LVL */

#if ((ADAPTIVESEC_CONF_UNICAST_SEC_LVL & 3) == 1)
#define ADAPTIVESEC_CONF_UNICAST_MIC_LEN      6
#elif ((ADAPTIVESEC_CONF_UNICAST_SEC_LVL & 3) == 2)
#define ADAPTIVESEC_CONF_UNICAST_MIC_LEN      8
#elif ((ADAPTIVESEC_CONF_UNICAST_SEC_LVL & 3) == 3)
#define ADAPTIVESEC_CONF_UNICAST_MIC_LEN      10
#else
#error "unsupported security level"
#endif

#ifndef ADAPTIVESEC_CONF_BROADCAST_SEC_LVL
#define ADAPTIVESEC_CONF_BROADCAST_SEC_LVL    ADAPTIVESEC_CONF_UNICAST_SEC_LVL
#endif /* ADAPTIVESEC_CONF_BROADCAST_SEC_LVL */

#if ((ADAPTIVESEC_CONF_BROADCAST_SEC_LVL & 3) == 1)
#define ADAPTIVESEC_CONF_BROADCAST_MIC_LEN    6
#elif ((ADAPTIVESEC_CONF_BROADCAST_SEC_LVL & 3) == 2)
#define ADAPTIVESEC_CONF_BROADCAST_MIC_LEN    8
#elif ((ADAPTIVESEC_CONF_BROADCAST_SEC_LVL & 3) == 3)
#define ADAPTIVESEC_CONF_BROADCAST_MIC_LEN    10
#else
#error "unsupported security level"
#endif

#undef AKES_NBR_CONF_WITH_GROUP_KEYS
#define AKES_NBR_CONF_WITH_GROUP_KEYS         (ADAPTIVESEC_CONF_BROADCAST_SEC_LVL & 4)
#undef PACKETBUF_CONF_WITH_UNENCRYPTED_BYTES
#define PACKETBUF_CONF_WITH_UNENCRYPTED_BYTES AKES_NBR_CONF_WITH_GROUP_KEYS

#undef NBR_TABLE_CONF_MAX_NEIGHBORS
#define NBR_TABLE_CONF_MAX_NEIGHBORS          ((127 - 11 - LINKADDR_CONF_SIZE)/ADAPTIVESEC_CONF_BROADCAST_MIC_LEN)

#undef LLSEC802154_CONF_ENABLED
#define LLSEC802154_CONF_ENABLED              1

#undef ADAPTIVESEC_CONF_ENABLED
#define ADAPTIVESEC_CONF_ENABLED              1
