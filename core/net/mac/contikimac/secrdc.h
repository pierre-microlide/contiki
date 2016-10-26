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

/**
 * \file
 *         A secure version of ContikiMAC.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef SECRDC_H_
#define SECRDC_H_

#include "net/mac/rdc.h"
#include "net/llsec/adaptivesec/potr.h"
#include "sys/rtimer.h"

#ifdef SECRDC_CONF_ENABLED
#define SECRDC_ENABLED SECRDC_CONF_ENABLED
#else /* SECRDC_CONF_ENABLED */
#define SECRDC_ENABLED 0
#endif /* SECRDC_CONF_ENABLED */

#if POTR_ENABLED
#ifdef SECRDC_CONF_WITH_SECURE_PHASE_LOCK
#define SECRDC_WITH_SECURE_PHASE_LOCK SECRDC_CONF_WITH_SECURE_PHASE_LOCK
#else /* SECRDC_CONF_WITH_SECURE_PHASE_LOCK */
#define SECRDC_WITH_SECURE_PHASE_LOCK 1
#endif /* SECRDC_CONF_WITH_SECURE_PHASE_LOCK */
#else /* POTR_ENABLED */
#define SECRDC_WITH_SECURE_PHASE_LOCK 0
#endif /* POTR_ENABLED */

#if SECRDC_WITH_SECURE_PHASE_LOCK || !SECRDC_ENABLED
#define SECRDC_WITH_ORIGINAL_PHASE_LOCK 0
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
#ifdef SECRDC_CONF_WITH_ORIGINAL_PHASE_LOCK
#define SECRDC_WITH_ORIGINAL_PHASE_LOCK SECRDC_CONF_WITH_ORIGINAL_PHASE_LOCK
#else /* SECRDC_CONF_WITH_ORIGINAL_PHASE_LOCK */
#define SECRDC_WITH_ORIGINAL_PHASE_LOCK 1
#endif /* SECRDC_CONF_WITH_ORIGINAL_PHASE_LOCK */
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */

#define SECRDC_WITH_PHASE_LOCK (SECRDC_WITH_SECURE_PHASE_LOCK || SECRDC_WITH_ORIGINAL_PHASE_LOCK)
#define SECRDC_UPDATE_THRESHOLD (RTIMER_ARCH_SECOND * 60 * 5) /* 5min */

#if SECRDC_WITH_PHASE_LOCK
struct secrdc_phase {
  rtimer_clock_t t;
};
#endif /* SECRDC_WITH_PHASE_LOCK */

extern const struct rdc_driver secrdc_driver;

#endif /* SECRDC_H_ */
