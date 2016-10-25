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

#include "net/mac/contikimac/secrdc.h"
#include "net/mac/mac.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "sys/rtimer.h"
#include "net/mac/framer-802154.h"
#include "net/mac/contikimac/contikimac-framer.h"
#include "net/llsec/adaptivesec/potr.h"
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/llsec/adaptivesec/akes.h"
#include "net/llsec/adaptivesec/akes-nbr.h"
#include "net/llsec/ccm-star-packetbuf.h"
#include "net/nbr-table.h"
#include "lib/aes-128.h"
#include "net/nbr-table.h"
#include "lpm.h"
#include "lib/random.h"

#ifdef SECRDC_CONF_WITH_DOZING
#define WITH_DOZING SECRDC_CONF_WITH_DOZING
#else /* SECRDC_CONF_WITH_DOZING */
#define WITH_DOZING 1
#endif /* SECRDC_CONF_WITH_DOZING */

#ifdef SECRDC_CONF_RECEIVE_CALIBRATION_TIME
#define RECEIVE_CALIBRATION_TIME SECRDC_CONF_RECEIVE_CALIBRATION_TIME
#else /* SECRDC_CONF_RECEIVE_CALIBRATION_TIME */
#define RECEIVE_CALIBRATION_TIME (US_TO_RTIMERTICKS(192) + 1)
#endif /* SECRDC_CONF_RECEIVE_CALIBRATION_TIME */

#ifdef SECRDC_CONF_TRANSMIT_CALIBRATION_TIME
#define TRANSMIT_CALIBRATION_TIME SECRDC_CONF_TRANSMIT_CALIBRATION_TIME
#else /* SECRDC_CONF_TRANSMIT_CALIBRATION_TIME */
#define TRANSMIT_CALIBRATION_TIME (US_TO_RTIMERTICKS(192) + 1)
#endif /* SECRDC_CONF_TRANSMIT_CALIBRATION_TIME */

#ifdef SECRDC_CONF_INTER_BROADCAST_FRAME_CORRECTION
#define INTER_BROADCAST_FRAME_CORRECTION SECRDC_CONF_INTER_BROADCAST_FRAME_CORRECTION
#else /* SECRDC_CONF_INTER_BROADCAST_FRAME_CORRECTION */
#define INTER_BROADCAST_FRAME_CORRECTION 2 /* tick */
#endif /* SECRDC_CONF_INTER_BROADCAST_FRAME_CORRECTION */

#define WAKEUP_INTERVAL (RTIMER_ARCH_SECOND / NETSTACK_RDC_CHANNEL_CHECK_RATE)
#define INTER_FRAME_PERIOD (US_TO_RTIMERTICKS(1068))
#define MAX_CCAS (2)
#define CCA_DURATION (US_TO_RTIMERTICKS(128) + 1)
#define MAX_NOISE (US_TO_RTIMERTICKS(4256) + 1)
#define SHR_DETECTION_TIME (US_TO_RTIMERTICKS(160) + 1)
#define INTER_CCA_PERIOD (INTER_FRAME_PERIOD - RECEIVE_CALIBRATION_TIME)
#define SILENCE_CHECK_PERIOD (US_TO_RTIMERTICKS(250))
#define CHECKSUM_LEN (2)
#define DOZING_PERIOD (INTER_FRAME_PERIOD \
    - RECEIVE_CALIBRATION_TIME \
    - CCA_DURATION)
#define PHASE_LOCK_FREQ_TOLERANCE (1)
#define LPM_SWITCHING ((LPM_CONF_MAX_PM > 0) ? 5 /* ticks */ : 0)
#define ACKNOWLEDGEMENT_WINDOW_MIN (US_TO_RTIMERTICKS(336))
#define ACKNOWLEDGEMENT_WINDOW_MAX (US_TO_RTIMERTICKS(427))
#define ACKNOWLEDGEMENT_WINDOW (ACKNOWLEDGEMENT_WINDOW_MAX \
    - ACKNOWLEDGEMENT_WINDOW_MIN \
    + 1)
#define PHASE_LOCK_GUARD_TIME (SECRDC_WITH_SECURE_PHASE_LOCK \
    ? (2 /* some tolerance */ \
        + ACKNOWLEDGEMENT_WINDOW /* allow for pulse-delay attacks */) \
    : (US_TO_RTIMERTICKS(1000)))
#define FIFOP_THRESHOLD (POTR_ENABLED \
    ? (POTR_HEADER_LEN - POTR_OTP_LEN) \
    : (FRAMER_802154_MIN_BYTES_FOR_FILTERING))

#if POTR_ENABLED
#if SECRDC_WITH_SECURE_PHASE_LOCK
#define ACKNOWLEDGEMENT_LEN (2 + ADAPTIVESEC_UNICAST_MIC_LEN)
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
#define ACKNOWLEDGEMENT_LEN 2
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
#else /* POTR_ENABLED */
#define ACKNOWLEDGEMENT_LEN 3
#endif /* POTR_ENABLED */

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

struct buffered_frame {
  struct buffered_frame *next;
  struct queuebuf *qb;
  mac_callback_t sent;
  int transmissions;
  void *ptr;
  struct rdc_buf_list *tail;
#if SECRDC_WITH_PHASE_LOCK
  enum akes_nbr_status receiver_status;
#endif /* SECRDC_WITH_PHASE_LOCK */
};

extern void cc2538_rf_read_raw(uint8_t *buf, uint8_t bytes);
extern uint8_t cc2538_rf_read_phy_header(void);
extern uint8_t cc2538_rf_read_phy_header_and_set_datalen(void);
extern int cc2538_rf_read_payload(uint8_t bytes);
extern int cc2538_rf_read_footer(void);
extern int cc2538_rf_flushrx(void);
static int is_schedulable(rtimer_clock_t time);
static void prepare_radio_for_duty_cycle(void);
static void enable_shr_search(void);
static void disable_shr_search(void);
static void schedule_duty_cycle(rtimer_clock_t time);
static void duty_cycle_wrapper(struct rtimer *t, void *ptr);
static char duty_cycle(void);
static void on_sfd(void);
static void on_rtimer_freed(struct rtimer *rt, void *ptr);
static void on_fifop(void);
static void prepare_acknowledgement(uint8_t delta);
static void on_final_fifop(void);
#if SECRDC_WITH_SECURE_PHASE_LOCK
static int received_authentic_unicast(void);
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
static void on_txdone(void);
static void finish_duty_cycle(void);
#if SECRDC_WITH_PHASE_LOCK
static struct secrdc_phase *obtain_phase_lock_information(void);
#endif /* SECRDC_WITH_PHASE_LOCK */
static void schedule_strobe(rtimer_clock_t time);
static void strobe_wrapper(struct rtimer *rt, void *ptr);
static char strobe(void);
static int should_strobe_again(void);
static int transmit(void);
static int is_valid(uint8_t *acknowledgement);
static void on_strobed(void);
static void send_list(mac_callback_t sent,
    void *ptr,
    struct rdc_buf_list *list);
static void queue_frame(mac_callback_t sent,
    void *ptr,
    struct queuebuf *qb,
    struct rdc_buf_list *tail);

static union {
  struct {
    int cca_count;
    rtimer_clock_t silence_timeout;
    volatile int got_shr;
    volatile int waiting_for_shr;
    volatile int rtimer_freed;
    struct packetbuf local_packetbuf;
    struct packetbuf *actual_packetbuf;
    int shall_send_acknowledgement;
#if SECRDC_WITH_SECURE_PHASE_LOCK
    int read_and_parsed;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  } duty_cycle;

  struct {
    int is_broadcast;
    int result;
    rtimer_clock_t next_transmission;
    rtimer_clock_t timeout;
    struct buffered_frame *bf;
    int sent_once_more;
    int strobed_once;
#if SECRDC_WITH_PHASE_LOCK
    struct secrdc_phase *phase;
#if SECRDC_WITH_SECURE_PHASE_LOCK
    rtimer_clock_t uncertainty;
    rtimer_clock_t t1[2];
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
    rtimer_clock_t t0[2];
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
#endif /* SECRDC_WITH_PHASE_LOCK */
#if DEBUG || SECRDC_WITH_SECURE_PHASE_LOCK
    uint8_t strobes;
#endif /* DEBUG || SECRDC_WITH_SECURE_PHASE_LOCK */
#if SECRDC_WITH_SECURE_PHASE_LOCK
    uint8_t acknowledgement_nonce[13];
#if NEIGHBOR_WITH_PAIRWISE_KEYS
    uint8_t acknowledgement_key[NEIGHBOR_KEY_LEN];
#endif /* NEIGHBOR_WITH_PAIRWISE_KEYS */
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
  uint8_t seqno;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  } strobe;
} u;

static struct rtimer timer;
static rtimer_clock_t duty_cycle_next;
static struct pt pt;
static volatile int is_duty_cycling;
static volatile int is_strobing;
PROCESS(post_processing, "post processing");
MEMB(buffered_frames_memb, struct buffered_frame, QUEUEBUF_NUM);
LIST(buffered_frames_list);
#if SECRDC_WITH_SECURE_PHASE_LOCK
static volatile rtimer_clock_t sfd_timestamp;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */

/*---------------------------------------------------------------------------*/
static int
has_timed_out(rtimer_clock_t timeout)
{
  return rtimer_smaller_than(timeout, RTIMER_NOW());
}
/*---------------------------------------------------------------------------*/
static rtimer_clock_t
shift_to_future(rtimer_clock_t time)
{
  /* TODO this assumes that WAKEUP_INTERVAL is a power of 2 */
  time = (RTIMER_NOW() & (~(WAKEUP_INTERVAL - 1)))
      | (time & (WAKEUP_INTERVAL - 1));
  while(!is_schedulable(time)) {
    time += WAKEUP_INTERVAL;
  }

  return time;
}
/*---------------------------------------------------------------------------*/
static int
is_schedulable(rtimer_clock_t time)
{
  /*
   * If time is less than RTIMER_GUARD_TIME ticks in the future,
   * rtimer_arch.c will schedule for time + RTIMER_GUARD_TIME.
   */
  return rtimer_greater_than(time, RTIMER_NOW() + RTIMER_GUARD_TIME + 1);
}
/*---------------------------------------------------------------------------*/
static void
disable_and_reset_radio(void)
{
  NETSTACK_RADIO.off();
  cc2538_rf_flushrx();
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  PRINTF("secrdc: t_i = %lu\n", INTER_FRAME_PERIOD);
  PRINTF("secrdc: t_c = %lu\n", INTER_CCA_PERIOD);
  PRINTF("secrdc: t_w = %i\n", WAKEUP_INTERVAL);
#if SECRDC_WITH_SECURE_PHASE_LOCK
  PRINTF("secrdc: t_a = %lu\n", ACKNOWLEDGEMENT_WINDOW);
  PRINTF("secrdc: t_s = %lu\n", PHASE_LOCK_GUARD_TIME);
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  memb_init(&buffered_frames_memb);
  list_init(buffered_frames_list);
  NETSTACK_RADIO.set_object(RADIO_PARAM_TXDONE_CALLBACK, on_txdone, 0);
  NETSTACK_RADIO.set_object(RADIO_PARAM_SFD_CALLBACK, on_sfd, 0);
  prepare_radio_for_duty_cycle();
  process_start(&post_processing, NULL);
  PT_INIT(&pt);
  duty_cycle_next = RTIMER_NOW() + WAKEUP_INTERVAL;
  schedule_duty_cycle(duty_cycle_next);
}
/*---------------------------------------------------------------------------*/
static void
prepare_radio_for_duty_cycle(void)
{
  NETSTACK_RADIO.set_object(RADIO_PARAM_FIFOP_CALLBACK,
      on_fifop,
      FIFOP_THRESHOLD);
  disable_shr_search();
}
/*---------------------------------------------------------------------------*/
static void
enable_shr_search(void)
{
  NETSTACK_RADIO.set_value(RADIO_PARAM_SHR_SEARCH, 1);
}
/*---------------------------------------------------------------------------*/
static void
disable_shr_search(void)
{
  NETSTACK_RADIO.set_value(RADIO_PARAM_SHR_SEARCH, 0);
}
/*---------------------------------------------------------------------------*/
static void
schedule_duty_cycle(rtimer_clock_t time)
{
  if(rtimer_set(&timer, time, 1, duty_cycle_wrapper, NULL) != RTIMER_OK) {
    PRINTF("secrdc: rtimer_set failed\n");
  }
}
/*---------------------------------------------------------------------------*/
static void
duty_cycle_wrapper(struct rtimer *rt, void *ptr)
{
  duty_cycle();
}
/*---------------------------------------------------------------------------*/
static char
duty_cycle(void)
{
  PT_BEGIN(&pt);

  is_duty_cycling = 1;
  lpm_set_max_pm(1);

  /* CCAs */
  while(1) {
    NETSTACK_RADIO.on();
    if(NETSTACK_RADIO.channel_clear()) {
      NETSTACK_RADIO.off();
      if(++u.duty_cycle.cca_count != MAX_CCAS) {
        schedule_duty_cycle(RTIMER_NOW() + INTER_CCA_PERIOD - LPM_SWITCHING);
        PT_YIELD(&pt);
        /* if we come from PM0, we will be too early */
        while(rtimer_greater_than(timer.time, RTIMER_NOW()));
        continue;
      }
    } else {
      u.duty_cycle.silence_timeout = RTIMER_NOW() + MAX_NOISE;
    }
    break;
  }

  /* fast-sleep optimization */
  if(u.duty_cycle.silence_timeout) {
    while(1) {

      /* look for silence period */
#if WITH_DOZING
      NETSTACK_RADIO.off();
      schedule_duty_cycle(RTIMER_NOW() + DOZING_PERIOD - LPM_SWITCHING);
      PT_YIELD(&pt);
      NETSTACK_RADIO.on();
#else /* WITH_DOZING */
      schedule_duty_cycle(RTIMER_NOW() + SILENCE_CHECK_PERIOD);
      PT_YIELD(&pt);
#endif /* WITH_DOZING */
      if(NETSTACK_RADIO.channel_clear()) {
        enable_shr_search();

        /* wait for SHR */
        u.duty_cycle.waiting_for_shr = 1;
        schedule_duty_cycle(RTIMER_NOW()
            + INTER_FRAME_PERIOD
            + SHR_DETECTION_TIME
            + 1 /* some tolerance */);
        PT_YIELD(&pt);
        u.duty_cycle.waiting_for_shr = 0;
        if(!u.duty_cycle.got_shr) {
          disable_and_reset_radio();
          PRINTF("secrdc: no SHR detected\n");
        }
        break;
      } else if(has_timed_out(u.duty_cycle.silence_timeout)) {
        disable_and_reset_radio();
        PRINTF("secrdc: noise too long\n");
        break;
      }
    }
  }

  if(!u.duty_cycle.got_shr) {
    finish_duty_cycle();
    u.duty_cycle.rtimer_freed = 1;
  }
  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
/**
 * Here, we assume that rtimer and radio interrupts have equal priorities,
 * such that they do not preempt each other.
 */
static void
on_sfd(void)
{
#if SECRDC_WITH_SECURE_PHASE_LOCK
  sfd_timestamp = RTIMER_NOW();
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  if(is_duty_cycling && u.duty_cycle.waiting_for_shr) {
    u.duty_cycle.got_shr = 1;
    rtimer_run_next();
    rtimer_set(&timer, RTIMER_NOW(), 1, on_rtimer_freed, NULL);
  }
}
/*---------------------------------------------------------------------------*/
static void
on_rtimer_freed(struct rtimer *rt, void *ptr)
{
  u.duty_cycle.rtimer_freed = 1;
}
/*---------------------------------------------------------------------------*/
static void
enable_local_packetbuf(void)
{
  u.duty_cycle.actual_packetbuf = packetbuf;
  packetbuf = &u.duty_cycle.local_packetbuf;
}
/*---------------------------------------------------------------------------*/
static void
disable_local_packetbuf(void)
{
  packetbuf = u.duty_cycle.actual_packetbuf;
}
/*---------------------------------------------------------------------------*/
#if POTR_ENABLED
static int
is_anything_locked(void)
{
  return aes_128_locked || akes_nbr_locked || nbr_table_locked;
}
#endif /* !POTR_ENABLED */
/*---------------------------------------------------------------------------*/
static void
on_fifop(void)
{
  if(is_duty_cycling) {
    if(!u.duty_cycle.got_shr) {
      PRINTF("secrdc: FIFOP unexpected\n");
    } else {
      enable_local_packetbuf();
      if(0
#if POTR_ENABLED
          || is_anything_locked()
#endif /* !POTR_ENABLED */
          || (cc2538_rf_read_phy_header_and_set_datalen() < CONTIKIMAC_FRAMER_SHORTEST_PACKET_SIZE)
          || !cc2538_rf_read_payload(FIFOP_THRESHOLD)
#if POTR_ENABLED
          || (potr_parse_and_validate() == FRAMER_FAILED)
#else /* !POTR_ENABLED */
          || (framer_802154_filter() == FRAMER_FAILED)
#endif /* !POTR_ENABLED */
          ) {
        disable_and_reset_radio();
        PRINTF("secrdc: rejected on the fly\n");
        finish_duty_cycle();
      } else {
#if POTR_ENABLED
        u.duty_cycle.shall_send_acknowledgement = potr_shall_send_acknowledgement();
#else /* !POTR_ENABLED */
        u.duty_cycle.shall_send_acknowledgement = !packetbuf_holds_broadcast();
#endif /* !POTR_ENABLED */

        if(u.duty_cycle.shall_send_acknowledgement) {
#if SECRDC_WITH_SECURE_PHASE_LOCK
          prepare_acknowledgement(sfd_timestamp
              - duty_cycle_next
              - INTER_FRAME_PERIOD
              - SHR_DETECTION_TIME);
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
          prepare_acknowledgement(0);
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
        }
        NETSTACK_RADIO.set_object(RADIO_PARAM_FIFOP_CALLBACK,
            on_final_fifop,
            packetbuf_datalen()
                + CHECKSUM_LEN
                - FIFOP_THRESHOLD
#if POTR_ENABLED
                - POTR_OTP_LEN
#if SECRDC_WITH_SECURE_PHASE_LOCK
                - (u.duty_cycle.shall_send_acknowledgement ? 1 : 0)
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
#endif /* !POTR_ENABLED */
        );
      }
      disable_local_packetbuf();
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
prepare_acknowledgement(uint8_t delta)
{
  uint8_t acknowledgement[ACKNOWLEDGEMENT_LEN];
#if POTR_ENABLED
#if SECRDC_WITH_SECURE_PHASE_LOCK
  uint8_t nonce[13];
  uint8_t a[2];

  /* create header */
  acknowledgement[0] = POTR_FRAME_TYPE_ACKNOWLEDGEMENT;
  acknowledgement[1] = delta;

  /* append MIC */
  ccm_star_packetbuf_set_acknowledgement_nonce(nonce, 0);
  cc2538_rf_read_payload(1);
  a[0] = ((uint8_t *)packetbuf_hdrptr())[POTR_HEADER_LEN];
  a[1] = delta;
  AES_128_GET_LOCK();
#if NEIGHBOR_WITH_PAIRWISE_KEYS
  ADAPTIVESEC_SET_KEY(akes_nbr_get_sender_entry()->permanent->pairwise_key);
#else /* NEIGHBOR_WITH_PAIRWISE_KEYS */
  ADAPTIVESEC_SET_KEY(akes_nbr_get_sender_entry()->permanent->group_key);
#endif /* NEIGHBOR_WITH_PAIRWISE_KEYS */
  CCM_STAR.aead(nonce,
      NULL, 0,
      a, 2,
      acknowledgement + 2, ADAPTIVESEC_UNICAST_MIC_LEN,
      1);
  AES_128_RELEASE_LOCK();
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
  acknowledgement[0] = POTR_FRAME_TYPE_ACKNOWLEDGEMENT;
  acknowledgement[1] = packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
#else /* !POTR_ENABLED */
  acknowledgement[0] = FRAME802154_ACKFRAME;
  acknowledgement[1] = 0;
  acknowledgement[2] = packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
#endif /* !POTR_ENABLED */
  NETSTACK_RADIO.prepare(acknowledgement, ACKNOWLEDGEMENT_LEN);
}
/*---------------------------------------------------------------------------*/
static void
on_final_fifop(void)
{
  if(is_duty_cycling) {
    if(!u.duty_cycle.shall_send_acknowledgement
          || !(NETSTACK_RADIO.transmit(ACKNOWLEDGEMENT_LEN) == RADIO_TX_OK)
#if SECRDC_WITH_SECURE_PHASE_LOCK
          || !received_authentic_unicast()
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
          ) {
      NETSTACK_RADIO.off();
      finish_duty_cycle();
    }
  }
}
/*---------------------------------------------------------------------------*/
#if SECRDC_WITH_SECURE_PHASE_LOCK
static int
received_authentic_unicast(void)
{
  struct akes_nbr_entry *entry;

  enable_local_packetbuf();
  if(is_anything_locked()
      || !cc2538_rf_read_payload(packetbuf_datalen() - (POTR_HEADER_LEN + 1))
      || (NETSTACK_FRAMER.parse() == FRAMER_FAILED)
      || !((entry = akes_nbr_get_sender_entry()))
      || !entry->permanent
      || ADAPTIVESEC_STRATEGY.verify(entry->permanent)) {
    packetbuf = u.duty_cycle.actual_packetbuf;
    PRINTF("secrdc: flushing unicast frame\n");
    cc2538_rf_flushrx();
    return 0;
  }
  disable_local_packetbuf();
  u.duty_cycle.read_and_parsed = 1;
  return 1;
}
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
static void
on_txdone(void)
{
  if(is_duty_cycling) {
    NETSTACK_RADIO.off();
    finish_duty_cycle();
  } else if(is_strobing) {
#if SECRDC_WITH_SECURE_PHASE_LOCK
    u.strobe.t1[0] = u.strobe.t1[1];
    u.strobe.t1[1] = RTIMER_NOW();
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
    strobe();
  }
}
/*---------------------------------------------------------------------------*/
static void
finish_duty_cycle(void)
{
  is_duty_cycling = 0;
  process_poll(&post_processing);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(post_processing, ev, data)
{
  int just_received_broadcast;
  int prepare_result;

  PROCESS_BEGIN();

  while(1) {
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
    while(!u.duty_cycle.rtimer_freed);

    just_received_broadcast = 0;

    /* read received frame */
    if(NETSTACK_RADIO.pending_packet()
#if SECRDC_WITH_SECURE_PHASE_LOCK
        || u.duty_cycle.read_and_parsed
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
        ) {
      enable_local_packetbuf();
#if SECRDC_WITH_SECURE_PHASE_LOCK
      if(!u.duty_cycle.read_and_parsed
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
      if(1
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
          && ((!cc2538_rf_read_payload(packetbuf_datalen()
              - (POTR_ENABLED ? POTR_HEADER_LEN : FRAMER_802154_MIN_BYTES_FOR_FILTERING)))
              || (NETSTACK_FRAMER.parse() == FRAMER_FAILED))) {
        PRINTF("secrdc: something went wrong while reading\n");
      } else {
        cc2538_rf_read_footer();
#if POTR_ENABLED
        just_received_broadcast = !potr_shall_send_acknowledgement();
#else /* POTR_ENABLED */
        just_received_broadcast = packetbuf_holds_broadcast();
#endif /* POTR_ENABLED */
        NETSTACK_MAC.input();
      }
      disable_local_packetbuf();
      cc2538_rf_flushrx();
    }

    /* send queued frames */
    if(!just_received_broadcast) {
      while(list_head(buffered_frames_list)) {
        enable_shr_search();
        memset(&u.strobe, 0, sizeof(u.strobe));
        u.strobe.bf = list_head(buffered_frames_list);
        queuebuf_to_packetbuf(u.strobe.bf->qb);

        /* create frame */
#if !POTR_ENABLED
        packetbuf_set_attr(PACKETBUF_ATTR_MAC_ACK, 1);
#endif /* !POTR_ENABLED */
        if(NETSTACK_FRAMER.create() == FRAMER_FAILED) {
          PRINTF("secrdc: NETSTACK_FRAMER.create failed\n");
          u.strobe.result = MAC_TX_ERR_FATAL;
          on_strobed();
          continue;
        }

        /* is this a broadcast? */
#if SECRDC_WITH_SECURE_PHASE_LOCK
        u.strobe.is_broadcast = !potr_shall_send_acknowledgement();
        if(!u.strobe.is_broadcast) {
          ccm_star_packetbuf_set_acknowledgement_nonce(u.strobe.acknowledgement_nonce, 1);
#if NEIGHBOR_WITH_PAIRWISE_KEYS
          memcpy(u.strobe.acknowledgement_key, entry->permanent->pairwise_key, NEIGHBOR_KEY_LEN);
#endif /* NEIGHBOR_WITH_PAIRWISE_KEYS */
        }
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
        u.strobe.seqno = packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
        u.strobe.is_broadcast = packetbuf_holds_broadcast();
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */

        /* move frame to radio */
        prepare_result = NETSTACK_RADIO.prepare(packetbuf_hdrptr(), packetbuf_totlen());
        if(prepare_result != RADIO_TX_OK) {
          PRINTF("secrdc: NETSTACK_RADIO.prepare failed with %i\n", prepare_result);
          u.strobe.result = mac_to_mac_result(prepare_result);
          on_strobed();
          continue;
        }

        /* starting to strobe */
#if SECRDC_WITH_PHASE_LOCK
        if(u.strobe.is_broadcast) {
          /* strobe broadcast frames immediately */
          strobe();
        } else {
          u.strobe.phase = obtain_phase_lock_information();
          if(!u.strobe.phase) {
            u.strobe.result = MAC_TX_ERR_FATAL;
            on_strobed();
            continue;
          }
          if(!u.strobe.phase->t) {
            /* no phase-lock information stored, yet */
            strobe();
          } else {
#if SECRDC_WITH_SECURE_PHASE_LOCK
            u.strobe.uncertainty = PHASE_LOCK_GUARD_TIME
                + (PHASE_LOCK_FREQ_TOLERANCE
                * ((rtimer_delta(u.strobe.phase->t, RTIMER_NOW()) / RTIMER_ARCH_SECOND) + 1));
            if(u.strobe.uncertainty >= (WAKEUP_INTERVAL / 2)) {
              /* uncertainty too high */
              u.strobe.uncertainty = 0;
              strobe();
            } else {
              is_strobing = 1;
              schedule_strobe(shift_to_future(u.strobe.phase->t
                  - LPM_SWITCHING
                  - RECEIVE_CALIBRATION_TIME
                  - CCA_DURATION
                  - TRANSMIT_CALIBRATION_TIME
                  - u.strobe.uncertainty));
            }
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
            schedule_strobe(shift_to_future(u.strobe.phase->t
                  - LPM_SWITCHING
                  - RECEIVE_CALIBRATION_TIME
                  - CCA_DURATION
                  - TRANSMIT_CALIBRATION_TIME
                  - PHASE_LOCK_GUARD_TIME));
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
          }
        }
#else /* SECRDC_WITH_PHASE_LOCK */
        strobe();
#endif /* SECRDC_WITH_PHASE_LOCK */

        /* process strobe result */
        PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
        u.strobe.bf->transmissions++;
        on_strobed();
      }
    }
    lpm_set_max_pm(LPM_CONF_MAX_PM);

    /* prepare next duty cycle */
    prepare_radio_for_duty_cycle();
    memset(&u.duty_cycle, 0, sizeof(u.duty_cycle));
    duty_cycle_next = shift_to_future(duty_cycle_next);
    schedule_duty_cycle(duty_cycle_next);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
#if SECRDC_WITH_PHASE_LOCK
static struct secrdc_phase *
obtain_phase_lock_information(void)
{
  struct akes_nbr_entry *entry;
  struct akes_nbr *nbr;

  entry = akes_nbr_get_receiver_entry();
  if(!entry) {
    PRINTF("secrdc: no entry found\n");
    return NULL;
  }
  nbr = entry->refs[u.strobe.bf->receiver_status];
  if(!nbr) {
    PRINTF("secrdc: no neighbor with status %i\n", u.strobe.bf->receiver_status);
    return NULL;
  }
  return &nbr->phase;
}
#endif /* SECRDC_WITH_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
static void
schedule_strobe(rtimer_clock_t time)
{
  if(rtimer_set(&timer, time, 1, strobe_wrapper, NULL) != RTIMER_OK) {
    PRINTF("secrdc: rtimer_set failed\n");
  }
}
/*---------------------------------------------------------------------------*/
static void
strobe_wrapper(struct rtimer *rt, void *ptr)
{
  strobe();
}
/*---------------------------------------------------------------------------*/
static char
strobe(void)
{
  uint8_t acknowledgement[ACKNOWLEDGEMENT_LEN];

  PT_BEGIN(&pt);
  is_strobing = 1;
  lpm_set_max_pm(0);

  /* enable RX to make a CCA before transmitting */
  u.strobe.next_transmission = RTIMER_NOW()
      + RECEIVE_CALIBRATION_TIME
      + CCA_DURATION;
  NETSTACK_RADIO.on();

#if SECRDC_WITH_SECURE_PHASE_LOCK
  if(u.strobe.uncertainty) {
    u.strobe.timeout = shift_to_future(u.strobe.phase->t + u.strobe.uncertainty);
    /* if we come from PM0, we will be too early */
    while(rtimer_greater_than(timer.time, RTIMER_NOW()));
  } else
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  {
    u.strobe.timeout = RTIMER_NOW() + WAKEUP_INTERVAL;
  }
  while(1) {
    if(!NETSTACK_RADIO.channel_clear()) {
      PRINTF("secrdc: collision\n");
      u.strobe.result = MAC_TX_COLLISION;
      break;
    }

    /* busy waiting for better timing */
    while(rtimer_greater_than(u.strobe.next_transmission, RTIMER_NOW()));

    if(transmit() != RADIO_TX_OK) {
      PRINTF("secrdc: NETSTACK_RADIO.transmit failed\n");
      u.strobe.result = MAC_TX_ERR;
      break;
    }
    PT_YIELD(&pt);
    u.strobe.next_transmission = RTIMER_NOW()
        + INTER_FRAME_PERIOD
        - TRANSMIT_CALIBRATION_TIME
        + 2 /* better transmit a tick too late than too early */;

    if(u.strobe.is_broadcast || !u.strobe.strobed_once++ /* little tweak */) {
      if(!should_strobe_again()) {
        u.strobe.result = MAC_TX_OK;
        break;
      }
      NETSTACK_RADIO.off();
      schedule_strobe(u.strobe.next_transmission
        - RECEIVE_CALIBRATION_TIME
        - CCA_DURATION
        - 2 /* the rtimer may wake us up too late otherwise */);
      PT_YIELD(&pt);
      NETSTACK_RADIO.on();
    } else {
      /* wait for acknowledgement */
      schedule_strobe(RTIMER_NOW() + ACKNOWLEDGEMENT_WINDOW_MAX);
      PT_YIELD(&pt);
      if(NETSTACK_RADIO.receiving_packet() || NETSTACK_RADIO.pending_packet()) {
        if(cc2538_rf_read_phy_header() != ACKNOWLEDGEMENT_LEN) {
          PRINTF("secrdc: unexpected frame\n");
          u.strobe.result = MAC_TX_COLLISION;
          break;
        }

#if SECRDC_WITH_SECURE_PHASE_LOCK
        schedule_strobe(sfd_timestamp + ACKNOWLEDGEMENT_LEN + CHECKSUM_LEN);
        PT_YIELD(&pt);
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */

        /* read acknowledgement */
        cc2538_rf_read_raw(acknowledgement, ACKNOWLEDGEMENT_LEN);
        cc2538_rf_flushrx();
        if(is_valid(acknowledgement)) {
          u.strobe.result = MAC_TX_OK;
#if SECRDC_WITH_PHASE_LOCK
#if SECRDC_WITH_SECURE_PHASE_LOCK
          u.strobe.phase->t = u.strobe.t1[0] - acknowledgement[1];
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
          u.strobe.phase->t = u.strobe.t0[0];
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
          if(!u.strobe.phase->t) {
            /* zero is reserved for uninitialized phase-lock data */
            u.strobe.phase->t = -WAKEUP_INTERVAL;
          }
#endif /* SECRDC_WITH_PHASE_LOCK */
#ifndef SECRDC_CONF_INFINITE_STROBE
          break;
#endif /* SECRDC_CONF_INFINITE_STROBE */
        }
      }

      /* schedule next transmission */
      if(!should_strobe_again()) {
        u.strobe.result = MAC_TX_NOACK;
        break;
      }
      schedule_strobe(u.strobe.next_transmission
          - 3 /* the rtimer may wake us up too late otherwise */);
      PT_YIELD(&pt);
    }
  }

  disable_and_reset_radio();
  is_strobing = 0;
  process_poll(&post_processing);
  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
static int
should_strobe_again(void)
{
  return rtimer_greater_than(u.strobe.timeout, u.strobe.next_transmission + TRANSMIT_CALIBRATION_TIME)
      || !u.strobe.sent_once_more++;
}
/*---------------------------------------------------------------------------*/
static int
transmit(void)
{
#if DEBUG || SECRDC_WITH_SECURE_PHASE_LOCK
  u.strobe.strobes++;
#endif /* DEBUG || SECRDC_WITH_SECURE_PHASE_LOCK */
#if SECRDC_WITH_ORIGINAL_PHASE_LOCK
  u.strobe.t0[0] = u.strobe.t0[1];
  u.strobe.t0[1] = RTIMER_NOW();
#endif /* SECRDC_WITH_ORIGINAL_PHASE_LOCK */
#if SECRDC_WITH_SECURE_PHASE_LOCK
  if(!u.strobe.is_broadcast) {
    NETSTACK_RADIO.set_object(RADIO_PARAM_TXFIFO_BYTE,
        &u.strobe.strobes,
        POTR_HEADER_LEN);
  }
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  return NETSTACK_RADIO.transmit(0);
}
/*---------------------------------------------------------------------------*/
static int
is_valid(uint8_t *acknowledgement)
{
#if SECRDC_WITH_SECURE_PHASE_LOCK
  uint8_t a[2];
  uint8_t expected_mic[ADAPTIVESEC_UNICAST_MIC_LEN];
  rtimer_clock_t diff;

  diff = rtimer_delta(u.strobe.t1[1], sfd_timestamp);
  if((diff < ACKNOWLEDGEMENT_WINDOW_MIN)
      || (diff > ACKNOWLEDGEMENT_WINDOW_MAX)) {
    PRINTF("secrdc: acknowledgement frame wasn't timely\n");
    return 0;
  }
  if(aes_128_locked) {
    PRINTF("secrdc: could not validate acknowledgement frame\n");
    return 0;
  }

  AES_128_GET_LOCK();
#if NEIGHBOR_WITH_PAIRWISE_KEYS
  ADAPTIVESEC_SET_KEY(u.strobe.acknowledgement_key);
#else /* NEIGHBOR_WITH_PAIRWISE_KEYS */
  ADAPTIVESEC_SET_KEY(adaptivesec_group_key);
#endif /* NEIGHBOR_WITH_PAIRWISE_KEYS */
  a[0] = u.strobe.strobes;
  a[1] = acknowledgement[1];
  CCM_STAR.aead(u.strobe.acknowledgement_nonce,
      NULL, 0,
      a, 2,
      expected_mic, ADAPTIVESEC_UNICAST_MIC_LEN,
      1);
  AES_128_RELEASE_LOCK();
  if(memcmp(expected_mic, acknowledgement + 2, ADAPTIVESEC_UNICAST_MIC_LEN)) {
    PRINTF("secrdc: inauthentic acknowledgement frame\n");
    return 0;
  }
  return 1;
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
  return u.strobe.seqno == acknowledgement[ACKNOWLEDGEMENT_LEN - 1];
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
}
/*---------------------------------------------------------------------------*/
static void
on_strobed(void)
{
#if DEBUG
  if(!u.strobe.is_broadcast) {
    PRINTF("secrdc: strobed %i times with %s\n",
        u.strobe.strobes,
        (u.strobe.result == MAC_TX_OK) ? "success" : "error");
  }
#endif /* DEBUG */
  queuebuf_to_packetbuf(u.strobe.bf->qb);
  queuebuf_free(u.strobe.bf->qb);
  mac_call_sent_callback(u.strobe.bf->sent,
      u.strobe.bf->ptr,
      u.strobe.result,
      u.strobe.bf->transmissions);
  if((u.strobe.result == MAC_TX_OK) && u.strobe.bf->tail) {
    send_list(u.strobe.bf->sent, u.strobe.bf->ptr, u.strobe.bf->tail);
  }
  list_remove(buffered_frames_list, u.strobe.bf);
  memb_free(&buffered_frames_memb, u.strobe.bf);
}
/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  queue_frame(sent, ptr, NULL, NULL);
}
/*---------------------------------------------------------------------------*/
/* TODO burst support */
static void
send_list(mac_callback_t sent, void *ptr, struct rdc_buf_list *list)
{
  queue_frame(sent, ptr, list->buf, list_item_next(list));
}
/*---------------------------------------------------------------------------*/
static void
queue_frame(mac_callback_t sent,
    void *ptr,
    struct queuebuf *qb,
    struct rdc_buf_list *tail)
{
  struct buffered_frame *bf;

  bf = memb_alloc(&buffered_frames_memb);
  if(!bf) {
    PRINTF("secrdc: buffer is full\n");
    mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
    return;
  }
  if(!qb) {
    bf->qb = queuebuf_new_from_packetbuf();
    if(!bf->qb) {
      PRINTF("secrdc: queubuf is full\n");
      memb_free(&buffered_frames_memb, bf);
      mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
      return;
    }
  } else {
    bf->qb = qb;
  }

  bf->ptr = ptr;
  bf->sent = sent;
  bf->transmissions = 0;
  bf->tail = tail;
#if SECRDC_WITH_PHASE_LOCK
  bf->receiver_status = akes_get_receiver_status();
#endif /* SECRDC_WITH_PHASE_LOCK */
  list_add(buffered_frames_list, bf);
}
/*---------------------------------------------------------------------------*/
static void
input(void)
{
  /* we operate in polling mode throughout */
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
  /* TODO implement if needed */
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
off(int keep_radio_on)
{
  /* TODO implement if needed  */
  return 1;
}
/*---------------------------------------------------------------------------*/
static unsigned short
channel_check_interval(void)
{
  return CLOCK_SECOND / NETSTACK_RDC_CHANNEL_CHECK_RATE;
}
/*---------------------------------------------------------------------------*/
const struct rdc_driver secrdc_driver = {
  "secrdc",
  init,
  send,
  send_list,
  input,
  on,
  off,
  channel_check_interval,
};
/*---------------------------------------------------------------------------*/
