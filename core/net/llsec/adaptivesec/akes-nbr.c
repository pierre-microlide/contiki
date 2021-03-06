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
 *         Neighbor management.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/frame802154.h"
#include "net/llsec/llsec802154.h"
#include "net/llsec/adaptivesec/akes-nbr.h"
#include "net/packetbuf.h"
#include "lib/memb.h"
#include "lib/list.h"

#ifdef AKES_NBR_CONF_LIFETIME
#define LIFETIME                 AKES_NBR_CONF_LIFETIME
#else /* AKES_NBR_CONF_LIFETIME */
#define LIFETIME                 (60 * 60) /* seconds */
#endif /* AKES_NBR_CONF_LIFETIME */

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

NBR_TABLE(struct akes_nbr_entry, entries_table);
MEMB(nbrs_memb, struct akes_nbr, AKES_NBR_MAX);

/*---------------------------------------------------------------------------*/
void
akes_nbr_copy_challenge(uint8_t *dest, uint8_t *source)
{
  memcpy(dest, source, AKES_NBR_CHALLENGE_LEN);
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_copy_key(uint8_t *dest, uint8_t *source)
{
  memcpy(dest, source, AKES_NBR_KEY_LEN);
}
/*---------------------------------------------------------------------------*/
linkaddr_t *
akes_nbr_get_addr(struct akes_nbr_entry *entry)
{
  return nbr_table_get_lladdr(entries_table, entry);
}
/*---------------------------------------------------------------------------*/
static void
on_entry_change(struct akes_nbr_entry *entry)
{
  if(!entry->permanent && !entry->tentative) {
    nbr_table_unlock(entries_table, entry);
    nbr_table_remove(entries_table, entry);
  }
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_head(void)
{
  return nbr_table_head(entries_table);
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_next(struct akes_nbr_entry *current)
{
  return nbr_table_next(entries_table, current);
}
/*---------------------------------------------------------------------------*/
int
akes_nbr_count(enum akes_nbr_status status)
{
  uint8_t count;
  struct akes_nbr_entry *next;

  count = 0;
  next = akes_nbr_head();
  while(next) {
    if(next->refs[status]) {
      count++;
    }
    next = akes_nbr_next(next);
  }

  return count;
}
/*---------------------------------------------------------------------------*/
int
akes_nbr_free_slots(void)
{
  return memb_numfree(&nbrs_memb);
}
/*---------------------------------------------------------------------------*/
#if AKES_NBR_WITH_INDICES
static void
init_local_index(struct akes_nbr_entry *entry)
{
  struct akes_nbr_entry *next;

  next = akes_nbr_head();
  entry->local_index = 0;
  while(next) {
    if((next->local_index != entry->local_index) || (next == entry)) {
      next = akes_nbr_next(next);
    } else {
      /* start over */
      entry->local_index++;
      next = akes_nbr_head();
    }
  }
}
#endif /* AKES_NBR_WITH_INDICES */
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_new(enum akes_nbr_status status)
{
  struct akes_nbr_entry *entry;

  if(status && (akes_nbr_count(AKES_NBR_TENTATIVE) >= AKES_NBR_MAX_TENTATIVES)) {
    PRINTF("akes-nbr: Too many tentative neighbors\n");
    return NULL;
  }

  entry = akes_nbr_get_sender_entry();
  if(!entry) {
    entry = nbr_table_add_lladdr(entries_table,
        packetbuf_addr(PACKETBUF_ADDR_SENDER),
        NBR_TABLE_REASON_LLSEC,
        NULL);
    if(!entry) {
      PRINTF("akes-nbr: Full\n");
      return NULL;
    }
#if AKES_NBR_WITH_INDICES
    init_local_index(entry);
#endif /* AKES_NBR_WITH_INDICES */
  }

  AKES_NBR_GET_LOCK();
  entry->refs[status] = memb_alloc(&nbrs_memb);
  if(!entry->refs[status]) {
    PRINTF("akes-nbr: RAM is running low\n");
    on_entry_change(entry);
    AKES_NBR_RELEASE_LOCK();
    return NULL;
  }
  nbr_table_lock(entries_table, entry);
  anti_replay_init_info(&entry->refs[status]->anti_replay_info);
  if(status) {
    entry->refs[status]->status = status;
  }
  entry->refs[status]->sent_authentic_hello = status;
#if SECRDC_ENABLED && SECRDC_WITH_PHASE_LOCK
  entry->refs[status]->phase.t = 0;
#endif /* SECRDC_ENABLED && SECRDC_WITH_PHASE_LOCK */
  AKES_NBR_RELEASE_LOCK();
  return entry;
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_update(struct akes_nbr *nbr, uint8_t *data, int with_group_key)
{
  anti_replay_was_replayed(&nbr->anti_replay_info);
#if ANTI_REPLAY_WITH_SUPPRESSION
  nbr->last_was_broadcast = 1;
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  akes_nbr_prolong(nbr);

#if AKES_NBR_WITH_INDICES
  nbr->foreign_index = data[0];
  data++;
#endif /* AKES_NBR_WITH_INDICES */
#if ANTI_REPLAY_WITH_SUPPRESSION
  {
    frame802154_frame_counter_t disordered_counter;
    data += 4;
    memcpy(disordered_counter.u8, data, 4);
    nbr->anti_replay_info.his_broadcast_counter.u32 = LLSEC802154_HTONL(disordered_counter.u32);
    data += 4;
  }
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
#if AKES_NBR_WITH_GROUP_KEYS
  if(with_group_key) {
    akes_nbr_copy_key(nbr->group_key, data);
  }
#endif /* AKES_NBR_WITH_GROUP_KEYS */

#if DEBUG
  {
    uint8_t i;

    PRINTF("akes-nbr: Neighbor ");
    for(i = 0; i < LINKADDR_SIZE; i++) {
      PRINTF("%02X", packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8[i]);
    }
    PRINTF("\n");
#if AKES_NBR_WITH_INDICES
    PRINTF("akes-nbr: Local index: %i\n", akes_nbr_get_sender_entry()->local_index);
    PRINTF("akes-nbr: Foreign index: %i\n", nbr->foreign_index);
#endif /* AKES_NBR_WITH_INDICES */
#if AKES_NBR_WITH_GROUP_KEYS
    PRINTF("akes-nbr: Group session key: ");
    for(i = 0; i < AKES_NBR_KEY_LEN; i++) {
      PRINTF("%x", nbr->group_key[i]);
    }
    PRINTF("\n");
#endif /* AKES_NBR_WITH_GROUP_KEYS */
#if AKES_NBR_WITH_PAIRWISE_KEYS
    PRINTF("akes-nbr: Pairwise key: ");
    for(i = 0; i < AKES_NBR_KEY_LEN; i++) {
      PRINTF("%x", nbr->pairwise_key[i]);
    }
    PRINTF("\n");
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS */
#if ANTI_REPLAY_WITH_SUPPRESSION
    PRINTF("akes-nbr: his_broadcast_counter: %lu\n", nbr->anti_replay_info.his_broadcast_counter.u32);
    PRINTF("akes-nbr: his_unicast_counter  : %lu\n", nbr->anti_replay_info.his_unicast_counter.u32);
    PRINTF("akes-nbr: my_unicast_counter   : %lu\n", nbr->anti_replay_info.my_unicast_counter.u32);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  }
#endif /* DEBUG */
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_do_prolong(struct akes_nbr *nbr, uint16_t seconds)
{
  PRINTF("akes-nbr: prolonging\n");
  nbr->expiration_time = clock_seconds() + seconds;
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_prolong(struct akes_nbr *nbr)
{
#if ANTI_REPLAY_WITH_SUPPRESSION
  int is_broadcast;

  is_broadcast = packetbuf_holds_broadcast();
  if(!is_broadcast && !nbr->last_was_broadcast) {
    return;
  }
  if(is_broadcast && nbr->last_was_broadcast) {
    return;
  }
  nbr->last_was_broadcast = is_broadcast;
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  akes_nbr_do_prolong(nbr, LIFETIME);
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_get_sender_entry(void)
{
  return nbr_table_get_from_lladdr(entries_table, packetbuf_addr(PACKETBUF_ADDR_SENDER));
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_get_receiver_entry(void)
{
  return nbr_table_get_from_lladdr(entries_table, packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_delete(struct akes_nbr_entry *entry, enum akes_nbr_status status)
{
  PRINTF("akes-nbr: Deleting %i\n", entry->local_index);
  AKES_NBR_GET_LOCK();
  memb_free(&nbrs_memb, entry->refs[status]);
  entry->refs[status] = NULL;
  on_entry_change(entry);
  AKES_NBR_RELEASE_LOCK();
}
/*---------------------------------------------------------------------------*/
int
akes_nbr_is_expired(struct akes_nbr *nbr)
{
  if(nbr->expiration_time < clock_seconds()) {
    return 1;
  }
#if SECRDC_WITH_SECURE_PHASE_LOCK
  if(!nbr->phase.t) {
    return 0;
  }
  return rtimer_delta(nbr->phase.t, RTIMER_NOW()) >= SECRDC_UPDATE_THRESHOLD;
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
  return 0;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_delete_expired_tentatives(void)
{
  struct akes_nbr_entry *next;
  struct akes_nbr_entry *current;

  next = akes_nbr_head();
  while(next) {
    current = next;
    next = akes_nbr_next(current);
    if(current->tentative && akes_nbr_is_expired(current->tentative)) {
      akes_nbr_delete(current, AKES_NBR_TENTATIVE);
    }
  }
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_init(void)
{
  memb_init(&nbrs_memb);
  nbr_table_register(entries_table, NULL);
}
/*---------------------------------------------------------------------------*/
