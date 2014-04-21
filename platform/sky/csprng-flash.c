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
 *         Helpers for preloading and restoring the CSPRNG seed.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "sys/csprng-flash.h"
#include "dev/xmem.h"

/*---------------------------------------------------------------------------*/
void
csprng_flash_preload_seed(struct csprng_seed *seed)
{
  xmem_erase(XMEM_ERASE_UNIT_SIZE, CSPRNG_FLASH_SEED_OFFSET);
  xmem_pwrite(seed, sizeof(struct csprng_seed), CSPRNG_FLASH_SEED_OFFSET);
}
/*---------------------------------------------------------------------------*/
void
csprng_flash_restore_seed(void)
{
  struct csprng_seed next_seed;
  
  xmem_pread(&csprng_seed, sizeof(struct csprng_seed), CSPRNG_FLASH_SEED_OFFSET);
  csprng_rand(&next_seed, sizeof(struct csprng_seed));
  csprng_flash_preload_seed(&next_seed);
}
/*---------------------------------------------------------------------------*/
