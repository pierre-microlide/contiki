[`coresec`](https://github.com/kkrentz/contiki/blob/apkes/core/net/llsec/coresec/coresec.c) implements 802.15.4 security, the Adaptable Pairwise Key Establishment Scheme ([APKES](https://github.com/kkrentz/contiki/blob/apkes/core/net/llsec/coresec/apkes.c)), as well as the Easy Broadcast Encryption and Authentication Protocol ([EBEAP](https://github.com/kkrentz/contiki/blob/apkes/core/net/llsec/coresec/ebeap.c)). APKES establishes pairwise 802.15.4 session keys with neighboring nodes. Different key predistribution schemes can be plugged into APKES so as to adapt to different 6LoWPAN networks and threat models. Presently, the Localized Encryption and Authentication Protocol ([LEAP](https://github.com/kkrentz/contiki/blob/apkes/core/net/llsec/coresec/leap.c)) and the fully pairwise keys scheme ([fully](https://github.com/kkrentz/contiki/blob/apkes/core/net/llsec/coresec/fully.c)) are available. EBEAP, on the over hand, is a lightweight version of TESLA++. EBEAP is used for authenticating (and optionally encrypting) broadcast frames.

### Enabling coresec

Below is a stripped-down configuration using nullrdc, nullmac, and coresec:
```c
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC                 nullrdc_driver
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC                 nullmac_driver
#undef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM                 5
#undef LLSEC802154_CONF_SECURITY_LEVEL
#define LLSEC802154_CONF_SECURITY_LEVEL   2
#define APKES_CONF_SCHEME                 leap_apkes_scheme
#include "net/llsec/coresec/coresec-autoconf.h"
```
The security level selects a security suite defined in [coresec-autoconf](https://github.com/kkrentz/contiki/blob/apkes/core/net/llsec/coresec/coresec-autoconf.h). You are free to override these configurations by not #including `coresec-autoconf.h`. Note however that some things are immutable. The security level must either be 1, 2, 3, 5, 6, or 7. Furthermore, a security level < 4 always disables encryption, while a security level > 4 always enables encryption.

The following is a fully fledged configuration using ContikiMAC, CSMA, as well as encryption.
```c
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC                       contikimac_driver
#define CONTIKIMAC_CONF_WITH_PHASE_OPTIMIZATION 1
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC                       csma_driver
#undef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM                       8
#undef LLSEC802154_CONF_SECURITY_LEVEL
#define LLSEC802154_CONF_SECURITY_LEVEL         6
#define APKES_CONF_SCHEME                       leap_apkes_scheme
#include "net/llsec/coresec/coresec-autoconf.h"
```
The above configuration may, however, consume too much memory. You can save memory by, e.g., disabling phase optimization, using nullmac, or disabling encryption as done below.
```c
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC                       contikimac_driver
#define CONTIKIMAC_CONF_WITH_PHASE_OPTIMIZATION 0
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC                       nullmac_driver
#undef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM                       5
#undef LLSEC802154_CONF_SECURITY_LEVEL
#define LLSEC802154_CONF_SECURITY_LEVEL         2
#define APKES_CONF_SCHEME                       leap_apkes_scheme
#include "net/llsec/coresec/coresec-autoconf.h"
```

### Preloading

1) Switch folder
```bash
cd examples/csprng/
```
2) Burn node id (optional)
```bash
make clean && make burn-nodeid.upload nodeid=8 && make login
```
3) Edit preload.c (fill out seed)

4) Run preload
```bash
make preload.upload && make login
```
5) Switch folder
```bash
cd examples/llsec/fully/
```
or
```bash
cd examples/llsec/leap/
```
6) Edit preload.c (fill out master key)

7) Run preload
```bash
make preload.upload && make login
```

### Disabling EBEAP's Encryption
You may want to encrypt unicast, but not broadcast frames. For this, add:
```c
#undef LLSEC802154_CONF_SECURITY_LEVEL
#define LLSEC802154_CONF_SECURITY_LEVEL         7
#include "net/llsec/coresec/coresec-autoconf.h"
#undef NEIGHBOR_CONF_BROADCAST_KEY_LEN
#define NEIGHBOR_CONF_BROADCAST_KEY_LEN         0
```

## Resources

* [Paper](http://dl.acm.org/citation.cfm?id=2523501.2523502)