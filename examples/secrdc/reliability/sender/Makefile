CONTIKI_PROJECT = sender
all: $(CONTIKI_PROJECT)

CONTIKI=../../../..

MODULES += core/net/llsec/adaptivesec

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"
SMALL=1

include $(CONTIKI)/Makefile.include
