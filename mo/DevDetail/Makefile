.DEFAULT_GOAL := all

# constants
IFLAGS = -I. -I../../dmcore/include -I../utils

CFLAGS = -g ${IFLAGS} -fPIC ${GLOBAL_IFLAGS}
LFLAGS = -shared -L../../lib -ldmclient -lcrypto -lssl ${GLOBAL_LFLAGS}

MKDIR  = mkdir -p

TARGET = ../../plugins/devdetails_plugin.so


# objects
target_objs = plugin_devdetails.o

common_objs = ../utils/memory_mo_util.o \
	      ../utils/static_mo_util.o


%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@


${TARGET}: ${target_objs} ${common_objs}
	$(CC) -o $@ $^ $(CFLAGS) $(LFLAGS)

clean:
	$(RM) ${target_objs} ${common_objs}
	$(RM) ${TARGET}


all: ${TARGET}

