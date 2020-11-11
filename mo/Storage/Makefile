.DEFAULT_GOAL := all

# constants
IFLAGS = -I. -I../../dmcore/include -I../utils

CFLAGS = -g ${IFLAGS} -fPIC
LFLAGS = -shared -L../../lib -ldmclient -lsqlite3

MKDIR  = mkdir -p

TARGET = ../../plugins/storage_plugin.so


# objects
target_objs = plugin_storage.o \
	      dmsettings.o \
	      dmsettings_utils.o \
	      dyn_buf.o

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

