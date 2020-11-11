.DEFAULT_GOAL := all

# constants
IFLAGS = -I. -I../dmcore/include/ \
	 -I../externals/SyncMLRTK/src \
	 -I../externals/SyncMLRTK/src/sml/inc \
	 -I../externals/SyncMLRTK/src/sml/inc/win \
	 -I../externals/SyncMLRTK/src/sml/mgr/inc \
	 -I../../update-orchestrator/include \
	 
CFLAGS = -g ${IFLAGS} -O0 -fPIC ${GLOBAL_IFLAGS}
LFLAGS = -L../lib -lcurl -ldmclient -lsyncml -ldl -lcrypto -ljansson ${GLOBAL_LFLAGS}


TARGET = ../dm-client


# objects
target_objs = oma_dm_client.o \
	      dm_register.o \
	      dm_udid.o

%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@


${TARGET}: ${target_objs}
	$(CC) -o $@ $^ $(CFLAGS) $(LFLAGS)

clean:
	$(RM) ${target_objs}
	$(RM) ${TARGET}


all: ${TARGET}

