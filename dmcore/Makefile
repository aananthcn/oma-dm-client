.DEFAULT_GOAL := all

# constants
IFLAGS = -I. -I../externals/SyncMLRTK/src -I../externals/SyncMLRTK/src/sml/inc \
	 -I../externals/SyncMLRTK/src/sml/inc/win -I../externals/SyncMLRTK/src/sml/mgr/inc \
	 -I./include \
	 -I../../update-orchestrator/include \
	 -I../dmclient \

CFLAGS = -g ${IFLAGS} -fPIC
LFLAGS = -shared -L../lib -lsyncml -lcrypto

MKDIR  = mkdir -p

TARGET = ../lib/libdmclient.so


# objects
target_objs = ./src/credentials.o \
	      ./src/utils.o \
	      ./src/uricheck.o \
	      ./src/package0.o \
	      ./src/log.o \
	      ./src/callbacks.o \
	      ./src/sml2tree.o \
	      ./src/omadmclient.o \
	      ./src/momgr.o \
	      ./src/dmtree.o \
	      ./src/codec.o \
	      ./src/defaultroot.o \
	      ./src/mo2list.o


# rules & targets
%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@


${TARGET}: ${target_objs}
	$(CC) -o $@ $^ $(CFLAGS) $(LFLAGS)


clean:
	$(RM) ${target_objs}
	$(RM) ${TARGET}


all: ${TARGET}

