.DEFAULT_GOAL := all

# constants
IFLAGS = -I. -I./src -I./src/sml/inc -I./src/sml/mgr/inc -I./src/sml/lib/inc -I./src/sml/wsm/inc -I./src/sml/inc/win -I./src/sml/xlt/inc -I./src/sml/xlt/all

CFLAGS = -g ${IFLAGS} -fPIC
LFLAGS = -shared

MKDIR  = mkdir -p

TARGET = ../../lib/libsyncml.so


# objects
target_objs = ./src/sml/mgr/all/mgrcmdbuilder.o \
	      ./src/sml/mgr/all/mgr.o \
	      ./src/sml/mgr/all/mgrutil.o \
	      ./src/sml/mgr/all/mgrinstancelist.o \
	      ./src/sml/mgr/all/mgrinstancemgr.o \
	      ./src/sml/mgr/all/mgrcmddispatcher.o \
	      ./src/sml/xlt/all/xltmetinf.o \
	      ./src/sml/xlt/all/xltencwbxml.o \
	      ./src/sml/xlt/all/xltdecwbxml.o \
	      ./src/sml/xlt/all/xltdevinf.o \
	      ./src/sml/xlt/all/xlttags.o \
	      ./src/sml/xlt/all/xltutilstack.o \
	      ./src/sml/xlt/all/xltenccom.o \
	      ./src/sml/xlt/all/xltenc.o \
	      ./src/sml/xlt/all/xltdec.o \
	      ./src/sml/xlt/all/xltdecxml.o \
	      ./src/sml/xlt/all/xltencxml.o \
	      ./src/sml/lib/all/libmem.o \
	      ./src/sml/lib/all/libutil.o \
	      ./src/sml/lib/all/libstr.o \
	      ./src/sml/lib/all/liblock.o



%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@


${TARGET}: ${target_objs}
	$(CC) -o $@ $^ $(CFLAGS) $(LFLAGS)

clean:
	$(RM) ${target_objs}
	$(RM) ${TARGET}


all: ${TARGET}

