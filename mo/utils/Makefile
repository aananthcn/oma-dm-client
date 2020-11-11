.DEFAULT_GOAL := all

# constants
IFLAGS = -I. -I../../dmcore/include -I../utils

CFLAGS = -g ${IFLAGS} -fPIC
LFLAGS = 

MKDIR  = mkdir -p

TARGET = ../../lib/libmo_util.a


# objects
target_objs = ../utils/memory_mo_util.o \
	      ../utils/static_mo_util.o


%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@


${TARGET}: ${target_objs}
	$(AR) rcs $@ $^

clean:
	$(RM) ${target_objs}
	$(RM) ${TARGET}


all: ${TARGET}

