.DEFAULT_GOAL := all

LIB_DIR = ${libdir}
BIN_DIR = ${bindir}
INCLUDE_DIR = ${includedir}
PLUGINS_DIR = ${libdir}/fota-plugins


ARGS   = GLOBAL_IFLAGS="${GLOBAL_IFLAGS}" GLOBAL_LFLAGS="${GLOBAL_LFLAGS}" DESTDIR="${DESTDIR}"

MKDIR = mkdir -p
COPY = cp -r

LIBS = lib
PLUGIN = plugins

all:
	${MKDIR} ${LIBS}
	${MKDIR} ${PLUGIN}
	$(MAKE) -C externals/SyncMLRTK
	$(MAKE) -C dmcore
	$(MAKE) -C dmclient ${ARGS}
	$(MAKE) -C mo/DevDetail
	$(MAKE) -C mo/DevInfo
	$(MAKE) -C mo/DMAcc
	$(MAKE) -C mo/Inbox
	$(MAKE) -C mo/Memory
	$(MAKE) -C mo/Storage
	$(MAKE) -C mo/utils


install:
	$(MKDIR) ${DESTDIR}${PLUGINS_DIR}
	$(COPY) ./plugins/* ${DESTDIR}${PLUGINS_DIR}
	$(MKDIR) ${DESTDIR}${LIB_DIR}
	$(COPY) ./lib/* ${DESTDIR}${LIB_DIR}
	$(MKDIR) ${DESTDIR}${BIN_DIR}
	$(COPY) ./dm-client ${DESTDIR}${BIN_DIR}
	$(MKDIR) ${DESTDIR}${INCLUDE_DIR}
	$(COPY) dmcore/include/* ${DESTDIR}${INCLUDE_DIR}
	$(COPY) mo/utils/*.h ${DESTDIR}${INCLUDE_DIR}
	$(COPY) dmclient/*.h ${DESTDIR}${INCLUDE_DIR}

clean:
	$(MAKE) clean -C externals/SyncMLRTK
	$(MAKE) clean -C dmcore
	$(MAKE) clean -C dmclient
	$(MAKE) clean -C mo/DevDetail
	$(MAKE) clean -C mo/DevInfo
	$(MAKE) clean -C mo/DMAcc
	$(MAKE) clean -C mo/Inbox
	$(MAKE) clean -C mo/Memory
	$(MAKE) clean -C mo/Storage
	$(MAKE) clean -C mo/utils

