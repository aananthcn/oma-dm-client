#! /bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

export LD_LIBRARY_PATH=${DIR}/lib/
export DYLD_LIBRARY_PATH=${DIR}/lib/

${DIR}/dm-client -p ${DIR}/plugins $* &
