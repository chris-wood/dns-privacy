#!/bin/bash

FILE=$1
STRING=$2

if ! grep "$STRING" "$FILE"
then
    echo ${STRING} >> ${FILE}
fi
