#!/bin/bash

./xmlrpcserver.py >/dev/null 2>&1 &
sleep 1
./xmlrpctest
pkill -f xmlrpcserver.py  >/dev/null 2>&1 &
