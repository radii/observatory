#!/bin/bash

./hackparse.py --create --readable /home/jesse/data/sslscanner{0,0b,1,1b,2} &
sleep 5s

./hackparse.py --readable /home/jesse/data/sslscanner{3,4,4b,5} &

./hackparse.py --readable /home/jesse/data/sslscanner{6,7,8} &

./hackparse.py --readable /home/jesse/data/sslscanner{9,9b,10,10bcd,11,11b} &

./hackparse.py --readable /home/jesse/data/sslscanner134
