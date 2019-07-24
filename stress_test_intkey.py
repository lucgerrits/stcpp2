import sys
import random
import subprocess
import time

nb_calls = int(sys.argv[1])
sleep_time = sys.argv[2]

for i in range(nb_calls):
    print("Call #{}".format(i))
    output = subprocess.check_output(['./transaction', '--mode', 'intkey', 
                    '--url', 'http://134.59.230.101:8008/batches', 
                    '--cmd', 'inc', 
                    '--key', 'luc', 
                    '--value', '1'])
    time.sleep(float(sleep_time))
