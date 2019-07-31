import sys
import random
import subprocess
import time

nb_calls = int(sys.argv[1])
sleep_time = sys.argv[2]

# subprocess.check_output(['ls','-l']) #all that is technically needed...
current_path = subprocess.check_output(['pwd']).decode("utf-8").strip()
print("Current path set to : {}".format(current_path))
pictures = subprocess.check_output(
    ['ls', current_path + '/tests/']).decode("utf-8").strip().split("\n")
# print(pictures)

for i in range(nb_calls):
    print("Call #{}".format(i))
    rnd_pic = random.choice(pictures)
    output = subprocess.check_output(['./transaction', '--mode', 'cartp', 
                    '--url', 'http://134.59.230.148:8008/batches', 
                    '--cmd', 'set_owner', 
                    '--owner', r'Voiture de {}'.format(rnd_pic.split(".")[0]), 
                    '--owner_pic', 'tests/{}'.format(rnd_pic)])
    time.sleep(float(sleep_time))
