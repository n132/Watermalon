import os

########################################
#               Setting
########################################
CHALL_NAME = "house_of_n132"
PORT = 6999
FLAG = "n132{n132_n132}"
TARGET_DIR = "template"
SOURCE = False # "./main.c"
BIN = "./pwn"
SHARE = True
# If it's true, the flag would not be copied so that you can
#  share this in the challenge attachment
########################################
#               Setting
########################################


# modify the dockerfile
with open(f"./{TARGET_DIR}/Dockfile") as f:
    data = f.read()
if not SHARE:
    data.replace("RUN echo FLAG > flag.txt",f"RUN echo {FLAG} > flag.txt")
else:
    data.replace("RUN echo FLAG > flag.txt","RUN echo flag{This_is_not_the_real_flag} > flag.txt")
with open(f"./{TARGET_DIR}/Dockfile",'w') as f:
    f.write(data)

# modify the docker-compose.yml

with open(f"./{TARGET_DIR}/Dockfile") as f:
    data = f.read()
data.replace("PWN_CHALL",CHALL_NAME)
data.replace("PORTVLAUE",str(PORT).encode())
with open(f"./{TARGET_DIR}/Dockfile",'w') as f:
    f.write(data)


# Cotent
if SOURCE:
    os.Popen(f"mv {SOURCE} ./{TARGET_DIR}/src/")
os.Popen(f"mv {BIN} ./{TARGET_DIR}/bin/pwn")