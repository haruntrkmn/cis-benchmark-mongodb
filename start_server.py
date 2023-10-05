import os

CONFIG_PATH = "C:/Program Files/MongoDB/Server/7.0/bin/mongod.cfg"
command = f"mongod.exe --config \"{CONFIG_PATH}\""

# "Can't initialize rotatable log file :: caused by :: Failed to open C:\\data\\log\\mongod.log"
# gibi bir hata verirse hali hazırda başka bir mongo server'ı ayakta olabilir
print('starting server...')
os.system(command)