import os
import re
import json
import time
import subprocess

############# command line arguments #############

# mongo.exe directory
MONGO_DIR = "C:/Program Files/MongoDB/Server/7.0/bin" 
# mongo shell directory
MONGOSH_DIR = "C:/Program Files/MongoDB/Server/7.0/mongosh-2.0.0-win32-x64/bin"
# config path
CONFIG_PATH = "C:/Program Files/MongoDB/Server/7.0/bin/mongod.cfg"
# output path to save
SAVE_DIR = 'C:/Users/harun/OneDrive/Desktop/projects/cis_benchmark/results.json'
# start_server.py path
START_SERVER_PATH = "C:/Users/harun/OneDrive/Desktop/projects/cis_benchmark/start_server.py"


def initialize_mongodb_server():
    # start_server.py dosyasını çalıştırır.
    # ayrı bir process olarak çalıştırmak gerektiği için bu şekilde çağrılıyor

    subprocess.Popen(["python", START_SERVER_PATH])
    # server'ın başlaması için 5 saniye bekler
    time.sleep(5)

def check_1_1():
    # mongodb versiyonu 7.0.1'se true, değilse false döner

    # os.system("cls")
    command = "mongod.exe --version"

    output = subprocess.check_output(command, shell=True, text=True)
    pattern = r'db version (\S+)'
    version = re.search(pattern, output).group(1)
    return version == 'v7.0.1'

def check_2_1():
    # config dosyasında "authorization" keyword'ü geçiyorsa true, geçmiyorsa false döner

    # os.system("cls")
    command = "type mongod.cfg | findstr authorization"
    return os.system(command) == 0

def check_2_2():
    # config dosyasında "enableLocalhostAuthBypass" keyword'ü geçiyorsa true, geçmiyorsa false döner

    # os.system("cls")
    command = "type mongod.cfg | findstr enableLocalhostAuthBypass"
    return os.system(command) == 0

def check_2_3():
    # mongo shell'i çalıştırır

    # shell içinde db.printShardingStatus() komutunu çalıştırır

    # "This db does not have sharding enabled" text'i geçiyorsa false döner. Geçmiyorsa:

    # Tek tek PEMKeyFile, CAFile, clusterFile, clusterAuthMode, authenticationMechanisms keyword'lerini
    # config dosyasında arar. Herhangi biri yoksa false döner. Hepsi varsa:

    # keyFile keyword'ünü config dosyasında arar. Varsa true, yoksa false döner



    # 1
    fail_1 = False
    # os.system("cls")
    os.chdir(MONGOSH_DIR)
    command = "mongosh.exe --eval db.printShardingStatus()"

    output = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        text=True
    )

    fail_1 = "This db does not have sharding enabled" in output.stderr

    # 2
    os.chdir(MONGO_DIR)
    # os.system("cls")

    commands = [
        "type mongod.cfg | findstr PEMKeyFile",
        "type mongod.cfg | findstr CAFile",
        "type mongod.cfg | findstr clusterFile",
        "type mongod.cfg | findstr clusterAuthMode",
        "type mongod.cfg | findstr authenticationMechanisms:"
        ]

    fail_2 = False
    for command in commands:
        # even if one of the commands return True, fail_2 will be set to True
        # print(command)
        fail_2 = fail_2 or os.system(command) != 0
    
    # 3
    # os.system("cls")
    command = "type mongod.cfg | findstr keyFile"

    fail_3 =  os.system(command) != 0

    return not(fail_1 or fail_2 or fail_3)


def contains_dictionary(input_str):
    # input stringinde herhangi bir dictionary varsa true, yoksa false döner

    # Define a regex pattern to match dictionary-like structures
    dictionary_pattern = r'{*}'

    # Use re.search to find a match in the input string
    match = re.search(dictionary_pattern, input_str)

    # If a match is found, return True; otherwise, return False
    return bool(match)

def get_dictionary(input_str):
    # input string'inde bulunan dictionary'yi döner

    start_i = input_str.find('{')
    ctr = 1
    dict_str = ""
    for i in range(start_i, len(input_str) - 1):
        if input_str[i] == '{':
            ctr += 1
        elif input_str[i] == '}':
            ctr -= 1
            if ctr == 0:
                break
        else:
            dict_str += input_str[i]

    return '{' + dict_str.strip() + '}'


def check_3_1():
    # mongo shell'i çalıştırır
    # "use admin" komutunu çalıştırır
    # db.system.users.find({ 'roles.role': { $in: ['dbOwner', 'userAdmin', 'userAdminAnyDatabase'] }, 'roles.db': 'admin' }) komutunu çalıştırır
    # çıktıda herhangi bir dictionary varsa true, yoksa false döner

    # os.system("cls")
    os.chdir(MONGOSH_DIR)
    command = """mongosh.exe --eval "use admin" --eval \"db.system.users.find({ 'roles.role': { $in: ['dbOwner', 'userAdmin', 'userAdminAnyDatabase'] }, 'roles.db': 'admin' })\""""
    output = subprocess.check_output(command, shell=True, text=True)
    return not contains_dictionary(output)

def check_3_2():
    # mongo shell'i çalıştırır
    # "show dbs" komutunu çalıştırıp bütün db'leri listeler
    # her bir db'yi sırasıyla dolaşarak db.getUsers() komutuyla o db'deki user'ları listeler
    # fonksiyon her db'yi ve içerdikleri user'ları döner

    # getting all databases
    # os.system("cls")
    os.chdir(MONGOSH_DIR)
    command = """mongosh.exe --eval "show dbs" """
    output = subprocess.check_output(command, shell=True, text=True)
    database_names = re.findall(r'(\w+)\s+\d+\.\d+\s+KiB', output)

    dbs = list(set(database_names))

    result_dict = {}
    #### for all databases, getting all users and roles
    for db in dbs:
        # os.system("cls")
        command = f"""mongosh.exe --eval "use {db}" --eval db.getUsers()"""
        s = subprocess.check_output(command, shell=True, text=True)

        list_str = ""
        brk = False
        opened_bracket_ctr = 0
        for i in range(len(s) - 5):
            if s[i: i + 5] == "users":
                for j in range(i, len(s)):
                    if s[j] == "[":
                        opened_bracket_ctr += 1
                    elif s[j] != "]":
                        list_str += s[j]
                    else:
                        opened_bracket_ctr -= 1
                        if opened_bracket_ctr == 0:
                            brk = True
                            break
            if brk:
                break

        list_str = list_str.replace("users:", "").strip()
        result_s = ""
        for row in list_str.split('\n'):
            if "user:" in row:
                result_s += row.split(':')[1].replace(',', '').strip()
            elif "roles" in row:
                result_s += row.replace('roles:', "").strip()

        result_dict[db] = result_s

    return result_dict

def check_3_3():
    # bütün mongo tasklarının bilgilerini döner

    command = """tasklist | findstr /i "mongos mongod" """

    output = subprocess.check_output(command, shell=True, text=True)
    return output

def check_3_4():
    # mongo shell'i çalıştırır
    # admin db'ye geçer
    # "db.runCommand( { rolesInfo: 1, showPrivileges: true, showBuiltinRoles: true } )" komutunu çalıştırır
    # # fonksiyon komutun çıktısını döner

    # os.system("cls")
    os.chdir(MONGOSH_DIR)
    command = """ mongosh.exe --eval "use admin" --eval "db.runCommand( { rolesInfo: 1, showPrivileges: true, showBuiltinRoles: true } )" """
    output = subprocess.check_output(command, shell=True, text=True)
    return output

def check_3_5():
    # mongo shell'i çalıştırır
    # bütün db'leri listeler
    # her bir db'yi dolaşarak "db.runCommand( { rolesInfo: "<gerekli rol>" } )"" komutunu çalıştırır
    # fonksiyon bütün komut çıktılarını birleştirip döner

    # getting all databases
    # os.system("cls")
    os.chdir(MONGOSH_DIR)
    command = """mongosh.exe --eval "show dbs" """
    output = subprocess.check_output(command, shell=True, text=True)
    database_names = re.findall(r'(\w+)\s+\d+\.\d+\s+KiB', output)

    dbs = list(set(database_names))
    results_dict = {}

    roles = ["dbOwner", "userAdmin", "userAdminAnyDatabase", "readWriteAnyDatabase", "dbAdminAnyDatabase", "userAdminAnyDatabase", "clusterAdmin", "hostManager"]
    for db in dbs:
        print('checking database:', db)
        d = {}
        for role in roles:
            print('checking role:', role)
            command = f"""mongosh.exe --eval "use {db}" --eval "db.runCommand( {{ rolesInfo: '{role}'}} )" """
            output = subprocess.check_output(command, shell=True, text=True)

            output_dict = get_dictionary(output)
            d[role] = output_dict

        results_dict[db] = d

    return results_dict

def check_4_1():
    # config dosyasında "tls" geçiyorsa true, geçmiyorsa false döner

    os.chdir(MONGO_DIR)
    # os.system("cls")
    command = "type mongod.cfg | findstr tls"
    return os.system(command) == 0

def read_config_into_list(cfg_path):
    # config dosyasını okur ve bir python list'ine çevirir

    config_contents = ''

    # Open the file in read mode
    with open(cfg_path, 'r') as file:
        # Read the entire file into the string
        config_contents = file.read().split('\n')
    return config_contents

def check_4_2():
    # config dosyasında "TLS1_0,TLS1_1" string'i geçiyorsa true, geçmiyorsa false döner

    config_contents = read_config_into_list(CONFIG_PATH)

    return "TLS1_0,TLS1_1" in [i.strip() for i in config_contents]

def check_4_3():
    # config dosyasında "mode: requireTLS" string'i geçiyorsa true, geçmiyorsa false döner

    config_contents = read_config_into_list(CONFIG_PATH)

    config_contents = [i.strip() for i in config_contents]
    config_contents = ''.join(config_contents)
    return "mode: requireTLS" in config_contents

def check_4_4():
    # config dosyasında "FIPSMode" string'i geçiyorsa true, geçmiyorsa false döner

    config_contents = read_config_into_list(CONFIG_PATH)

    config_contents = [i.strip() for i in config_contents]
    config_contents = ''.join(config_contents)
    return "FIPSMode" in config_contents

def check_4_5():
    # config dosyasında "enableEncryption" string'i geçiyorsa true, geçmiyorsa false döner

    os.chdir(MONGO_DIR)
    # os.system("cls")
    command = "type mongod.cfg | findstr enableEncryption"
    return os.system(command) == 0

def custom_index(query_string, query_list):
    # bir python list'inde (query_list) bir string (query_string) geçiyorsa (exact match olmak zorunda değil) index'i döner. geçmiyorsa -1 döner
    # ['abc123', 'qwe456'] list'inde 'qwe' stringini ararsak 1 döner  

    # returns first index of query_string in query_list. but It doesn't have to be exact match
    for i, j in enumerate(query_list):
        if query_string in j:
            return i
    return -1

def check_5_1():
    # " type mongod.conf | findstr –A4 "auditLog" | findstr "destination" " bu komut çalışmadığı için config dosyasını
    # python list'ine çevirip komutla aynı logic'i uyguluyoruz. fonksiyon true/false döner. 

    config_contents = read_config_into_list(CONFIG_PATH)
    start_i = custom_index('auditLog', config_contents)
    return custom_index('destination', config_contents[start_i: start_i + 4]) != -1

def check_5_2():
    # " type mongod.conf | findstr –A10 "auditLog" | findstr "filter" " bu komut çalışmadığı için config dosyasını
    # python list'ine çevirip komutla aynı logic'i uyguluyoruz. fonksiyon true/false döner. 

    config_contents = read_config_into_list(CONFIG_PATH)
    start_i = custom_index('systemLog', config_contents)
    if start_i == -1:
        return ""
    filter_i = custom_index('filter', config_contents[start_i: start_i + 10])
    if filter_i == -1:
        return ""
    return config_contents[filter_i + start_i].strip()

def check_5_3():
    # config dosyasında quiet keyword'ü varsa true, yoksa false döner

    os.chdir(MONGO_DIR)
    # os.system("cls")
    command = "type mongod.cfg | findstr quiet"
    return os.system(command) == 0

def check_5_4():
    # config dosyasında logAppend keyword'ü varsa true, yoksa false döner

    os.chdir(MONGO_DIR)
    # os.system("cls")
    command = "type mongod.cfg | findstr logAppend"
    return os.system(command) == 0

def check_6_1():
    # config dosyasında bulunan port 27017'yse false, değilse true döner

    config_contents = read_config_into_list(CONFIG_PATH)
    port_i = custom_index('port', config_contents)
    return config_contents[port_i].replace('port:', '').strip() != '27017'

def check_6_2():
    # mongo processinin ID'sini çeker
    # powershell komutunu çalıştırır: "Get-Process -Id <mongo_pid> | Format-Table -AutoSize"
    # fonksiyon komutun çıktısını döner

    # os.system("cls")
    command = """tasklist | findstr /i "mongos mongod" """

    output = subprocess.check_output(command, shell=True, text=True)
    mongo_pid = [i for i in output.split(' ') if i != ''][1]

    command = f"Get-Process -Id {mongo_pid} | Format-Table -AutoSize"
    output = subprocess.run(["powershell", "-Command", command], capture_output=True)
    return output.stdout

def check_6_3():
    # " type mongod.conf | findstr –A10 "security" | findstr "javascriptEnabled" " bu komut çalışmadığı için config dosyasını
    # python list'ine çevirip komutla aynı logic'i uyguluyoruz. fonksiyon true/false döner. 

    config_contents = read_config_into_list(CONFIG_PATH)
    security_i = custom_index('security', config_contents)
    return custom_index('javascriptEnabled', config_contents[security_i: security_i + 10]) != -1

def check_7_1():
    # keyFile, PEMKeyFile ve CAFile path'lerini config dosyasından okur.
    # her bir path için powershell komutunu çalıştırır: "ls -l <path>"
    # fonksiyon komut çıktılarını birleştirip döner

    config_contents = read_config_into_list(CONFIG_PATH)

    keyfile_i = custom_index('keyFile:', config_contents)
    pem_i = custom_index('PEMKeyFile:', config_contents)
    ca_i = custom_index('CAFile:', config_contents)

    keyfile_path = config_contents[keyfile_i].strip().replace('keyFile:', '').strip()
    pem_path = config_contents[pem_i].strip().replace('PEMKeyFile:', '').strip()
    ca_path = config_contents[ca_i].strip().replace('CAFile:', '').strip()

    command = "ls -l " + keyfile_path
    output_keyfile = subprocess.run(["powershell", "-Command", command], capture_output=True).stdout

    command = "ls -l " + pem_path
    output_pem = subprocess.run(["powershell", "-Command", command], capture_output=True).stdout

    command = "ls -l " + ca_path
    output_ca = subprocess.run(["powershell", "-Command", command], capture_output=True).stdout

    permissions = {}

    try:
        permissions['keyfile'] = [i.replace('\\n', '').replace('\\n', '').replace('\\r', '') for i in str(output_keyfile).split(' ') if i != ''][10]
        permissions['pem'] = [i.replace('\\n', '').replace('\\n', '').replace('\\r', '') for i in str(output_pem).split(' ') if i != ''][10]
        permissions['ca'] = [i.replace('\\n', '').replace('\\n', '').replace('\\r', '') for i in str(output_ca).split(' ') if i != ''][10]

        return permissions

    except:
        return False

def check_7_2():
    # config dosyasından dbPath değerini okur
    # "icacls <dbPath>" komutunu çalıştırır
    # fonksiyon komut çıktısını döner

    config_contents = read_config_into_list(CONFIG_PATH)

    dbpath = config_contents[custom_index('dbPath:', config_contents)].replace('dbPath:', '').strip()

    command = "icacls " + dbpath
    output = subprocess.check_output(command, shell=True, text=True)
    return output

if __name__ == '__main__':
    os.chdir(MONGO_DIR)

    initialize_mongodb_server()

    results_dict = {}

    results_dict['1.1'] = check_1_1()
    print(results_dict)
    results_dict['2.1'] = check_2_1()
    print(results_dict)
    results_dict['2.2'] = check_2_2()
    print(results_dict)
    results_dict['2.3'] = check_2_3()
    print(results_dict)

    results_dict['3.1'] = check_3_1()
    print(results_dict)
    results_dict['3.2'] = check_3_2()
    print(results_dict)
    results_dict['3.3'] = check_3_3()
    print(results_dict)
    results_dict['3.4'] = check_3_4()
    print(results_dict)
    results_dict['3.5'] = check_3_5()
    print(results_dict)

    results_dict['4.1'] = check_4_1()
    print(results_dict)
    results_dict['4.2'] = check_4_2()
    print(results_dict)
    results_dict['4.3'] = check_4_3()
    print(results_dict)
    results_dict['4.4'] = check_4_4()
    print(results_dict)
    results_dict['4.5'] = check_4_5()
    print(results_dict)

    results_dict['5.1'] = check_5_1()
    print(results_dict)
    results_dict['5.2'] = check_5_2()
    print(results_dict)
    results_dict['5.3'] = check_5_3()
    print(results_dict)

    results_dict['6.1'] = check_6_1()
    print(results_dict)
    results_dict['6.2'] = check_6_2()
    print(results_dict)
    results_dict['6.3'] = check_6_3()
    print(results_dict)

    results_dict['7.1'] = check_7_1()
    print(results_dict)
    results_dict['7.2'] = check_7_2()
    print(results_dict)

    # result dictionary'sinin her value'sunu string'e çevirip json olarak kaydediyoruz
    b = {}
    for k in results_dict:
        b[k] = str(results_dict[k])

    with open(SAVE_DIR, 'w') as f:
        json.dump(b, f)

