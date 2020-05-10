import requests, json, telnetlib, time, socket, argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def eveng_login(url_base, username, password):
    '''Function to log into EVE'''
    eve_session = requests.Session()
    login_details = eve_session.post(url_base + 'auth/login', json={ 'username': username, 'password': password, 'html5': '-1' }, verify=False)
    login_json_data = login_details.json()
    if login_json_data['code'] == 200:
        return login_details, eve_session
    else:
        print('Login Failed')
        exit(1)

def eveng_get_nodes(eve_session, url_base, eve_user, eve_lab_name):
    '''Get information of nodes running in lab'''
    node_url = url_base + 'labs/{0}/nodes'.format(eve_lab_name)
    node_details = eve_session.get(node_url, verify=False)
    return node_details

def create_data_for_connections(node_data):
    '''Take data from EVE and transform into data that will be used
    for connections'''
    node_data = node_data['data']
    telnet_data = {}
    for node in node_data:
        if node_data[node]['console'] == 'telnet':
            telnet_data[node_data[node]['name']] = {'telnet_url': node_data[node]['url']}
    return telnet_data

def config_over_socket(connection_data, root_pass, user_name, user_pass, silent):
    '''Connect over socket and send commands
       https://stackoverflow.com/questions/24183413/python-telnetlib-and-console-connection-cisco-node
    '''
    mgmt_ip_info = {}
    for connection in connection_data:
        junk, conn_url = connection_data[connection]['telnet_url'].split(r'telnet://')
        telnet_host, telnet_port = conn_url.split(r':')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if silent == False:
                print('Connecting to device...')
                s.connect((telnet_host, int(telnet_port)))
                print('Connected to {0}'.format(connection))
            else:
                s.connect((telnet_host, int(telnet_port)))
        except:
            print('Could not connect to {0} on port {1}'.format(telnet_host, telnet_port))
        data1 = s.recv(1024)
        #print(data1)
        s.sendall(b'\xff\xfe\x01\xff\xfd\x03\xff\xfc\x18\xff\xfc\x1f')
        data2 = s.recv(1024)
        #print(data2)
        s.sendall(b'\r')
        data3 = s.recv(2048)
        while not b'login:' in data3:
            data3 = s.recv(2048)
            if silent == False:
                print('Waiting for login prompt...')
        time.sleep(0.1)
        #print(data3)
        s.send(b'root\r')
        time.sleep(0.1)
        data5 = s.recv(2048)
        #print(data5)
        s.send(b'cli\r')
        time.sleep(0.5)
        data6 = s.recv(2048)
        if silent == False:
            print('Logged in')
        #print(data6)
        s.send(b'configure\r')
        time.sleep(0.5)
        s.recv(2048)
        if silent == False:
            print('Configuring device...')
        s.send(b'set system root-authentication plain-text-password\r')
        time.sleep(0.5)
        s.recv(2048)
        s.send(bytes(root_pass, 'ascii') + b'\r')
        time.sleep(0.5)
        s.recv(2048)
        s.send(bytes(root_pass, 'ascii') + b'\r')
        time.sleep(0.5)
        s.recv(2048)
        s.send(b'set interfaces fxp0 unit 0 family inet dhcp\r')
        time.sleep(0.5)
        s.recv(2048)
        s.send(b'set system login user ' + bytes(user_name, 'ascii') + b' class super-user authentication plain-text-password \r')
        time.sleep(0.5)
        user_password_prompt1 = s.recv(2048)
        #print(user_password_prompt1)
        s.send(bytes(user_pass, 'ascii') + b'\r')
        user_password_prompt2 = s.recv(2048)
        #print(user_password_prompt2)
        s.send(bytes(user_pass, 'ascii') + b'\r')
        time.sleep(0.5)
        s.send(b'set system services netconf ssh\r')
        time.sleep(0.5)
        s.recv(2048)
        s.send(b'commit\r')
        if silent == False:
            print('Waiting for configuration to be comitted...')
        time.sleep(5)
        s.recv(2048)
        s.send(b'quit\r')
        if silent == False:
            print('Waiting 30 seconds for fxp0 to get dhcp lease')
            for i in range(30, 0, -1):
                print('{0} seconds remaining...'.format(i))
                time.sleep(1)
        else:
            time.sleep(30)
        s.recv(2048)
        s.send(b'show interfaces fxp0.0 | display json | no-more\r')
        time.sleep(2)
        mgmt_info_raw = s.recv(8192)
        s.close()
        if silent == False:
            print('Closing connection to {0}'.format(connection))
        sliced_mgmt_info = mgmt_info_raw[50:-10]
        json_sliced_mgmt_info = json.loads(sliced_mgmt_info)
        mgmt_ip = json_sliced_mgmt_info['interface-information'][0]['logical-interface'][0]['address-family'][0]['interface-address'][0]['ifa-local'][0]['data']
        mgmt_ip_info[connection] = mgmt_ip
    return mgmt_ip_info

def generate_ini_inventory(mgmt_ip_info, eve_lab_name, user_name, user_pass):
    '''Generate INI Inventory file to be used by Ansible'''
    lab_name = eve_lab_name[:-4]
    with open('inventory', 'w') as inv_file:
        inv_file.write('[{0}-devices]\n'.format(lab_name.lower()))
        for device in mgmt_ip_info:
            inv_file.write('{0} ansible_host={1} ansible_user={2} ansible_password={3} ansible_network_os=junos ansible_connection=netconf\n'.format(device.lower(), mgmt_ip_info[device], user_name, user_pass))
    return 'inventory'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("eve_ip", help="The IP Address or hostname of the EVE-NG API")
    parser.add_argument("eve_lab", help="The lab .unl name within EVE you want to bootstrap, include .unl in value")
    parser.add_argument("-u", "--user", help="The API username to authenticate against EVE-NG API")
    parser.add_argument("-p", "--password", help="The API password to authenticate against EVE-NG API")
    parser.add_argument("-r", "--root-password", help="The password to use for the root account on the Juniper devices")
    parser.add_argument("-U", "--local-user", help="The local user account name on the Juniper devices")
    parser.add_argument("-P", "--local-pass", help="The local user password on the Juniper devices")
    parser.add_argument("-s", "--silent", help="This disables output to console, good for when launched with automation")
    arg = parser.parse_args()
    try:
        url_base = 'https://{}/api/'.format(arg.eve_ip)
    except:
        print('You must enter an IP address or hostname for this tool to connect to')
    if arg.user:
        eve_user=arg.user
    else:
        eve_user='admin'
    if arg.password:
        eve_password=arg.password
    else:
        eve_password='eve'
    if arg.eve_lab:
        eve_lab_name=arg.eve_lab
    else:
        print('You need a lab!')
        exit(1)
    if arg.root_password:
        root_pass = arg.root_password
    else:
        root_pass = 'Password1'
    if arg.local_user:
        user_name = arg.local_user
    else:
        user_name = 'ansible'
    if arg.local_pass:
        user_pass = arg.local_pass
    else:
        user_pass = 'Password1'
    if arg.silent:
        silent = True
    else:
        silent = False
    login_data, eve_session = eveng_login(url_base, eve_user, eve_password)
    node_data = eveng_get_nodes(eve_session, url_base, eve_user, eve_lab_name)
    node_data_json = node_data.json()
    node_json_formatted = json.dumps(node_data_json['data'], indent=2)
    connection_data = create_data_for_connections(node_data_json)
    mgmt_info = config_over_socket(connection_data, root_pass, user_name, user_pass, silent)
    file_name = generate_ini_inventory(mgmt_info, eve_lab_name, user_name, user_pass)
    if silent == False:
        print(mgmt_info)
        print('The hosts have been put into an ini file type inventory called {0}'.format(file_name))
