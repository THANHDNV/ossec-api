#!/usr/bin/env python

from utils import execute, cut_array, sort_array, search_array, chmod_r, chown_r, OssecVersion, plain_dict_to_nested_dict, get_fields_to_nest
from exception import OssecAPIException
from ossec_queue import OssecQueue
from ossec_socket import OssecSocket
from database import Connection
from InputValidator import InputValidator
import manager
import common
from glob import glob
from datetime import date, datetime, timedelta
from base64 import b64encode
from shutil import copyfile, move, copytree
from platform import platform
from os import remove, chown, chmod, path, makedirs, rename, urandom, listdir, stat
from time import time, sleep, timezone
import socket
import hashlib
from operator import setitem
import re
import fcntl
from json import loads

timeoffset = -timezone

try:
    from urllib2 import urlopen, URLError, HTTPError
except ImportError:
    from urllib.request import urlopen, URLError, HTTPError

def create_exception_dic(id, e):
    """
    Creates a dictionary with a list of agent ids and it's error codes.
    """
    exception_dic = {}
    exception_dic['id'] = id
    exception_dic['error'] = {'message': e.message}

    if isinstance(e, OssecAPIException):
        exception_dic['error']['code'] = e.code
    else:
        exception_dic['error']['code'] = 1000


    return exception_dic


def get_timeframe_in_seconds(timeframe):
    """
    Gets number of seconds from a timeframe.
    :param timeframe: Time in seconds | "[n_days]d" | "[n_hours]h" | "[n_minutes]m" | "[n_seconds]s".
    :return: Time in seconds.
    """
    if not timeframe.isdigit():
        regex = re.compile(r'(\d*)(\w)$')
        g = regex.findall(timeframe)
        number = int(g[0][0])
        unit = g[0][1]
        time_equivalence_seconds = {'d': 86400, 'h': 3600, 'm': 60, 's':1}
        seconds = number * time_equivalence_seconds[unit]
    else:
        seconds = int(timeframe)

    return seconds


class Agent(object):
    """
    OSSEC Agent object.
    """

    fields = {'id': 'id', 'name': 'name', 'ip': 'ip', 'status': 'status', 'dateAdd': 'dateAdd',
              'version': 'version', 'configSum': 'config_sum', # 'mergedSum': 'merged_sum',
              'os': 'os', 'os.arch': 'os_arch', 'lastKeepAlive': 'lastAlive', 'key':'key'}


    def __init__(self, id=None, name=None, ip=None, key=None, force=-1):
        """
        Initialize an agent.
        'id': When the agent exists
        'name' and 'ip': Add an agent (generate id and key automatically)
        'name', 'ip' and 'force': Add an agent (generate id and key automatically), removing old agent with same IP if disconnected since <force> seconds.
        'name', 'ip', 'id', 'key': Insert an agent with an existent id and key
        'name', 'ip', 'id', 'key', 'force': Insert an agent with an existent id and key, removing old agent with same IP if disconnected since <force> seconds.
        """
        self.id            = id
        self.name          = name
        self.ip            = ip
        self.internal_key  = key
        self.dateAdd       = None
        self.os            = {}
        self.version       = None
        self.lastKeepAlive = None
        self.status        = None
        self.key           = None
        self.configSum     = None
        # self.mergedSum     = None

        # if the method has only been called with an ID parameter, no new agent should be added.
        # Otherwise, a new agent must be added
        if name != None and ip != None:
            self._add(name=name, ip=ip, id=id, key=key, force=force)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'id': self.id, 'name': self.name, 'ip': self.ip, 'internal_key': self.internal_key, 'os': self.os, 'version': self.version, 'dateAdd': self.dateAdd, 'lastKeepAlive': self.lastKeepAlive, 'status': self.status, 'key': self.key,
        # 'configSum': self.configSum,
        }

        return dictionary
    
    def __getattribute__(self, name):
        return object.__getattribute__(self,name)

    @staticmethod
    def calculate_status(last_keep_alive, pending, today=datetime.today()):
        """
        Calculates state based on last keep alive
        """

        if last_keep_alive == "None":
            return "Never connected"
        else:
            # divide date in format YY:mm:dd HH:MM:SS to create a datetime object.
            last_date = datetime(year=int(last_keep_alive[:4]), month=int(last_keep_alive[5:7]), day=int(last_keep_alive[8:10]),
                                hour=int(last_keep_alive[11:13]), minute=int(last_keep_alive[14:16]), second=int(last_keep_alive[17:19]))
            difference = (today - last_date).total_seconds()

            return "Disconnected" if difference > common.limit_seconds else ("Pending" if pending else "Active")


    def _load_info_from_DB(self, select=None):
        """
        Gets attributes of existing agent.
        """

        db_url = common.database_path
        collection = common.global_db

        conn = Connection(db_url, collection)

        if conn.getDb() == None:
            raise OssecAPIException(1600)

        pending = True

        valid_select_fields = set(self.fields.values())
        select_fields = {}
        # Select
        if select:
            select['fields'] = list(map(lambda x: self.fields[x] if x in self.fields else x, select['fields']))
            select_fields_set = set(select['fields'])
            if not select_fields_set.issubset(valid_select_fields):
                incorrect_fields = list(map(lambda x: str(x), select_fields_set - valid_select_fields))
                raise OssecAPIException(1724, "Allowed select fields: {0}. Fields {1}".\
                        format(self.fields.keys(), incorrect_fields))

            # to compute the status field, lastKeepAlive and version are necessary
            select_fields_set = {'id'} | select_fields_set if 'status' not in select_fields_set \
                                                       else select_fields_set | {'id', 'lastAlive', 'version'}
            for x in select_fields_set:
                select_fields[x] = 1
        else:
            for x in valid_select_fields:
                select_fields[x] = 1

        db_select_fields = select_fields.copy()
        db_select_fields.pop('status', None)
        db_data = conn.getDb()['agent'].find_one({'id': str(int(self.id)).zfill(3)}, db_select_fields)

        if db_data is None:
            raise OssecAPIException(1701)

        no_result = True

        if db_data != None:
            no_result = False
            db_data.pop('_id')
            self.id =  str(db_data.get("id","")).zfill(3)
            self.name = str(db_data.get("name",""))
            self.ip = str(db_data.get("ip",""))
            self.internal_key = str(db_data.get("key",""))
            self.dateAdd = (db_data.get("dateAdd") + timedelta(seconds=timeoffset)).__str__() if db_data.get("dateAdd") != None else "None"
            self.version = str(db_data.get("version",""))
            pending = False if self.version != "" else True
            self.os['name'] = str(db_data.get("os",""))
            self.os['os_arch'] = str(db_data.get("os_arch",""))
            self.lastKeepAlive = (db_data.get("lastAlive") + timedelta(seconds=timeoffset)).__str__() if db_data.get("lastAlive") != None else "None"
            self.configSum = str(db_data.get("config_sum","")) if str(db_data.get("config_sum","")) != "" else None

        if self.id != "000":
            self.status = Agent.calculate_status(self.lastKeepAlive, pending)
        else:
            self.status = 'Active'
            self.ip = '127.0.0.1' if 'ip' in select_fields else None

        if no_result:
            raise OssecAPIException(1701, self.id)


    # def _load_info_from_agent_db(self, table, select, filters={}, count=False, offset=0, limit=common.database_limit, sort={}, search={}):
    #     """
    #     Make a request to agent's database using Wazuh DB
    #     :param table: DB table to retrieve data from
    #     :param select: DB fields to retrieve
    #     :param filters: filter conditions
    #     :param sort: Dictionary of form {'fields':[], 'order':'asc'}/{'fields':[], 'order':'desc'}
    #     :param search: Dictionary of form {'value': '', 'negation':false, 'fields': []}
    #     """
    #     wdb_conn = OssecDBConnection()

    #     query = "agent {} sql select {} from {}".format(self.id, ','.join(select), table)

    #     if filters:
    #         for key, value in filters.items():
    #             query += " and {} = '{}'".format(key, value)

    #     if search:
    #         query += " and not" if bool(search['negation']) else " and"
    #         query += '(' + " or ".join("{} like '%{}%'".format(x, search['value']) for x in search['fields']) + ')'

    #     if "from {} and".format(table) in query:
    #         query = query.replace("from {} and".format(table), "from {} where".format(table))

    #     if limit:
    #         if limit > common.maximum_database_limit:
    #             raise OssecAPIException(1405, str(limit))
    #         query += ' limit {} offset {}'.format(limit, offset)
    #     elif limit == 0:
    #         raise OssecAPIException(1406)

    #     if sort and sort['fields']:
    #         str_order = "desc" if sort['order'] == 'asc' else "asc"
    #         order_str_fields = []
    #         for field in sort['fields']:
    #             order_str_field = '{0} {1}'.format(field, str_order)
    #             order_str_fields.append(order_str_field)
    #         query += ' order by ' + ','.join(order_str_fields)

    #     return wdb_conn.execute(query, count)


    def get_basic_information(self, select=None):
        """
        Gets public attributes of existing agent.
        """
        self._load_info_from_DB(select)

        select_fields = {'id', 'last_keepalive', 'status', 'version'} if select is None else select['fields']

        info = {}

        if self.id and 'id' in select_fields:
            info['id'] = self.id
        if self.name:
            info['name'] = self.name
        if self.ip:
            info['ip'] = self.ip
        #if self.internal_key:
        #    info['internal_key'] = self.internal_key
        if self.os:
            os_no_empty = dict((k, v) for k, v in self.os.items() if v)
            if os_no_empty:
                info['os'] = os_no_empty
        if self.version and 'version' in select_fields:
            info['version'] = self.version
        if self.lastKeepAlive and 'last_keepalive' in select_fields:
            info['lastKeepAlive'] = self.lastKeepAlive
        if self.status and 'status' in select_fields:
            info['status'] = self.status
        if self.configSum:
            info['configSum'] = self.configSum
        # if self.mergedSum:
        #     info['mergedSum'] = self.mergedSum
        #if self.key:
        #    info['key'] = self.key

        return info

    def compute_key(self):
        str_key = "{0} {1} {2} {3}".format(self.id, self.name, self.ip, self.internal_key)
        return b64encode(str_key.encode()).decode()


    def get_key(self):
        """
        Gets agent key.
        :return: Agent key.
        """

        self._load_info_from_DB()
        if self.id != "000":
            self.key = self.compute_key()
        else:
            self.key = ""

        return self.key

    def restart(self):
        """
        Restarts the agent.
        :return: Message generated by OSSEC.
        """

        if self.id == "000":
            raise OssecAPIException(1703)
        else:
            # Check if agent exists and it is active
            agent_info = self.get_basic_information()

            if self.status.lower() != 'active':
                raise OssecAPIException(1707, '{0} - {1}'.format(self.id, self.status))

            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS, self.id)
            oq.close()

        return ret_msg

    def use_only_authd(self):
        """
        Function to know the value of the option "use_only_authd" in API configuration
        """
        try:
            with open(common.api_config_path) as f:
                data = f.readlines()

            use_only_authd = list(filter(lambda x: x.strip().startswith('config.use_only_authd'), data))

            return loads(use_only_authd[0][:-2].strip().split(' = ')[1]) if use_only_authd != [] else False
        except IOError:
            return False

    def remove(self, backup=False, purge=False):
        """
        Deletes the agent.
        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Message.
        """

        manager_status = manager.status()
        is_authd_running = 'ossec-authd' in manager_status and manager_status['ossec-authd'] == 'running'

        if self.use_only_authd():
            if not is_authd_running:
                raise OssecAPIException(1726)

        if not is_authd_running:
            data = self._remove_manual(backup, purge)
        else:
            data = self._remove_authd(purge)

        return data

    def _remove_authd(self, purge=False):
        """
        Deletes the agent.
        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Message.
        """

        msg = { "function": "remove", "arguments": { "id": str(self.id).zfill(3), "purge": purge } }

        authd_socket = OssecSocket(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        return data

    def _remove_manual(self, backup=False, purge=False):
        """
        Deletes the agent.
        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Message.
        """

        # Get info from DB
        self._load_info_from_DB()

        f_keys_temp = '{0}.tmp'.format(common.client_keys)
        open(f_keys_temp, 'a').close()

        f_keys_st = stat(common.client_keys)
        chown(f_keys_temp, common.ossec_uid, common.ossec_gid)
        chmod(f_keys_temp, f_keys_st.st_mode)

        f_tmp = open(f_keys_temp, 'w')
        agent_found = False
        with open(common.client_keys) as f_k:
            for line in f_k.readlines():
                line_data = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key

                if self.id == line_data[0] and line_data[1][0] not in ('#!'):
                    if not purge:
                        # f_tmp.write('{0} !{1} {2} {3}\n'.format(line_data[0], line_data[1], line_data[2], line_data[3]))
                        f_tmp.write(line[:4] + "#*#*#*#*#*#*#*#*#*#*#" + line[25:])
                    agent_found = True
                else:
                    f_tmp.write(line)
        f_tmp.close()

        if not agent_found:
            remove(f_keys_temp)
            raise OssecAPIException(1701, self.id)

        # Overwrite client.keys
        move(f_keys_temp, common.client_keys)

        # Remove rid file
        rids_file = '{0}/queue/rids/{1}'.format(common.ossec_path, self.id)
        if path.exists(rids_file):
            remove(rids_file)

        if not backup:
            # Remove agent files
            agent_files = []
            agent_files.append('{0}/queue/agent-info/{1}-{2}'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/({1}) {2}->syscheck'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/.({1}) {2}->syscheck.cpt'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/({1}) {2}->syscheck-registry'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/.({1}) {2}->syscheck-registry.cpt'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/rootcheck/({1}) {2}->rootcheck'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/agent-groups/{1}'.format(common.ossec_path, self.id))

            for agent_file in agent_files:
                if path.exists(agent_file):
                    remove(agent_file)
        else:
            # Create backup directory
            # /var/ossec/backup/agents/yyyy/Mon/dd/id-name-ip[tag]
            date_part = date.today().strftime('%Y/%b/%d')
            main_agent_backup_dir = '{0}/agents/{1}/{2}-{3}-{4}'.format(common.backup_path, date_part, self.id, self.name, self.ip)
            agent_backup_dir = main_agent_backup_dir

            not_agent_dir = True
            i = 0
            while not_agent_dir:
                if path.exists(agent_backup_dir):
                    i += 1
                    agent_backup_dir = '{0}-{1}'.format(main_agent_backup_dir, str(i).zfill(3))
                else:
                    makedirs(agent_backup_dir)
                    chmod_r(agent_backup_dir, 0o750)
                    not_agent_dir = False

            # Move agent file
            agent_files = []
            agent_files.append(['{0}/queue/agent-info/{1}-{2}'.format(common.ossec_path, self.name, self.ip), '{0}/agent-info'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/({1}) {2}->syscheck'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/.({1}) {2}->syscheck.cpt'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck.cpt'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/({1}) {2}->syscheck-registry'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck-registry'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/.({1}) {2}->syscheck-registry.cpt'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck-registry.cpt'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/rootcheck/({1}) {2}->rootcheck'.format(common.ossec_path, self.name, self.ip), '{0}/rootcheck'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/agent-groups/{1}'.format(common.ossec_path, self.id), '{0}/agent-group'.format(agent_backup_dir)])

            for agent_file in agent_files:
                if path.exists(agent_file[0]) and not path.exists(agent_file[1]):
                    rename(agent_file[0], agent_file[1])

        return 'Agent deleted successfully.'

    def _add(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.
        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """
        manager_status = manager.status()
        is_authd_running = 'ossec-authd' in manager_status and manager_status['ossec-authd'] == 'running'

        if self.use_only_authd():
            if not is_authd_running:
                raise OssecAPIException(1726)

        if not is_authd_running:
            data = self._add_manual(name, ip, id, key, force)
        else:
            data = self._add_authd(name, ip, id, key, force)

        return data

    def _add_authd(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC using authd.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.
        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """

        # Check arguments
        if id:
            id = id.zfill(3)

        ip = ip.lower()

        if key and len(key) < 64:
            raise OssecAPIException(1709)

        force = force if type(force) == int else int(force)

        msg = ""
        if name and ip:
            if id and key:
                msg = { "function": "add", "arguments": { "name": name, "ip": ip, "force": force } }
            else:
                msg = { "function": "add", "arguments": { "name": name, "ip": ip, "id": id, "key": key, "force": force } }

        authd_socket = OssecSocket(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        self.id  = data['id']
        self.internal_key = data['key']
        self.key = self.compute_key()


    def _add_manual(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC manually.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.
        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """

        # Check arguments
        if id:
            id = id.zfill(3)

        ip = ip.lower()

        if key and len(key) < 64:
            raise OssecAPIException(1709)

        force = force if type(force) == int else int(force)

        # Check manager name
        # not needed yet since haven't add manager to database
        db_url = common.database_path
        collection = common.global_db

        conn = Connection(db_url, collection)

        if conn.getDb() == None:
            raise OssecAPIException(1600)

        manager = conn.getDb()['agent'].find_one({"id": "000"})
        manager_name = str(manager['name'])

        if name == manager_name:
            raise OssecAPIException(1705, name)

        # Check if ip, name or id exist in client.keys
        last_id = 0
        lock_file = open("{}/var/run/.api_lock".format(common.ossec_path), 'a+')
        fcntl.lockf(lock_file, fcntl.LOCK_EX)
        with open(common.client_keys) as f_k:
            try:
                for line in f_k.readlines():
                    if not line.strip():  # ignore empty lines
                        continue

                    if line[0] in ('# '):  # starts with # or ' '
                        continue

                    line_data = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key

                    line_id = int(line_data[0])
                    if last_id < line_id:
                        last_id = line_id

                    if line_data[1][0] in ('#!'):  # name starts with # or !
                        continue

                    check_remove = 0
                    if id and id == line_data[0]:
                        raise OssecAPIException(1708, id)
                    if name == line_data[1]:
                        if force < 0:
                            raise OssecAPIException(1705, name)
                        else:
                            check_remove = 1
                    if ip != 'any' and ip == line_data[2]:
                        if force < 0:
                            raise OssecAPIException(1706, ip)
                        else:
                            check_remove = 2

                    if check_remove:
                        if force == 0 or Agent.check_if_delete_agent(line_data[0], force):
                            Agent.remove_agent(line_data[0], backup=True)
                        else:
                            if check_remove == 1:
                                raise OssecAPIException(1705, name)
                            else:
                                raise OssecAPIException(1706, ip)


                if not id:
                    agent_id = str(last_id + 1).zfill(3)
                else:
                    agent_id = id

                if not key:
                    # Generate key
                    epoch_time = int(time())
                    str1 = "{0}{1}{2}".format(epoch_time, name, platform())
                    str2 = "{0}{1}".format(ip, agent_id)
                    hash1 = hashlib.md5(str1.encode())
                    hash1.update(urandom(64))
                    hash2 = hashlib.md5(str2.encode())
                    hash1.update(urandom(64))
                    agent_key = hash1.hexdigest() + hash2.hexdigest()
                else:
                    agent_key = key

                # Tmp file
                f_keys_temp = '{0}.tmp'.format(common.client_keys)
                open(f_keys_temp, 'a').close()
                f_keys_st = stat(common.client_keys)
                chown(f_keys_temp, common.ossec_uid, common.ossec_gid)
                chmod(f_keys_temp, f_keys_st.st_mode)

                copyfile(common.client_keys, f_keys_temp)


                # Write key
                with open(f_keys_temp, 'a') as f_kt:
                    f_kt.write('{0} {1} {2} {3}\n'.format(agent_id, name, ip, agent_key))

                # Overwrite client.keys
                move(f_keys_temp, common.client_keys)
            except OssecAPIException as ex:
                fcntl.lockf(lock_file, fcntl.LOCK_UN)
                lock_file.close()
                raise ex
            except Exception as ex:
                fcntl.lockf(lock_file, fcntl.LOCK_UN)
                lock_file.close()
                raise OssecAPIException(1725, str(ex))


            fcntl.lockf(lock_file, fcntl.LOCK_UN)
            lock_file.close()

        self.id = agent_id
        self.internal_key = agent_key
        self.key = self.compute_key()

    @staticmethod
    def filter_agents_by_status(status, request):
        result = datetime.now() - timedelta(seconds=common.limit_seconds) - timedelta(seconds=timeoffset)
        status_filter = {"$or":[]}
        list_status = status.split(',')

        for status in list_status:
            status = status.lower()
            status_con = {}
            if status == 'active':
                status_con["lastAlive"] = {"$gte": result}
                status_con["version"] = { "$exists": True }
                status_con = {
                    "$or": [
                        {
                            "lastAlive": {
                                "$gte": result
                            },
                            "version": {
                                "$exist": True
                            }
                        },
                        {
                            "id": "000"
                        }
                    ]
                }
            elif status == 'disconnected':
                status_con["lastAlive"] = {
                    "$and": [
                        {
                            "$exist": True,
                            "$lt": result,
                        }
                    ]
                }
            elif status == "never connected" or status == "neverconnected":
                status_con["lastAlive"] = None
            elif status == 'pending':
                status_con["lastAlive"] = {
                    "$exists": True,
                    "$ne": None
                }
                status_con["version"] = None
            else:
                raise OssecAPIException(1729, status)
            status_filter["$or"].append(status_con)
        if status_filter["$or"]:
            request["$and"].append(status_filter)


    @staticmethod
    def filter_agents_by_timeframe(older_than, request):
        time_con = {"$or": []}
        older_second = get_timeframe_in_seconds(older_than)
        time_old = datetime.now() - timedelta(seconds=older_second)
        # If the status is not neverconnected, compare older_than with the last keepalive:
        # query += "(last_keepalive IS NOT NULL AND CAST(strftime('%s', last_keepalive) AS INTEGER) < CAST(strftime('%s', 'now', 'localtime') AS INTEGER) - :older_than) "
        first_con = {
            "lastAlive": {
                "$ne": None,
                "$lte": time_old
            }
        }
        time_con["$or"].append(first_con)
        # If the status is neverconnected, compare older_than with the date add:
        # query += "(last_keepalive IS NULL AND id != 0 AND CAST(strftime('%s', date_Add) AS INTEGER) < CAST(strftime('%s', 'now', 'localtime') AS INTEGER) - :older_than) "
        second_con = {
            "lastAlive": None,
            "dateAdd": {"$lte": time_old}
        }
        time_con["$or"].append(second_con)
        if time_con["$or"]:
            request["$and"].append(time_con)

    @staticmethod
    def filter_query(filters, request):
        """
        Add filters to a database query
        :param filters: Dictionary which key is the name of the field and the value is the value to filter.
        :param request: Request dictionary for sqlite3
        :param query: Database query
        :return: Updated database query
        """
        for filter_name, db_filter in filters.items():
            if db_filter == "all":
                continue

            if filter_name == "status":
                # doesn't do += because query is a parameter of the function
                Agent.filter_agents_by_status(db_filter, request)
            elif filter_name == "older_than":
                # doesn't do += because query is a parameter of the function
                Agent.filter_agents_by_timeframe(db_filter, request)
            else:
                filter_con = {}
                filter_con[filter_name] = {}
                if isinstance(db_filter, list):
                    filter_con[filter_name] = {
                    }
                    filter_con[filter_name]["$in"] = [re.compile(name.lower(), re.IGNORECASE) if filter_name != "version"
                                                else re.compile(re.sub( r'([a-zA-Z])([v])', r'\1 \2', name), re.IGNORECASE)
                                  for name in db_filter]
                else: # str
                    filter_con[filter_name] = re.compile(name.lower(), re.IGNORECASE) if filter_name != "version" \
                                                else re.compile(re.sub( r'([a-zA-Z])([v])', r'\1 \2', name), re.IGNORECASE)
                if filter_con:
                    request["$and"].append(filter_con)


    @staticmethod
    def get_agents_overview(offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters={}):
        """
        Gets a list of available agents with basic attributes.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
        :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        db_url = common.database_path
        collection = common.global_db

        conn = Connection(db_url, collection)

        if conn.getDb() == None:
            raise OssecAPIException(1600)

        valid_select_fields = set(Agent.fields.values()) | {'status'}
        # at least, we should retrieve those fields since other fields depending on those
        search_fields = {"id", "name", "ip", "os", "dateAdd", "version"}
        request = {"$and": []}
        select_fields = {}
        # Select
        if select:
            select['fields'] = list(map(lambda x: Agent.fields[x] if x in Agent.fields else x, select['fields']))
            select_fields_set = set(select['fields'])
            if not select_fields_set.issubset(valid_select_fields):
                incorrect_fields = list(map(lambda x: str(x), select_fields_set - valid_select_fields))
                raise OssecAPIException(1724, "Allowed select fields: {0}. Fields {1}".\
                        format(Agent.fields.keys(), incorrect_fields))

            # to compute the status field, lastKeepAlive and version are necessary
            select_fields_set = {'id'} | select_fields_set if 'status' not in select_fields_set \
                                                       else select_fields_set | {'id', 'lastAlive', 'version'}
            for x in select_fields_set:
                select_fields[x] = 1
        else:
            for x in valid_select_fields:
                select_fields[x] = 1

        # save the fields that the user has selected
        user_select_fields = select_fields.copy()
        select_fields.pop('status', None)

        # add special filters to the database query
        Agent.filter_query(filters, request)

        # Search
        if search:
            search['value'] = re.sub( r'([OSSEC HIDS])([v])', r'\1 \2', search['value'] )
            search_con = {
                "$or": []
            }
            regex = re.compile("{0}".format(int(search['value']) if search['value'].isdigit() \
                                                                    else search['value']))
            for x in search_fields:
                search_con["$or"].append({
                    x: regex
                })
            if bool(search['negation']):
                if search_con["$or"]:
                    request["$and"].append({
                        "$not": search_con
                    })
            else:
                if search_con["$or"]:
                    request["$and"].append(search_con)

        if not request["$and"]:
            request = {}
        
        db_data = conn.getDb()['agent'].find(request, select_fields)
        # Count
        data = {'totalItems': db_data.count()}

        # Sorting
        sort_con = []
        if sort:
            if sort['fields']:
                allowed_sort_fields = set(Agent.fields.keys())
                # Check if every element in sort['fields'] is in allowed_sort_fields.
                if not set(sort['fields']).issubset(allowed_sort_fields):
                    raise OssecAPIException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

                for i in sort['fields']:
                    # Order by status ASC is the same that order by last_keepalive DESC.
                    if i == 'status':
                        str_order = -1 if sort['order'] == 'asc' else 1
                        sort_con.append((Agent.fields['lastKeepAlive'], str_order))
                    else:
                        str_order = 1 if sort['order'] == 'asc' else -1
                        sort_con.append((Agent.fields[i], str_order))
            else:
                sort_con.append((Agent.fields["id"], 1 if sort['order'] == 'asc' else -1))
        else:
            sort_con.append((Agent.fields["id"], 1))


        if limit:
            if limit > common.maximum_database_limit:
                raise OssecAPIException(1405, str(limit))
        elif limit == 0:
            raise OssecAPIException(1406)
        else:
            limit = common.maximum_database_limit

        db_data = db_data.sort(sort_con).skip(offset).limit(limit)

        data['items'] = []

        for agent in db_data:
            agent.pop('_id')
            if 'dateAdd' in user_select_fields:
                if agent.get("dateAdd") != None:
                    agent['dateAdd'] = (agent.get("dateAdd") + timedelta(seconds=timeoffset)).__str__()
                else:
                    agent['dateAdd'] = agent.get("dateAdd").__str__()
            if 'lastAlive' in user_select_fields:
                if agent.get("lastAlive") != None:
                    agent['lastAlive'] = (agent.get("lastAlive") + timedelta(seconds=timeoffset)).__str__()
                else:
                    agent['lastAlive'] = agent.get("lastAlive").__str__()
            if 'status' in user_select_fields:
                agent['status'] = Agent.calculate_status(agent.get("lastAlive"), False if agent.get("version", "") != "" else True)  if agent.get("id") != "000" else "Alive"
            data['items'].append(agent)
        
        return data


    @staticmethod
    def get_agents_summary():
        """
        Counts the number of agents by status.
        :return: Dictionary with keys: total, Active, Disconnected, Never connected
        """

        db_url = common.database_path
        collection = common.global_db

        conn = Connection(db_url, collection)

        if conn.getDb() == None:
            raise OssecAPIException(1600)

        result = datetime.now() -timedelta(seconds=timeoffset) - timedelta(seconds=common.limit_seconds)
        # request['time_active'] = result.strftime('%Y-%m-%d %H:%M:%S')

        total = conn.getDb()['agent'].find().count()
        active = conn.getDb()['agent'].find({
            "$or": [
                {
                    "lastAlive": {
                        "$exists": True,
                        "$gte": result
                    },
                    "version": {
                        "$exists": True,
                        "$ne": None
                    }
                },
                {
                    "id": "000"
                }
            ]
        }).count()

        disconnected = conn.getDb()['agent'].find({
            "lastAlive": {
                "$exists": True,
                "$lt": result
            },
            "id": {
                "$exists": True,
                "$ne": "000"
            },
            "version": {
                "$exists": True,
                "$ne": None
            }
        }).count()

        never = conn.getDb()['agent'].find({
            "lastAlive": {
                "$exists": False
            },
            "id": {
                "$exists": True,
                "$ne": "000"
            }
        }).count()

        pending = conn.getDb()['agent'].find({
            "lastAlive": {
                "$exists": True,
                "$ne": None
            },
            "version": None
        }).count()

        return {'Total': total, 'Active': active, 'Disconnected': disconnected, 'Never connected': never, "Pending": pending}

    @staticmethod
    def restart_agents(agent_id=None, restart_all=False):
        """
        Restarts an agent or all agents.
        :param agent_id: Agent ID of the agent to restart. Can be a list of ID's.
        :param restart_all: Restarts all agents.
        :return: Message.
        """

        if restart_all:
            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS)
            oq.close()
            return ret_msg
        else:
            if not agent_id:
                raise OssecAPIException(1732)
            failed_ids = list()
            affected_agents = list()
            if isinstance(agent_id, list):
                for id in agent_id:
                    try:
                        Agent(id).restart()
                        affected_agents.append(id)
                    except Exception as e:
                        failed_ids.append(create_exception_dic(id, e))
            else:
                try:
                    Agent(agent_id).restart()
                    affected_agents.append(agent_id)
                except Exception as e:
                    failed_ids.append(create_exception_dic(agent_id, e))
            if not failed_ids:
                message = 'All selected agents were restarted'
            else:
                message = 'Some agents were not restarted'

            final_dict = {}
            if failed_ids:
                final_dict = {'msg': message, 'affected_agents': affected_agents, 'failed_ids': failed_ids}
            else:
                final_dict = {'msg': message, 'affected_agents': affected_agents}

            return final_dict

    @staticmethod
    def get_agent_by_name(agent_name, select=None):
        """
        Gets an existing agent called agent_name.
        :param agent_name: Agent name.
        :return: The agent.
        """
        db_url = common.database_path
        collection = common.global_db

        conn = Connection(db_url, collection)

        if conn.getDb() == None:
            raise OssecAPIException(1600)

        agent = conn.getDb()['agent'].find_one({"name": agent_name}, {"id": 1})

        if agent:
            return Agent(agent.get("id")).get_basic_information(select)
        else:
            raise OssecAPIException(1701, agent_name)        

    @staticmethod
    def get_agent(agent_id, select=None):
        """
        Gets an existing agent.
        :param agent_id: Agent ID.
        :return: The agent.
        """

        return Agent(agent_id).get_basic_information(select)

    @staticmethod
    def get_agent_key(agent_id):
        """
        Get the key of an existing agent.
        :param agent_id: Agent ID.
        :return: Agent key.
        """

        return Agent(agent_id).get_key()

    @staticmethod
    def remove_agent(agent_id, backup=False, purge=False):
        """
        Removes an existing agent.
        :param agent_id: Agent ID.
        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Dictionary with affected_agents (agents removed), failed_ids if it necessary (agents that cannot been removed), and a message.
        """

        failed_ids = []
        affected_agents = []
        try:
            Agent(agent_id).remove(backup, purge)
            affected_agents.append(agent_id)
        except Exception as e:
            failed_ids.append(create_exception_dic(agent_id, e))

        if not failed_ids:
            message = 'All selected agents were removed'
        else:
            message = 'Some agents were not removed'

        final_dict = {}
        if failed_ids:
            final_dict = {'msg': message, 'affected_agents': affected_agents, 'failed_ids': failed_ids}
        else:
            final_dict = {'msg': message, 'affected_agents': affected_agents}

        return final_dict

    @staticmethod
    def remove_agents(list_agent_ids="all", backup=False, purge=False, status="all", older_than="7d"):
        """
        Removes an existing agent.
        :param list_agent_ids: List of agents ID's.
        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :param older_than:  Filters out disconnected agents for longer than specified. Time in seconds | "[n_days]d" | "[n_hours]h" | "[n_minutes]m" | "[n_seconds]s". For never connected agents, uses the register date.
        :param status: Filters by agent status: Active, Disconnected or Never connected. Multiples statuses separated by commas.
        :return: Dictionary with affected_agents (agents removed), timeframe applied, failed_ids if it necessary (agents that cannot been removed), and a message.
        """


        agents = Agent.get_agents_overview(filters={'status':status, 'older_than': older_than}, limit = None)

        id_purgeable_agents = [agent['id'] for agent in agents['items']]

        failed_ids = []
        affected_agents = []

        if list_agent_ids != "all":
            for id in list_agent_ids:
                try:
                    if id not in id_purgeable_agents:
                        raise OssecAPIException(1731, "The agent has a status different to '{}' or the specified time frame 'older_than {}' does not apply.".format(status, older_than))
                    Agent(id).remove(backup, purge)
                    affected_agents.append(id)
                except Exception as e:
                    failed_ids.append(create_exception_dic(id, e))
        else:
            for id in id_purgeable_agents:
                try:
                    Agent(id).remove(backup, purge)
                    affected_agents.append(id)
                except Exception as e:
                    failed_ids.append(create_exception_dic(id, e))

        if not failed_ids:
            message = 'All selected agents were removed' if affected_agents else "No agents were removed"
        else:
            message = 'Some agents were not removed'

        if failed_ids:
            final_dict = {'msg': message, 'affected_agents': affected_agents, 'failed_ids': failed_ids,
                          'older_than': older_than, 'total_affected_agents':len(affected_agents),
                          'total_failed_ids':len(failed_ids)}
        else:
            final_dict = {'msg': message, 'affected_agents': affected_agents, 'older_than': older_than,
                          'total_affected_agents':len(affected_agents)}

        return final_dict

    @staticmethod
    def add_agent(name, ip='any', force=-1):
        """
        Adds a new agent to OSSEC.
        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param force: Remove old agent with same IP if disconnected since <force> seconds.
        :return: Agent ID.
        """

        new_agent = Agent(name=name, ip=ip, force=force)
        return {'id': new_agent.id, 'key': new_agent.key}

    @staticmethod
    def insert_agent(name, id, key, ip='any', force=-1):
        """
        Create a new agent providing the id, name, ip and key to the Manager.
        :param id: id of the new agent.
        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param key: name of the new agent.
        :param force: Remove old agent with same IP if disconnected since <force> seconds.
        :return: Agent ID.
        """

        new_agent = Agent(name=name, ip=ip, id=id, key=key, force=force)
        return {'id': new_agent.id, 'key': key}

    @staticmethod
    def check_if_delete_agent(id, seconds):
        """
        Check if we should remove an agent: if time from last connection is greater thant <seconds>.
        :param id: id of the new agent.
        :param seconds: Number of seconds.
        :return: True if time from last connection is greater thant <seconds>.
        """
        remove_agent = False

        agent_info = Agent(id=id).get_basic_information()

        if 'lastKeepAlive' in agent_info:
            if agent_info['lastKeepAlive'] == 0:
                remove_agent = True
            else:
                last_date = datetime.strptime(agent_info['lastKeepAlive'], '%Y-%m-%d %H:%M:%S')
                difference = (datetime.now() - last_date).total_seconds()
                if difference >= seconds:
                    remove_agent = True

        return remove_agent

    @staticmethod
    def get_outdated_agents(offset=0, limit=common.database_limit, sort=None):
        """
        Gets the outdated agents.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        # Connect DB
        db_url = common.database_path
        collection = common.global_db

        conn = Connection(db_url, collection)

        if conn.getDb() == None:
            raise OssecAPIException(1600)
        
        # Get manager version
        manager = Agent(id=0)
        manager._load_info_from_DB()
        manager_ver = manager.version

        # Init query
        query = "SELECT {0} FROM agent WHERE version <> :manager_ver AND id <> 0"
        fields = {'id': 'id', 'name': 'name', 'version': 'version'}  # field: db_column
        select = ['id','name','version']
        request = {'manager_ver': manager_ver}

        select_fields = {}
        for x in select:
            select_fields[x] = 1
        
        # Count
        db_data = conn.getDb()['agent'].find({
            "$and": [
                {
                    "version": { "$ne": manager_ver }
                },
                {
                    "id": { "$ne": "000" }
                }
            ]
        }, select_fields)
        data = {'totalItems': db_data.count()}

        # Sorting
        sort_con = []
        if sort:
            if sort['fields']:
                allowed_sort_fields = fields.keys()
                # Check if every element in sort['fields'] is in allowed_sort_fields.
                if not set(sort['fields']).issubset(allowed_sort_fields):
                    raise OssecAPIException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

                for i in sort['fields']:
                    str_order = 1 if sort['order'] == 'asc' else -1
                    sort_con.append((Agent.fields[i], str_order))
            else:
                sort_con.append((Agent.fields["id"], 1 if sort['order'] == 'asc' else -1))
        else:
            sort_con.append((Agent.fields["id"], 1))

        # OFFSET - LIMIT
        if limit:
            if limit > common.maximum_database_limit:
                raise OssecAPIException(1405, str(limit))
        elif limit == 0:
            raise OssecAPIException(1406)

        # Data query
        db_data = db_data.sort(sort_con).skip(offset).limit(limit)

        data['items'] = []

        for agent in db_data:
            agent.pop('_id')
            data['items'].append(agent)

        return data


    def _get_protocol(self, wpk_repo, use_http=False):
        protocol = ""
        if "http://" not in wpk_repo and "https://" not in wpk_repo:
            protocol = "https://" if not use_http else "http://"

        return protocol

    def _get_versions(self, wpk_repo=common.wpk_repo_url, version=None, use_http=False):
        """
        Generates a list of available versions for its distribution and version.
        """
        invalid_platforms = ["darwin", "solaris", "aix", "hpux", "bsd"]
        not_valid_versions = [("sles", 11), ("rhel", 5), ("centos", 5)]

        if self.os['platform'] in invalid_platforms or (self.os['platform'], self.os['major']) in not_valid_versions:
            error = "The WPK for this platform is not available."
            raise OssecAPIException(1713, error)

        protocol = self._get_protocol(wpk_repo, use_http)
        if (version is None or version[:4] >= "v3.4") and self.os['platform'] != "windows":
            versions_url = protocol + wpk_repo + "linux/" + self.os['arch'] + "/versions"
        else:
            if self.os['platform']=="windows":
                versions_url = protocol + wpk_repo + "windows/versions"
            elif self.os['platform']=="ubuntu":
                versions_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "." + self.os['minor'] + "/" + self.os['arch'] + "/versions"
            else:
                versions_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "/" + self.os['arch'] + "/versions"

        try:
            result = urlopen(versions_url)
        except HTTPError as e:
            raise OssecAPIException(1713, e.code)
        except URLError as e:
            if "SSL23_GET_SERVER_HELLO" in str(e.reason):
              error = "HTTPS requires Python 2.7.9 or newer. You may also run with Python 3."
            else:
              error = str(e.reason)
            raise OssecAPIException(1713, error)

        lines = result.readlines()
        lines = filter(None, lines)
        versions = []

        for line in lines:
            ver_readed = line.decode().split()
            version = ver_readed[0]
            sha1sum = ver_readed[1] if len(ver_readed) > 1 else ''
            versions.append([version, sha1sum])

        return versions


    def _get_wpk_file(self, wpk_repo=common.wpk_repo_url, debug=False, version=None, force=False, use_http=False):
        """
        Searchs latest Wazuh WPK file for its distribution and version. Downloads the WPK if it is not in the upgrade folder.
        """
        agent_new_ver = None
        versions = self._get_versions(wpk_repo=wpk_repo, version=version, use_http=use_http)
        if not version:
            agent_new_ver = versions[0][0]
            agent_new_shasum = versions[0][1]
        else:
            for versions in versions:
                if versions[0] == version:
                    agent_new_ver = versions[0]
                    agent_new_shasum = versions[1]
                    break
        if not agent_new_ver:
            raise OssecAPIException(1718, version)

        # Get manager version
        manager = Agent(id=0)
        manager._load_info_from_DB()
        manager_ver = manager.version
        if debug:
            print("Manager version: {0}".format(manager_ver.split(" ")[1]))

        # Comparing versions
        agent_ver = self.version
        if debug:
            print("Agent version: {0}".format(agent_ver.split(" ")[1]))
            print("Agent new version: {0}".format(agent_new_ver))

        if OssecVersion(manager_ver.split(" ")[2]) < OssecVersion(agent_new_ver):
            raise OssecAPIException(1717, "Manager: {0} / Agent: {1} -> {2}".format(manager_ver.split(" ")[1], agent_ver.split(" ")[1], agent_new_ver))

        if (OssecVersion(agent_ver.split(" ")[2]) >= OssecVersion(agent_new_ver) and not force):
            raise OssecAPIException(1716, "Agent ver: {0} / Agent new ver: {1}".format(agent_ver.split(" ")[1], agent_new_ver))

        protocol = self._get_protocol(wpk_repo, use_http)
        # Generating file name
        if self.os['platform']=="windows":
            wpk_file = "wazuh_agent_{0}_{1}.wpk".format(agent_new_ver, self.os['platform'])
            wpk_url = protocol + wpk_repo + "windows/" + wpk_file

        else:
            if version is None or version[:4] >= "v3.4":
                wpk_file = "wazuh_agent_{0}_linux_{1}.wpk".format(agent_new_ver, self.os['arch'])
                wpk_url = protocol + wpk_repo + "linux/" + self.os['arch'] + "/" + wpk_file

            else:
                if self.os['platform']=="ubuntu":
                    wpk_file = "wazuh_agent_{0}_{1}_{2}.{3}_{4}.wpk".format(agent_new_ver, self.os['platform'], self.os['major'], self.os['minor'], self.os['arch'])
                    wpk_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "." + self.os['minor'] + "/" + self.os['arch'] + "/" + wpk_file
                else:
                    wpk_file = "wazuh_agent_{0}_{1}_{2}_{3}.wpk".format(agent_new_ver, self.os['platform'], self.os['major'], self.os['arch'])
                    wpk_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "/" + self.os['arch'] + "/" + wpk_file

        wpk_file_path = "{0}/var/upgrade/{1}".format(common.ossec_path, wpk_file)

        # If WPK is already downloaded
        if path.isfile(wpk_file_path):
            # Get SHA1 file sum
            sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()
            # Comparing SHA1 hash
            if not sha1hash == agent_new_shasum:
                if debug:
                    print("Downloaded file SHA1 does not match (downloaded: {0} / repository: {1})".format(sha1hash, agent_new_shasum))
            else:
                if debug:
                    print("WPK file already downloaded: {0} - SHA1SUM: {1}".format(wpk_file_path, sha1hash))
                return [wpk_file, sha1hash]

        # Download WPK file
        if debug:
            print("Downloading WPK file from: {0}".format(wpk_url))

        try:
            result = urlopen(wpk_url)
            with open(wpk_file_path, "wb") as local_file:
                local_file.write(result.read())
        except HTTPError as e:
            raise OssecAPIException(1714, e.code)
        except URLError as e:
            if "SSL23_GET_SERVER_HELLO" in str(e.reason):
              error = "HTTPS requires Python 2.7.9 or newer. You may also run with Python 3."
            else:
              error = str(e.reason)
            raise OssecAPIException(1714, error)

        # Get SHA1 file sum
        sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()

        # Comparing SHA1 hash
        if not sha1hash == agent_new_shasum:
            raise OssecAPIException(1714)

        if debug:
            print("WPK file downloaded: {0} - SHA1SUM: {1}".format(wpk_file_path, sha1hash))

        return [wpk_file, sha1hash]


    def _send_wpk_file(self, wpk_repo=common.wpk_repo_url, debug=False, version=None, force=False, show_progress=None, chunk_size=None, rl_timeout=-1, timeout=common.open_retries, use_http=False):
        """
        Sends WPK file to agent.
        """
        if not chunk_size:
            chunk_size = common.wpk_chunk_size
        # Check WPK file
        _get_wpk = self._get_wpk_file(wpk_repo=wpk_repo, debug=debug, version=version, force=force, use_http=use_http)
        wpk_file = _get_wpk[0]
        file_sha1 = _get_wpk[1]
        wpk_file_size = stat("{0}/var/upgrade/{1}".format(common.ossec_path, wpk_file)).st_size
        if debug:
            print("Upgrade PKG: {0} ({1} KB)".format(wpk_file, wpk_file_size/1024))
        # Open file on agent
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        counter = 0
        while data.startswith('err') and counter < timeout:
            sleep(common.open_sleep)
            counter = counter + 1
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(common.ossec_path + "/queue/ossec/request")
            msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
            s.send(msg.encode())
            if debug:
                print("MSG SENT: {0}".format(str(msg)))
            data = s.recv(1024).decode()
            s.close()
            if debug:
                print("RESPONSE: {0}".format(data))
        if data != 'ok':
            raise OssecAPIException(1715, data.replace("err ",""))

        # Sending reset lock timeout
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com lock_restart {1}".format(str(self.id).zfill(3), str(rl_timeout))
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if data != 'ok':
            raise OssecAPIException(1715, data.replace("err ",""))


        # Sending file to agent
        if debug:
            print("Chunk size: {0} bytes".format(chunk_size))
        file = open(common.ossec_path + "/var/upgrade/" + wpk_file, "rb")
        if not file:
            raise OssecAPIException(1715, data.replace("err ",""))
        if debug:
            print("Sending: {0}".format(common.ossec_path + "/var/upgrade/" + wpk_file))
        try:
            start_time = time()
            bytes_read = file.read(chunk_size)
            bytes_read_acum = 0
            while bytes_read:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(common.ossec_path + "/queue/ossec/request")
                msg = "{0} com write {1} {2} ".format(str(self.id).zfill(3), str(len(bytes_read)), wpk_file)
                s.send(msg.encode() + bytes_read)
                data = s.recv(1024).decode()
                s.close()
                if data != 'ok':
                    raise OssecAPIException(1715, data.replace("err ",""))
                bytes_read = file.read(chunk_size)
                if show_progress:
                    bytes_read_acum = bytes_read_acum + len(bytes_read)
                    show_progress(int(bytes_read_acum * 100 / wpk_file_size) + (bytes_read_acum * 100 % wpk_file_size > 0))
            elapsed_time = time() - start_time
        finally:
            file.close()

        # Close file on agent
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com close {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if data != 'ok':
            raise OssecAPIException(1715, data.replace("err ",""))

        # Get file SHA1 from agent and compare
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com sha1 {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok '):
            raise OssecAPIException(1715, data.replace("err ",""))
        rcv_sha1 = data.split(' ')[1]
        if rcv_sha1 == file_sha1:
            return ["WPK file sent", wpk_file]
        else:
            raise OssecAPIException(1715, data.replace("err ",""))


    def upgrade(self, wpk_repo=None, debug=False, version=None, force=False, show_progress=None, chunk_size=None, rl_timeout=-1, use_http=False):
        """
        Upgrade agent using a WPK file.
        """
        if int(self.id) == 0:
            raise OssecAPIException(1703)

        self._load_info_from_DB()

        # Check if agent is active.
        if not self.status == 'Active':
            raise OssecAPIException(1720)

        # Check if remote upgrade is available for the selected agent version
        if OssecVersion(self.version.split(' ')[2]) < OssecVersion("3.0.0-alpha4"):
            raise OssecAPIException(1719, version)

        if self.os['platform']=="windows" and int(self.os['major']) < 6:
            raise OssecAPIException(1721, self.os['name'])

        if wpk_repo == None:
            wpk_repo = common.wpk_repo_url

        if not wpk_repo.endswith('/'):
            wpk_repo = wpk_repo + '/'

        # Send file to agent
        sending_result = self._send_wpk_file(wpk_repo=wpk_repo, debug=debug, version=version, force=force,
                                             show_progress=show_progress, chunk_size=chunk_size, rl_timeout=rl_timeout, use_http=use_http)
        if debug:
            print(sending_result[0])

        # Send upgrading command
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        if self.os['platform']=="windows":
            msg = "{0} com upgrade {1} upgrade.bat".format(str(self.id).zfill(3), sending_result[1])
        else:
            msg = "{0} com upgrade {1} upgrade.sh".format(str(self.id).zfill(3), sending_result[1])
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if data.startswith('ok'):
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): started. Current version: {2}".format(str(self.id).zfill(3), self.name, self.version)).encode(), common.ossec_path + "/queue/ossec/queue")
            s.close()
            return "Upgrade procedure started"
        else:
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): aborted: {2}".format(str(self.id).zfill(3), self.name, data.replace("err ",""))).encode(), common.ossec_path + "/queue/ossec/queue")
            s.close()
            raise OssecAPIException(1716, data.replace("err ",""))