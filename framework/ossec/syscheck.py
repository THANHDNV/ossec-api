#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from exception import OssecAPIException
from utils import execute, filemode
from agent import Agent
from database import Connection
from ossec_queue import OssecQueue
import common
from glob import glob
from os import remove, path
import re
from datetime import timedelta, datetime
from time import timezone

timeoffset = -timezone


def run(agent_id=None, all_agents=False):
    """
    Runs rootcheck and syscheck.

    :param agent_id: Run rootcheck/syscheck in the agent.
    :param all_agents: Run rootcheck/syscheck in all agents.
    :return: Message.
    """

    if agent_id == "000" or all_agents:
        try:
            SYSCHECK_RESTART = "{0}/var/run/.syscheck_run".format(common.ossec_path)

            fp = open(SYSCHECK_RESTART, 'w')
            fp.write('{0}\n'.format(SYSCHECK_RESTART))
            fp.close()
            ret_msg = "Restarting Syscheck/Rootcheck locally"
        except:
            raise OssecAPIException(1601, "locally")

        if all_agents:
            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(OssecQueue.HC_SK_RESTART)
            oq.close()
    else:
        # Check if agent exists
        agent_info = Agent(agent_id).get_basic_information()
        if 'status' in agent_info:
            agent_status = agent_info['status']
        else:
            agent_status = "N/A"

        if agent_status.lower() != 'active':
            raise OssecAPIException(1602, '{0} - {1}'.format(agent_id, agent_status))

        oq = OssecQueue(common.ARQUEUE)
        ret_msg = oq.send_msg_to_agent(OssecQueue.HC_SK_RESTART, agent_id)
        oq.close()

    return ret_msg


def clear(agent_id=None, all_agents=False):
    """
    Clears the database.

    :param agent_id: For an agent.
    :param all_agents: For all agents.
    :return: Message.
    """

    # Clear DB
    conn = Connection(common.database_path)
    
    regex = re.compile(r'^\d{,3}-\S+$')
    db_agents_list = []

    if not int(all_agents):
        raw_str = r'^' + "{}".format(int(agent_id)).zfill(3) + r'-\S+$'
        regex = re.compile(raw_str)

    for db_agent in conn.getDbsName():
        if (regex.search(db_agent) != None):
            db_agents_list.append(db_agent)

    if (db_agents_list.count() <= 0):
        raise OssecAPIException(1600)

    for db_agent in db_agents_list:
        conn.connect(db_agent)
        if conn.getDb() != None:
            doc = conn.getDb()['fim_event']
            if doc != None:
                doc.drop()
                conn.vacuum()
            doc = conn.getDb()['fim_file']
            if doc != None:
                doc.drop()
                conn.vacuum()
            doc = conn.getDb()['fimCounterInfo']
            if doc != None:
                doc.drop()
                conn.vacuum()

    # Clear OSSEC info
    if int(all_agents):
        syscheck_files = glob('{0}/queue/syscheck/*'.format(common.ossec_path))
    else:
        if agent_id == "000":
            syscheck_files = ['{0}/queue/syscheck/syscheck'.format(common.ossec_path)]
        else:
            agent_info = Agent(agent_id).get_basic_information()
            syscheck_files = glob('{0}/queue/syscheck/({1}) {2}->syscheck'.format(common.ossec_path, agent_info['name'], agent_info['ip']))

    for syscheck_file in syscheck_files:
        if path.exists(syscheck_file):
            remove(syscheck_file)

    return "Syscheck database deleted"


def last_scan(agent_id):
    """
    Gets the last scan of the agent.

    :param agent_id: Agent ID.
    :return: Dictionary: end, start.
    """

    # Connection
    db_url = common.database_path
    conn = Connection(db_url)
    conn.connect(conn.getDbById(str(agent_id).zfill(3)))
    if (conn.getDb() == None):
        raise OssecAPIException(1600)

    data = {}

    lastSyscheckEndTime = None
    lastSyscheckEndTimeObj = list((conn.getDb()['pm_event'].find( { "log": 'Ending syscheck scan.'} ).sort([('date_last', -1)]).limit(1)))[0]
    if (lastSyscheckEndTimeObj != None):
        lastSyscheckEndTime = lastSyscheckEndTimeObj.get('date_last')

    if lastSyscheckEndTime != None:
        data['end'] = (lastSyscheckEndTime + timedelta(seconds=timeoffset)).__str__()
    else:
        data['end'] = lastSyscheckEndTime.__str__()

    lastSyscheckStartTime = None
    lastSyscheckStartTimeObj = list((conn.getDb()['pm_event'].find( { "log": 'Starting syscheck scan.'} ).sort([('date_last', -1)]).limit(1)))[0]
    if (lastSyscheckStartTimeObj != None):
        lastSyscheckStartTime = lastSyscheckStartTimeObj.get('date_last')

    if lastSyscheckStartTime != None:
        data['start'] = (lastSyscheckStartTime + timedelta(seconds=timeoffset)).__str__()
    else:
        data['start'] = lastSyscheckStartTime.__str__()

    return data


def files(agent_id=None, event=None, filename=None, filetype='file', md5=None, sha1=None, hash=None, summary=False, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Return a list of files from the database that match the filters

    :param agent_id: Agent ID.
    :param event: Filters by event: added, readded, modified, deleted.
    :param filename: Filters by filename.
    :param filetype: Filters by filetype: file or registry.
    :param md5: Filters by md5 hash.
    :param sha1: Filters by sha1 hash.
    :param hash: Filters by md5 or sha1 hash.
    :param summary: Returns a summary grouping by filename.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """

    # Connection
    db_url = common.database_path
    conn = Connection(db_url)
    conn.connect(conn.getDbById(str(agent_id).zfill(3)))
    if (conn.getDb() == None):
        raise OssecAPIException(1600)

    agent_info = Agent(agent_id).get_basic_information()
    if 'os' in agent_info:
        if 'windows' in agent_info['os']['name'].lower():
            windows_agent = True
        else:
            windows_agent = False
    else: 
        windows_agent = False

    # if 'os' in agent_info and 'platform' in agent_info['os']:
    #     if agent_info['os']['platform'].lower() == 'windows':
    #         windows_agent = True
    #     else:
    #         windows_agent = False
    # else:
    #     # We do not know if it is a windows or linux agent.
    #     # It is set to windows agent in order to avoid wrong data (uid, gid, ...)
    #     windows_agent = True

    eventRequest = { "$and": [] }
    fileRequest = { "$and": [] }
    
    eventFields = {'scanDate': 'date', 'modificationDate': 'mtime',  'size': 'size', 'user': 'uname', 'group': 'gname'}
    fileFields = {'file': 'path', 'filetype': 'type'}
    # Query
    # query = "SELECT {0} FROM fim_event, fim_file WHERE fim_event.id_file = fim_file.id AND fim_file.type = :filetype"

    # fileRequest['$and'].append({
    #     'type': filetype
    # })

    # if event:
    #     # query += ' AND fim_event.type = :event'
    #     # request['event'] = event
    #     eventRequest['$and'].append({
    #         'event': event
    #     })

    # if filename:
    #     # query += ' AND path = :filename'
    #     # request['filename'] = filename
    #     fileRequest['$and'].append({
    #         'path': filename
    #     })

    # if md5:
    #     # query += ' AND md5 = :md5'
    #     # request['md5'] = md5
    #     eventRequest['$and'].append({
    #         'md5': md5
    #     })

    # if sha1:
    #     # query += ' AND sha1 = :sha1'
    #     # request['sha1'] = sha1
    #     eventRequest['$and'].append({
    #         'sha1': sha1
    #     })

    # if hash:
    #     # query += ' AND (md5 = :hash OR sha1 = :hash)'
    #     # request['hash'] = hash
    #     eventRequest['$and'].append({
    #         '$or': [
    #             {
    #                 'md5': hash
    #             },
    #             {
    #                 'sha1': hash
    #             }
    #         ]
    #     })

    # if search:
    #     query += " AND NOT" if bool(search['negation']) else ' AND'
    #     query += " (" + " OR ".join(x + ' LIKE :search' for x in ('path', "date", 'size', 'md5', 'sha1', 'uname', 'gname', 'inode', 'perm')) + " )"
    #     request['search'] = '%{0}%'.format(search['value'])
    
    if search:
        regex = re.compile(".*{0}.*".format(int(search['value']) if search['value'].isdigit() \
                                                                    else search['value']), re.IGNORECASE)
        event_search_con = {
            "$or": []
        }
        file_search_con = {
            "$or": []
        }
        for x in ['path', "date", 'size', 'md5', 'sha1', 'uname', 'gname', 'perm']:
            if x == 'path':
                file_search_con["$or"].append({
                    x: regex
                })
            else:
                event_search_con["$or"].append({
                    x: regex
                })
        if bool(search['negation']):
            if event_search_con["$or"]:
                eventRequest["$and"].append({
                    "$not": event_search_con
                })
            if file_search_con["$or"]:
                fileRequest["$and"].append({
                    "$not": file_search_con
                })
        else:
            if event_search_con["$or"]:
                eventRequest["$and"].append(event_search_con)
            if file_search_con["$or"]:
                fileRequest["$and"].append(file_search_con)

    # Total items
    db_data = None

    events = []
    if summary:
        db_data = conn.getDb()['fim_file'].aggregate([
            {
                '$lookup': {
                    'from': 'fim_event',
                    'localField': '_id',
                    'foreignField': 'file_id',
                    'as': 'fim_events'
                }
            },
        ], cursor={})
        for sysFile in db_data:
            item = sysFile
            for fEvent in item['fim_events']:
                if not item.get('fim_event'):
                    item['fim_event'] = fEvent
                else:
                    if fEvent['date'] > item['fim_event']['date']:
                        item['fim_event'] = fEvent
            item.pop('fim_events')
            if item['type'] != filetype:
                continue

            if event:
                if item['fim_event']['type'] != event:
                    continue
            if filename:
                if item['path'] != filename:
                    continue
            if md5:
                if item['fim_event']['md5'] != md5:
                    continue
            
            if sha1:
                if item['fim_event']['sha1'] != md5:
                    continue
            
            if hash:
                if (item['fim_event']['sha1'] != hash) and (item['fim_event']['md5'] != hash):
                    continue
            if search:
                search_value = int(search['value']) if search['value'].isdigit() else search['value']

                if (search_value not in item['path']) and (search_value not in item['fim_event']['date']) \
                and (search_value not in item['fim_event']['size']) and (search_value not in item['fim_event']['md5']) \
                and (search_value not in item['fim_event']['sha1']) and (search_value not in item['fim_event']['uname']) \
                and (search_value not in item['fim_event']['gname']) and (search_value not in item['fim_event']['perm']):
                    continue
            item['sha1'] = item['fim_event']['sha1']
            item['uid'] = item['fim_event']['uid']
            item['date'] = item['fim_event']['date']
            item['gid'] = item['fim_event']['gid']
            # item['mtime'] = item['fim_event']['mtime']
            item['perm'] = item['fim_event']['perm']
            item['md5'] = item['fim_event']['md5']
            item.pop('fim_event')
            item['fim_event.type'] = item['type']
            item.pop('type')
            events.append(item)

        # rFileRequest = fileRequest.copy()
        # if not rFileRequest['$and']:
        #     rFileRequest = {}
        # db_data = conn.getDb()['fim_file'].find_one(rFileRequest)
        # # list_db_data = list(db_data)
        # for eFile in db_data:
        #     rEventRequest = eventRequest.copy()
        #     rEventRequest['$and'].append({
        #         'file_id': eFile.get('_id')
        #     })
        #     event_data = conn.getDb()['fim_event'].find(rEventRequest).sort(('date', -1)).limit(1)
        #     if event_data.count() == 1:
        #         item = list(event_data)[0]
        #         item['type'] = eFile.get('type')
        #         item['type'] = eFile.get('path')
        #         print(item)
        #         events.append(item)

        # query += ' group by path'
        # conn.execute("SELECT COUNT(*) FROM ({0}) AS TEMP".format(query.format("max(date)")), request)
    else:        
        db_data = conn.getDb()['fim_event'].aggregate([
            {
                '$lookup': {
                    'from': 'fim_file',
                    'localField': 'file_id',
                    'foreignField': '_id',
                    'as': 'fim_file'
                }
            },
        ], cursor={})
        for sysEvent in db_data:
            if sysEvent['fim_file'][0]['type'] != filetype:
                continue

            if event:
                if sysEvent['type'] != event:
                    continue
            if filename:
                if sysEvent['fim_file'][0]['path'] != filename:
                    continue
            if md5:
                if sysEvent['md5'] != md5:
                    continue
            
            if sha1:
                if sysEvent['sha1'] != md5:
                    continue
            
            if hash:
                if (sysEvent['sha1'] != hash) and (sysEvent['md5'] != hash):
                    continue
            if search:
                search_value = int(search['value']) if search['value'].isdigit() else search['value']

                if (search_value not in sysEvent['fim_file'][0]['path']) and (search_value not in sysEvent['date']) \
                and (search_value not in sysEvent['size']) and (search_value not in sysEvent['md5']) \
                and (search_value not in sysEvent['sha1']) and (search_value not in sysEvent['uname']) \
                and (search_value not in sysEvent['gname']) and (search_value not in sysEvent['perm']):
                    continue
            item = sysEvent
            item['fim_event.type'] = item['fim_file'][0]['type']
            item['path'] = item['fim_file'][0]['path']
            # print(item)
            item.pop('_id')
            item.pop('fim_file')
            events.append(item)

    data = {'totalItems': len(events)}
    # Sorting
    event_sort_con = []
    file_sort_con = []
    if sort:
        if sort['fields']:
            allowed_sort_fields = set(eventFields.keys() + fileFields.keys())
            # Check if every element in sort['fields'] is in allowed_sort_fields
            if not set(sort['fields']).issubset(allowed_sort_fields):
                uncorrect_fields = list(map(lambda x: str(x), set(sort['fields']) - set(allowed_sort_fields)))
                raise OssecAPIException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, uncorrect_fields))
            
            for i in sort['fields']:
                # str_order = 1 if sort['order'] == 'asc' else -1
                sort_order = False if sort['order'] == 'asc' else True
                events.sort(key=lambda e: e[i], reverse=sort_order)
                # if i in eventFields.keys():
                #     event_sort_con.append((eventFields[i], str_order))
                #     events.sort(key=lambda e: e[i], reverse=sort_order)
                # elif i in fileFields.keys():
                #     file_sort_con.append((fileFields[i], str_order))
        else:
            # event_sort_con.append((eventFields["date"], 1 if sort['order'] == 'asc' else -1))
            sort_order = False if sort['order'] == 'asc' else True
            events.sort(key=lambda e: e['date'], reverse=sort_order)
    else:
        # event_sort_con.append((eventFields["date"], -1))
        events.sort(key=lambda e: e['date'], reverse=True)

    # if sort:
    #     if sort['fields']:
    #         allowed_sort_fields = fields.keys()
    #          # Check if every element in sort['fields'] is in allowed_sort_fields
    #         if not set(sort['fields']).issubset(allowed_sort_fields):
    #             uncorrect_fields = list(map(lambda x: str(x), set(sort['fields']) - set(allowed_sort_fields)))
    #             raise OssecAPIException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, uncorrect_fields))

    #         query += ' ORDER BY ' + ','.join(['{0} {1}'.format(fields[i], sort['order']) for i in sort['fields']])
    #     else:
    #         query += ' ORDER BY date {0}'.format(sort['order'])
    # else:
    #     query += ' ORDER BY date DESC'
    if limit:
        if limit > common.maximum_database_limit:
            raise OssecAPIException(1405, str(limit))
        # query += ' LIMIT :offset,:limit'
        # request['offset'] = offset
        # request['limit'] = limit
        if offset >= 0:
            events = events[int(offset):(int(offset) + int(limit))]
    elif limit == 0:
        raise OssecAPIException(1406)
    
    # if summary:
    #     select = ["max(date)", "mtime", "fim_event.type", "path"]
    # else:
    #     select = ["date", "mtime", "fim_event.type", "path", "size", "perm", "uid", "gid", "md5", "sha1"]
    
    

    data['items'] = []
    for fEvent in events:
        data_tuple = {}
        if fEvent.get('date') != None:
            data_tuple['scanDate'] = (fEvent.get('date') + timedelta(seconds=timeoffset)).__str__()
        else:
            data_tuple['scanDate'] = fEvent.get('date').__str__()
        # if fEvent.get('mtime') != None:
        #     data_tuple['modificationDate'] = (fEvent.get('mtime') + timedelta(seconds=timeoffset)).__str__()  # modificationDate
        # else:
        #     data_tuple['modificationDate'] = data_tuple['scanDate']  # scanDate
        if fEvent.get('fim_event.type') != None:
            data_tuple['event'] = fEvent.get('fim_event.type')
        if fEvent.get('path') != None:
            data_tuple['file'] = fEvent.get('path')

        if not summary:
            try:
                permissions = filemode(int(fEvent.get('perm'), 8))
            except TypeError:
                permissions = None

            if fEvent.get('size') != None:
                data_tuple['size'] = fEvent.get('size')
            if fEvent.get('md5') != None:
                data_tuple['md5'] = fEvent.get('md5')
            if fEvent.get('sha1') != None:
                data_tuple['sha1'] = fEvent.get('sha1')

            if not windows_agent:
                if fEvent.get('uid') != None:
                    data_tuple['uid'] = fEvent.get('uid')
                if fEvent.get('gid') != None:
                    data_tuple['gid'] = fEvent.get('gid')

                if fEvent.get('perm') != None:
                    data_tuple['octalMode'] = fEvent.get('perm')
                if permissions:
                    data_tuple['permissions'] = permissions


        data['items'].append(data_tuple)
    return data
