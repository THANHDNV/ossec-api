#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from exception import OssecAPIException
from utils import execute
from agent import Agent
from database import Connection
from ossec_queue import OssecQueue
import common
from glob import glob
from os import remove, path
import re
from time import timezone
from datetime import timedelta, datetime

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
        # Check if agent exists and it is active
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
            doc = conn.getDb()['pm_event']
            if doc != None:
                doc.drop()
                conn.vacuum()
            doc = conn.getDb()['pmCounterInfo']
            if doc != None:
                doc.drop()
                conn.vacuum()

    # Clear OSSEC info
    if int(all_agents):
        rootcheck_files = glob('{0}/queue/rootcheck/*'.format(common.ossec_path))
    else:
        if agent_id == "000":
            rootcheck_files = ['{0}/queue/rootcheck/rootcheck'.format(common.ossec_path)]
        else:
            agent_info = Agent(agent_id).get_basic_information()
            rootcheck_files = glob('{0}/queue/rootcheck/({1}) {2}->rootcheck'.format(common.ossec_path, agent_info['name'], agent_info['ip']))

    for rootcheck_file in rootcheck_files:
        if path.exists(rootcheck_file):
            remove(rootcheck_file)

    return "Rootcheck database deleted"


def print_db(agent_id=None, status='all', pci=None, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Returns a list of events from the database.

    :param agent_id: Agent ID.
    :param status: Filters by status: outstanding, solved, all.
    :param pci: Filters by PCI DSS requirement.
    :param cis: Filters by CIS.
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

    request = { "$and": [] }
    
    lastRootcheckEndTime = None
    lastRootcheckEndTimeObj = list((conn.getDb()['pm_event'].find( { "log": 'Ending rootcheck scan.'} ).sort([('date_last', -1)]).limit(1)))[0]
    if (lastRootcheckEndTimeObj != None):
        lastRootcheckEndTime = lastRootcheckEndTimeObj.get('date_last', datetime.now())

    fields = {'status': 'status', 'event': 'log', 'oldDay': 'date_first', 'readDay': 'date_last'}

    request['$and'].append({
        'log': {
            '$nin': [
                'Starting rootcheck scan.',
                'Ending rootcheck scan.',
                'Starting syscheck scan.',
                'Ending syscheck scan.'
            ]
        }
    })
    if status == 'outstanding':
        if lastRootcheckEndTime != None:
            request['$and'].append({
                'date_last': {
                    '$gt': (lastRootcheckEndTime - timedelta(second=86400))
                }
            })
    elif status == 'solved':
        if lastRootcheckEndTime != None:
            request['$and'].append({
                'date_last': {
                    '$lte': (lastRootcheckEndTime - timedelta(second=86400))
                }
            })

    if pci:
        request["$and"].append({"pci_dss": pci})

    # search
    if search:
        regex = re.compile(".*{0}.*".format(int(search['value']) if search['value'].isdigit() \
                                                                    else search['value']), re.IGNORECASE)
        search_con = {
            "$or": []
        }

        for x in fields.values():
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

    # Sorting
    sort_con = []
    if sort:
        if sort['fields']:
            allowed_sort_fields = set(fields.keys())
            # Check if every element in sort['fields'] is in allowed_sort_fields
            if not set(sort['fields']).issubset(allowed_sort_fields):
                uncorrect_fields = list(map(lambda x: str(x), set(sort['fields']) - set(allowed_sort_fields)))
                raise OssecAPIException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, uncorrect_fields))
            
            for i in sort['fields']:
                str_order = 1 if sort['order'] == 'asc' else -1
                sort_con.append((Agent.fields[i], str_order))
        else:
            sort_con.append((fields["readDay"], 1 if sort['order'] == 'asc' else -1))
    else:
        sort_con.append((fields["readDay"], -1))

    if limit:
        if limit > common.maximum_database_limit:
            raise OssecAPIException(1405, str(limit))
    elif limit == 0:
        raise OssecAPIException(1406)

    select = ["status", "date_first", "date_last", "log", "pci_dss"]
    select_fields = {}
    for x in set(select):
        select_fields[x] = 1

    if not request["$and"]:
        request = {}

    data = {}
    db_data = conn.getDb()['pm_event'].find(request, select_fields)
    data['totalItems'] = db_data.count()
    db_data = db_data.sort(sort_con).skip(offset).limit(limit)

    # process get data
    data['items'] = []

    for pmEvent in db_data:
        pmEvent.pop('_id')
        if pmEvent.get("date_last") != None:
            if (pmEvent['date_last'] > lastRootcheckEndTime) :
                pmEvent['status'] = 'outstanding'
            elif (pmEvent['date_last'] <= lastRootcheckEndTime) :
                pmEvent['status'] = 'solved'

        if pmEvent.get("date_first") != None:
            pmEvent['date_first'] = (pmEvent.get("date_first") + timedelta(seconds=timeoffset)).__str__()
        else:
            pmEvent['date_first'] = pmEvent.get("date_first").__str__()

        if pmEvent.get("date_last") != None:
            pmEvent['date_last'] = (pmEvent.get("date_last") + timedelta(seconds=timeoffset)).__str__()
        else:
            pmEvent['date_last'] = pmEvent.get("date_last").__str__()

        data['items'].append(pmEvent)
    return data


def get_pci(agent_id=None, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Get all the PCI requirements used in the rootchecks of the agent.

    :param agent_id: Agent ID.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    
    fields = {}
    request = { "$and": [
        {
            'pci_dss': {
                '$ne': None
            }
        }
    ] }

    # Connection
    db_url = common.database_path
    conn = Connection(db_url)
    conn.connect(conn.getDbById(str(agent_id).zfill(3)))
    if (conn.getDb() == None):
        raise OssecAPIException(1600)

    # Search
    if search:
        regex = re.compile(".*{0}.*".format(int(search['value']) if search['value'].isdigit() \
                                                                    else search['value']), re.IGNORECASE)
        search_con = {
            "$or": []
        }

        search_con["$or"].append({
            'pci_dss': regex
        })
            
        if bool(search['negation']):
            if search_con["$or"]:
                request["$and"].append({
                    "$not": search_con
                })
        else:
            if search_con["$or"]:
                request["$and"].append(search_con)

    # Total items
    # conn.execute(query.format('COUNT(DISTINCT pci_dss)'), request)
    # data = {'totalItems': conn.fetch()[0]}

    # Sorting
    sort_con = []
    if sort:
        if sort['fields']:
            allowed_sort_fields = set(fields.keys())
            # Check if every element in sort['fields'] is in allowed_sort_fields
            if not set(sort['fields']).issubset(allowed_sort_fields):
                uncorrect_fields = list(map(lambda x: str(x), set(sort['fields']) - set(allowed_sort_fields)))
                raise OssecAPIException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, uncorrect_fields))
            
            for i in sort['fields']:
                str_order = 1 if sort['order'] == 'asc' else -1
                sort_con.append((fields[i], str_order))
        else:
            sort_con.append(('pci_dss', 1 if sort['order'] == 'asc' else -1))
    else:
        sort_con.append(('pci_dss', 1))

    if limit:
        if limit > common.maximum_database_limit:
            raise OssecAPIException(1405, str(limit))
    elif limit == 0:
        raise OssecAPIException(1406)

    if not request["$and"]:
        request = {}
    db_data = conn.getDb()['pm_event'].find(request).sort(sort_con).skip(offset).limit(limit).distinct('pci_dss')
    data = {}
    data['items'] = []
    for pmEvent in db_data:
        data['items'].append(pmEvent)

    return data

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

    lastRootcheckEndTime = None
    lastRootcheckEndTimeObj = list((conn.getDb()['pm_event'].find( { "log": 'Ending rootcheck scan.'} ).sort([('date_last', -1)]).limit(1)))[0]
    if (lastRootcheckEndTimeObj != None):
        lastRootcheckEndTime = lastRootcheckEndTimeObj.get('date_last')

    if lastRootcheckEndTime != None:
        data['end'] = (lastRootcheckEndTime + timedelta(seconds=timeoffset)).__str__()
    else:
        data['end'] = lastRootcheckEndTime.__str__()

    lastRootcheckStartTime = None
    lastRootcheckStartTimeObj = list((conn.getDb()['pm_event'].find( { "log": 'Starting rootcheck scan.'} ).sort([('date_last', -1)]).limit(1)))[0]
    if (lastRootcheckStartTimeObj != None):
        lastRootcheckStartTime = lastRootcheckStartTimeObj.get('date_last')

    if lastRootcheckStartTime != None:
        data['start'] = (lastRootcheckStartTime + timedelta(seconds=timeoffset)).__str__()
    else:
        data['start'] = lastRootcheckStartTime.__str__()

    return data
