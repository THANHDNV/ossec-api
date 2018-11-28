#!/usr/bin/env python

# Created by ossec, Inc. <info@ossec.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from sys import argv, exit, path
from getopt import getopt, GetoptError
from os import path as os_path, getcwd
import json
import signal

error_ossec_package = 0
exception_error = None
try:
    new_path = ""
    if (os_path.exists(os_path.abspath("../framework"))):
        new_path = os_path.abspath('../framework')
    else:
        new_path = os_path.abspath('./framework')
    path.append(new_path)
    from ossec import Ossec_API
    from ossec.exception import OssecAPIException
    from ossec.agent import Agent
    from ossec.rule import Rule
    from ossec.decoder import Decoder
    import ossec.configuration as configuration
    import ossec.manager as manager
    import ossec.stats as stats
    # import ossec.rootcheck as rootcheck
    import ossec.active_response as active_response
    # import ossec.syscheck as syscheck
except (ImportError, SyntaxError) as e:
    error = str(e)
    error_ossec_package = -1
except OssecAPIException as e:
    error_ossec_package = -3
    error = e.message
    error_code = e.code
except Exception as e:
    error = str(e)
    if str(e).startswith("Error 4000"):
        error_ossec_package=-1
    else:
        error_ossec_package = -2
        exception_error = e

def print_json(data, error=0):
    output = {'error': error}

    if error == 0:
        key = 'data'
    else:
        key = 'message'

    output[key] = data

    if pretty:
        print(json.dumps(output, default=encode_json, indent=4))
    else:
        print(json.dumps(output, default=encode_json))


def encode_json(o):
    if isinstance(o, Rule):
        return o.to_dict()
    elif isinstance(o, Agent):
        return o.to_dict()
    elif isinstance(o, Decoder):
        return o.to_dict()

    print_json("ossec-Python Internal Error: data encoding unknown", 1000)
    exit(1)


def is_json(myjson):
    try:
        json_object = json.loads(myjson)
    except:
        return False

    return json_object


def get_stdin(msg):
    try:
        stdin = raw_input(msg)
    except:
        # Python 3
        stdin = input(msg)
    return stdin


def signal_handler(n_signal, frame):
    exit(1)


def usage():
    help_msg = '''
    ossec Control

    \t-p, --pretty       Pretty JSON
    \t-d, --debug        Debug mode
    \t-l, --list         List functions
    \t-h, --help         Help
    '''
    print(help_msg)
    exit(1)

if __name__ == "__main__":
    request = {}
    pretty = False
    debug = False
    list_f = False

    if error_ossec_package < 0:
        if error_ossec_package == -1:
            print_json("ossec-Python Internal Error: {0}".format(error), 1000)
        if error_ossec_package == -2:
            print_json("ossec-Python Internal Error: uncaught exception: {0}".format(exception_error), 1000)
        if error_ossec_package == -3:
            print_json(error, error_code)
        exit(0)  # error code 0 shows the msg in the API response.

    # Read and check arguments
    try:
        opts, args = getopt(argv[1:], "pdlh", ["pretty", "debug", "list", "help"])
        n_args = len(opts)
        if not (0 <= n_args <= 2):
            print("Incorrect number of arguments.\nTry '--help' for more information.")
            exit(1)
    except GetoptError as err_args:
        print(str(err_args))
        print("Try '--help' for more information.")
        exit(1)

    for o, a in opts:
        if o in ("-p", "--pretty"):
            pretty = True
        elif o in ("-d", "--debug"):
            debug = True
        elif o in ("-l", "--list"):
            list_f = True
        elif o in ("-h", "--help"):
            usage()
        else:
            print("Wrong argument combination.")
            print("Try '--help' for more information.")
            exit(1)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    if not list_f:
        stdin = get_stdin("")
        request = is_json(stdin)
        if not request:
            print_json("ossec-Python Internal Error: Bad JSON input", 1000)
            exit(1)

    if 'function' not in request:
        print_json("ossec-Python Internal Error: 'JSON input' must have the 'function' key", 1000)
        exit(1)

    if 'ossec_path' not in request:
        print_json("ossec-Python Internal Error: 'JSON input' must have the 'ossec_path' key", 1000)
        exit(1)

    # Main
    try:
        ossec = Ossec_API(ossec_path=request['ossec_path'])

        functions = {
            # Agents
            '/agents/:agent_id': Agent.get_agent,
            '/agents/name/:agent_name': Agent.get_agent_by_name,
            '/agents/:agent_id/key': Agent.get_agent_key,
            '/agents': Agent.get_agents_overview,
            '/agents/summary': Agent.get_agents_summary,
            '/agents/outdated': Agent.get_outdated_agents,
            'PUT/agents/:agent_id/restart': Agent.restart_agents,
            'PUT/agents/restart': Agent.restart_agents,
            'PUT/agents/:agent_name': Agent.add_agent,
            'POST/agents/restart': Agent.restart_agents,
            'POST/agents': Agent.add_agent,
            'POST/agents/insert': Agent.insert_agent,
            'DELETE/agents/:agent_id': Agent.remove_agent,
            'DELETE/agents/': Agent.remove_agents,

            # Re-check
            # Decoders
            '/decoders': Decoder.get_decoders,
            '/decoders/files': Decoder.get_decoders_files,

            # Re-check
            # Managers
            '/manager/info': ossec.get_ossec_init,
            '/manager/status': manager.status,
            '/manager/configuration': configuration.get_ossec_conf,
            '/manager/stats': stats.totals,
            '/manager/stats/hourly': stats.hourly,
            '/manager/stats/weekly': stats.weekly,
            '/manager/logs/summary': manager.ossec_log_summary,
            '/manager/logs': manager.ossec_log,

            # Check later
            # Rootcheck
            # '/rootcheck/:agent_id': rootcheck.print_db,
            # '/rootcheck/:agent_id/pci': rootcheck.get_pci,
            # '/rootcheck/:agent_id/cis': rootcheck.get_cis,
            # '/rootcheck/:agent_id/last_scan': rootcheck.last_scan,
            # 'PUT/rootcheck': rootcheck.run,
            # 'DELETE/rootcheck': rootcheck.clear,

            # Re-check
            # Rules
            '/rules': Rule.get_rules,
            '/rules/pci': Rule.get_pci,
            '/rules/files': Rule.get_rules_files,

            # Check later
            # Syscheck
            # '/syscheck/:agent_id': syscheck.files,
            # '/syscheck/:agent_id/last_scan': syscheck.last_scan,
            # 'PUT/syscheck': syscheck.run,
            # 'DELETE/syscheck': syscheck.clear,

            # Re-check
            # Active response
            '/PUT/active-response/:agent_id': active_response.run_command,
        }

        if list_f:
            print_json(sorted(functions.keys()))
            exit(0)

        if 'arguments' in request and request['arguments']:
            data = functions[request['function']](**request['arguments'])
        else:
            data = functions[request['function']]()
        
        print_json(data)
    except OssecAPIException as e:
        print_json(e.message, e.code)
        if debug:
            raise
    except Exception as e:
        print_json("ossec-Python Internal Error: {0}".format(str(e)), 1000)
        if debug:
            raise
