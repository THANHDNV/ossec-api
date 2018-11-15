#!/usr/bin/env python

# Created by ossec, Inc. <info@ossec.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from sys import argv, exit, path
from getopt import getopt, GetoptError
from os import path as os_path, getcwd
import json
import signal

def print_json(data, error=0):
    output = {'error': error}

    if error == 0:
        key = 'data'
    else:
        key = 'message'

    output[key] = data

    if pretty:
        print(json.dumps(output, indent=4))
    else:
        print(json.dumps(output))


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
        if list_f:
            print("This is a demo module, there's no function list")
            exit(0)
        
        request["result"] = "Return from test module"
        data = request

        print_json(data)
    except Exception as e:
        print_json("ossec-Python Internal Error: {0}".format(str(e)), 1000)
        if debug:
            raise
