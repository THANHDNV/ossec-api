#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from os import listdir, path as os_path
import re
from exception import OssecAPIException
from agent import Agent
import common
from utils import cut_array, load_ossec_xml
# Python 2/3 compability
try:
    from ConfigParser import RawConfigParser, NoOptionError
    from StringIO import StringIO
except ImportError:
    from configparser import RawConfigParser, NoOptionError
    from io import StringIO

import logging
logger = logging.getLogger(__name__)

# Aux functions

# Type of configuration sections:
#   * Duplicate -> there can be multiple independent sections. Must be returned as multiple json entries.
#   * Merge -> there can be multiple sections but all are dependent with each other. Must be returned as a single json entry.
#   * Last -> there can be multiple sections in the configuration but only the last one will be returned. The rest are ignored.
conf_sections = {
    'active-response': { 'type': 'duplicate', 'list_options': [] },
    'command': { 'type': 'duplicate', 'list_options': [] },
    'agentless': { 'type': 'duplicate', 'list_options': [] },
    'localfile': { 'type': 'duplicate', 'list_options': [] },
    'remote': { 'type': 'duplicate', 'list_options': [] },
    'syslog_output': { 'type': 'duplicate', 'list_options': [] },
    'integration': { 'type': 'duplicate', 'list_options': [] },

    'alerts': { 'type': 'merge', 'list_options': [] },
    'client': { 'type': 'merge', 'list_options': [] },
    'database_output': { 'type': 'merge', 'list_options': [] },
    'email_alerts': { 'type': 'merge', 'list_options': [] },
    'reports': { 'type': 'merge', 'list_options': [] },
    'global': {
        'type': 'merge',
        'list_options': ['white_list']
    },
    'open-scap': {
        'type': 'merge',
        'list_options': ['content']
    },
    'rootcheck': {
        'type': 'merge',
        'list_options': ['rootkit_files', 'rootkit_trojans', 'windows_audit', 'system_audit', 'windows_apps', 'windows_malware']
    },
    'rules': {
        'type': 'merge',
        'list_options':  ['include', 'rule', 'rule_dir', 'decoder', 'decoder_dir']
    },
    'syscheck': {
        'type': 'merge',
        'list_options': ['directories', 'ignore', 'nodiff']
    },
    'auth': {
        'type': 'merge',
        'list_options': []
    },

    'cluster': {
        'type': 'last',
        'list_options': ['nodes']
    }
}


def _insert(json_dst, section_name, option, value):
    """
    Inserts element (option:value) in a section (json_dst) called section_name
    """

    if not value:
        return

    if option in json_dst:
        if type(json_dst[option]) is list:
            json_dst[option].append(value)  # Append new values
        else:
            json_dst[option] = value  # Update values
    else:
        if section_name in conf_sections and option in conf_sections[section_name]['list_options']:
            json_dst[option] = [value]  # Create as list
        else:
            json_dst[option] = value  # Update values


def _insert_section(json_dst, section_name, section_data):
    """
    Inserts a new section (section_data) called section_name in json_dst.
    """

    if section_name in conf_sections and conf_sections[section_name]['type'] == 'duplicate':
        if section_name in json_dst:
            json_dst[section_name].append(section_data)  # Append new values
        else:
            json_dst[section_name] = [section_data]  # Create as list
    elif section_name in conf_sections and conf_sections[section_name]['type'] == 'merge':
        if section_name in json_dst:
            for option in section_data:
                if option in json_dst[section_name] and option in conf_sections[section_name]['list_options']:
                    json_dst[section_name][option].extend(section_data[option])  # Append new values
                else:
                    json_dst[section_name][option] = section_data[option]  # Update values
        else:
            json_dst[section_name] = section_data  # Create
    elif section_name in conf_sections and conf_sections[section_name]['type'] == 'last':
        if section_name in json_dst:
            # if the option already exists it is overwritten. But a warning is shown.
            logger.warning("There are multiple {} sections in configuration. Using only last section.".format(section_name))
        json_dst[section_name] = section_data  # Create


def _read_option(section_name, opt):
    """
    Reads an option (inside a section) and returns the name and the value.
    """

    opt_name = opt.tag.lower()

    if section_name == 'open-scap':
        if opt.attrib:
            opt_value = {}
            for a in opt.attrib:
                opt_value[a] = opt.attrib[a]
            # profiles
            profiles_list = []
            for profiles in opt.iter():
                profiles_list.append(profiles.text)

            if profiles_list:
                opt_value['profiles'] = profiles_list
        else:
            opt_value = opt.text
    elif section_name == 'syscheck' and opt_name == 'directories':
        opt_value = []

        json_attribs = {}
        for a in opt.attrib:
            json_attribs[a] = opt.attrib[a]

        for path in opt.text.split(','):
            json_path = {}
            json_path = json_attribs.copy()
            json_path['path'] = path.strip()
            opt_value.append(json_path)
    elif section_name == 'cluster' and opt_name == 'nodes':
        opt_value = [child.text for child in opt]
    else:
        if opt.attrib:
            opt_value = {}
            opt_value['item'] = opt.text
            for a in opt.attrib:
                opt_value[a] = opt.attrib[a]
        else:
            opt_value = opt.text

    return opt_name, opt_value


def _conf2json(src_xml, dst_json):
    """
    Parses src_xml to json. It is inserted in dst_json.
    """

    for section in list(src_xml):
        section_name = section.attrib['name'] if section.tag.lower() == 'wodle' else section.tag.lower()
        section_json = {}

        for option in list(section):
            option_name, option_value = _read_option(section_name, option)
            if type(option_value) is list:
                for ov in option_value:
                    _insert(section_json, section_name, option_name, ov)
            else:
                _insert(section_json, section_name, option_name, option_value)

        _insert_section(dst_json, section_name, section_json)


def _ossecconf2json(xml_conf):
    """
    Returns ossec.conf in JSON from xml
    """
    final_json = {}

    for root in list(xml_conf):
        if root.tag.lower() == "ossec_config":
            _conf2json(root, final_json)

    return final_json


def _agentconf2json(xml_conf):
    """
    Returns agent.conf in JSON from xml
    """

    final_json = []

    for root in xml_conf.iter():
        if root.tag.lower() == "agent_config":
            # Get attributes (os, name, profile)
            filters = {}
            for attr in root.attrib:
                filters[attr] = root.attrib[attr]

            # Check if we have read the same filters before (we will need to merge them)
            previous_config = -1
            for idx, item in enumerate(final_json):
                if 'filters' in item and item['filters'] == filters:
                    previous_config = idx
                    break

            if previous_config != -1:
                _conf2json(root, final_json[previous_config]['config'])
            else:
                config = {}
                _conf2json(root, config)
                final_json.append({'filters': filters, 'config': config})

    return final_json


def _rcl2json(filepath):
    """
    Returns the RCL file as dictionary.

    :return: rcl file (system_audit, windows_audit) as dictionary.
    """

    data = {'vars': {}, 'controls': []}
    # [Application name] [any or all] [reference]
    # type:<entry name>;
    regex_comment = re.compile(r"^\s*#")
    regex_title = re.compile(r"^\s*\[(.*)\]\s*\[(.*)\]\s*\[(.*)\]\s*")
    regex_name_groups = re.compile(r"(\{\w+:\s+\S+\s*\S*\})")
    regex_check = re.compile(r"^\s*(\w:.+)")
    regex_var = re.compile(r"^\s*\$(\w+)=(.+)")

    try:
        item = {}

        with open(filepath) as f:
            for line in f:
                if re.search(regex_comment, line):
                    continue

                match_title = re.search(regex_title, line)
                if match_title:
                    # Previous
                    if item:
                        data['controls'].append(item)

                    # New
                    name = match_title.group(1)
                    condition = match_title.group(2)
                    reference = match_title.group(3)

                    item = {}

                    # Name
                    end_name = name.find('{')
                    item['name'] = name[:end_name].strip()

                    # Extract PCI and CIS from name
                    name_groups = re.findall(regex_name_groups, name)

                    cis = []
                    pci = []
                    if name_groups:

                        for group in name_groups:
                            # {CIS: 1.1.2 RHEL7}
                            g_value = group.split(':')[-1][:-1].strip()
                            if 'CIS' in group:
                                 cis.append(g_value)
                            elif 'PCI' in group:
                                 pci.append(g_value)

                    if cis:
                        item['cis'] = cis
                    if pci:
                        item['pci'] = pci

                    # Conditions
                    if condition:
                        item['condition'] = condition
                    if reference:
                        item['reference'] = reference
                    item['checks'] = []

                    continue

                match_checks = re.search(regex_check, line)
                if match_checks:
                    item['checks'].append(match_checks.group(1))
                    continue

                match_var = re.search(regex_var, line)
                if match_var:
                    data['vars'][match_var.group(1)] = match_var.group(2)
                    continue

            # Last item
            data['controls'].append(item)

    except Exception as e:
        raise OssecAPIException(1101, str(e))

    return data


def _rootkit_files2json(filepath):
    """
    Returns the rootkit file as dictionary.

    :return: rootkit file as dictionary.
    """

    data = []

    # file_name ! Name ::Link to it
    regex_comment = re.compile(r"^\s*#")
    regex_check = re.compile(r"^\s*(.+)\s+!\s*(.+)\s*::\s*(.+)")

    try:
        with open(filepath) as f:
            for line in f:
                if re.search(regex_comment, line):
                    continue

                match_check= re.search(regex_check, line)
                if match_check:
                    new_check = {'filename': match_check.group(1).strip(), 'name': match_check.group(2).strip(), 'link': match_check.group(3).strip()}
                    data.append(new_check)

    except Exception as e:
        raise OssecAPIException(1101, str(e))

    return data


def _rootkit_trojans2json(filepath):
    """
    Returns the rootkit trojans file as dictionary.

    :return: rootkit trojans file as dictionary.
    """

    data = []

    # file_name !string_to_search!Description
    regex_comment = re.compile(r"^\s*#")
    regex_check = re.compile(r"^\s*(.+)\s+!\s*(.+)\s*!\s*(.+)")

    try:
        with open(filepath) as f:
            for line in f:
                if re.search(regex_comment, line):
                    continue

                match_check= re.search(regex_check, line)
                if match_check:
                    new_check = {'filename': match_check.group(1).strip(), 'name': match_check.group(2).strip(), 'description': match_check.group(3).strip()}
                    data.append(new_check)

    except Exception as e:
        raise OssecAPIException(1101, str(e))

    return data

def _ar_conf2json(file_path):
    """
    Returns the lines of the ar.conf file
    """
    with open(file_path) as f:
        data = [line.strip('\n') for line in f.readlines()]
    return data


# Main functions
def get_ossec_conf(section=None, field=None, filename=common.ossec_conf):
    """
    Returns ossec.conf (manager) as dictionary.

    :param section: Filters by section (i.e. rules).
    :param field: Filters by field in section (i.e. included).
    :return: ossec.conf (manager) as dictionary.
    """

    try:
        # Read XML
        xml_data = load_ossec_xml(filename)

        # Parse XML to JSON
        data = _ossecconf2json(xml_data)
    except Exception as e:
        raise OssecAPIException(1101, str(e))

    if section:
        try:
            data = data[section]
        except KeyError as e:
            if section not in conf_sections.keys():
                raise OssecAPIException(1102, e.args[0])
            else:
                raise OssecAPIException(1106, e.args[0])

    if section and field:
        try:
            data = data[field]  # data[section][field]
        except:
            raise OssecAPIException(1103)

    return data


def get_agent_conf(group_id=None, offset=0, limit=common.database_limit, filename=None):
    """
    Returns agent.conf as dictionary.

    :return: agent.conf as dictionary.
    """
    if group_id:
        if not Agent.group_exists(group_id):
            raise OssecAPIException(1710, group_id)

        agent_conf = "{0}/{1}".format(common.shared_path, group_id)

    if filename:
        agent_conf_name = filename
    else:
        agent_conf_name = 'agent.conf'

    agent_conf += "/{0}".format(agent_conf_name)

    if not os_path.exists(agent_conf):
        raise OssecAPIException(1006, agent_conf)

    try:
        # Read XML
        xml_data = load_ossec_xml(agent_conf)

        # Parse XML to JSON
        data = _agentconf2json(xml_data)
    except Exception as e:
        raise OssecAPIException(1101, str(e))


    return {'totalItems': len(data), 'items': cut_array(data, offset, limit)}


def get_file_conf(filename, group_id=None, type_conf=None):
    """
    Returns the configuration file as dictionary.

    :return: configuration file as dictionary.
    """

    if group_id:
        if not Agent.group_exists(group_id):
            raise OssecAPIException(1710, group_id)

        file_path = "{0}/{1}".format(common.shared_path, filename) \
                    if filename == 'ar.conf' else \
                    "{0}/{1}/{2}".format(common.shared_path, group_id, filename)
    else:
        file_path = "{0}/{1}".format(common.shared_path, filename)

    if not os_path.exists(file_path):
        raise OssecAPIException(1006, file_path)

    types = {
        'conf': get_agent_conf,
        'rootkit_files': _rootkit_files2json,
        'rootkit_trojans': _rootkit_trojans2json,
        'rcl': _rcl2json
    }

    data = {}
    if type_conf:
        if type_conf in types:
            if type_conf == 'conf':
                data = types[type_conf](group_id, limit=None, filename=filename)
            else:
                data = types[type_conf](file_path)
        else:
            raise OssecAPIException(1104, "{0}. Valid types: {1}".format(type_conf, types.keys()))
    else:
        if filename == "agent.conf":
            data = get_agent_conf(group_id, limit=None, filename=filename)
        elif filename == "rootkit_files.txt":
            data = _rootkit_files2json(file_path)
        elif filename == "rootkit_trojans.txt":
            data = _rootkit_trojans2json(file_path)
        elif filename == "ar.conf":
            data = _ar_conf2json(file_path)
        else:
            data = _rcl2json(file_path)

    return data


def parse_internal_options(high_name, low_name):
    def get_config(config_path):
        with open(config_path) as f:
            str_config = StringIO('[root]\n' + f.read())

        config = RawConfigParser()
        config.readfp(str_config)

        return config


    if not os_path.exists(common.internal_options):
        raise OssecAPIException(1107)

    # Check if the option exists at local internal options
    if os_path.exists(common.local_internal_options):
        try:
            return get_config(common.local_internal_options).get('root',
                                    '{0}.{1}'.format(high_name, low_name))
        except NoOptionError:
            pass

    try:
        return get_config(common.internal_options).get('root',
                            '{0}.{1}'.format(high_name, low_name))
    except NoOptionError as e:
        raise OssecAPIException(1108, e.args[0])


def get_internal_options_value(high_name, low_name, max, min):
    option = parse_internal_options(high_name, low_name)
    if not option.isdigit():
        raise OssecAPIException(1109, 'Option: {}.{}. Value: {}'.format(high_name, low_name, option))

    option = int(option)
    if option < min or option > max:
        raise OssecAPIException(1110, 'Max value: {}. Min value: {}. Found: {}.'.format(max, min, option))

    return option
