#!/usr/bin/env python

import re
import operator
from functools import reduce

class InputValidator:
    """
    Class to do Input Validation
    """

    def check_name(self, name, regex_str="\w+"):
        regex = re.compile(regex_str)
        matching = regex.match(name)
        if matching:
            return matching.group() == name
        else: 
            return False

    def check_length(self, name, length=100, func=operator.lt):
        return func(len(name), length)

    def group(self, group_name):
        """
        function to validate the name of a group. Returns True if the
        input name is valid and False otherwise
        group_name: name of the group to be validated
        """
        def check_single_group_name(group_name):
            return self.check_length(group_name) and self.check_name(group_name)

        if isinstance(group_name, list):
            return reduce(operator.mul, map(lambda x: check_single_group_name(x), group_name))
        else:
            return check_single_group_name(group_name)
            