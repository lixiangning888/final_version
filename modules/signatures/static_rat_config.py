# -*- coding: utf-8 -*-
# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RATConfig(Signature):
    name = "static_rat_config"
    description = "包含提取出的RAT配置"
    severity = 3
    weight = 3
    categories = ["static"]
    authors = ["Optiv"]
    minimum = "1.3"

    def run(self):
        if "static" in self.results and "rat" in self.results["static"] and "name" in self.results["static"]["rat"] and len(self.results["static"]["rat"]["name"]):
            self.description = "包含RAT配置" + self.results["static"]["rat"]["name"] + " (see Static Analysis tab)"
            self.families = [ self.results["static"]["rat"]["name"] ]
            return True

        return False
