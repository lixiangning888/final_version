# -*- coding: utf-8 -*-
# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PreventsSafeboot(Signature):
    name = "prevents_safeboot"
    description = "通过删除注册表键尝试屏蔽SafeBoot"
    severity = 3
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "1.2"

    def run(self):
        if self.check_delete_key(pattern=".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\SafeBoot\\\\.*", regex=True):
            return True
        return False
