# -*- coding: utf-8 -*-
# Copyright (C) 2015 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiAnalysisDetectReg(Signature):
    name = "antianalysis_detectreg"
    description = "尝试通过注册表键探测已安装的流量分析工具"
    severity = 3
    categories = ["anti-analysis"]
    authors = ["Optiv"]
    minimum = "1.2"

    def run(self):
        reg_indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Wireshark\.exe$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Wireshark$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Fiddler\.exe$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Fiddler2\.exe$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Fiddler2$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Fiddler2$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\SOFTWARE\\\\IEInspectorSoft.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\IEHTTPAnalyzer\.HTTPAnalyzerAddon$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\IEHTTPAnalyzerStd\.HTTPAnalyzerStandAlone$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\Charles\.AMF\.Document$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?XK72\\ Ltd\\ folder$",
        ]
        found = False
        for indicator in reg_indicators:
            reg_match = self.check_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                for match in reg_match:
                    self.data.append({"key" : match })
                found = True
        return found
