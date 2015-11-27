# -*- coding: utf-8 -*-
# Copyright (C) 2012-2015 KillerInstinct
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class Office_Macro(Signature):
    name = "office_macro"
    description = "Office文件中包含宏（macro）"
    severity = 2
    categories = ["office"]
    authors = ["KillerInstinct"]
    minimum = "1.3"

    def run(self):
        ret = False
        if "static" in self.results and "office" in self.results["static"]:
            # 97-2003 OLE and 2007+ XML macros
            if "Macro" in self.results["static"]["office"]:
                if "Code" in self.results["static"]["office"]["Macro"]:
                    ret = True
                    total = len(self.results["static"]["office"]["Macro"]["Code"])
                    if total > 1:
                        self.description = " Office文件包含了 %s 个 macros." % str(total)
            # 97-2003 XML macros
            if not ret and "strings" in self.results:
                header = False
                for line in self.results["strings"]:
                    if "<?xml" in line:
                        header = True
                    if header and 'macrosPresent="yes"' in line:
                        ret = True
                        self.description = " Office文件包含了一个基于 MSO/ActiveMime 的macro "
                        self.severity = 3
                        break

        # Check for known lures
        if ret and "strings" in self.results:
            lures = ["bank account",
                     "enable content",
                     "tools > macro",
                     "macros must be enabled",
                     "enable macro",
                    ]
            positives = list()
            for string in self.results["strings"]:
                for lure in lures:
                    if lure in string.lower():
                        if string not in positives:
                            positives.append(string)
                            self.weight += 1

            if positives != []:
                self.severity = 3
                self.description += " 文件还包含常见钓鱼(phishing)欺诈相关字符串 "
                for positive in positives:
                    self.data.append({"Lure": positive})

        # Increase severity on office documents with suspicious characteristics
        if ret and "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    words = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["num_words"]
                    if words == "0" or words == "None":
                        self.severity = 3
                        self.weight += 2
                        self.data.append({"content" : "文件无内容."})

        if ret and "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    time = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["total_edit_time"]
                    if time == "0" or time == "None":
                        self.severity = 3
                        self.weight += 2
                        self.data.append({"edit_time" : "文件无修改时间."})
                        
        if ret and "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    pages = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["num_pages"]
                    if pages == "0" or pages == "None":
                        self.severity = 3
                        self.weight += 2
                        self.data.append({"no_pages" : "该文件似乎没有页面可能被它所恶意或故意损坏造成的."})

        if ret and "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    author = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["author"]
                    if author == "1" or author == "Alex" or author == "Microsoft Office":
                        self.severity = 3
                        self.weight += 2
                        self.data.append({"author" : "该文件似乎是由一个已知的假作者创建的一个自动文档创建工具包."})

        return ret
