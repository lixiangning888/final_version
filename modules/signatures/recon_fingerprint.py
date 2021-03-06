# -*- coding: utf-8 -*-
# Copyright (C) 2012,2015 Claudio "nex" Guarnieri (@botherder), Optiv, Inc. (brad.spengler@optiv.com)
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

class Fingerprint(Signature):
    name = "recon_fingerprint"
    description = "收集信息以计算系统信息指纹(MachineGuid, DigitalProductId, SystemBiosDate)"
    severity = 3
    categories = ["recon"]
    authors = ["nex", "Optiv"]
    minimum = "1.2"

    def run(self):
        matches = 0

        indicators = [
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\DigitalProductId$",
            ".*\\\\Microsoft\\\\Cryptography\\\\MachineGuid$",
            ".*\\\\HARDWARE\\\\DESCRIPTION\\\\System\\\\SystemBIOSDate$",
        ]

        for indicator in indicators:
            if self.check_read_key(pattern=indicator, regex=True):
                matches += 1

        if matches >= 2:
            return True

        return False
