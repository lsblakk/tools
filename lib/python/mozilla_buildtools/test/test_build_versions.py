import unittest

from build.versions import bumpFile, nextVersion, BuildVersionsException

class TestBuildVersions(unittest.TestCase):
    def _doTest(self, original, expected):
        got = nextVersion(original)
        self.assertEquals(got, expected)

    def testNextVersionAlpha(self):
        self._doTest("4.1a2", "4.1a3")

    def testNextVersionBeta(self):
        self._doTest("3.5b3", "3.5b4")

    def testNextVersion3Part(self):
        self._doTest("4.0.1", "4.0.2")

    def testNextVersion4Part(self):
        self._doTest("5.0.0.4", "5.0.0.5")

    def testNextVersionBigNumber(self):
        self._doTest("5.0.0.24", "5.0.0.25")

    def testNextVersionFinalVersion(self):
        self._doTest("4.0", "4.0")

    def testNextVersionAlphaPre(self):
        self._doTest("4.3a4pre", "4.3a5pre")

    def testNextVersionBetaPre(self):
        self._doTest("5.6b2pre", "5.6b3pre")

    def testNextVersion3PartPre(self):
        self._doTest("2.0.3pre", "2.0.4pre")

    def testNextVersion4PartPre(self):
        self._doTest("6.0.0.2pre", "6.0.0.3pre")

    def testNextVersionBigNumberPre(self):
        self._doTest("78.2.42.510pre", "78.2.42.511pre")

    def testNextVersionFinalVersionPre(self):
        self._doTest("4.0pre", "4.0pre")

unbumpedConfVarsSh = """\
# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is Mozilla.
#
# The Initial Developer of the Original Code is
# the Mozilla Foundation <http://www.mozilla.org/>.
# Portions created by the Initial Developer are Copyright (C) 2007
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Mark Finkle <mfinkle@mozilla.com>
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****

MOZ_APP_NAME=fennec
MOZ_APP_UA_NAME=Fennec

MOZ_APP_VERSION=4.0b5pre

MOZ_BRANDING_DIRECTORY=mobile/branding/nightly
MOZ_OFFICIAL_BRANDING_DIRECTORY=mobile/branding/official
# MOZ_APP_DISPLAYNAME is set by branding/configure.sh

MOZ_SERVICES_SYNC=1

MOZ_ENABLE_LIBXUL=1
MOZ_DISABLE_DOMCRYPTO=1

if test "$LIBXUL_SDK"; then
MOZ_XULRUNNER=1
else
MOZ_XULRUNNER=
MOZ_MORK=
MOZ_PLACES=1
fi"""

bumpedConfVarsSh = """\
# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is Mozilla.
#
# The Initial Developer of the Original Code is
# the Mozilla Foundation <http://www.mozilla.org/>.
# Portions created by the Initial Developer are Copyright (C) 2007
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Mark Finkle <mfinkle@mozilla.com>
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****

MOZ_APP_NAME=fennec
MOZ_APP_UA_NAME=Fennec

MOZ_APP_VERSION=4.0b6pre

MOZ_BRANDING_DIRECTORY=mobile/branding/nightly
MOZ_OFFICIAL_BRANDING_DIRECTORY=mobile/branding/official
# MOZ_APP_DISPLAYNAME is set by branding/configure.sh

MOZ_SERVICES_SYNC=1

MOZ_ENABLE_LIBXUL=1
MOZ_DISABLE_DOMCRYPTO=1

if test "$LIBXUL_SDK"; then
MOZ_XULRUNNER=1
else
MOZ_XULRUNNER=
MOZ_MORK=
MOZ_PLACES=1
fi"""
class TestBumpFile(unittest.TestCase):
    def _doTest(self, filename, oldContents, expectedContents, version):
        newContents = bumpFile(filename, oldContents, version)
        self.assertEquals(newContents, expectedContents)

    def testBumpVersionTxtNoChange(self):
        self._doTest("browser/config/version.txt", "3.5.4", "3.5.4", "3.5.4")

    def testBumpVersionTxt(self):
        self._doTest("browser/config/version.txt", "4.0b5", "4.0b6", "4.0b6")

    def testBumpVersionTxtToRC(self):
        self._doTest("browser/config/version.txt", "4.0b10", "4.0", "4.0")

    def testBumpDifferentlyNamedVersionTxt(self):
        self._doTest("mail/config/version-192.txt", "3.1b2", "3.1b3", "3.1b3")

    def testBumpMilestoneTxt(self):
        self._doTest("config/milestone.txt", "1.9.2.2", "1.9.2.3", "1.9.2.3")
    
    def testBumpMilestoneTxtPreVersion(self):
        self._doTest("js/src/config/milestone.txt",
                     "1.9.2.4pre", "1.9.2.5pre", "1.9.2.5pre")

    def testBumpDefaultVersionTxt(self):
        self._doTest("default-version.txt", "1.1.2pre", "1.1.3pre", "1.1.3pre")

    def testBumpConfVarsSh(self):
        self._doTest("confvars.sh", unbumpedConfVarsSh, bumpedConfVarsSh,
                     "4.0b6pre")

    def testBumpUnknownFile(self):
        self.assertRaises(BuildVersionsException, bumpFile, "random.txt",
                          "blahblah", "3.4.5")