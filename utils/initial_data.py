import os
import sys
from time import time

sys.path.append(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from fame.core import fame_init
from fame.core.config import Config
from fame.core.internals import Internals


def create_types():
    types = Config.get(name='types')
    if types is None:
        types = Config({
            'name': 'types',
            'description': 'Mappings for file type determination.',
            'config': [
                {
                    'name': 'mappings',
                    'type': 'text',
                    'value': """[types]

application/x-dosexec = executable
application/x-mach-binary = macho
application/x-executable = elf
application/vnd.openxmlformats-officedocument.wordprocessingml.document = word
application/vnd.openxmlformats-officedocument.spreadsheetml.sheet = excel
application/msword = word
application/vnd.ms-excel = excel
application/vnd.ms-powerpoint = powerpoint
text/html = html
text/rtf = rtf
application/x-coredump = memory_dump
application/pdf = pdf
application/zip = zip
application/gzip = gzip
text/x-mail = eml
message/rfc822 = eml
application/CDFV2-unknown = msg
application/java-archive = jar

[details]

MIME entity, ISO-8859 text, with CRLF line terminators = word
MIME entity, ISO-8859 text, with very long lines, with CRLF line terminators = word
Dalvik dex file = dex
Mach-O = macho
ELF = elf
gzip compressed data = gzip
Java archive data = jar
Zip archive data = zip
PE32 executable = executable
PE32+ executable = executable
PDF document = pdf

[extensions]
elf = elf
oat = oat
odex = oat
macho = macho
dylib = macho
vdex = vdex
dex = dex
art = art
exe = executable
scr = executable
dll = executable
doc = word
docx = word
docm = word
xls = excel
xlsx = excel
xslm = excel
ppt = powerpoint
pptx = powerpoint
rtf = rtf
html = html
js = javascript
pdf = pdf
apk = apk
jar = jar
zip = zip
gzip = gzip
gz = gzip
msg = msg
eml = eml""",
                    'description': "In order to determine the file type, FAME will use the `python-magic` library. It will then try to find a match in 'mappings' for either the extension, the detailed type or the mime type (in this order of priority). If no matching type was found, the mime type will be used."
                }
            ]
        })

        types.save()


def create_internals():
    updates = Internals.get(name='updates')
    if updates is None:
        updates = Internals({
            'name': 'updates',
            'last_update': time()
        })

        updates.save()


def create_virustotal_configuration():
    vt = Config.get(name='virustotal')
    if vt is None:
        vt = Config({
            'name': 'virustotal',
            'description': 'VirusTotal API configuration, in order to be able to submit hashes.',
            'config': [
                {
                    'name': 'api_key',
                    'description': 'VirusTotal Intelligence API key.',
                    'type': 'str',
                    'value': None
                }
            ]})

        vt.save()

def create_reverseit_configuration():
    reverseit = Config.get(name='reverseit')
    if reverseit is None:
        reverseit = Config({
            'name': 'reverseit',
            'description': 'Reverseit API configuration, in order to be able to submit hashes.',
            'config': [
                {
                    'name': 'api_key',
                    'description': 'Reverseit API key.',
                    'type': 'str',
                    'value': None
                }
            ]})

        reverseit.save()

def create_initial_data():
    create_types()
    create_virustotal_configuration()
    create_reverseit_configuration()
    create_internals()


if __name__ == '__main__':
    fame_init()
    create_initial_data()
    print "[+] Created initial data."
