#!/usr/bin/env python3
# file:     extract-Stamp-From-TgzFile.py
# author:   Photubias <github.com/tijldeneut> & yunzheng <github.com/yunzheng>
# 
### Open support.citrix.com. Download "Citrix ADC Release" nCore package and save as build-14.1-47.46_nc_64.tgz.
###   That's all that is needed together with this script
### The rdx_en.json.gz file is found at build-14.1-47.46_nc_64.tgz\build_zion_47_46_nc_64.tar\ns-14.1-47.46-gui.tar\vpn\js\rdx\core\lang\rdx_en.json.gz

import tarfile, io, datetime, re, sys

def main(sFilename):
    version = re.findall(r'\d+.\d+-\d+.\d+',sFilename)[0]
    tarFile1 = tarfile.open(sFilename,'r:gz')

    oNSfile = tarFile1.extractfile(tarFile1.getmember(f'ns-{version}-gui.tar'))
    bNSfile = oNSfile.read()
    tarNSfile = tarfile.open(fileobj=io.BytesIO(bNSfile))

    oRDXfile = tarNSfile.extractfile(tarNSfile.getmember('vpn/js/rdx/core/lang/rdx_en.json.gz'))
    bRDXfile = oRDXfile.read()

    vhash = ''
    for tinfo in (t for t in tarNSfile if t.name.endswith('index.html')):
        for line in tarNSfile.extractfile(tinfo):
            if b'?v=' in line:
                _, _, vhash = line.partition(b'?v=')
                vhash, _, _ = vhash.partition(b'"')
                vhash = vhash.decode()

    if bRDXfile.startswith(b'\x1f\x8b\x08\x08') and b'rdx_en.json' in bRDXfile: stamp = int.from_bytes(bRDXfile[4:8], 'little')
    dt = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc)
    return '{},{},{}'.format(dt, stamp, version)

if __name__ == '__main__':
    if len(sys.argv)<2: exit('Error: please provide filename as parameter. E.g. extract-Stamp-From-TgzFile.py build-14.1-47.46_nc_64.tgz')
    sFilename = sys.argv[1]
    print(f'Parsing file {sFilename}, might take some time')
    (dt,stamp,version) = main(sFilename).split(',')
    #print('Extracted timestamp: {},{},{},{}'.format(dt, stamp, vhash, version))
    print('Extracted timestamp: {},{},{}'.format(dt, stamp, version))