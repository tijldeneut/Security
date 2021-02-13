#! /usr/bin/env python3
''' 
	Copyright 2015 Photubias(c)

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.

        File name snmpautoenum.py
        written by tijl[dot]deneut[at]howest[dot]be

        This script will scan a whole range of IP addresses and store all their SNMP OIDs.
        They are stored in text-files called <ipaddress>.snmp
        After that, the script can parse these large files,
           selecting only the strings into stringresults.txt
           and also only *some* strings like admin into smallresults.txt
           this last file will also including preceding and following lines (+5 & -5)
        This script works on Linux and Windows, for Windows get snmptools here:
        http://sourceforge.net/projects/net-snmp/files/ (use setup but uncheck *all* options)
        Linux' version works better and faster!
'''
## Imports
import sys, os, socket, subprocess, argparse, glob, re
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat

## Global variables, change at will
keywords = ['admin','root','pass','failure','traphost']
bigtxt='stringresults.txt'
smalltxt='smallresults.txt'

## Functions
# Function to get local IP of the machine
def get_lan_ip():
    if os.name == 'nt':
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror as err:
            print('Cannot resolve hostname: ', socket.gethostname(), err)
            ip = '127.0.0.1'

    else:
        interfaces = ["eth0","eth1","eth2","wlan0","wlan1","wifi0","ath0","ath1","ppp0"]
        for ifname in interfaces:
            try:
                proc = subprocess.Popen("ip -4 addr show " + ifname + " | grep -oP '(?<=inet\s)\d+(\.\d+){3}'",shell=True, stdout=subprocess.PIPE)
                ip = proc.stdout.readlines()[0].decode().replace('\n','')
                break
            except IOError:
                pass
    return ip

# 4 Functions to convert CIDR notation into IP array
def ip2bin(ip):
    b = ''
    inQuads = ip.split('.')
    outQuads = 4
    for q in inQuads:
        if q != '':
            b += dec2bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += '00000000'
        outQuads -= 1
    return b

def dec2bin(n,d=None):
    s = ''
    while n>0:
        if n&1:
            s = '1'+s
        else:
            s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "": s = "0"
    return s

def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

def get_ips(cidr):
    iplist=[]
    parts = cidr.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    if subnet == 32:
        iplist.append(bin2ip(baseIP))
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            iplist.append(bin2ip(ipPrefix + dec2bin(i, (32-subnet))))
    return iplist

# Function to be threaded to actually scan one IP
def scanIP(args):
    ip = args[0]
    if len(args) == 1: string = 'public'
    else: string = args[1]
    if len(args) < 3: timeout = 2
    else: timeout = args[2]
    
    print('Starting scan on: ' + str(ip))
    if os.name != 'nt':
        proc = subprocess.Popen("snmpbulkwalk -On -t"+str(timeout)+" -r1 -v2c -c '"+string+"' "+str(ip)+" 1 | grep -v 'Timeout' >"+str(ip)+".snmp 2>&1", shell=True)
    else:
        proc = subprocess.Popen("snmpbulkwalk -On -t"+str(timeout)+" -r1 -v2c -c "+string+" "+str(ip)+" 1 2> nul 1> "+str(ip)+".snmp", shell=True)
    proc.wait()
    statinfo = os.stat(str(ip) + '.snmp')
    if statinfo.st_size == 0:
        if os.name != 'nt':
            subprocess.Popen('rm ' + str(ip) + '.snmp', shell=True)
        else:
            subprocess.Popen('del ' + str(ip) + '.snmp', shell=True)
                        
# Function to detect location of a program (for windows the exe-suffix is needed)
def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program): return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file): return exe_file

    return None

# Function to actually perform all parsing
def parseBulk(f,bulkhandler,finehandler,keywordarr):
    name = f.split('.snm')[0]
    bfrlines = []   # Let's store a buffer to write if we find anything
    linestowrite=0  # Number of lines left to write
    for line in open(f, 'r'):
        bfrlines.append(line) # add line to buffer
        if len(bfrlines)==7:  # if bufferlength is 7, remove the oldest lines
            bfrlines = bfrlines[1:]
        if linestowrite:      # if linestowrite is not zero
            linestowrite-=1
            finehandler.write(name+':'+line)
            if linestowrite==0:
                finehandler.write('\n')
        if "STRING" in line and not 'Hex' in line:
            bulkhandler.write(name+':'+line)
            if linestowrite==0 and re.search("|".join(keywordarr), line.lower()): # Fine check is not needed when buffer is still being written
                # Write the 5 previous lines from buffer content
                for l in bfrlines:
                    finehandler.write(name+':'+l)
                # Set linestowrite to 5 so next 5 lines are written
                linestowrite=5

# Function to start the parsing
def parseRoutine(regexfile = ''):
    if regexfile != '':
        keywordarr = []
        with open(regexfile,'r') as f:
            for x in f:
                keywordarr.append(x.replace("\n",""))
    else:
        keywordarr = keywords
    os.system('cls' if os.name == 'nt' else 'clear')
    print('Parsing ' + str(len(glob.glob1('','*.snmp'))) + ' files')
    print('--------------------------------------------------------------------------------')
    ## First clean files (will delete previous bulk parses)
    try: os.remove(bigtxt)
    except OSError: pass
    try: os.remove(smalltxt)
    except OSError: pass
    ## Then generate filelist and create bigresult
    filelist= glob.glob("*.snmp")
    bulkfile=open(bigtxt,'w')
    finefile=open(smalltxt,'w')
    for f in filelist:
        parseBulk(f,bulkfile,finefile,keywordarr)
    bulkfile.close()
    finefile.close()
    if os.name == 'nt':
        proc = subprocess.Popen('type '+bigtxt+' 2> nul | find /C "."',shell=True, stdout=subprocess.PIPE)
    else:
        proc = subprocess.Popen('cat '+bigtxt+' | wc -l',shell=True, stdout=subprocess.PIPE)
    numberoflines = int(proc.stdout.readlines()[0].decode().replace("\n",""))
    print('Done parsing, ' + bigtxt + ' has ' + str(numberoflines) + ' lines')
    if numberoflines == 0:
        os.remove(bigtxt)
        print('    so I removed it')
    print('--------------------------------------------------------------------------------')
    if os.name == 'nt':
        proc=subprocess.Popen('type '+smalltxt+' 2> nul | find /C "."',shell=True, stdout=subprocess.PIPE)
    else:
        proc=subprocess.Popen('cat '+smalltxt+' | wc -l',shell=True, stdout=subprocess.PIPE)
    numberoflines = int(proc.stdout.readlines()[0].decode().replace("\n",""))
    print('Done parsing, ' + smalltxt + ' has ' + str(numberoflines) + ' lines.')
    if numberoflines == 0:
        os.remove(smalltxt)
        print('    so I removed it')

### The program
## The Banner
os.system('cls' if os.name == 'nt' else 'clear')
print("""
[*****************************************************************************]
                      --- SNMP Automatic Enumeration ---
This script will automatically enumerate a complete network and parsing.
However, it will need your expert guidance...
Just run it without arguments, or provide arguments of your choice
-> This script relies on 'snmpbulkwalk', make sure this program works!
______________________/-> Created By Tijl Deneut(c) <-\_______________________
[*****************************************************************************]
""")
## Defaults and parsing arguments
parser = argparse.ArgumentParser()
parser.add_argument('-s', help="Provide subnet to scan (CIDR, e.g. 192.168.0.0/24)")
parser.add_argument('-c', help="Provide community string to use, default is 'public'", default='public')
parser.add_argument('-t', help="Provide number of threads to use, default is 64", default=64, type=int)
parser.add_argument('-r', help="Provide file with a regex per line, used for finegrained parse.", default='')
parser.add_argument('-p', help="Only perform parsing", action='store_true')
args = parser.parse_args()

SubNet = '192.168.0.0/24'
if args.s: SubNet = args.s
else: LocalIP = get_lan_ip()
ComString='public'
if args.c:
    ComString = args.c
Threads = 64
if args.t: Threads = int(args.t)
RegexFile = ''
if args.r:
    if os.path.isfile(args.r):
        RegexFile = args.r
    else:
        print('Error: File \'' + args.r + '\' does not exist!')
if args.p:
    parseRoutine(RegexFile)
    exit()

if os.name != 'nt' and not args.s:
    proc = subprocess.Popen("ip a | grep -m1 "+LocalIP+" | cut -d' ' -f6", shell=True, stdout=subprocess.PIPE)
    SubNet = proc.stdout.readlines()[0].decode().replace("\n","")
elif os.name == 'nt' and not args.s:
    proc = subprocess.Popen("netsh int ip show addr | findstr /I subnet", shell=True, stdout=subprocess.PIPE)
    SubNet = proc.stdout.readlines()[0].decode().replace("\n","").split()[2]

## Verify presence of snmpbulkwalk
if not which('snmpbulkwalk') and not which('snmpbulkwalk.exe'):
    print('!!! ERROR: snmpbulkwalk not found !!!')
    exit()

## Show overview of what to do
if len(sys.argv) == 1:
    print('You provided no arguments, I will assume this:')
print('Will now start: ')
print(sys.argv[0]+' -s '+SubNet+' -c '+ComString+' -t '+str(Threads))
print('')
input('When ready press [Enter]')

## Start the scan
print('')
print('Will now scan '+str(len(get_ips(SubNet)))+' IP addresses using '+str(Threads)+' threads')
print('with a community string of \''+ComString+'\'')
print('--------------------------------------------------------------------------------')
###------------------- SCANNING ---------------------------
iplist=get_ips(SubNet)

pool = ThreadPool(Threads)
pool.map(scanIP, zip(iplist, repeat(ComString)))

###------------------- REPORTING ----------------------------
print('--------------------------------------------------------------------------------')
os.system('cls' if os.name == 'nt' else 'clear')
print('All done, got '+str(len(glob.glob1('','*.snmp')))+' responses out of '+str(len(iplist))+' IPs')
if os.name == 'nt':
    proc = subprocess.Popen('type *.snmp 2> nul | find /C "."', shell=True, stdout=subprocess.PIPE)
else:
    proc = subprocess.Popen("cat *.snmp 2> /dev/null | wc -l", shell=True, stdout=subprocess.PIPE)
numberoflines = int(proc.stdout.readlines()[0].decode().replace("\n",""))
print('The result totals at ' + str(numberoflines) + ' line(s)')
print('')
print('-> Will now try to parse.')
print('First result will have ALL STRINGS, second one is more finegrained ...')
input('Press [Enter] when ready or Ctrl+C to finish')

###--------------------- PARSING ----------------------------
parseRoutine(RegexFile)
