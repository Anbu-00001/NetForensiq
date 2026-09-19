# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
import os, sys
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
from scapy.all import conf
from scapy.layers.dns import DNS
from capture import fastparse, fastdns
CAPS=[]
for d in ('reference_captures','synthetic_captures'):
    p=f'/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend/{d}'
    if os.path.isdir(p): CAPS+=[os.path.join(p,f) for f in sorted(os.listdir(p)) if f.endswith(('.pcap','.pcapng'))]
CAPS.append('/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/RealAttacksPCAP/4SICS-GeekLounge-151022.pcap')
tot=bad=0
for path in CAPS:
    for data,_ts,lt in fastparse.iter_frames(path):
        p=fastparse.parse(data,lt)
        if p is None: continue
        _s,_d,proto,sp,dp,_f,pay=p
        if 53 not in (sp,dp) or not pay: continue
        tot+=1
        try: ref=fastdns.from_scapy(DNS(pay[2:]) if proto=='TCP' else DNS(pay))
        except Exception: ref=None
        got=fastdns.parse(pay, over_tcp=(proto=='TCP'))
        if ref!=got:
            bad+=1
            if bad<=3:
                print(f"{os.path.basename(path)} proto={proto} payload={len(pay)} octets {pay[:24].hex()}")
                print(f"   scapy  : {ref}")
                print(f"   fastdns: {got}")
print(f"total DNS={tot} divergent={bad}")
