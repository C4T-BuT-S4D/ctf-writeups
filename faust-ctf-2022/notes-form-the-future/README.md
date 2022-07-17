# FAUST CTF 2022 | Notes form the Future

A challenge from [FAUST CTF 2022](https://ctftime.org/event/1598) attack-defense competition.

# Description

The service is located at 1338 TCP port.

According to source file [app.py](service/src/app/app.py) this is a simple key-value storage, based on filesystem. Users can perform two operations on _notes_:

- list all existing notes (`ls`)
- put their note with name and some content (`create`)
- get note's content by name (`read`)

By the way, in this challenge `ls` was not needed, since [the checksystem](https://github.com/fausecteam/ctf-gameserver) provides all valid note's names, so we only want to use `read` command.

Obviously, there should be some kind of protection in order to prevent arbitrary access to every flag. And there is.

# Cryptography

The server implements a proof of knowledge protocol based on [Schnorr algorithm](https://en.wikipedia.org/wiki/Proof_of_knowledge#Schnorr_protocol), which is known as zero-knowledge.

The security of the protocol is based on [discrete logarithm](https://en.wikipedia.org/wiki/Discrete_logarithm) problem, and it could be vulnerable if the parameters are vulnerable. Let's look at them:

```python
p = 0xca5fd16f55e38bc578bd1f79d73cdb7a93ce6e142c704aa6829620456989e76c335cbc88e56053a170bd1a7744d862c5b95bfa2a6bec9aecf901c5616ffaa70fd8d338e46d2861242b00052f36fe7f87a180284d64cff42f943cfc53c9992cd1c601337bc5b86c32fc17148d4983e8005764bc0927b21a473e9e16e662afa7df96acdd8d877f07510d06d29eac7e67afc600c1bd51db10c81179d2fdf8be03b0be4689777c074fbeb300e8cbd7f0f14aef6611e5017ecbf682e222873326dd181ee472ba383b1e34db087fdd00015ffd70f5fd3a10ac89527f5e0fe5578d006e2f50f05e74ec3159a7d460e8374556b1d4636f197c784177ad0d20fa6d467e29be90ff861071175a3b7f9689fe97a3e41de1835428350eb8d586fd3036090920d2b1e43553e83937c87e81b5c2036d96f1aebcb1a6e1ff1e178dac6d970703250f9af4914b0f045a5a0911336b091063f44b7fe540ff97b929777f9854ca3fa84d365a14518a5cb3967465df77f7b57565532375e1aea56eeea01771b03911871303153b85970e9f9c6060a01ed2266c65f452384853a7f2359af66dc932acbbfbab640e77db685f461d58a525470ee93d1713676e7a28d1eaf44ff54593ba459331932e6e7643017fd794ae621338f615ea3aadeba80844b4b405c70ad0f3920d9ffd6456c4d3ce80e6032aa60bcc90868926e3f00bc5ee6cf1a8bded5ffadb
g = 0x1337
```

Surprisingly, the prime `p` is a [safe prime](https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes), here is the [factorization](http://factordb.com/index.php?query=825615069568423401321596519652534117405055611646324387787343752621669687184880237834296421550011293578012529118126243932866238186652402210246895094446694440653420748403669135715932889626570508161308333991787656072492285044547575484873244719258722037771555298288846096394505416284166434283854658450353737732219449806018498351320160907769553345256208923473449819267581068386661654806969886248971646991922190065947924378347465240408063358671309528163205948704108991084663296390999481312790315177694435503010061341593828336114427919602592848607168707960262759351153462282202463312328203640604295886569207207250924299611035056746598938744970848597358758947845299486279769821231492522754110450982154483657636264804953437596337119518335649055315984491302479712581090166329226455361393939202547644217876152285538643183579523138639777712905681719432966570450248986624460955637723717552278748902824854615505498890142889415352186762034132705659256430350308621572586337201338088916969392561042581809519865074713273145779634042156223568351625704328911933365630898320708427742127794200964128514479718844507196216066873093836979360288952051988990698572244921188200404625116842659273288248922164341961126159363877684987102422859014962145036668500698) of `p - 1`. So the calculation of discrete logarithm is not trivial.

We did't find any crypto-related vulnerabilities in the _implementation_ of protocol. But we've found another.

# Vulnerability

Schnorr protocol requires a source of entropy in order to generate random numbers. And there was a vulnerability. Let's look at the function:

```python
def sample_random_element() -> int:

    e = getrandbits(p.bit_length()-1)
    while e == 0:  # 0 is not part of the group
        e = getrandbits(p.bit_length()-1)

    return e
```

Seems legit? Yes, if it would be an abstract random implementation. But Python uses [MT19937](https://en.wikipedia.org/wiki/Mersenne_Twister) internally, and it's not safe. Well-known fact: this generator is predictable.

The number `e` is a raw output of MT19937, exactly 4095 bits (since `p` has 4096 bits), therefore it uses 128 numbers from MT19937 internal state. In order to attack the generator, we need to retrieve the full state. Since the single number has 32 bits and the state length is 624, we need 5 outputs of function (`624 * 32 / 4095 ~ 5`).

But one bit we don't know, because it was [truncated](https://github.com/python/cpython/blob/07aeb7405ea42729b95ecae225f1d96a4aea5121/Modules/_randommodule.c#L518) by `getrandbits()` function. This is not a problem, because we can bruteforce 5 bits and run the attack 32 times.

When we've recovered the full state of MT19937 generator, we could predict the next output of `sample_random_element()` function (only once, because then generator will be reloaded by another function in the challenge). And we can use this in order to prove the access to other flag:

```python
def verify_knowledge(self, y :int):
    self.send_line(f"Please proove you know x s.t. y = g^x in Z_q where g={g:#x} p={p:#x} and y={y:#x} to authenticate yourself.")
    self.send_line("All numbers are implicitly base 16")
    # <-- [r]
    t = self.recv_value("Please provide [r]")
    self.l.debug(f"<-- [r] {t:x}")
    # --> c
    c = sample_random_element()
    self.send_value("Here is your challenge c", c)
    self.l.debug(f"--> c {c:x}")
    # <-- s
    s = self.recv_value("Please provide r + c·x mod p-1")
    self.l.debug(f"<-- s {s:x}")
    if verify(y, t, c, s):
        self.send_line(f"verification succeeded")
        return True
    self.send_line(f"verification failed")
    return False
```

# Exploitation

Let's look at the algorithm:

1. server sends `y = g^x`
2. client sends `t = g^r`, where `r` is arbitrary chosen by client
3. server sends a random `c`
4. client sends `s = r + c*x`
5. server verifies that `g^s == t * y^c`

We can notice that with `t = y^(-c)` and `s = p - 1` the proof is valid:

```
g^s == t * y^c
g^(p - 1) == y^(-c) * y^c
1 == 1
```

So the scenario is straightforward:

1. Get 5 outputs of `sample_random_element()` function. It could be just five calls to `read <flag>`, then gathering all `c` values.

2. Recover the internal state of MT19937 generator, using any open-source utility (I've used [this](https://github.com/tna0y/Python-random-module-cracker/blob/master/randcrack/randcrack.py)).

3. Predict next 4095 output of MT19937 and get the next `c` value (the server will generate same value).

4. Call `read <flag>` again and retrieve `y`.

5. Calculate `t = y^(-c)` for given `y` and predicted `c`, then send `s = p - 1`.

6. Get the flag.

# Fix

The simplest fix is wasting bits of entropy, something like this:

```python
def sample_random_element() -> int:

    e = getrandbits(p.bit_length()-1)
    e = getrandbits(p.bit_length()-1)
    e = getrandbits(p.bit_length()-1)
    while e == 0:  # 0 is not part of the group
        e = getrandbits(p.bit_length()-1)

    return e
```

Now the prediction becomes harder. And it's enough for attack-defense CTF.
