#!env -S APP_PORT=1338 LOGLEVEL=DEBUG python3

import os, logging, itertools, socket, inspect, time
from socketserver import BaseRequestHandler, ForkingTCPServer, StreamRequestHandler
from typing import Any, Callable, Generator, Tuple
from random import getrandbits, seed
from math import ceil

class ForkingTCPv6Server(ForkingTCPServer):
    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: Callable[[Any, Any, ForkingTCPServer], BaseRequestHandler], bind_and_activate: bool = ...) -> None:
        self.address_family = socket.AF_INET6
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

logging.basicConfig(level=os.environ.get("LOGLEVEL", "info").upper(), format="{asctime} ┃ {name} ┃ {msg}", datefmt="%H:%M:%S", style="{", )
addr = ("::", int(os.environ["APP_PORT"]))

r"""
we are using the multiplicative cyclic group induced by g in mod p.
because p is prime any g ∈ [2,p) is a generator and it generates all q=p-1 elements (the order of the group), see https://en.wikipedia.org/wiki/Euler%27s_totient_function#Euler's_product_formula.
it also follows that there is no efficient algorithm for dlog, see https://en.wikipedia.org/wiki/Discrete_logarithm#Cryptography.

in the following [z] will be used to express g^z mod p


this means that for any g ∈ [2,p): p is the smallest integer n for which g ≡ g^n  mod p.


these are public parameters so feel free to generate your own p:
    openssl prime -generate -safe -bits 4096 -hex
g can be any number ∈ [2,p), 1 is the only element that is not a generator as it is the neutral element.

changing these parameters will break your service for a short time as old private values do not work anymore.
"""
p = int('CA5FD16F55E38BC578BD1F79D73CDB7A93CE6E142C704AA6829620456989E76C335CBC88E56053A170BD1A7744D862C5B95BFA2A6BEC9AECF901C5616FFAA70FD8D338E46D2861242B00052F36FE7F87A180284D64CFF42F943CFC53C9992CD1C601337BC5B86C32FC17148D4983E8005764BC0927B21A473E9E16E662AFA7DF96ACDD8D877F07510D06D29EAC7E67AFC600C1BD51DB10C81179D2FDF8BE03B0BE4689777C074FBEB300E8CBD7F0F14AEF6611E5017ECBF682E222873326DD181EE472BA383B1E34DB087FDD00015FFD70F5FD3A10AC89527F5E0FE5578D006E2F50F05E74EC3159A7D460E8374556B1D4636F197C784177AD0D20FA6D467E29BE90FF861071175A3B7F9689FE97A3E41DE1835428350EB8D586FD3036090920D2B1E43553E83937C87E81B5C2036D96F1AEBCB1A6E1FF1E178DAC6D970703250F9AF4914B0F045A5A0911336B091063F44B7FE540FF97B929777F9854CA3FA84D365A14518A5CB3967465DF77F7B57565532375E1AEA56EEEA01771B03911871303153B85970E9F9C6060A01ED2266C65F452384853A7F2359AF66DC932ACBBFBAB640E77DB685F461D58A525470EE93D1713676E7A28D1EAF44FF54593BA459331932E6E7643017FD794AE621338F615EA3AADEBA80844B4B405C70AD0F3920D9FFD6456C4D3CE80E6032AA60BCC90868926E3F00BC5EE6CF1A8BDED5FFADB', 16)
g = 0x1337

q = p-1  # φ(p), assuming p is prime

assert pow(g, q, p) == 1, "There is something wrong with your public parameters, most likely your p is not prime"
logging.debug(f"using public paremters g={g:#x} p={p:#x}")

notes_dir = os.path.join(os.path.dirname(__file__), "notes")
filenamelength_max = os.statvfs(notes_dir).f_namemax
filesize_max = 0x100
filename_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-"
keylen_hex_max = ceil(p.bit_length()/4)
keylen_byte_max = ceil(p.bit_length()/8)
prompt = "> "

def verify(y :int, t :int, c :int, s :int) -> bool:
    return pow(g, s, p) == (t * pow(y, c, p)) % p

def sample_random_element() -> int:

    e = getrandbits(p.bit_length()-1)
    while e == 0:  # 0 is not part of the group
        e = getrandbits(p.bit_length()-1)

    return e

def iter_note_titles() -> Generator[str, None, None]:
    for ftitle in os.listdir(notes_dir):
        if ftitle.startswith("."):
            # skip .gitignore
            continue
        yield ftitle

def cleanup_old_files():
    current_time = time.time()
    for title in iter_note_titles():
        note_path = os.path.join(notes_dir, title)
        modified_time = int( os.stat(note_path).st_mtime )
        timeδ_minutes = (current_time - modified_time)//60
        if timeδ_minutes > 20:
            logging.debug(f"deleting {title}, it is {timeδ_minutes} minutes old")
            os.remove(note_path)

def create_note(title :str, key :int, content :str):
    if not all(c in filename_alphabet for c in title):
        e = OSError()
        e.strerror = f"note name may only contain '{filename_alphabet}'"
        raise e

    note_file = os.path.join(notes_dir, title)
    with open(note_file, 'xb') as f:
        seed(0)
        f.write(key.to_bytes(keylen_byte_max, byteorder='big'))
        f.write(b"\n")
        bbb = bytes(c^r for c, r in zip(content.encode("utf-8"), (getrandbits(8) for _ in itertools.count())))
        f.write(bbb)
        seed()

    return

def read_note(title :str) -> str:
    if not all(c in filename_alphabet for c in title):
        e = OSError()
        e.strerror = f"filename may only contain '{filename_alphabet}'"
        raise e

    note_file = os.path.join(notes_dir, title)
    with open(note_file, 'rb') as f:
        seed(0)
        f.seek(keylen_byte_max+1)
        content = bytes(c^r for c, r in zip(b"".join(f), (getrandbits(8) for _ in itertools.count()))).decode("utf-8")
        seed()

    return content


def read_key(title :str) -> int:
    if not all(c in filename_alphabet for c in title):
        e = OSError()
        e.strerror = f"filename may only contain '{filename_alphabet}'"
        raise e

    note_file = os.path.join(notes_dir, title)
    with open(note_file, 'rb') as f:
        key = int.from_bytes(f.read(keylen_byte_max+1).rstrip(b"\n"), byteorder='big')
    return key

class NotesFromTheFutureHandler(StreamRequestHandler):

    def setup(self) -> None:
        self._commands = {
            "help": self.help,
            "ls": self.ls,
            "create": self.create,
            "read": self.read,
            "exit": None,
            "quit": None,
        }
        self.l = logging.getLogger(f"[{self.client_address[0]}]:{self.client_address[1]}")
        return super().setup()

    def handle(self) -> None:

        cleanup_old_files()

        try:
            self.send_line(f"""Note Taking Service by Doc Brown
Time Travel can get very confusing and taking notes helps a lot!
However it is very hard to get a hold of an ssl implementation in lets say 1885.
So the authentication mechanism used here is timeless, no ssl or other things required.
To store and retrieve your note you just need to remember a single number,
so it can even be used when you only have a connection and a basic calculator (no roads required)!

Im using a zero knowledge proof called the Schnorr Protocol.
It verifies that the proover knows the witness x that satisfies [x] = y where [x] := g^x mod q.
see https://en.wikipedia.org/wiki/Proof_of_knowledge#Schnorr_protocol for more details.
It is zero knowledge meaning the witness (x) is not exposed to this service at any time

The protocol works like this, you are the prover:
                    Verifier ____ Prover

                             <--- [r], r from Z_q
                  c from Z_q --->
                             <--- s := r + c·x % q
   verify [s] == [r]·y^c % q

In this instance public parameters g={g:#x} and p={p:#x} are used.

Truly future stuff here.

Dr. Emmett Brown Enterprise is not liable for the loss of any note that is, will be or was saved on this service.""")
            self.help()

            while True:
                self.l.debug("prompting")
                self.send_line(prompt, end="")
                try:
                    line = self.read_line().split()
                except OSError:  # closed stream
                    break

                if not line:
                    continue

                if line[0] not in self._commands:
                    self.send_line(f"command '{line[0]}' not found")
                    self.help()
                    continue

                f = self._commands[line[0]]
                if f is None:  # exit or quit command
                    break

                self.l.debug(f"executing command: '{' '.join(line)}'")
                try:
                    f(*line[1:])
                except TypeError as e:
                    self.send_line(f"{e}")

        except (BrokenPipeError,):  # add more uninteresting exceptions as you please
            pass


    def help(self):
        self.send_line("valid commands are:")
        for c, f in self._commands.items():
            argstr = " ".join(name for name in inspect.signature(f).parameters) if f is not None else ""
            self.send_line(f"\t{c} {argstr}")


    def ls(self):
        for ftitle in iter_note_titles():
            self.send_line(f"{ftitle}")


    def create(self, title :str):

        try:
            existing_y = read_key(title)
        except OSError as e:
            existing_y = None

        if existing_y is not None:
            self.send_line(f"failed creating note {title}, it already exists with y={existing_y:#x}")
            return
        self.send_line("Ok")

        y = self.recv_value("Please provide the y with which the file will be secured")
        if not self.verify_knowledge(y):
            self.l.warning(f"failed creating '{title}'")
            return

        self.send_line(f"You may now send the contents of that note (send an empty line to stop, maximum {filesize_max} bytes):")
        quota = filesize_max
        content = ""
        while quota > 0:
            line = self.read_line(max_size=quota)
            if line == "\n":
                break
            content += line
            quota = filesize_max - len(line.encode("utf-8"))

        self.l.info(f"creating '{title}'")
        try:
            create_note(title, y, content)
        except OSError as e:
            self.send_line(f"failed creating note: {e.strerror}")
            return
        self.send_line(f"created note {title}")


    def read(self, title :str) -> None:

        try:
            y = read_key(title)
        except OSError as e:
            self.send_line(f"failed reading key for note '{title}': {e.strerror}")
            return
        self.send_line("Ok")

        if not self.verify_knowledge(y):
            self.l.warning(f"failed read attempt for '{title}'")
            return

        try:
            content = read_note(title)
        except OSError as e:
            self.send_line(f"failed reading key for note '{title}': {e.strerror}")
            return
        self.l.info(f"success read '{title}'")
        self.send_line("Here are the contents of the note (empty line is last line):")
        self.send_line(content)
        self.send_line()


    # === helpers ===
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

    def recv_value(self, msg :str) -> int:
        self.send_line(f"{msg} <--", end="")
        v = int(self.read_line().strip(), 16)
        return v

    def read_line(self, max_size :int =-1) -> str:
        return self.rfile.readline(max_size).decode("utf-8")

    def send_value(self, msg :str, v :int) -> None:
        self.send_line(f"{msg} -->{v:#x}")

    def send_line(self, msg :str ="", end :str ="\n") -> None:
        self.request.sendall(f"{msg}{end}".encode("utf-8"))


if __name__ == "__main__":
    with ForkingTCPv6Server(addr, NotesFromTheFutureHandler) as server:
        print(f"Serving at {addr[0]}:{addr[1]}")
        server.serve_forever()
