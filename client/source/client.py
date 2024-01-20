from pwn import *
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
from hashlib import sha256
from requests import post, get

context.log_level = 'critical'


class logger:
    def __init__(self, identity, server):
        self.identity = identity
        self.server = server

    def reset(self):
        get(f'{self.server}/api/reset')

    def log(self, message):
        try:
            post(f'{self.server}/api/add/{self.identity}', data={
                'message': message
            })
        except Exception as ex:
            print(ex)


class RSA:
    def __init__(self):
        self.e = 65537
        self.p = getPrime(1024)
        self.q = getPrime(1024)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = pow(self.e, -1, self.phi)

    def get_publickey(self):
        return self.e, self.n

    def get_privatekey(self):
        return self.d

    def encrypt(self, message):
        return pow(bytes_to_long(message), self.e, self.n)

    def decrypt(self, message):
        return long_to_bytes(pow(message, self.d, self.n))


class client:
    def __init__(self, url, port):
        self.l = logger('client', 'http://logger:5000')
        self.m = None
        self.url = url
        self.port = port

        self.l.log(f'Establishing TCP connection on port {self.port}')
        self.io = remote(self.url, self.port)
        self.rsa = RSA()



    def send_public(self):
        self.l.log(f'[Pairing part] Public key sended (e, n)')
        self.io.sendline(str(self.rsa.get_publickey()).encode())

    def get_challenge(self):
        self.m = self.io.recv(1024)
        self.l.log(f'[Authentification part] Challenge received')
        assert len(self.m) == 20

    def send_signed(self):
        self.l.log(f'[Authentification part] Signature created using sha256')
        hashed = sha256(self.m).digest()

        # PKCS-1.1 padding standard
        asn1_sha256 = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
        suffix = b'\x00' + asn1_sha256 + hashed
        msg = b'\x00\x01' + b'\xff' * (256 - 2 - len(suffix)) + suffix

        # Sign: s = m^e % n
        enc = self.rsa.decrypt(bytes_to_long(msg))
        self.l.log(f'[Authentification part] Signature sended')
        self.io.sendline(enc)

    def get_message(self):
        data = self.io.recvall(timeout=1).decode()
        self.l.log(f'[Authentification part] Result message received: {data}')
        return data

