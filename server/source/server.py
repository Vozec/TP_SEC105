import socket
import string
from random import choice
from os import getenv
from ast import literal_eval as leval
from hashlib import sha256
from Crypto.Util.number import long_to_bytes, bytes_to_long
from requests import post, get
from binascii import hexlify

asn1_sha256 = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'


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


class connection:
    def __init__(self, socket, client_address):
        self.l = logger('server', 'http://logger:5000')
        self.e = None
        self.n = None
        self.socket = socket
        self.hash = None
        self.verified = None
        self.l.log(f'Connexion accepted from {client_address}')

    def gen_challenge(self):
        self.m = ''.join([choice(string.printable) for _ in range(20)])
        self.l.log(f'[Authentification part] Challenge generated = {self.m}')
        return self.m

    def get_public(self):
        data = self.socket.recv(1024).decode('utf-8')
        self.l.log(f'[Pairing part] Public key received')
        self.e, self.n = leval(data)

    def send_challenge(self):
        self.l.log(f'[Authentification part] Challenge sended')
        self.socket.send(self.m.encode())

    def get_signature(self):
        data = self.socket.recv(4096).strip()
        self.l.log(f'[Authentification part] Data received')

        # # Sign: m = s^d % n
        data = long_to_bytes(pow(bytes_to_long(data), self.e, self.n))
        if asn1_sha256 not in data:
            return
        self.hash = data.split(asn1_sha256)[1]
        self.l.log(f'[Authentification part] Hash extracted (hex): {hexlify(self.hash).decode()}')

    def verify(self):
        valid_hash = sha256(self.m.encode()).digest()
        if valid_hash == self.hash:
            self.verified = True
        else:
            self.verified = False
        self.l.log(f'[Authentification part] Verification result: {str(self.verified)}')

    def send_message(self):
        self.l.log(f'Result message sended')
        msg = b'You successfully login !'
        if not self.verified:
            msg = b'There is a problem during auth part.'
        self.socket.send(msg)

    def close(self):
        self.socket.close()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', int(getenv('PORT'))))
    server_socket.listen()
    print(f"Server listening on '0.0.0.0':{getenv('PORT')}")

    while True:
        client_socket, client_address = server_socket.accept()

        c = connection(client_socket, client_address)
        c.get_public()
        c.gen_challenge()
        c.send_challenge()
        c.get_signature()
        c.verify()
        c.send_message()
        c.close()


if __name__ == '__main__':
    main()
