#!/usr/bin/env python3
import struct
import typing
import socketserver
import string
from random import SystemRandom, choice
from binascii import crc32

class Hey(Exception):
    pass

class Oops(Exception):
    pass

TEXT = ''.join(choice(string.ascii_letters) for i in range(0x600))

random = SystemRandom()

def clip(x: float, minimum: float, maximum: float) -> float:
    if x < minimum:
        return minimum
    if x > maximum:
        return maximum
    return x


def chaotic_map(x: float, my_secret: float, q: float):
    r = my_secret if x <= my_secret else 1 - my_secret
    return ((-q) / (r ** 2)) * (my_secret - x) ** 2 + q


def coupled_chaotic_maps(
    v: typing.Tuple[float, float], my_secret: float, b: float, c: float
) -> typing.Tuple[float, float]:
    x, y = v
    x = (1 - y) * chaotic_map(x, my_secret, b)
    y = (1 - x) * chaotic_map(y, my_secret, c)

    if v == (x,y):
        print(v)
        raise Oops

    return x, y


def prng(my_secret, b, c, init=(0.45, 0.55), transient=1024):
    v = init

    for i in range(transient):
        print(f"{i}: {v}")
        v = coupled_chaotic_maps(v, my_secret, b, c)

    while True:
        new_v = coupled_chaotic_maps(v, my_secret, b, c)
        v = new_v
        random_bytes = struct.pack("d", v[0]+v[1])
        print("Random bytes: {}, crc32: {}".format(hex(crc32(random_bytes)), struct.pack("I", crc32(random_bytes))))
        yield from struct.pack("I", crc32(random_bytes))


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        client_secret = struct.unpack("d", data)[0]

        if client_secret >= 5 or client_secret <= 0:
            raise Hey

        # my secret
        q = 1 - (random.random()/10)
        r = 1 - (random.random()/10)

        # Create a shared state from the client secret and my secret
        keystream = prng((5+client_secret)/10, q,r)

        ct = bytes(a ^ b for a, b in zip(TEXT.encode(), keystream))

        self.request.sendall(ct)
        self.request.close()

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 10701

    ThreadingTCPServer.allow_reuse_address = True

    with ThreadingTCPServer((HOST, PORT), Handler) as server:
        server.serve_forever()
