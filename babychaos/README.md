babychaos
=========

This challenge was part of the Tasteless CTF 2020.
I played with [Shellphish](https://ctftime.org/team/285).

356 points, 19 solves

Tags: `cry`, `chaos`

Challenge caption:
```
nc okboomer.tasteless.eu 10701

props to Mueslikoenig who helped make this.
```

One source file was available: `chall.py`


## Solution

Looking at [`chall.py`](./chall.py) we can see that the script starts a threaded TCP-Server and listens on port 10701.
For every incoming connection the `handle` function is triggered:

```python
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

        from secret import long_text_containing_flag
        ct = bytes(a ^ b for a, b in zip(long_text_containing_flag.encode(), keystream))

        self.request.sendall(ct)
        self.request.close()
```

It first reads a secret from the client which needs to be a float between 0 and 5.
The client secret and some random values are used to initialize a custom PRNG (`prng`).
With the custom PRNG the server encrypts a _long_ text which is supposed to contain the flag.
If we connect to the server it returns almost 0x600 bytes after we send a client secret (a packed float).
Those bytes must be the "encrypted" text with the flag.
Therefore, if we can somehow predict the values of the PRNG we can decrypt the text and get the flag.
But, we do not necessarily need to predict the PRNG values.
If the PRNG always returns the same value, we can run a dictionary attack and try to predict the key with an [xor-cracker tool](https://wiremask.eu/tools/xor-cracker/).

But how do we control the PRNG? Let's look at the code!

```python
def prng(a, b, c, init=(0.45, 0.55), transient=1024):
    v = init

    for _ in range(transient):
        v = coupled_chaotic_maps(v, a, b, c)

    while True:
        new_v = coupled_chaotic_maps(v, a, b, c)
        v = new_v
        random_bytes = struct.pack("d", v[0]+v[1])
        yield from struct.pack("I", crc32(random_bytes))
```

Some mysterious function `coupled_chaotic_maps` is called on a variable `v` for 1024 times and then used for creating the "random" keystream.
The values `b` and `c` are derived from random, `a` is derived from the client secret.
The `coupled_chaotic_maps` function only calls another function (`chaotic_map`), which performs mathematical operations on the current values of `v`, `a`, `b`, and `c`.
But `coupled_chaotic_maps` also contains a check:

```python
def coupled_chaotic_maps(
    v: typing.Tuple[float, float], a: float, b: float, c: float
) -> typing.Tuple[float, float]:
    x, y = v
    x = (1 - y) * chaotic_map(x, a, b)
    y = (1 - x) * chaotic_map(y, a, c)

    if v == (x,y):
        raise Oops

    return x, y
```

Thus, if `v` does not change after one iteration, an exception is raised.
Therefore, the PRNG will never reach a point, where it only returns a single value again and again.
_Spoiler_: It turns out, we can get close enough.

At this point I added some debug output to the python script (see [`chall_patched.py`](./chall_patched.py)) and looked at the values of the PRNG.
While playing with the client secret, I noticed that sometimes the PRNG periodically returns the same values!
In some cases it only toggled between two different pairs of values, where one of the values is close to zero (the client secret only seems to change the probability of that behaviour):

```
[...]
1009: (-5.202047107890553e-18, 0.9493756039938469)
1010: (-5.620437005377298e-18, 0.9531441251666807)
1011: (-5.202047107890553e-18, 0.9493756039938469)
1012: (-5.620437005377298e-18, 0.9531441251666807)
1013: (-5.202047107890553e-18, 0.9493756039938469)
1014: (-5.620437005377298e-18, 0.9531441251666807)
1015: (-5.202047107890553e-18, 0.9493756039938469)
1016: (-5.620437005377298e-18, 0.9531441251666807)
1017: (-5.202047107890553e-18, 0.9493756039938469)
1018: (-5.620437005377298e-18, 0.9531441251666807)
1019: (-5.202047107890553e-18, 0.9493756039938469)
1020: (-5.620437005377298e-18, 0.9531441251666807)
1021: (-5.202047107890553e-18, 0.9493756039938469)
1022: (-5.620437005377298e-18, 0.9531441251666807)
1023: (-5.202047107890553e-18, 0.9493756039938469)
[...]
```

Given this behaviour of the PRNG we only need to detect, when the keystream is 2-periodic and then perform a dictionary attack on the XOR-encryption with an 8-byte key.
I assumed that the "encrypted" text only contains 7-bit ASCII characters.
By looking at the most significant bit we can then determine, if the keystream is 2-periodic.
This is likely the case if the most significant bits of the first 8 bytes repeat every 8 bytes throughtout the entire "encrypted" text.

We can easily check this (see [`check_data`](https://github.com/fab1ano/tasteless-ctf-20/blob/master/babychaos/x.py#L9) in `x.py`).
Once the server provides a text which is likely "encrypted" with a 2-periodic keystream, we save the text blob and use an [xor-cracker](https://wiremask.eu/tools/xor-cracker/) to get the key and the original text.

You can find the exploit in [`x.py`](./x.py) and the decrypted text in [`decrypted_text.txt`](./decrypted_text.txt).

The flag is: `tstlss{0p3r4ti0n_M!nDfuCK_i5_a_fn0rD!}`.
