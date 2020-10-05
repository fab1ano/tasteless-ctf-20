#!/usr/bin/env python
import typing
from pwn import *


context.log_level = 'info'


def check_data(encrypted_data: bytes):
    """Returns True if the keystream is likely to be 2-periodic."""
    # We only consider the most significant bit ...
    data_parsed = [x & 0x80 for x in encrypted_data]

    # ... and check if it is 2-periodic (2 keys with length 32 bit each)
    for i in range(8):
        if len(set(data_parsed[i::8])) != 1:
            return False
    return True


def main():
    """Runs the exploit."""

    if len(sys.argv) == 2 and sys.argv[1] == 'local':
        host, port = 'localhost', 10701
    else:
        host, port = 'okboomer.tasteless.eu', 10701

    while True:
        r = remote(host, port)

        # Send our key
        r.send(struct.pack('d', 4.5))

        # Receive the encrypted data
        encrypted_data = r.recvall()

        # Check data
        if check_data(encrypted_data):
            # Save the encrypted data and exit
            log.info('Saving data to "encrypted_data.raw"')
            with open('encrypted_data.raw', 'bw') as fptr:
                fptr.write(encrypted_data)
            break


if __name__ == '__main__':
    main()
