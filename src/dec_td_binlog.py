# -*- coding: utf-8 -*-
# ------------------------------------------------------------------
# File:     dectdbinlog.py
# Author:   poping520
# Created:  2021/8/19
# Function: 
# ------------------------------------------------------------------

import hashlib
import binascii
import os
import sys

import ppyaes as aes


def hex_str(data: bytes):
    return binascii.hexlify(data).decode()


def gen_secret_key(salt: bytes) -> bytes:
    # pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
    return hashlib.pbkdf2_hmac('sha256', "cucumber".encode(encoding='UTF-8'), salt, 2)


def aes_encrypt(s_key: bytes, data: bytes) -> bytes:
    return aes.new(s_key, aes.MODE_ECB).encrypt(data)


def xor_frame(factor: bytes, frame: bytes) -> bytes:
    return bytes(a ^ b for (a, b) in zip(factor, frame))


def start(filepath: str):
    with open(filepath, mode='rb') as file:
        file.seek(0x21)

        s_key_salt = file.read(0x20)
        print('secret key salt', hex_str(s_key_salt))

        s_key = gen_secret_key(s_key_salt)
        print('secret key', hex_str(s_key))

        file.seek(0x45)
        factor_base = file.read(0x10)
        print('factor base: ', hex_str(factor_base))

        factor_sub = factor_base[:-4]
        print('factor sub: ', hex_str(factor_sub))

        factor_num = int.from_bytes(factor_base[-4:], byteorder='big', signed=False)

        file.seek(0x80)

        out_file = open(file.name + ".dec", mode="wb")

        while True:
            if file.tell() >= os.path.getsize(file.name):
                break

            factor = factor_sub + factor_num.to_bytes(4, byteorder='big', signed=False)
            enc_factor = aes_encrypt(s_key, factor)
            enc_frame = file.read(0x10)
            xor_data = xor_frame(enc_factor, enc_frame)
            print(f'factor: {hex_str(factor)}; decode frame: {hex_str(enc_frame)} -> {hex_str(xor_data)}')
            out_file.write(xor_data)
            factor_num += 1

        print("decode td.binlog finish")
        out_file.close()

        with open(out_file.name, mode='rb') as dec_file:
            dec_file.seek(0x29)
            sqlite_key = dec_file.read(0x20)
            print("sqlite key: ", binascii.hexlify(sqlite_key))


if __name__ == '__main__':
    if sys.argv is None or len(sys.argv) <= 1:
        print("usage: python dec_td_binlog.py [td.binlog file path]")
    else:
        start(sys.argv[1])
