#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Simple AES cipher implementation in pure Python following PEP-272 API

Based on: https://bitbucket.org/intgr/pyaes/ to compatible with PEP-8.

The goal of this module is to be as fast as reasonable in Python while still
being Pythonic and readable/understandable. It is licensed under the permissive
MIT license.

Hopefully the code is readable and commented enough that it can serve as an
introduction to the AES cipher for Python coders. In fact, it should go along
well with the Stick Figure Guide to AES:
http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html

Contrary to intuition, this implementation numbers the 4x4 matrices from top to
bottom for efficiency reasons::

  0  4  8 12
  1  5  9 13
  2  6 10 14
  3  7 11 15

Effectively it's the transposition of what you'd expect. This actually makes
the code simpler -- except the ShiftRows step, but hopefully the explanation
there clears it up.

"""

####
# Copyright (c) 2010 Marti Raudsepp <marti@juffo.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
####


from array import array

# Globals mandated by PEP 272:
# http://www.python.org/dev/peps/pep-0272/
MODE_ECB = 1
MODE_CBC = 2
# MODE_CTR = 6

block_size = 16
# variable length key: 16, 24 or 32 bytes
key_size = None


def new(key, mode, iv=None):
    if mode == MODE_ECB:
        return ECBMode(AES(key))
    elif mode == MODE_CBC:
        if iv is None:
            raise ValueError("CBC mode needs an IV value!")
        return CBCMode(AES(key), iv)
    else:
        raise NotImplementedError


# AES cipher implementation
class AES(object):
    block_size = 16

    def __init__(self, key):
        self.setkey(key)

    def setkey(self, key):
        """Sets the key and performs key expansion."""

        self.key = key
        self.key_size = len(key)

        if self.key_size == 16:
            self.rounds = 10
        elif self.key_size == 24:
            self.rounds = 12
        elif self.key_size == 32:
            self.rounds = 14
        else:
            raise ValueError("Key length must be 16, 24 or 32 bytes")

        self.expand_key()

    def expand_key(self):
        """Performs AES key expansion on self.key and stores in self.exkey"""

        # The key schedule specifies how parts of the key are fed into the
        # cipher's round functions. "Key expansion" means performing this
        # schedule in advance. Almost all implementations do this.
        #
        # Here's a description of AES key schedule:
        # http://en.wikipedia.org/wiki/Rijndael_key_schedule

        # The expanded key starts with the actual key itself
        exkey = array('B', self.key)

        # extra key expansion steps
        if self.key_size == 16:
            extra_cnt = 0
        elif self.key_size == 24:
            extra_cnt = 2
        else:
            extra_cnt = 3

        # 4-byte temporary variable for key expansion
        word = exkey[-4:]
        # Each expansion cycle uses 'i' once for Rcon table lookup
        for i in range(1, 11):

            # key schedule core:
            # left-rotate by 1 byte
            word = word[1:4] + word[0:1]

            # apply S-box to all bytes
            for j in range(4):
                word[j] = aes_sbox[word[j]]

            # apply the Rcon table to the leftmost byte
            word[0] ^= aes_Rcon[i]
            # end key schedule core

            for z in range(4):
                for j in range(4):
                    # mix in bytes from the last subkey
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)

            # Last key expansion cycle always finishes here
            if len(exkey) >= (self.rounds + 1) * self.block_size:
                break

            # Special substitution step for 256-bit key
            if self.key_size == 32:
                for j in range(4):
                    # mix in bytes from the last subkey XORed with S-box of
                    # current word bytes
                    word[j] = aes_sbox[word[j]] ^ exkey[-self.key_size + j]
                exkey.extend(word)

            # Twice for 192-bit key, thrice for 256-bit key
            for z in range(extra_cnt):
                for j in range(4):
                    # mix in bytes from the last subkey
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)

        self.exkey = exkey

    def add_round_key(self, block, round):
        """AddRoundKey step. This is where the key is mixed into plaintext"""

        offset = round * 16
        exkey = self.exkey

        for i in range(16):
            block[i] ^= exkey[offset + i]

        # print 'AddRoundKey:', block

    def sub_bytes(self, block, sbox):
        """
        SubBytes step, apply S-box to all bytes

        Depending on whether encrypting or decrypting, a different sbox array
        is passed in.
        """

        for i in range(16):
            block[i] = sbox[block[i]]

        # print 'SubBytes   :', block

    def shift_rows(self, b):
        """
        ShiftRows step in AES.

        Shifts 2nd row to left by 1, 3rd row by 2, 4th row by 3

        Since we're performing this on a transposed matrix, cells are numbered
        from top to bottom first::

          0  4  8 12 ->  0  4  8 12  -- 1st row doesn't change
          1  5  9 13 ->  5  9 13  1  -- row shifted to left by 1 (wraps around)
          2  6 10 14 -> 10 14  2  6  -- shifted by 2
          3  7 11 15 -> 15  3  7 11  -- shifted by 3
        """

        b[1], b[5], b[9], b[13] = b[5], b[9], b[13], b[1]
        b[2], b[6], b[10], b[14] = b[10], b[14], b[2], b[6]
        b[3], b[7], b[11], b[15] = b[15], b[3], b[7], b[11]

        # print 'ShiftRows  :', b

    def shift_rows_inv(self, b):
        """
        Similar to shift_rows above, but performed in inverse for decryption.
        """
        b[5], b[9], b[13], b[1] = b[1], b[5], b[9], b[13]
        b[10], b[14], b[2], b[6] = b[2], b[6], b[10], b[14]
        b[15], b[3], b[7], b[11] = b[3], b[7], b[11], b[15]

        # print 'ShiftRows  :', b

    def mix_columns(self, block):
        """MixColumns step. Mixes the values in each column"""

        # Cache global multiplication tables (see below)
        mul_by_2 = gf_mul_by_2
        mul_by_3 = gf_mul_by_3

        # Since we're dealing with a transposed matrix, columns are already
        # sequential
        for col in range(0, 16, 4):
            v0, v1, v2, v3 = block[col:col + 4]

            block[col] = mul_by_2[v0] ^ v3 ^ v2 ^ mul_by_3[v1]
            block[col + 1] = mul_by_2[v1] ^ v0 ^ v3 ^ mul_by_3[v2]
            block[col + 2] = mul_by_2[v2] ^ v1 ^ v0 ^ mul_by_3[v3]
            block[col + 3] = mul_by_2[v3] ^ v2 ^ v1 ^ mul_by_3[v0]

        # print 'MixColumns :', block

    def mix_columns_inv(self, block):
        """
        Similar to mix_columns above, but performed in inverse for decryption.
        """
        # Cache global multiplication tables (see below)
        mul_9 = gf_mul_by_9
        mul_11 = gf_mul_by_11
        mul_13 = gf_mul_by_13
        mul_14 = gf_mul_by_14

        # Since we're dealing with a transposed matrix, columns are already
        # sequential
        for col in range(0, 16, 4):
            v0, v1, v2, v3 = block[col:col + 4]

            block[col] = mul_14[v0] ^ mul_9[v3] ^ mul_13[v2] ^ mul_11[v1]
            block[col + 1] = mul_14[v1] ^ mul_9[v0] ^ mul_13[v3] ^ mul_11[v2]
            block[col + 2] = mul_14[v2] ^ mul_9[v1] ^ mul_13[v0] ^ mul_11[v3]
            block[col + 3] = mul_14[v3] ^ mul_9[v2] ^ mul_13[v1] ^ mul_11[v0]

        # print 'MixColumns :', block

    def encrypt_block(self, block):
        """Encrypts a single block. This is the main AES function"""

        # For efficiency reasons, the state between steps is transmitted via a
        # mutable array, not returned
        self.add_round_key(block, 0)

        for round in range(1, self.rounds):
            self.sub_bytes(block, aes_sbox)
            self.shift_rows(block)
            self.mix_columns(block)
            self.add_round_key(block, round)

        self.sub_bytes(block, aes_sbox)
        self.shift_rows(block)
        # no mix_columns step in the last round
        self.add_round_key(block, self.rounds)

    def decrypt_block(self, block):
        """Decrypts a single block. This is the main AES decryption function"""

        # For efficiency reasons, the state between steps is transmitted via a
        # mutable array, not returned
        self.add_round_key(block, self.rounds)

        # count rounds down from (self.rounds) ... 1
        for round in range(self.rounds - 1, 0, -1):
            self.shift_rows_inv(block)
            self.sub_bytes(block, aes_inv_sbox)
            self.add_round_key(block, round)
            self.mix_columns_inv(block)

        self.shift_rows_inv(block)
        self.sub_bytes(block, aes_inv_sbox)
        self.add_round_key(block, 0)
        # no mix_columns step in the last round


# ECB mode implementation
class ECBMode(object):
    """Electronic CodeBook (ECB) mode encryption.

    Basically this mode applies the cipher function to each block individually;
    no feedback is done. NB! This is insecure for almost all purposes
    """

    def __init__(self, cipher):
        self.cipher = cipher
        self.block_size = cipher.block_size

    def ecb(self, data, block_func):
        """Perform ECB mode with the given function"""

        if len(data) % self.block_size != 0:
            raise ValueError("Input length must be multiple of 16")

        block_size = self.block_size
        data = array('B', data)

        for offset in range(0, len(data), block_size):
            block = data[offset:offset + block_size]
            block_func(block)
            data[offset:offset + block_size] = block

        return data.tobytes()

    def encrypt(self, data):
        """Encrypt data in ECB mode"""

        return self.ecb(data, self.cipher.encrypt_block)

    def decrypt(self, data):
        """Decrypt data in ECB mode"""

        return self.ecb(data, self.cipher.decrypt_block)


# CBC mode
class CBCMode(object):
    """
    Cipher Block Chaining(CBC) mode encryption. This mode avoids content leaks.

    In CBC encryption, each plaintext block is XORed with the ciphertext block
    preceding it; decryption is simply the inverse.
    """

    # A better explanation of CBC can be found here:
    # http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#-
    # Cipher-block_chaining_.28CBC.29

    def __init__(self, cipher, IV):
        self.cipher = cipher
        self.block_size = cipher.block_size
        self.IV = array('B', IV)

    def encrypt(self, data):
        """Encrypt data in CBC mode"""

        block_size = self.block_size
        if len(data) % block_size != 0:
            raise ValueError("Plaintext length must be multiple of 16")

        data = array('B', data)
        IV = self.IV

        for offset in range(0, len(data), block_size):
            block = data[offset:offset + block_size]

            # Perform CBC chaining
            for i in range(block_size):
                block[i] ^= IV[i]

            self.cipher.encrypt_block(block)
            data[offset:offset + block_size] = block
            IV = block

        self.IV = IV
        return data.tobytes()

    def decrypt(self, data):
        """Decrypt data in CBC mode"""

        block_size = self.block_size
        if len(data) % block_size != 0:
            raise ValueError("Ciphertext length must be multiple of 16")

        data = array('B', data)
        IV = self.IV

        for offset in range(0, len(data), block_size):
            ctext = data[offset:offset + block_size]
            block = ctext[:]
            self.cipher.decrypt_block(block)

            # Perform CBC chaining
            # for i in xrange(block_size):
            #    data[offset + i] ^= IV[i]
            for i in range(block_size):
                block[i] ^= IV[i]
            data[offset:offset + block_size] = block

            IV = ctext
            # data[offset : offset+block_size] = block

        self.IV = IV
        return data.tobytes()


def galois_multiply(a, b):
    """Galois Field multiplicaiton for AES"""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x1b
        b >>= 1

    return p & 0xff


# Precompute the multiplication tables for encryption
gf_mul_by_2 = array('B', [galois_multiply(x, 2) for x in range(256)])
gf_mul_by_3 = array('B', [galois_multiply(x, 3) for x in range(256)])
# ... for decryption
gf_mul_by_9 = array('B', [galois_multiply(x, 9) for x in range(256)])
gf_mul_by_11 = array('B', [galois_multiply(x, 11) for x in range(256)])
gf_mul_by_13 = array('B', [galois_multiply(x, 13) for x in range(256)])
gf_mul_by_14 = array('B', [galois_multiply(x, 14) for x in range(256)])

####

# The S-box is a 256-element array, that maps a single byte value to another
# byte value. Since it's designed to be reversible, each value occurs only once
# in the S-box
#
# More information: http://en.wikipedia.org/wiki/Rijndael_S-box

aes_sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

# This is the inverse of the above. In other words:
# aes_inv_sbox[aes_sbox[val]] == val

aes_inv_sbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

# The Rcon table is used in AES's key schedule (key expansion)
# It's a pre-computed table of exponentation of 2 in AES's finite field
#
# More information: http://en.wikipedia.org/wiki/Rijndael_key_schedule

aes_Rcon = bytes.fromhex(
    '8d01020408102040801b366cd8ab4d9a'
    '2f5ebc63c697356ad4b37dfaefc59139'
    '72e4d3bd61c29f254a943366cc831d3a'
    '74e8cb8d01020408102040801b366cd8'
    'ab4d9a2f5ebc63c697356ad4b37dfaef'
    'c5913972e4d3bd61c29f254a943366cc'
    '831d3a74e8cb8d01020408102040801b'
    '366cd8ab4d9a2f5ebc63c697356ad4b3'
    '7dfaefc5913972e4d3bd61c29f254a94'
    '3366cc831d3a74e8cb8d010204081020'
    '40801b366cd8ab4d9a2f5ebc63c69735'
    '6ad4b37dfaefc5913972e4d3bd61c29f'
    '254a943366cc831d3a74e8cb8d010204'
    '08102040801b366cd8ab4d9a2f5ebc63'
    'c697356ad4b37dfaefc5913972e4d3bd'
    '61c29f254a943366cc831d3a74e8cb'
)
