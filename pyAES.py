#!/usr/bin/python2.5
# Copyright (c) 2007 Brandon Sterne
# Licensed under the MIT license.
# http://brandon.sternefamily.net/files/mit-license.txt
# Python AES implementation

import sys, hashlib, string, getpass
from copy import copy
from random import randint
import StringIO, base64

# The actual Rijndael specification includes variable block size, but
# AES uses a fixed block size of 16 bytes (128 bits)

# Additionally, AES allows for a variable key size, though this implementation
# of AES uses only 256-bit cipher keys (AES-256)

sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

sboxInv = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]

rcon = [
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
        ]

# returns a copy of the word shifted n bytes (chars)
# positive values for n shift bytes left, negative values shift right
def rotate(word, n):
    return word[n:]+word[0:n]

# iterate over each "virtual" row in the state table and shift the bytes
# to the LEFT by the appropriate offset
def shiftRows(state):
    for i in range(4):
        state[i*4:i*4+4] = rotate(state[i*4:i*4+4],i)

# iterate over each "virtual" row in the state table and shift the bytes
# to the RIGHT by the appropriate offset
def shiftRowsInv(state):
    for i in range(4):
        state[i*4:i*4+4] = rotate(state[i*4:i*4+4],-i)

# takes 4-byte word and iteration number
def keyScheduleCore(word, i):
    # rotate word 1 byte to the left
    word = rotate(word, 1)
    newWord = []
    # apply sbox substitution on all bytes of word
    for byte in word:
        newWord.append(sbox[byte])
    # XOR the output of the rcon[i] transformation with the first part of the word
    newWord[0] = newWord[0]^rcon[i]
    return newWord

# expand 256 bit cipher key into 240 byte key from which
# each round key is derived
def expandKey(cipherKey):
    cipherKeySize = len(cipherKey)
    assert cipherKeySize == 32
    # container for expanded key
    expandedKey = []
    currentSize = 0
    rconIter = 1
    # temporary list to store 4 bytes at a time
    t = [0,0,0,0]

    # copy the first 32 bytes of the cipher key to the expanded key
    for i in range(cipherKeySize):
        expandedKey.append(cipherKey[i])
    currentSize += cipherKeySize

    # generate the remaining bytes until we get a total key size
    # of 240 bytes
    while currentSize < 240:
        # assign previous 4 bytes to the temporary storage t
        for i in range(4):
            t[i] = expandedKey[(currentSize - 4) + i]

        # every 32 bytes apply the core schedule to t
        if currentSize % cipherKeySize == 0:
            t = keyScheduleCore(t, rconIter)
            rconIter += 1

        # since we're using a 256-bit key -> add an extra sbox transform
        if currentSize % cipherKeySize == 16:
            for i in range(4):
                t[i] = sbox[t[i]]

        # XOR t with the 4-byte block [16,24,32] bytes before the end of the
        # current expanded key.  These 4 bytes become the next bytes in the
        # expanded key
        for i in range(4):
            expandedKey.append(((expandedKey[currentSize - cipherKeySize]) ^ (t[i])))
            currentSize += 1
            
    return expandedKey

# do sbox transform on each of the values in the state table
def subBytes(state):
    for i in range(len(state)):
        #print "state[i]:", state[i]
        #print "sbox[state[i]]:", sbox[state[i]]
        state[i] = sbox[state[i]]

# inverse sbox transform on each byte in state table
def subBytesInv(state):
    for i in range(len(state)):
        state[i] = sboxInv[state[i]]

# XOR each byte of the roundKey with the state table
def addRoundKey(state, roundKey):
    for i in range(len(state)):
        #print i
        #print "old state value:", state[i]
        #print "new state value:", state[i] ^ roundKey[i]
        state[i] = state[i] ^ roundKey[i]

# Galois Multiplication
def galoisMult(a, b):
    p = 0
    hiBitSet = 0
    for i in range(8):
        if b & 1 == 1:
            p ^= a
        hiBitSet = a & 0x80
        a <<= 1
        if hiBitSet == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256

# mixColumn takes a column and does stuff
def mixColumn(column):
    temp = copy(column)
    column[0] = galoisMult(temp[0],2) ^ galoisMult(temp[3],1) ^ \
                galoisMult(temp[2],1) ^ galoisMult(temp[1],3)
    column[1] = galoisMult(temp[1],2) ^ galoisMult(temp[0],1) ^ \
                galoisMult(temp[3],1) ^ galoisMult(temp[2],3)
    column[2] = galoisMult(temp[2],2) ^ galoisMult(temp[1],1) ^ \
                galoisMult(temp[0],1) ^ galoisMult(temp[3],3)
    column[3] = galoisMult(temp[3],2) ^ galoisMult(temp[2],1) ^ \
                galoisMult(temp[1],1) ^ galoisMult(temp[0],3)

# mixColumnInv does stuff too
def mixColumnInv(column):
    temp = copy(column)
    column[0] = galoisMult(temp[0],14) ^ galoisMult(temp[3],9) ^ \
                galoisMult(temp[2],13) ^ galoisMult(temp[1],11)
    column[1] = galoisMult(temp[1],14) ^ galoisMult(temp[0],9) ^ \
                galoisMult(temp[3],13) ^ galoisMult(temp[2],11)
    column[2] = galoisMult(temp[2],14) ^ galoisMult(temp[1],9) ^ \
                galoisMult(temp[0],13) ^ galoisMult(temp[3],11)
    column[3] = galoisMult(temp[3],14) ^ galoisMult(temp[2],9) ^ \
                galoisMult(temp[1],13) ^ galoisMult(temp[0],11)

# mixColumns is a wrapper for mixColumn - generates a "virtual" column from
# the state table and applies the weird galois math
def mixColumns(state):
    for i in range(4):
        column = []
        # create the column by taking the same item out of each "virtual" row
        for j in range(4):
            column.append(state[j*4+i])

        # apply mixColumn on our virtual column
        mixColumn(column)

        # transfer the new values back into the state table
        for j in range(4):
            state[j*4+i] = column[j]

# mixColumnsInv is a wrapper for mixColumnInv - generates a "virtual" column from
# the state table and applies the weird galois math
def mixColumnsInv(state):
    for i in range(4):
        column = []
        # create the column by taking the same item out of each "virtual" row
        for j in range(4):
            column.append(state[j*4+i])

        # apply mixColumn on our virtual column
        mixColumnInv(column)

        # transfer the new values back into the state table
        for j in range(4):
            state[j*4+i] = column[j]

# aesRound applies each of the four transformations in order
def aesRound(state, roundKey):
    #print "aesRound - before subBytes:", state
    subBytes(state)
    #print "aesRound - before shiftRows:", state
    shiftRows(state)
    #print "aesRound - before mixColumns:", state
    mixColumns(state)
    #print "aesRound - before addRoundKey:", state
    addRoundKey(state, roundKey)
    #print "aesRound - after addRoundKey:", state

# aesRoundInv applies each of the four inverse transformations
def aesRoundInv(state, roundKey):
    #print "aesRoundInv - before addRoundKey:", state
    addRoundKey(state, roundKey)
    #print "aesRoundInv - before mixColumnsInv:", state
    mixColumnsInv(state)
    #print "aesRoundInv - before shiftRowsInv:", state
    shiftRowsInv(state)
    #print "aesRoundInv - before subBytesInv:", state
    subBytesInv(state)
    #print "aesRoundInv - after subBytesInv:", state


# returns a 16-byte round key based on an expanded key and round number
def createRoundKey(expandedKey, n):
    return expandedKey[(n*16):(n*16+16)]

# create a key from a user-supplied password using SHA-256
def passwordToKey(password):
    sha256 = hashlib.sha256()
    sha256.update(password)
    key = []
    for c in list(sha256.digest()):
        key.append(ord(c))
    return key

# wrapper function for 14 rounds of AES since we're using a 256-bit key
def aesMain(state, expandedKey, numRounds=14):
    roundKey = createRoundKey(expandedKey, 0)
    addRoundKey(state, roundKey)
    for i in range(1, numRounds):
        roundKey = createRoundKey(expandedKey, i)
        aesRound(state, roundKey)
    # final round - leave out the mixColumns transformation
    roundKey = createRoundKey(expandedKey, numRounds)
    subBytes(state)
    shiftRows(state)
    addRoundKey(state, roundKey)

# 14 rounds of AES inverse since we're using a 256-bit key
def aesMainInv(state, expandedKey, numRounds=14):
    # create roundKey for "last" round since we're going in reverse
    roundKey = createRoundKey(expandedKey, numRounds)
    # addRoundKey is the same funtion for inverse since it uses XOR
    addRoundKey(state, roundKey)
    shiftRowsInv(state)
    subBytesInv(state)
    for i in range(numRounds-1,0,-1):
        roundKey = createRoundKey(expandedKey, i)
        aesRoundInv(state, roundKey)
    # last round - leave out the mixColumns transformation
    roundKey = createRoundKey(expandedKey, 0)
    addRoundKey(state, roundKey)
    
# aesEncrypt - encrypt a single block of plaintext
def aesEncrypt(plaintext, key):
    block = copy(plaintext)
    expandedKey = expandKey(key)
    aesMain(block, expandedKey)
    return block

# aesDecrypt - decrypte a single block of ciphertext
def aesDecrypt(ciphertext, key):
    block = copy(ciphertext)
    expandedKey = expandKey(key)
    aesMainInv(block, expandedKey)
    return block

# return 16-byte block from an open file
# pad to 16 bytes with null chars if needed
def getBlock(fp):
    raw = fp.read(16)
    # reached end of file
    if len(raw) == 0:
        return ""
    # container for list of bytes
    block = []
    for c in list(raw):
        block.append(ord(c))
    # if the block is less than 16 bytes, pad the block
    # with the string representing the number of missing bytes
    if len(block) < 16:
        padChar = 16-len(block)
        while len(block) < 16:
            block.append(padChar)
    return block

# encrypt - wrapper function to allow encryption of arbitray length
# plaintext using Output Feedback (OFB) mode
def encrypt(text, password):
    block = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] # plaintext
    ciphertext = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] # ciphertext
    # Initialization Vector
    IV = []
    for i in range(16):
        IV.append(randint(0, 255))

    #PADDING
    numpads = 16 - (len(text)%16)
    text = text + numpads*chr(numpads)

    # convert password to AES 256-bit key
    aesKey = passwordToKey(password)

    fp = StringIO.StringIO(text)
    outfile = StringIO.StringIO()

    # write IV to outfile
    for byte in IV:
        outfile.write(chr(byte))

    # get the file size (bytes) 
    # if the file size is a multiple of the block size, we'll need 
    # to add a block of padding at the end of the message
    fp.seek(0,2)
    filesize = fp.tell()
    # put the file pointer back at the beginning of the file
    fp.seek(0)

    # begin reading in blocks of input to encrypt
    firstRound = True
    block = getBlock(fp)
    while block != "":
        if firstRound:
            blockKey = aesEncrypt(IV, aesKey)
            firstRound = False
        else:
            blockKey = aesEncrypt(blockKey, aesKey)

        for i in range(16):
            ciphertext[i] = block[i] ^ blockKey[i]

        # write ciphertext to outfile
        for c in ciphertext:
            outfile.write(chr(c))

        # grab next block from input file
        block = getBlock(fp)

    # close file pointers
    fp.close()
    s = base64.b64encode(outfile.getvalue())
    outfile.close()
    return s

# decrypt - wrapper function to allow decryption of arbitray length
# ciphertext using Output Feedback (OFB) mode
def decrypt(text, password):
    block = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] # ciphertext
    plaintext = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] # plaintext container

    # convert password to AES 256-bit key
    aesKey = passwordToKey(password)

    fp = StringIO.StringIO(base64.b64decode(text))
    outfile = StringIO.StringIO()

    # recover Initialization Vector, the first block in file
    IV = getBlock(fp)

    # get the file size (bytes) in order to handle the
    # padding at the end of the file
    fp.seek(0,2)
    filesize = fp.tell()
    # put the file pointer back at the first block of ciphertext
    fp.seek(16)

    # begin reading in blocks of input to decrypt
    firstRound = True
    block = getBlock(fp)
    while block != "":
        if firstRound:
            blockKey = aesEncrypt(IV, aesKey)
            firstRound = False
        else:
            blockKey = aesEncrypt(blockKey, aesKey)

        for i in range(16):
            plaintext[i] = block[i] ^ blockKey[i]

        # if we're in the last block of text -> throw out the
        # number of bytes represented by the last byte in the block
        if fp.tell() == filesize:
            plaintext = plaintext[0:-(plaintext[-1])]

        # write ciphertext to outfile
        for c in plaintext:
            outfile.write(chr(c))

        # grab next block from input file
        block = getBlock(fp)
    # close file pointers
    fp.close()
    s = outfile.getvalue()
    outfile.close()
    return s

