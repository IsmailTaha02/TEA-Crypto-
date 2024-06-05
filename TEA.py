#import cv2
import os
import struct

import cv2
import numpy
import numpy as np
from matplotlib import pyplot as plt

cipher_num = 1
plain_num = 1
#png = cv2.imread('Aqsa.png', 0)

#print(png)
def stringToHex (s):
    hex_string = ""
    hex_list = []
    for c in s:
        c = ord(c)
        c = format(c, '02x')
        hex_string += c

    return hex_string

def ECB (plain):
    index1 = 0  #copy from this index
    index2 = 8  #to this index

    blocks = []   #list to contain 64 bit blocks

    #broke the plain text into several blocks (each block with 64 bits)
    while index2 <= len(plain):
        p = plain[index1:index2]
        blocks.append(p)
        index1 += 8
        index2 += 8

        if index2 > len(plain):
            p = plain[index1:len(plain)]
            for i in range (0, index2 - len(plain)):
                p += ' '    #add spcaes to get the block to 64 bits (8 characters)

            blocks.append(p)

    return blocks

def TEA_Encryption(block,key):

    global cipher_num

    l = block[0:4]  #copy the first 4 bytes (32 bits) intp left ..least significant
    r = block[4:8]  #copy the last 4 bytes (32 bits) into right ..most significant

    l = np.frombuffer(l.tobytes(), dtype=np.uint32)[0]
    r = np.frombuffer(r.tobytes(), dtype=np.uint32)[0]

    #print(l)
    #print(r)
    #l = int(l, 16)   #convert from hexa to decimal
    #r = int(r, 16)

    delta = 0x9E3779B9
    sum = 0

    for i in range (0, 32):
        sum = (sum + delta) & 0xFFFFFFFF
        l = l + ( ((r << 4) + key[0]) ^ (r + sum) ^ (r >> 5 + key[1]) ) & 0xFFFFFFFF
        r = r + ( (l << 4 + key[2]) ^ (l + sum) ^ ((l >> 5) + key[3]) ) & 0xFFFFFFFF

    #l_hex = hex(l)[2:].zfill(8)  #conv back to hex
    #r_hex = hex(r)[2:].zfill(8)

    #conv l and r back to array of bytes
    byte_array = bytearray(struct.pack('<I', l))
    l_array = np.array(byte_array)

    byte_array = bytearray(struct.pack('<I', r))
    r_array = np.array(byte_array)

    enc_msg = numpy.concatenate((l_array , r_array))

    print("Cipher text " + str(cipher_num) + ": " + str(enc_msg))
    cipher_num += 1

    return l_array, r_array

def TEA_Decryption(block,key):

    global plain_num

    l = block[0:4]  #copy the first 4 bytes (32 bits) intp left ..least significant
    r = block[4:8]  #copy the last 4 bytes (32 bits) into right ..most significant

    #make each byte  array as a single integer
    l = np.frombuffer(l.tobytes(), dtype=np.uint32)[0]
    r = np.frombuffer(r.tobytes(), dtype=np.uint32)[0]

    #l = int(l, 16)   #convert from hexa to decimal
    #r = int(r, 16)

    delta = 0x9E3779B9
    sum = delta << 5

    for i in range (0, 32):
        l = l - ( ((r << 4) + key[0]) ^ (r + sum) ^ (r >> 5 + key[1]) ) & 0xFFFFFFFF
        r = r - ( (l << 4 + key[2]) ^ (l + sum) ^ ((l >> 5) + key[3]) ) & 0xFFFFFFFF
        sum = (sum - delta)

    #l_hex = hex(l)[2:].zfill(8)  #conv back to hex
    #r_hex = hex(r)[2:].zfill(8)

    l_array = np.frombuffer(struct.pack('<I', l), dtype=np.uint8)
    r_array = np.frombuffer(struct.pack('<I', r), dtype=np.uint8)

    dec_msg = numpy.concatenate((l_array, r_array))

    print("Plain text " + str(plain_num) + ": " + str(dec_msg))
    plain_num += 1

    return l_array,r_array

def broke_img_into_blocks(img,height,width):
    img_blocks = []
    for i in range(height):
        for j in range(0, width - 1, 2):
            img_block = np.concatenate((img[i][j], img[i][j + 1]))
            img_blocks.append(img_block)

    return img_blocks

def ECB_enc_dec(img,blocks,height,width,key,flag):

    enc_dec_img = np.zeros([height, width, 4], np.uint8)  #in encreption this will be the encreption array ..in dec it will be dec array

    # copy first 10 blocks as they are
    for j in range(20):
        enc_dec_img[0][j] = img[0][j]

    i = 0
    j = 20
    for block in range(11, height * width // 2):
        if j == width:
            i += 1
            j = 0

        if i == height:
            break

        if flag == 0:
            enc_dec_img[i][j], enc_dec_img[i][j + 1] = TEA_Encryption(blocks[block], key)

        else:
            enc_dec_img[i][j], enc_dec_img[i][j + 1] = TEA_Decryption(blocks[block], key)

        j += 2

    return enc_dec_img

def CBC_Encryption(img, blocks, key):

    enc_img = np.zeros([height, width, 4], np.uint8)  #in encreption this will be the encreption array ..in dec it will be dec array
    # copy first 10 blocks as they are
    for j in range(20):
        enc_img[0][j] = img[0][j]

    IV_size = 8
    # generate a random IV
    IV = os.urandom(IV_size)

    IV_int = []
    for value in IV:
        value = int(value)
        IV_int.append(value)

    # Assign the first 4 elements of IV_int to a slice of enc_dec_img
    enc_img[0, 20] = IV_int[:4]
    # Assign the rest of the elements of IV_int to another slice of enc_dec_img
    enc_img[0, 21] = IV_int[4:]

    i = 0
    j = 20

    for block in range(11, len(blocks)):

        if j >= width - 3:
            i += 1
            j = 0

        if i == height:
            break

        sub_block1 = np.array(blocks[block][0:4])
        sub_block2 = np.array(blocks[block][4:])
        P_XOR_C = np.concatenate((sub_block1 ^ enc_img[i, j], sub_block2 ^ enc_img[i, j+1]))

        enc_img[i][j+2], enc_img[i][j+3] = TEA_Encryption(P_XOR_C, key)

        j += 2

    return enc_img

def CBC_Decryption(enc_img, blocks, key):

    dec_img = np.zeros([height, width, 4], np.uint8)  #in encreption this will be the encreption array ..in dec it will be dec array
    # copy first 10 blocks as they are
    for j in range(20):
        dec_img[0][j] = enc_img[0][j]

    cipher_dec = TEA_Decryption(blocks[11],key)
    #block 10 = IV
    block1 = blocks[10][0:4]
    block2 = blocks[10][4:]
    #p0 = c0 xor dec(c0,key)
    dec_img[0][20] = block1
    dec_img[0][21] = block2

    i = 0
    j = 22

    for block in range(11, len(blocks)):
        if j >= width - 3:
            i += 1
            j = 0

        if i == height:
            break

        cipher_dec = TEA_Decryption(blocks[block], key)
        # block 10 = IV
        block1 = blocks[block-1][0:4]
        block2 = blocks[block-1][4:]
        # pi = ci-1 xor dec(ci,key)
        dec_img[i][j] = cipher_dec[0] ^ block1
        dec_img[i][j+1] = cipher_dec[1] ^ block2

        j += 2

    return dec_img

def plot_and_save_img(img,img_name,flag):
    plt.title(img_name)
    plt.imshow(img)
    plt.show()

    if flag == 0:
        plt.imsave('ECB_Encrypted_Aqsa.png', img)
    elif flag == 1:
        plt.imsave('ECB_Decrypted_Aqsa.png', img)
    elif flag == 2:
        plt.imsave('CBC_Encrypted_Aqsa.png', img)
    else:
        plt.imsave('CBC_Decrypted_Aqsa.png', img)

key = ['0x1234', '0x1234', '0x1234', '0x1234']
key = [int(k, 16) for k in key]

img = cv2.imread('Aqsa.png', -1)

height, width = img.shape[:2]
img_blocks = broke_img_into_blocks(img, height, width)

enc_img = np.zeros([height, width, 4], np.uint8)

mode = input("Chose the encryption/decryption type:\n1.ECB  \n2.CBC\n")

if mode == '1':

    # encrypt the blocks
    enc_img = ECB_enc_dec(img, img_blocks, height, width, key, 0)

    # show and save encrypted image
    plot_and_save_img(enc_img, "Encrypted Image", 0)

    # broke the encrypted image into blocks of 8 byte each
    enc_img_blocks = []
    enc_img_blocks = broke_img_into_blocks(enc_img, height, width)

    # creat byte array for decrypted image
    dec_img = np.zeros([height, width, 4], np.uint8)

    # decrypt the blocks
    dec_img = ECB_enc_dec(enc_img, enc_img_blocks, height, width, key, 1)

    # show and save decrypted image
    plot_and_save_img(dec_img, "Decrypted Image", 1)

elif mode == '2':

    enc_img = CBC_Encryption(img, img_blocks, key)
    plot_and_save_img(enc_img, "CBC Encrypted Aqsa", 2)

    CBC_enc_img_blocks = broke_img_into_blocks(enc_img, height, width)

    CBC_dec_img = np.zeros([height, width, 4], np.uint8)
    CBC_dec_img = CBC_Decryption(enc_img, CBC_enc_img_blocks, key)
    print(CBC_dec_img)
    plot_and_save_img(CBC_dec_img, "CBC Decrypted Aqsa", 3)

'''''
plain_blocks = ECB(plain_text)
print(plain_blocks)
#convert blocks & key to hexa decimal values
plain_blocks_hex = []
for block in plain_blocks:
    hex_string = stringToHex(block)
    plain_blocks_hex.append(hex_string)
print(plain_blocks_hex)
key_hex = stringToHex(key)

cipher_blocks_hex = []
for block in plain_blocks_hex:
    cipher_hex = TEA_Encryption(block,key_hex)
    cipher_blocks_hex.append(cipher_hex)

print(cipher_blocks_hex)

for block in cipher_blocks_hex:
    TEA_Decryption(block,key_hex)
'''