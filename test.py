import os
import numpy as np
import tqdm as tqdm


Sbox = (
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


Rcon = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )


print(bytes.hex(os.urandom(1)))
x = 0x7C
print(type(x))
text1 = "014e57edaa17e5ddbe48a6505901129d"
state = []
for i in range(16):
  byte = int(text1[i*2:i*2+2], 16)
  print(byte)
  if i % 4 ==0:
    state.append([byte])
  else:
       # Append byte to the row i // 4 
          state[i // 4].append(byte) 
print(state)
len =16
text = ""
for i in range(len // 4):
            for j in range(4):
                text += format(state[i][j], '02x')

print(text)
for i in range(4):
            for j in range(4):
                print("value of elements " + str(state[i][j]) + " at position")
                print(i,j)
                state[i][j] = Sbox[state[i][j]]
                print("after Sbox is " + str(state[i][j])+"\n")
print(state[0][1])

      
            
'''
mix_columns_matrix = np.array([
            [2, 1, 1, 3],
            [3, 2, 1, 1],
            [1, 3, 2, 1],
            [1, 1, 3, 2]
        ], dtype=np.uint8)
col1_matrix = np.array([
            [state[0][0]],
            [state[0][1]],
            [state[0][2]],
            [state[0][3]]
        ], dtype=np.uint8)
col2_matrix = np.array([
            [state[1][0]],
            [state[1][1]],
            [state[1][2]],
            [state[1][3]]
        ], dtype=np.uint8)
col3_matrix = np.array([
            [state[2][0]],
            [state[2][1]],
            [state[2][2]],
            [state[2][3]]
        ], dtype=np.uint8)
col4_matrix = np.array([
            [state[3][0]],
            [state[3][1]],
            [state[3][2]],
            [state[3][3]]
        ], dtype=np.uint8)

print(col1_matrix)
print(mix_columns_matrix)

resultCol1_matrix = np.dot(mix_columns_matrix, col1_matrix)
resultCol2_matrix = np.dot(mix_columns_matrix, col2_matrix)
resultCol3_matrix = np.dot(mix_columns_matrix, col3_matrix)
resultCol4_matrix = np.dot(mix_columns_matrix, col4_matrix)

print(resultCol1_matrix)

#for i in range(4):
 #     state[0][i] = resultCol1_matrix[i][0]

for i in range(4):
       state[1][i] = resultCol2_matrix[i][0]

for i in range(4):
       state[2][i] = resultCol3_matrix[i][0]

for i in range(4):
       state[3][i] = resultCol4_matrix[i][0]

print(state)


'''

print(state)


def mix_columns(s):
    mix_columns_matrix = np.array([
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ], dtype=np.uint8)
    print(mix_columns_matrix[0][1])


    state = s

    # Extract columns
    col1_matrix = np.array([
                [state[0][0]],
                [state[0][1]],
                [state[0][2]],
                [state[0][3]]
            ], dtype=np.uint8)
    col2_matrix = np.array([
                [state[1][0]],
                [state[1][1]],
                [state[1][2]],
                [state[1][3]]
            ], dtype=np.uint8)
    col3_matrix = np.array([
                [state[2][0]],
                [state[2][1]],
                [state[2][2]],
                [state[2][3]]
            ], dtype=np.uint8)
    col4_matrix = np.array([
                [state[3][0]],
                [state[3][1]],
                [state[3][2]],
                [state[3][3]]
            ], dtype=np.uint8)

    for i in range(4):
        print(mix_columns_matrix[0][i])
        
    for i in range(4):
        print(col1_matrix[i])

    state[0][0] = mix_columns_matrix[0][0] * int(col1_matrix[0, 0]) + mix_columns_matrix[0][1] * int(col1_matrix[1, 0]) + mix_columns_matrix[0][2] * int(col1_matrix[2, 0]) + mix_columns_matrix[0][3] * int(col1_matrix[3, 0])
    state[0][1] = mix_columns_matrix[1][0] * int(col1_matrix[0, 0]) + mix_columns_matrix[1][1] * int(col1_matrix[1, 0]) + mix_columns_matrix[1][2] * int(col1_matrix[2, 0]) + mix_columns_matrix[1][3] * int(col1_matrix[3, 0])
    state[0][2] = mix_columns_matrix[2][0] * int(col1_matrix[0, 0]) + mix_columns_matrix[2][1] * int(col1_matrix[1, 0]) + mix_columns_matrix[2][2] * int(col1_matrix[2, 0]) + mix_columns_matrix[2][3] * int(col1_matrix[3, 0])
    state[0][3] = mix_columns_matrix[3][0] * int(col1_matrix[0, 0]) + mix_columns_matrix[3][1] * int(col1_matrix[1, 0]) + mix_columns_matrix[3][2] * int(col1_matrix[2, 0]) + mix_columns_matrix[3][3] * int(col1_matrix[3, 0])

    state[1][0] = mix_columns_matrix[0][0] * int(col2_matrix[0, 0]) + mix_columns_matrix[0][1] * int(col2_matrix[1, 0]) + mix_columns_matrix[0][2] * int(col2_matrix[2, 0]) + mix_columns_matrix[0][3] * int(col2_matrix[3, 0])
    state[1][1] = mix_columns_matrix[1][0] * int(col2_matrix[0, 0]) + mix_columns_matrix[1][1] * int(col2_matrix[1, 0]) + mix_columns_matrix[1][2] * int(col2_matrix[2, 0]) + mix_columns_matrix[1][3] * int(col2_matrix[3, 0])
    state[1][2] = mix_columns_matrix[2][0] * int(col2_matrix[0, 0]) + mix_columns_matrix[2][1] * int(col2_matrix[1, 0]) + mix_columns_matrix[2][2] * int(col2_matrix[2, 0]) + mix_columns_matrix[2][3] * int(col2_matrix[3, 0])
    state[1][3] = mix_columns_matrix[3][0] * int(col2_matrix[0, 0]) + mix_columns_matrix[3][1] * int(col2_matrix[1, 0]) + mix_columns_matrix[3][2] * int(col2_matrix[2, 0]) + mix_columns_matrix[3][3] * int(col2_matrix[3, 0])

    state[2][0] = mix_columns_matrix[0][0] * int(col3_matrix[0, 0]) + mix_columns_matrix[0][1] * int(col3_matrix[1, 0]) + mix_columns_matrix[0][2] * int(col3_matrix[2, 0]) + mix_columns_matrix[0][3] * int(col3_matrix[3, 0])
    state[2][1] = mix_columns_matrix[1][0] * int(col3_matrix[0, 0]) + mix_columns_matrix[1][1] * int(col3_matrix[1, 0]) + mix_columns_matrix[1][2] * int(col3_matrix[2, 0]) + mix_columns_matrix[1][3] * int(col3_matrix[3, 0])
    state[2][2] = mix_columns_matrix[2][0] * int(col3_matrix[0, 0]) + mix_columns_matrix[2][1] * int(col3_matrix[1, 0]) + mix_columns_matrix[2][2] * int(col3_matrix[2, 0]) + mix_columns_matrix[2][3] * int(col3_matrix[3, 0])
    state[2][3] = mix_columns_matrix[3][0] * int(col3_matrix[0, 0]) + mix_columns_matrix[3][1] * int(col3_matrix[1, 0]) + mix_columns_matrix[3][2] * int(col3_matrix[2, 0]) + mix_columns_matrix[3][3] * int(col3_matrix[3, 0])

    state[3][0] = mix_columns_matrix[0][0] * int(col4_matrix[0, 0]) + mix_columns_matrix[0][1] * int(col4_matrix[1, 0]) + mix_columns_matrix[0][2] * int(col4_matrix[2, 0]) + mix_columns_matrix[0][3] * int(col4_matrix[3, 0])
    state[3][1] = mix_columns_matrix[1][0] * int(col4_matrix[0, 0]) + mix_columns_matrix[1][1] * int(col4_matrix[1, 0]) + mix_columns_matrix[1][2] * int(col4_matrix[2, 0]) + mix_columns_matrix[1][3] * int(col4_matrix[3, 0])
    state[3][2] = mix_columns_matrix[2][0] * int(col4_matrix[0, 0]) + mix_columns_matrix[2][1] * int(col4_matrix[1, 0]) + mix_columns_matrix[2][2] * int(col4_matrix[2, 0]) + mix_columns_matrix[2][3] * int(col4_matrix[3, 0])
    state[3][3] = mix_columns_matrix[3][0] * int(col4_matrix[0, 0]) + mix_columns_matrix[3][1] * int(col4_matrix[1, 0]) + mix_columns_matrix[3][2] * int(col4_matrix[2, 0]) + mix_columns_matrix[3][3] * int(col4_matrix[3, 0])
    # state[i][0] = mix_columns_matrix[0][i] * int(col1_matrix[i, 0]) + mix_columns_matrix[0][i] * int(col1_matrix[i, 0]) + mix_columns_matrix[0][i] * int(col1_matrix[i, 0]) + mix_columns_matrix[0][i] * int(col1_matrix[i, 0])
    print(state)
    return state

Nk = 4
Nb = 4
Nr = 10

def random_key_generator(key_length):
    """
    Creates a random key with key_length written
    in hexadecimal as string

    Paramaters
    ----------

    key_length : int
        Key length in bits

    Returns
    -------

    key : string
        Key in hexadecimal as string
    """
    return bytes.hex(os.urandom(key_length // 8))
key = random_key_generator(128)
print(key)

def text2matrix(text, len=16):
        """
        Transforms a 128/192/256 bit block written in plain text form to the State form.

        Parameters
        ----------

        text : string
            128 bit block in plain text
        """
        state = []

        for i in range(len):
            # two hex characters == 1 byte
            byte = int(text[i*2:i*2+2], 16)
            if i % 4 == 0:
                # this means that the byte to append is the first of the column
                state.append([byte])
            else:
                # Append byte to the row i // 4 
                state[i // 4].append(byte) 

        return state



def sub_word(w):
        """
        Take a four-byte word and applies the S-Box

        Parameters
        ----------
        w : vector
            Word 
        """
        for i in range(len(int(w))):
            w[i] = Sbox[w[i]]

def rotate_word(w):
        """
        Take a four-byte word and performs a cyclic
        permutation.

        Parameters
        ----------
        w : vector
            Word
        """

        w[0], w[1], w[2], w[3] = w[1], w[2], w[3], w[0]

key1 = text2matrix(key,16)
round_keys = key1
print(round_keys)
'''for i in range(Nk, Nb * (Nr + 1)):
            
            print(i)
            round_keys.append([0, 0, 0, 0])
            temp = round_keys[i - 1][:]
            print(temp)
            # word is multiple of Nk
            if i % Nk == 0:
                rotate_word(temp)
                print(len(temp))
                print(temp)
                sub_word(temp)
                print(temp)
               temp[0] = temp[0] ^ Rcon[i // Nk]
            elif Nk > 6 and i % Nk == 4:
                """If Nk = 8 (AES-256) and i - 4 is multiple of Nk
                then SUbWord() is applied to word[i - 1] prior to
                the XOR. Nist Fips 192. Section 5.2"""
                sub_word(temp)

            for j in range(4):
                round_keys[i][j] = round_keys[i - Nk][j] ^ temp[j]
'''
mylist = ["apple", "banana", "cherry"]
x = len(mylist) 
print(x)


