import os
import numpy as np

# ENCRYPT

Nr = 10
Nb = 4
Nk = 4


def random_key_generator(key_length):
 
    return bytes.hex(os.urandom(key_length // 8))

key = random_key_generator(128)
print("\n")
print(key)

def text2matrix(text, len=16):
     
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

InvSbox = (
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


Rcon = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )


def sub_word(w):
      
        for i in range(len(w)):
            w[i] = Sbox[w[i]]


def rotate_word(w):
   
        w[0], w[1], w[2], w[3] = w[1], w[2], w[3], w[0]

key = random_key_generator(128)
key1 = text2matrix(key,16)


def key_expansion(key):
    round_keys = key

    for i in range(Nk, Nb * (Nr + 1)):     
                print(i)
                round_keys.append([0, 0, 0, 0])
                temp = round_keys[i - 1][:]
                print("temp is")
                print(temp)
                # word is multiple of Nk
                if i % Nk == 0:
                    rotate_word(temp)
                    print(temp)
                    sub_word(temp)
                    print(temp)
                    temp[0] = temp[0] ^ Rcon[i // Nk]
                    print(temp)
                

                for j in range(4):
                    print(i,j)
                    print(i - Nk, j)
                    print(temp[j])
                    round_keys[i][j] = round_keys[i - Nk][j] ^ temp[j]
                    print(round_keys)
                    print("\n\n")
    return(round_keys)

lastKey = key_expansion(key1)
print(lastKey)
print(len(lastKey))
print("\n")
print("Above is our key after key expansion")
print(len(Sbox))

# Output
# [[183, 16, 29, 48], [83, 41, 200, 234], [102, 157, 100, 19], [26, 35, 163, 42]]
# 4
# temp is
# [26, 35, 163, 42]
# [35, 163, 42, 26]
# [38, 10, 229, 162]
# [39, 10, 229, 162]
# 4 0
# 0 0
# 39
# [[183, 16, 29, 48], [83, 41, 200, 234], [102, 157, 100, 19], [26, 35, 163, 42], [144, 0, 0, 0]]



# 4 1
# 0 1
# 10
# [[183, 16, 29, 48], [83, 41, 200, 234], [102, 157, 100, 19], [26, 35, 163, 42], [144, 26, 0, 0]]



# 4 2
# 0 2
# 229
# [[183, 16, 29, 48], [83, 41, 200, 234], [102, 157, 100, 19], [26, 35, 163, 42], [144, 26, 248, 0]]



# 4 3
# 0 3
# 162
# [[183, 16, 29, 48], [83, 41, 200, 234], [102, 157, 100, 19], [26, 35, 163, 42], [144, 26, 248, 146]]

        
# 5
# temp is
# [144, 26, 248, 146]
# 5 0
# 1 0
# 144
# [[183, 16, 29, 48], [83, 41, 200, 234], [102, 157, 100, 19], [26, 35, 163, 42], [144, 26, 248, 146], [195, 0, 0, 0]]



# 5 1
# 1 1
# 26
# [[183, 16, 29, 48], [83, 41, 200, 234], [102, 157, 100, 19], [26, 35, 163, 42], [144, 26, 248, 146], [195, 51, 0, 0]]



# 5 2
# 1 2
# 248
# [[183, 16, 29, 48], [83, 41, 200, 234], [102, 157, 100, 19], [26, 35, 163, 42], [144, 26, 248, 146], [195, 51, 48, 0]]



# 5 3
# 1 3
# 146
# [[183, 16, 29, 48], [83, 41, 200, 234], [102, 157, 100, 19], [26, 35, 163, 42], [144, 26, 248, 146], [195, 51, 48, 120]]

...
# ...
# .....
# .......
                
                 
# 43 3
# 39 3
# 207
# [[183, 16, 29, 48], [83, 41, 200, 234], [102, 157, 100, 19], [26, 35, 163, 42], [144, 26, 248, 146], [195, 51, 48, 120], [165, 174, 84, 107], [191, 141, 247, 65], [207, 114, 123, 154], [12, 65, 75, 226], [169, 239, 31, 137], [22, 98, 232, 200], [97, 233, 147, 221], [109, 168, 216, 63], [196, 71, 199, 182], [210, 37, 47, 126], [86, 252, 96, 104], [59, 84, 184, 87], [255, 19, 127, 225], [45, 54, 80, 159], [67, 175, 187, 176], [120, 251, 3, 231], [135, 232, 124, 6], [170, 222, 44, 153], [126, 222, 85, 28], [6, 37, 86, 251], [129, 205, 42, 253], [43, 19, 6, 100], [67, 177, 22, 237], [69, 148, 64, 22], [196, 89, 106, 235], [239, 74, 108, 143], [21, 225, 101, 50], [80, 117, 37, 36], [148, 44, 79, 207], [123, 102, 35, 64], [61, 199, 108, 19], [109, 178, 73, 55], [249, 158, 6, 248], [130, 248, 37, 184], [74, 248, 0, 0], [39, 74, 73, 55], [222, 212, 79, 207], [92, 44, 106, 119]]


def matrix2text(s, len=16):
        """
        Transforms a 128/192/256 bit block written in State form into plain text.

        Parameters
        ----------

        s : matrix
            State
        """
        text = ""
        for i in range(len // 4):
            for j in range(4):
                text += format(s[i][j], '02x')

        return text


def mix_columns(s):
    mix_columns_matrix = np.array([
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ], dtype=np.uint8)

    state = s.copy()  # Make a copy to avoid modifying the original matrix

    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        state[0][col] = (
            gf_mul(mix_columns_matrix[0][0], s0) ^
            gf_mul(mix_columns_matrix[0][1], s1) ^
            gf_mul(mix_columns_matrix[0][2], s2) ^
            gf_mul(mix_columns_matrix[0][3], s3)
        )

        state[1][col] = (
            gf_mul(mix_columns_matrix[1][0], s0) ^
            gf_mul(mix_columns_matrix[1][1], s1) ^
            gf_mul(mix_columns_matrix[1][2], s2) ^
            gf_mul(mix_columns_matrix[1][3], s3)
        )

        state[2][col] = (
            gf_mul(mix_columns_matrix[2][0], s0) ^
            gf_mul(mix_columns_matrix[2][1], s1) ^
            gf_mul(mix_columns_matrix[2][2], s2) ^
            gf_mul(mix_columns_matrix[2][3], s3)
        )

        state[3][col] = (
            gf_mul(mix_columns_matrix[3][0], s0) ^
            gf_mul(mix_columns_matrix[3][1], s1) ^
            gf_mul(mix_columns_matrix[3][2], s2) ^
            gf_mul(mix_columns_matrix[3][3], s3)
        )

    return state

def inv_mix_columns(s):
    inv_mix_columns_matrix = np.array([
         [0x0E, 0x0B, 0x0D, 0x09],
         [0x09, 0x0E, 0x0B, 0x0D],
         [0x0D, 0x09, 0x0E, 0x0B],
         [0x0B, 0x0D, 0x09, 0x0E]
    ], dtype=np.uint8)

    state = s.copy()  # Make a copy to avoid modifying the original matrix

    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        state[0][col] = (
            gf_mul(inv_mix_columns_matrix[0][0], s0) ^
            gf_mul(inv_mix_columns_matrix[0][1], s1) ^
            gf_mul(inv_mix_columns_matrix[0][2], s2) ^
            gf_mul(inv_mix_columns_matrix[0][3], s3)
        )

        state[1][col] = (
            gf_mul(inv_mix_columns_matrix[1][0], s0) ^
            gf_mul(inv_mix_columns_matrix[1][1], s1) ^
            gf_mul(inv_mix_columns_matrix[1][2], s2) ^
            gf_mul(inv_mix_columns_matrix[1][3], s3)
        )

        state[2][col] = (
            gf_mul(inv_mix_columns_matrix[2][0], s0) ^
            gf_mul(inv_mix_columns_matrix[2][1], s1) ^
            gf_mul(inv_mix_columns_matrix[2][2], s2) ^
            gf_mul(inv_mix_columns_matrix[2][3], s3)
        )

        state[3][col] = (
            gf_mul(inv_mix_columns_matrix[3][0], s0) ^
            gf_mul(inv_mix_columns_matrix[3][1], s1) ^
            gf_mul(inv_mix_columns_matrix[3][2], s2) ^
            gf_mul(inv_mix_columns_matrix[3][3], s3)
        )

    return state

def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x11B  # Modulo 0x11B
        b >>= 1
    return p



A = text2matrix("2b7e151628aed2a6abf7158809cf4f3c")
B = mix_columns(text2matrix("2b7e151628aed2a6abf7158809cf4f3c"))
C = inv_mix_columns(A)
print("before\n")
print(A)
print("after\n")
print(B)
print("before")
print(C)

def shift_rows(s):
    

        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
        

        s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]



def sub_bytes(s):
       
        for i in range(4):
            for j in range(4):    
                s[i][j] = Sbox[s[i][j] % 256]

def inv_sub_bytes(s):
      
        for i in range(Nb):
            for j in range(4):
                s[i][j] = InvSbox[s[i][j] % 256]


def add_round_key(s, k):
     
        for i in range(Nb):
            for j in range(4):
                s[i][j] ^= k[i][j]



def cipher(text):
 
        state = text2matrix(text)
        round_keys = lastKey

        add_round_key(state,round_keys[:4])  #Transform 0
        

        for i in range(1, Nr):
              sub_bytes(state)
              shift_rows(state)
              mix_columns(state)
              print("round " + str(i) + " is: ")
              #return(round_keys[Nb * i : Nb * (i + 1)])
              add_round_key(state, round_keys[Nb * i : Nb * (i + 1)])  #to transform 9th
              print(state)
        sub_bytes(state)
        shift_rows(state)
        add_round_key(state, round_keys[len(round_keys) - 4:]) #last transform
        print("Ciphertext : ")
        return matrix2text(state)

C = cipher("2b7e151628aed2a6abf7158809cf4f3c")
print(C)             



# DECRYPT


def decipher(text):
        
        encrypted_state =  text2matrix(text)
        print(encrypted_state)
        print("Given key is")
        print(lastKey)

        add_round_key(encrypted_state, lastKey[len(lastKey) - 4:])
        inv_shift_rows(encrypted_state)
        inv_sub_bytes(encrypted_state)

        for i in range(Nr - 1, 0, -1):
               add_round_key(encrypted_state, lastKey[Nb * i : Nb * (i + 1)])
               inv_mix_columns(encrypted_state)
               inv_shift_rows(encrypted_state)
               inv_sub_bytes(encrypted_state)

        add_round_key(encrypted_state, lastKey[:4])
        return matrix2text(encrypted_state)

M = decipher(C)

print("Plaintext is : ")
print(M)