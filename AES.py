from BitVector import *
import binascii
import time

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

InvSbox = [['0' for y in range(16)] for x in range(16)]


def SBox_gen():
    Matrix = [['0' for y in range(16)] for x in range(16)]

    for j in range(16):
        temp = 16 * j
        for i in range(16):
            Matrix[j][i] = hex(temp+i)[2:].upper()

    AES_modulus = BitVector(bitstring='100011011')
    for i in range(16):
        for j in range(16):
            a = BitVector(hexstring=Matrix[i][j])
            if a.int_val() == 0:
                Matrix[i][j] = "63"
            else:
                b = a.gf_MI(AES_modulus, 8)
                bv = BitVector(hexstring="63") ^ b ^ (b << 1) ^ (b << 1) ^ (b << 1) ^ (b << 1)
                Matrix[i][j] = hex(bv.int_val())[2:].upper()

    for i in range(16):
        for j in range(16):
            if len(Matrix[i][j]) < 2:
                Matrix[i][j] = '0' + Matrix[i][j]

            InvSbox[int(Matrix[i][j][0], 16)][int(Matrix[i][j][1], 16)] = hex(i << 4 | j)[2:].upper()

            Matrix[i][j] = "0x"+Matrix[i][j]

    for i in range(16):
        for j in range(16):
            if len(InvSbox[i][j]) < 2:
                InvSbox[i][j] = '0' + InvSbox[i][j]
            InvSbox[i][j] = "0x" + InvSbox[i][j]
    return Matrix


Sbox = SBox_gen()

choose_key = input('Choose key length :\n 1. 128-bit\n 2. 192-bit\n 3. 256-bit\n')
if choose_key == '1':
    key_len = 16
elif choose_key == '2':
    key_len = 24
else:
    key_len = 32

key = input('Enter key ')

if len(key) < key_len:
    key = key.ljust(key_len, '0')
elif len(key) > key_len:
    key = key[0:key_len]


def ascii_to_hexstring(st):
    length = len(st)
    a_list = []
    for i in range(length):
        temp = str.encode(st[i])
        temp = binascii.hexlify(temp)
        a_list.append(str(temp, "ascii").upper())
    return a_list


key0 = ascii_to_hexstring(key)
w_len = int(key_len/4)
w_lists = []
print(*key0, '[HEX] ', sep=" ")
text = ''
file_ext = ''
file_name = ''
inp = input("Choose option: 1. Input text from Console 2. Input filename: ")

if inp == '1':
    text_len = key_len
    plain_text = input('Enter plaintext ')
    if len(plain_text) < text_len:
        plain_text = plain_text.ljust(text_len, ' ')
    elif len(plain_text) > text_len:
        plain_text = plain_text[0:text_len]

    text = ascii_to_hexstring(plain_text)
    print(*text, '[HEX] ', sep=" ")
else:
    print('Filename: ')
    filename1 = input()
    extension = filename1.split(".")
    file_ext = extension[len(extension)-1]
    file_name = extension[0]
    # print(file_name)
    tlist = []

    with open(filename1, "rb") as f:
        while True:
            br = f.read(key_len)
            t = binascii.hexlify(br)
            t = str(t, 'ascii').upper()
            if not br:
                break
            tlist.append(t)
            # print(t)
    f.close()
    tlist_len = len(tlist)
    if len(tlist[tlist_len - 1]) < key_len * 2:
        last_len = len(tlist[tlist_len - 1])
        x = int((key_len * 2 - last_len) / 2)
        for it in range(x):
            tlist[tlist_len - 1] += "20"
    ttlist = []
    for it in range(tlist_len):
        list12 = []
        jt = 0
        while jt < key_len * 2 - 1:
            list12.append(tlist[it][jt:jt + 2])
            jt += 2
        ttlist.append(list12)
    # print(*ttlist, sep='\n')


def gen_lists(key_list):
    # a_list = []
    for j in range(w_len):
        w_lists.append(key_list[j * 4:4 * (j + 1)])
    # return w_lists


def circ_shift_left(w_list, n=0):
    return w_list[n::] + w_list[:n:]


def circ_shift_right(w_list, n=0):
    last = w_list[0:len(w_list) - n:]
    first = w_list[len(w_list) - n:len(w_list):]
    return first + last
    # return w_list[n:len(w_list):] + w_list[0:n:]


def byte_substitute(lists):
    l_size = len(lists)
    for j in range(l_size):
        if len(lists[j]) < 2:
            a = BitVector(hexstring="0")
            b = BitVector(hexstring=lists[j])
        else:
            a = BitVector(hexstring=lists[j][0])
            b = BitVector(hexstring=lists[j][1])
        x = a.intValue()
        y = b.intValue()
        lists[j] = Sbox[x][y][2:]


def finite_field_xor(s1, s2):
    return hex(int(s1, 16) ^ int(s2, 16))[2:].upper()


rc1 = "01"
rcon1 = ['1', '0', '0', '0']


def gen_round_const():
    global rc1
    AES_modulus = BitVector(bitstring='100011011')
    bv1 = BitVector(hexstring="02")
    bv2 = BitVector(hexstring=rc1)
    bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
    rc1 = hex(bv3.int_val())[2:].upper()
    global rcon1
    rcon1 = [rc1, '0', '0', '0']
    return rc1


def xor_op(list1, list2):
    l_size = len(list1)
    list3 = []
    for j in range(l_size):
        list3.append(hex(int(list1[j], 16) ^ int(list2[j], 16))[2:].upper())
    return list3


def g_of_rotword():
    new_w = circ_shift_left(w_lists[w_len - 1], 1)
    byte_substitute(new_w)
    new_w = xor_op(new_w, rcon1)
    return new_w


def gen_key(full_key):
    new_key = []
    w_lists.clear()
    gen_lists(full_key)
    rot = g_of_rotword()
    w_lists[0] = xor_op(w_lists[0], rot)
    new_key.append(w_lists[0])

    for j in range(w_len - 1):
        w_lists[j + 1] = xor_op(w_lists[j + 1], w_lists[j])
        new_key.append(w_lists[j + 1])

    return new_key


list_of_keys = [key0]
no_of_keys = 10

if key_len == 16:
    no_of_keys = 10
elif key_len == 24:
    no_of_keys = 12
else:
    no_of_keys = 14


def gen_all_keys(key_zero):

    flat_list = key_zero
    for j in range(no_of_keys):
        if j != 0:
            gen_round_const()
        new_key = gen_key(flat_list)
        flat_list = [item for sublist in new_key for item in sublist]
        list_of_keys.append(flat_list)


def print_keys():
    itr = 0
    for item in list_of_keys:
        print('Round ', itr, ': ', *item, sep=" ")
        itr = itr + 1


def gen_matrix(lst, r, c):
    w_lists.clear()
    gen_lists(lst)
    row = r
    col = c
    Matrix = [['0' for y in range(col)] for x in range(row)]

    for j in range(col):
        for i in range(row):
            Matrix[i][j] = w_lists[j][i]
    return Matrix


def print_matrix(mat):
    r = len(mat)
    # c = len(mat[0])
    for i in range(r):
        print(*mat[i], sep=" ")


def xor_matrices(m1, m2):
    mat = []
    s = len(m1)
    for i in range(s):
        mat.append(xor_op(m1[i], m2[i]))
    return mat


def matrix_substitute(mat):
    s = len(mat)
    for i in range(s):
        byte_substitute(mat[i])
    return mat


def matrix_shift(mat, sel=0):
    s = len(mat)
    for i in range(s):
        if sel == 0:
            mat[i] = circ_shift_left(mat[i], i)
        else:
            # print("hi")
            mat[i] = circ_shift_right(mat[i], i)
    return mat


def finite_field_multiply(s1, s2):
    AES_modulus = BitVector(bitstring='100011011')
    bv1 = s1
    bv2 = BitVector(hexstring=s2)
    bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
    # print(bv3)
    return hex(bv3.int_val())[2:].upper()


def matrix_mix_col(mat, sel=0):
    r = len(mat)
    c = len(mat[0])
    Matrix = [['0' for y in range(c)] for x in range(r)]

    for i in range(r):
        for j in range(c):
            for k in range(r):
                if sel == 0:
                    temp = finite_field_multiply(Mixer[i][k], mat[k][j])
                else:
                    temp = finite_field_multiply(InvMixer[i][k], mat[k][j])
                Matrix[i][j] = finite_field_xor(Matrix[i][j], temp)
    return Matrix


def inv_matrix_substitute(mat):
    sz = len(mat)
    for i in range(sz):
        l_size = len(mat[i])
        for j in range(l_size):
            if len(mat[i][j]) < 2:
                a = BitVector(hexstring="0")
                b = BitVector(hexstring=mat[i][j])
            else:
                a = BitVector(hexstring=mat[i][j][0])
                b = BitVector(hexstring=mat[i][j][1])
            x = a.intValue()
            y = b.intValue()
            mat[i][j] = InvSbox[x][y][2:]
    return mat


def adjust_mat_values(mat):
    r = len(mat)
    c = len(mat[0])
    for i in range(r):
        for j in range(c):
            if len(mat[i][j]) < 2:
                mat[i][j] = '0' + mat[i][j]
    return mat


start = time.time()
gen_all_keys(key0)
end = time.time()
Key_Scheduling = end - start
# print_keys()


if inp == '1':
    state_matrix = gen_matrix(text, 4, w_len)
    round_key_matrix = gen_matrix(list_of_keys[0], 4, w_len)
    state_matrix = xor_matrices(state_matrix, round_key_matrix)


    def ciphertext_gen():
        global state_matrix
        global round_key_matrix
        for i in range(no_of_keys):
            if i != no_of_keys-1:
                state_matrix = matrix_substitute(state_matrix)
                state_matrix = matrix_shift(state_matrix, 0)
                state_matrix = matrix_mix_col(state_matrix, 0)
                round_key_matrix = gen_matrix(list_of_keys[i+1], 4, w_len)
                state_matrix = xor_matrices(state_matrix, round_key_matrix)
            else:
                state_matrix = matrix_substitute(state_matrix)
                state_matrix = matrix_shift(state_matrix, 0)
                round_key_matrix = gen_matrix(list_of_keys[i+1], 4, w_len)
                state_matrix = xor_matrices(state_matrix, round_key_matrix)
        return state_matrix


    start = time.time()
    ciphertext_gen()
    end = time.time()
    Encryption_Time = end-start

    ciphertext = []


    def print_ciphertext():
        global state_matrix
        state_matrix = adjust_mat_values(state_matrix)
        r = len(state_matrix)
        c = len(state_matrix[0])

        for j in range(c):
            for i in range(r):
                ciphertext.append(state_matrix[i][j])

        print(*ciphertext, sep=" ")


    print("\nCipher Text")
    print_ciphertext()

    # state_matrix = gen_matrix(ciphertext, w_len, w_len)
    # round_key_matrix = gen_matrix(list_of_keys[no_of_keys], w_len, w_len)
    state_matrix = xor_matrices(state_matrix, round_key_matrix)


    def plaintext_gen():
        global state_matrix
        global round_key_matrix
        for i in range(no_of_keys-1, -1, -1):
            # print(i)
            if i != 0:
                state_matrix = matrix_shift(state_matrix, 1)
                state_matrix = inv_matrix_substitute(state_matrix)
                round_key_matrix = gen_matrix(list_of_keys[i], 4, w_len)
                state_matrix = xor_matrices(state_matrix, round_key_matrix)
                state_matrix = matrix_mix_col(state_matrix, 1)
            else:
                state_matrix = matrix_shift(state_matrix, 1)
                state_matrix = inv_matrix_substitute(state_matrix)
                round_key_matrix = gen_matrix(list_of_keys[i], 4, w_len)
                state_matrix = xor_matrices(state_matrix, round_key_matrix)
        return state_matrix


    start = time.time()
    plaintext_gen()
    end = time.time()
    Decryption_Time = end-start

    plaintext = []
    res = ''


    def print_plaintext():
        global state_matrix
        global res
        state_matrix = adjust_mat_values(state_matrix)
        r = len(state_matrix)
        c = len(state_matrix[0])

        for j in range(c):
            for i in range(r):
                plaintext.append(state_matrix[i][j])
                res += state_matrix[i][j]

        print(*plaintext, sep=" ")


    print("\nDeciphered Text:")
    print_plaintext()
    print(str(binascii.unhexlify(res), "ascii"))
    print('\nExecution Time')
    print('Key Scheduling ', Key_Scheduling, 'seconds')
    print('Encryption Time ', Encryption_Time, 'seconds')
    print('Decryption Time ', Decryption_Time, 'seconds')

else:
    def file_encryption():
        list_1 = []

        for j in range(len(ttlist)):

            text2 = ttlist[j]
            state_matrix2 = gen_matrix(text2, 4, w_len)
            round_key_matrix2 = gen_matrix(list_of_keys[0], 4, w_len)
            state_matrix2 = xor_matrices(state_matrix2, round_key_matrix2)

            for i in range(no_of_keys):
                if i != no_of_keys - 1:
                    state_matrix2 = matrix_substitute(state_matrix2)
                    state_matrix2 = matrix_shift(state_matrix2, 0)
                    state_matrix2 = matrix_mix_col(state_matrix2, 0)
                    round_key_matrix2 = gen_matrix(list_of_keys[i + 1], 4, w_len)
                    state_matrix2 = xor_matrices(state_matrix2, round_key_matrix2)
                else:
                    state_matrix2 = matrix_substitute(state_matrix2)
                    state_matrix2 = matrix_shift(state_matrix2, 0)
                    round_key_matrix2 = gen_matrix(list_of_keys[i + 1], 4, w_len)
                    state_matrix2 = xor_matrices(state_matrix2, round_key_matrix2)

            state_matrix2 = adjust_mat_values(state_matrix2)
            r = len(state_matrix2)
            c = len(state_matrix2[0])
            list_2 = []
            for n in range(c):
                for m in range(r):
                    list_2.append(state_matrix2[m][n])
            # print(list_2)
            list_1.append(list_2)
            # print(list_1)
            # list_2.clear()
            state_matrix2.clear()
            round_key_matrix2.clear()
        # print(*list_1, sep="\n")
        return list_1

    start = time.time()
    encrypted_file = file_encryption()
    end = time.time()
    f_encrypt = end - start

    result = []
    # comb = ''

    def file_decryption():
        list_1 = []

        for j in range(len(encrypted_file)):

            text2 = encrypted_file[j]
            state_matrix2 = gen_matrix(text2, 4, w_len)
            round_key_matrix2 = gen_matrix(list_of_keys[no_of_keys], 4, w_len)
            state_matrix2 = xor_matrices(state_matrix2, round_key_matrix2)
            for i in range(no_of_keys - 1, -1, -1):
                # print(i)
                if i != 0:
                    state_matrix2 = matrix_shift(state_matrix2, 1)
                    state_matrix2 = inv_matrix_substitute(state_matrix2)
                    round_key_matrix2 = gen_matrix(list_of_keys[i], 4, w_len)
                    state_matrix2 = xor_matrices(state_matrix2, round_key_matrix2)
                    state_matrix2 = matrix_mix_col(state_matrix2, 1)
                else:
                    state_matrix2 = matrix_shift(state_matrix2, 1)
                    state_matrix2 = inv_matrix_substitute(state_matrix2)
                    round_key_matrix2 = gen_matrix(list_of_keys[i], 4, w_len)
                    state_matrix2 = xor_matrices(state_matrix2, round_key_matrix2)

            state_matrix2 = adjust_mat_values(state_matrix2)
            r = len(state_matrix2)
            c = len(state_matrix2[0])
            list_2 = []
            global result
            # global comb
            for n in range(c):
                for m in range(r):
                    list_2.append(state_matrix2[m][n])
                    result.append(int(state_matrix2[m][n], 16))
                    # comb += state_matrix2[m][n]

            list_1.append(list_2)
            state_matrix2.clear()
            round_key_matrix2.clear()
            # print(*list_1, sep="\n")
        return list_1

    start = time.time()
    decrypted_file = file_decryption()
    end = time.time()
    f_decrypt = end - start
    # print(binascii.unhexlify(comb))
    print('\nExecution Time')
    print('Key Scheduling ', Key_Scheduling, 'seconds')
    print('Encryption Time ', f_encrypt, 'seconds')
    print('Decryption Time ', f_decrypt, 'seconds')

    byte_array = []
    for z in range(len(result)):
        # byte_array.append(ord(chr(result[i])))
        byte_array.append(result[z])
    some_bytes = bytearray(byte_array)
    with open(file_name+"_output."+file_ext, "wb") as output_file:
        output_file.write(some_bytes)
    output_file.close()


# def Inv_SBox_gen():
#     Matrix = [['0' for y in range(16)] for x in range(16)]
#
#     for j in range(16):
#         temp = 16 * j
#         for i in range(16):
#             Matrix[j][i] = hex(temp + i)[2:].upper()
#             if j == 0:
#                 Matrix[j][i] = "0" + Matrix[j][i]
#
#     AES_modulus = BitVector(bitstring='100011011')
#     for i in range(16):
#         for j in range(16):
#             b = BitVector(hexstring=Matrix[i][j])
#             bv = BitVector(hexstring="05") ^ (b << 1) ^ (b << 2) ^ (b << 3)
#             if bv.int_val() == 0:
#                 Matrix[i][j] = hex(0)[2:].upper()
#             else:
#                 Matrix[i][j] = hex((bv.gf_MI(AES_modulus, 8)).int_val())[2:].upper()
#
#     for i in range(16):
#         for j in range(16):
#             if len(Matrix[i][j]) < 2:
#                 Matrix[i][j] = '0' + Matrix[i][j]
#             Matrix[i][j] = "0x" + Matrix[i][j]
#     return Matrix
#
#
# Inv_Sbox = Inv_SBox_gen()
