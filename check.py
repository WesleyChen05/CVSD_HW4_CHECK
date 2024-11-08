import csv

def hex_to_bin(hex_str):
    binary_str = bin(int(hex_str, 16))[2:]
    binary_str = binary_str.zfill(len(hex_str) * 4)
    return binary_str

def bin_to_hex(bin_str, length=16):
    hex_str = hex(int(bin_str, 2))[2:] 
    hex_str = hex_str.upper()
    hex_str = hex_str.zfill(length)
    return hex_str

def bin_to_dec(bin_str):
    return int(bin_str, 2)

def dec_to_bin(dec_str):
    return bin(dec_str)[2:].zfill(4)

def init_permute(input_str):
    with open('./lut/Initial_permutation.csv', newline='') as csvfile:
        
        str_len = 64
        if len(input_str) != str_len:
            raise ValueError("The length of the string and indices must match.")
        output_str = [''] * str_len

        rows = csv.DictReader(csvfile)

        for row in rows:
            output_index = str_len - 1 - int(row['Output index'])
            input_index = str_len - 1 - int(row['Input index'])
            # print(output_index, input_index)
            output_str[output_index] = input_str[input_index]
    
    return ''.join(output_str)

def final_permute(input_str):
    with open('./lut/Final_permutation.csv', newline='') as csvfile:
        
        str_len = 64
        if len(input_str) != str_len:
            raise ValueError("The length of the string and indices must match.")
        output_str = [''] * str_len

        rows = csv.DictReader(csvfile)

        for row in rows:
            output_index = str_len - 1 - int(row['Output index'])
            input_index = str_len - 1 - int(row['Input index'])
            # print(output_index, input_index)
            output_str[output_index] = input_str[input_index]
    
    return ''.join(output_str)

# generate K1 to K16
def key_generation(main_key, print_detail=False):

    # Cipher key generation
    with open('./lut/PC1.csv', newline='') as csvfile:
        
        if len(main_key) != 64:
            raise ValueError("The length of the string and indices must match.")
        output_str = [''] * 56

        rows = csv.DictReader(csvfile)
        for row in rows:
            output_index = 55 - int(row['Output index'])
            input_index = 63 - int(row['Input index'])
            output_str[output_index] = main_key[input_index]

    cipher_key = ''.join(output_str)

    if (print_detail):
        print("Main Key:", bin_to_hex(main_key))
        print("Cipher Key (After PC1): ", bin_to_hex(cipher_key, 12))

    def left_circular_shift(input_str, n):
        n = n % len(input_str)
        return input_str[n:] + input_str[:n] 

    # Generate Key 1 to Key 16
    key_list = []

    for i in range(1, 17):
        with open('./lut/PC2.csv', newline='') as csvfile:
        
            if len(cipher_key) != 56:
                raise ValueError("The length of the string and indices must match.")
            output_str = [''] * 56

            rows = csv.DictReader(csvfile)
                
            shift = 1 if (i == 1) | (i == 2) | (i == 9) | (i == 16) else 2
            # print(i, shift)

            left_key = cipher_key[:28]
            right_key = cipher_key[28:]

            left_shifted = left_circular_shift(left_key, shift)
            right_shifted = left_circular_shift(right_key, shift)

            cipher_key = left_shifted + right_shifted

            for row in rows:
                output_index = 55 - int(row['Output index'])
                input_index = 55 - int(row['Input index'])
                output_str[output_index] = cipher_key[input_index]

            key_list.append(''.join(output_str))

    return key_list

def xor(s1, s2):
    if len(s1) != len(s2):
        raise ValueError("The length of two strings must match.") 
    
    ret = ''
    for i in range(0, len(s1)):
        ret += str(int(s1[i]) ^ int(s2[i]))
    return ret

def round(plain_text, key, print_detail=False):

    # Cipher key generation
    with open('./lut/Expansion.csv', newline='') as csvfile:
        
        if len(plain_text) != 32:
            raise ValueError("The length of the string and indices must match.")
        output_str = [''] * 48

        rows = csv.DictReader(csvfile)
        for row in rows:
            output_index = 47 - int(row['Output index'])
            input_index = 31 - int(row['Input index'])
            output_str[output_index] = plain_text[input_index]
    
    def sbox(input_str):
        ret = ''

        for i in range (0, 8):
            curr = input_str[i * 6: (i + 1) * 6]
            curr = bin_to_dec(curr)
            
            r = curr % 2 + 1
            if (curr >= 32): r += 2

            c = (curr // 2) % 16 + 1

            index = str(i + 1)

            with open('./lut/S' + index + '.csv', newline='') as csvfile:
                reader = csv.reader(csvfile)
                data = [row for row in reader]  # 將每一行加入主列表中

            ret += dec_to_bin(int(data[r][c]))

        return ret
    
    def pbox(input_str):
        # Cipher key generation
        with open('./lut/P.csv', newline='') as csvfile:
        
            if len(input_str) != 32:
                raise ValueError("The length of the string and indices must match.")
            output_str = [''] * 32
            
            rows = csv.DictReader(csvfile)
            for row in rows:
                output_index = 31 - int(row['Output index'])
                input_index = 31 - int(row['Input index'])
                output_str[output_index] = input_str[input_index]

        return ''.join(output_str)

    expanded_text = ''.join(output_str)
    xor_text = xor(expanded_text, key)
    sbox_text = sbox(xor_text)
    pbox_text = pbox(sbox_text)

    if (print_detail):
        print("Expanded text", bin_to_hex(expanded_text, 12))
        print("After XOR", bin_to_hex(xor_text, 12))
        print("After Sboxes", bin_to_hex(sbox_text, 8))
        print("After Pbox", bin_to_hex(pbox_text, 8))

    return pbox_text

def encode(input_data, print_detail=False):
    main_key = hex_to_bin(input_data[:16])
    data = hex_to_bin(input_data[16:])

    permuted_data = init_permute(data)
    key_list = key_generation(main_key)

    if (print_detail):
        print("After initial permutation", bin_to_hex(permuted_data))

    upper = permuted_data[32:]
    lower = permuted_data[:32]

    for i in range(0, 16):
        result = round(upper, key_list[i])
        after_xor = xor(result, lower)
        if (i != 15):
            lower = upper
            upper = after_xor
        else: 
            lower = after_xor

        if (print_detail): 
            print ("Round", i)
            print("Key", i, ":", bin_to_hex(key_list[i], 12))
            print("After F box (32 bits):", bin_to_hex(result, 8))
            print("After XOR (32 bits):", bin_to_hex(after_xor, 8))
            print("\n")

    final_input = lower + upper
    final_result = final_permute(final_input)

    if (print_detail):
        print("Final cipher text", bin_to_hex(final_result))

    return input_data[:16] + bin_to_hex(final_result, 16)

def decode(input_data, print_detail=False):
    main_key = hex_to_bin(input_data[:16])
    data = hex_to_bin(input_data[16:])

    permuted_data = init_permute(data)
    key_list = key_generation(main_key)

    if (print_detail):
        print("After initial permutation", bin_to_hex(permuted_data))

    upper = permuted_data[32:]
    lower = permuted_data[:32]

    for i in range(0, 16):
        result = round(upper, key_list[15-i])
        after_xor = xor(result, lower)
        if (i != 15):
            lower = upper
            upper = after_xor
        else: 
            lower = after_xor

        if (print_detail): 
            print ("Round", i)
            print("Key", i, ":", bin_to_hex(key_list[15-i], 12))
            print("After F box (32 bits):", bin_to_hex(result, 8))
            print("After XOR (32 bits):", bin_to_hex(after_xor, 8))
            print("\n")

    final_input = lower + upper
    final_result = final_permute(final_input)

    if (print_detail):
        print("Final cipher text", bin_to_hex(final_result))

    return input_data[:16] + bin_to_hex(final_result, 16)

def read_text_dat(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    data = [line.strip().split() for line in lines]
    return data

# Example Usage
input_data = "2E897E9178611622BDC49DCABDE5208D"

print(encode(input_data))
print(decode(input_data))

# File IO
# i_data = read_text_dat("../pattern1_data/pattern1.dat")
# enc_golden = read_text_dat("../pattern1_data/f1.dat")
# dec_golden = read_text_dat("../pattern1_data/f2.dat")

# error = 0
# for i in range(0, len(i_data)):
#     enc = encode(i_data[i][0])
#     dec = decode(i_data[i][0])
#     if ((enc != enc_golden[i][0]) | (dec != dec_golden[i][0])):
#         print("Error on test", i)
#         error += 1
# if error:
#     print("Total error:", error)
# else:
#     print("All tests passed!")

