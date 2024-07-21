# Initial Permutation
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38,
      30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39,
      31, 23, 15, 7]

# Final permutation
FB = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14,
      54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49,
      17, 57, 25]

# Permuted Choice 1
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
       27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38,
       30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

# Permuted Choice 2
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27,
       20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34,
       53, 46, 42, 50, 36, 29, 32]

# Expansion
EP = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16,
      17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28,
      29, 30, 31, 32, 1]

# Permutation
P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32,
     27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

# S-Box
sbox = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

shift_bits = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def hexa_to_bin(input_str):
    n = len(input_str) * 4
    binary_str = bin(int(input_str, 16))[2:]
    # Ensure leading zeros are added to make the length a multiple of 4
    binary_str = '0' * (n - len(binary_str)) + binary_str
    return binary_str


def bin_to_hexa(input_str):
    n = len(input_str) // 4
    hex_str = hex(int(input_str, 2))[2:]
    # Ensure leading zeros are added to make the length a multiple of 4
    hex_str = '0' * (n - len(hex_str)) + hex_str
    return hex_str

def hex_to_string(hex_str):
    print (hex_str+"done")
    try:
        # Decode the hexadecimal string to bytes and then decode bytes to string
        result_str = bytes.fromhex(hex_str.upper()).decode('utf-8')
        return result_str
    except ValueError:
        # Handle the case where the input is not a valid hexadecimal string
        print("Invalid hexadecimal string")
        return None

def pad_plaintext(PlainText):
    # Pad PlainText with 'X' if it's less than 8 bytes (16 hex characters)
    while len(PlainText) < 16:
        PlainText += 'A'
    return PlainText


def split_plaintext(PlainText):
    # Split PlainText into blocks of 16 hex numbers (64 bits)
    blocks = [PlainText[i:i + 16] for i in range(0, len(PlainText), 16)]
    # Pad the last block with 'A' if it's not 16 hex numbers long
    if len(blocks[-1]) < 16:
        blocks[-1] += 'A' * (16 - len(blocks[-1]))
    return blocks


def validate_key(Key):
    # Ensure the Key is exactly 8 bytes (16 hex characters)
    if len(Key) != 16:
        return False
    return True


def get_valid_key():
    while True:
        Key = input("Enter the Key: ").encode('latin-1').hex()
        if validate_key(Key):
            return Key
        else:
            print("Invalid key. Please enter a key that is exactly 8 bytes long.")


def permutation(sequence, input_str):
    output = ""
    input_str = hexa_to_bin(input_str)
    for i in sequence:
        output += input_str[i - 1]
    output = bin_to_hexa(output)
    return output


def left_circular_shift(input_str, num_bits):
    n = len(input_str) * 4
    perm = [(i + 2) % n for i in range(n - 1)] + [1]
    while num_bits > 0:
        input_str = permutation(perm, input_str)
        num_bits -= 1
    return input_str


def xor(a, b):
    # hexadecimal to decimal (base 10)
    t_a = int(a, 16)
    # hexadecimal to decimal (base 10)
    t_b = int(b, 16)
    # xor
    t_a = t_a ^ t_b
    # decimal to hexadecimal
    a = hex(t_a)[2:]  # [2:] to remove the '0x' prefix
    # prepend 0's to maintain length
    while len(a) < len(b):
        a = "0" + a
    return a


def get_keys(Key):
    keys = [None] * 16
    # first Key permutation
    Key = permutation(PC1, Key)
    for i in range(16):
        left_part = left_circular_shift(Key[:7], shift_bits[i])
        right_part = left_circular_shift(Key[7:14], shift_bits[i])
        Key = left_part + right_part
        # second Key permutation
        keys[i] = permutation(PC2, Key)
    return keys


def s_box(input_str):
    output = ""
    input_str = hexa_to_bin(input_str)

    for i in range(0, 48, 6):
        temp = input_str[i:i + 6]
        num = i // 6
        row = int(temp[0] + temp[5], 2)
        col = int(temp[1:5], 2)
        output += format(sbox[num][row][col], 'x')

    return output


def round_function(input_str, Key, num):
    # fk
    left = input_str[:8]
    temp = input_str[8:16]
    right = temp

    # Expansion permutation
    temp = permutation(EP, temp)

    # xor temp and round Key
    temp = xor(temp, Key)

    # lookup in s-box table
    temp = s_box(temp)

    # Straight D-box
    temp = permutation(P, temp)

    # xor
    left = xor(left, temp)

    # print(f"Round {num + 1} {right.upper()} {left.upper()} {Key.upper()}")

    # swapper
    return right + left


def encrypt(plain_text, Key):
    # Validate and pad/split the PlainText
    plain_text_blocks = split_plaintext(plain_text) if len(plain_text) > 16 else [pad_plaintext(plain_text)]

    # Validate the Key
    if not validate_key(Key):
        return "Invalid Key. Please enter a Key that is exactly 8 bytes long."

    encrypted_text = ""
    # Process each PlainText block
    for block in plain_text_blocks:
        # Get round keys
        keys = get_keys(Key)

        # Initial permutation
        block = permutation(IP, block)
        print("-----------------------------------------------------------------------------")
        
        # print("After initial permutation:", block.upper())
        # print("After splitting: L0=" + block[:8].upper() + " R0=" + block[8:16].upper() + "\n")

        # 16 rounds
        for i in range(16):
            block = round_function(block, keys[i], i)

        # 32-bit swap
        block = block[8:16] + block[:8]

        # Final permutation
        block = permutation(FB, block)

        # Append encrypted block to the overall encrypted text
        encrypted_text=encrypted_text.join(block)
    encrypted_text = hexa_to_bin(encrypted_text)
    # bytes_data = int(encrypted_text, 2).to_bytes((len(encrypted_text) + 7) // 8, byteorder='big')
    bytes_result = bytes(int(encrypted_text[i:i+8], 2) for i in range(0, len(encrypted_text), 8))

    print (bytes_result)

    encrypted_text=bytes_result.decode('latin-1')
    # encrypted_text=hex_to_string(str(encrypted_text))

    return encrypted_text


def decrypt(cipher_text, Key):
    # Validate the Key
    print (cipher_text)
    cipher_text=cipher_text.encode('latin-1').hex()
    print (cipher_text)
    if not validate_key(Key):
        return "Invalid Key. Please enter a Key that is exactly 8 bytes long."

    # Split the ciphertext into blocks of 16 hex characters
    cipher_text_blocks = split_plaintext(cipher_text)

    decrypted_text = ''
    # Process each ciphertext block
    for block in cipher_text_blocks:
        # Get round keys
        keys = get_keys(Key)

        # Initial permutation
        block = permutation(IP, block)
        print("------------------------------------------------------------------------------")
        # print("After initial permutation:", block.upper())
        # print("After splitting: L0=" + block[:8].upper() + " R0=" + block[8:16].upper() + "\n")

        # 16 rounds in reverse order
        for i in range(15, -1, -1):
            block = round_function(block, keys[i], 15 - i)

        # 32-bit swapDE
        block = block[8:16] + block[:8]

        # Final permutation
        block = permutation(FB, block)

        # Append decrypted block to the overall decrypted text
        decrypted_text += block

    # Remove padding if present
    decrypted_text = decrypted_text.rstrip('A')
    return decrypted_text
def print_dycreption(ciphertext,key):
    choice = input("Do you want to decrypt (y/n): ")
    if choice == 'y': 
       OriginalText = decrypt(ciphertext, key)
       OriginalText = hexa_to_bin(OriginalText)
       bytes_result = bytes(int(OriginalText[i:i+8], 2) for i in range(0, len(OriginalText), 8))
       print (bytes_result)
       OriginalText=bytes_result.decode('latin-1')

       print("Dycrepted Text:"+ str(OriginalText.upper()))
    elif choice == 'n':
        print("Good Bye...")
    else:
        print("Please enter a valaid input")
        print_dycreption(ciphertext,key)


# Example usage
plaintext = input("Enter the PlainText: ").encode('latin-1').hex()
key = get_valid_key()

if validate_key(key):
    ciphertext = encrypt(plaintext, key)
    print("Cipher Text:"+ str(ciphertext))
    print("---------------------------------------")
    print_dycreption(ciphertext,key)
else:
    print("Invalid Key. Please enter a Key that is exactly 8 bytes long.")
