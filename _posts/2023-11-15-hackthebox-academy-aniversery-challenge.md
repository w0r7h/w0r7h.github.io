---
layout: post
title: Hackthebox Academy Aniversery Challenge
date: 2023-11-15 12:50 +0000
---

After finishing a module in Hakcthebox Academy I have received a message from Jack with a challenge to win free Silver Annual subscription if I decrypt the code. I stopped everything I was doing and started to solve the challenge. Bellow is the challenge code that I have translated to python.

```python
def encryption(plain_text, key):
    encrypted_text = ""
    key_extended = (key * (len(plain_text) // len(key))) + key[:len(plain_text) % len(key)]
    for i in range(len(plain_text)):
        char_plain = plain_text[i]
        char_key = key_extended[i]
        if char_plain.isalpha():
            if char_plain.isupper():
                offset_plain = ord('A')
            else:
                offset_plain = ord('a')
            encrypted_char = chr((ord(char_plain) + ord(char_key) - 2 * offset_plain) % 26 + offset_plain)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char_plain
    return encrypted_text

plain_text = ?
key = "happybirthdayacademy"
encrypted_text = encryption(plain_text, key)
print("Encrypted text:", encrypted_text)
// OUTPUT: otqamwmjn25164-8pu9dd9reyddw4olgkio-vmxtlr12k
```

Basically we have the key, the encryption function and the output. We created a function to decrypt each character, one by one, using only a list of letters in uppercase and lowercase. Since the function `isalpha` is ignoring numbers and special characters we did not need to worry about them. We brute force it and comparing to the output. If the letter from the list after decrypting is equal to the letter in the output in that index then it is the plain text character in that index.  
Bellow is the decryption function I have made:

```python
import string
uppercase_letters = list(string.ascii_uppercase)

# Lowercase letters
lowercase_letters = list(string.ascii_lowercase)

# Combined list of all letters
all_letters = uppercase_letters + lowercase_letters

def decryption(output, key):
    decrypted_text = ""
    output_analyzed = ""
    for i in range(len(output)):
        char_output_analyzed = output_analyzed + output[i]
        print(char_output_analyzed)
        char_output = output[i]
        if char_output.isalpha():
            for l in all_letters:
                temp = decrypted_text + l
                if encryption(temp, key) == char_output_analyzed:
                    decrypted_text += l
                    output_analyzed += char_output
        else:    
            decrypted_text += char_output
            output_analyzed += char_output

    return decrypted_text

output = "otqamwmjn25164-8pu9dd9reyddw4olgkio-vmxtlr12k"
key = "happybirthdayacademy"
decrypted_text = decryption(output, key)
print("Decrypted text:", decrypted_text)
# Decrypted text: htblovesu25164-8mq9fw9cpacvf4higmim-silver12m
```

It was a fun challenge but we were not able to win the subscription unfortunately.