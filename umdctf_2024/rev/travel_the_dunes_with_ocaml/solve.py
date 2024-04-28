#!/usr/bin/env python3

import subprocess
import string

def pwn():
    index = 1
    length = 123
    flag = ""
    tmp_flag = ""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    alphabet_len = len(alphabet)
    alphabet_index = 0
    
    while True:
        flag = tmp_flag + alphabet[alphabet_index]
        while len(flag) != length:
            flag += "A"
        p = subprocess.run(f"echo {flag} | ./ocaml_executable", shell=True, capture_output=True)
        p = p.stdout.decode('ascii')
        matches = p.split("- Match!")
        if len(matches) != index + 1:
            alphabet_index += 1
            if alphabet_index == alphabet_len:
                print("Something went horribly wrong...")
                print(f"index is {alphabet_index}")
                exit(1)
        else:
            tmp_flag = tmp_flag + alphabet[alphabet_index]
            alphabet_index = 0
            index += 1

        print(flag)
        if index >length:
            exit(0)

def main():
    pwn()

if __name__ == "__main__":
    main()
