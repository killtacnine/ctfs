#!/root/bin/python3 

import subprocess 

enc_flag = "75ac713a945e9f78f657b735b7e1913cdece53b8853f3a7daade83b319c49139f8f655b0b77b"
dec_flag = [ ]

start = 33
end = 126

dec_index = 0
guess = ""
answer = ""
while True:
    dec_flag.append(0x0)
    for i in range(start, end):
        cmp_offset = (dec_index + 1) * 2
        dec_flag[dec_index] = str(hex(i)[2:])
        guess = ''.join(dec_flag)

        ret_val = subprocess.run(f"echo {guess} | ./PES", shell=True, capture_output=True)
        ret_val = ret_val.stdout.decode('ascii').split("\n")[-1]

        if enc_flag[:cmp_offset] == ret_val[:cmp_offset]:
            answer += str(chr(i))
            print(answer)
            break

    if ''.join(dec_flag) == enc_flag:
        break

    dec_index += 1
