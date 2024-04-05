# PROMPT 

Introducing the Parallel Encryption Standard PES-128 cipher! It's super high throughput and notable nonrequirement of keys makes it a worthy contender for NIST standardization as a secure PRF.

By Jeriah (@jyu on discord)

# SOLUTION 

We are given an encrypted flag (`flag.enc`) and a binary named `PES`. This isn't a pwn challenge, so I will skip a lot of the things I normally do first and just run the binary. 

We see immediately that we are prompted for input and we see that entering random data results in seemingly-random responses; however, after some basic testing, we also notice that the same input results in the same response.

Okay, so we clearly have an encryption algorithm where known input results in known output and therefore it can be reversed (because it is a CTF challenge -- not as a general rule). 

After having done several annoying encryption algorithm challenges (many of which I have written myself to annoy other CTF players), I know that one of the first things we should check is if the same input results in the same output *on a block-by-block basis*. 

For example, if "abcd" results in "1234" and "efgh" results in "5678", does the string "efghabcd" result in "56781234"?

Turns out, the answer is "no":

```
>> echo "abcd" | ./PES
16
abd5

>> echo "efgh" | ./PES
16
ef00

echo "efghabcd" | ./PES
16
ef003eda
```

Okay, so the answer to that is "no", which typically means the algorithm builds off of itself (i.e., the first byte gets encrypted and is used as an IV for the algorithm using the next byte). We do however notice that the first "byte" returned always seems to be the first "byte" entered. How can we test this? Let's enter a non hex value:

```
echo "zzxxww" | ./PES 
16
000000
```
So, we are clearly intended to enter hex bytes and we receive hex bytes back. Any invalid hex byte results in a NULL byte returned. 

I haven't focused on the "16" that is being returned yet, but that is only because it isn't important. I noticed by sending significant amounts of data to the binary that this number is based on the size of what we enter and it increments by 16 (16, 32, 48, etc.). This number doesn't matter for the challenge, though, so I won't talk about it further. If it is supposed to matter, then I guess I found an unintended solution. I assume it just means "block size".

Final test before the decompiler... our decrypted flag probably starts with "utflag{". The encrypted flag starts with "75ac713a945e9f". If we enter "utflag{" into `PES`, is this what we see? Well, we have inferred we must enter hex, so what is "utflag{" in hex? 7574666c61677b ! Let's enter that into `PES`:

```
echo 7574666c61677b | ./PES 
16
75ac713a945e9f
```

Sure enough, we have confirmed that each byte builds off of the previous one and the start of our flag must be "utflag{".

Wow! We have learned a significant amount about this binary without even having opened a decompiler.

In fact... let's just solve the entire thing knowing what we know now and not use a decompiler at all.

## The Facts

Here is what we know:

1. Each "byte" representation of characters we enter (i.e., "aa", "0a", "10", "1f", etc) results in a "byte" representation returned. 
2. Our "bytes" must be valid hex (of course) 
3. The encrypted flag we are given is 76 bytes; but if we count each two characters as a single byte (hex representation), it is actually 38. This means our flag is 38 bytes
4. Each byte must build off of the previous byte. If any byte is wrong, the rest of the flag will be wrong
5. The ASCII table printable characters start at decimal 33 and end at decimal 126

Hopefully that final point drove home what we are going to do...

Because each byte builds off of the previous one, we only need to test 126 - 33 values (93) 38 times (bytes in the flag). That is only 8,277 possibilities for the flag which is far, *FAR* lower of guesses than any reasonable brute force attempt should be afraid of *especially* since we have the program and encrypted flag locally. 

If each byte was a value that could stand on its own (not dependent on the previous byte), then our guesses would have to be 93 ** 38 (634,383,743,030,634,732,523,262,634,097,402,860,378,969,470,010,099,074,901,574,691,021,202,141,849 guesses), which is terrifying. My 2017 Lenovo Thinkpad can't handle that, but fewer than 10,000 guesses is easy work! Also, I am not a math student, so it could be 38 ** 93? I don't remember, and it doesn't matter. 

Let's just write a brute forcer and solve this challenge in 30 minutes or less.

```
   1   │ #!/usr/bin/python3
   2   │ 
   3   │ import subprocess
   4   │
   5   │ enc_flag = "75ac713a945e9f78f657b735b7e1913cdece53b8853f3a7daade83b319c49139f8f655b0b77b"
   6   │ dec_flag = [ ]
   7   │
   8   │ start = 33
   9   │ end = 126
  10   │
  11   │ dec_index = 0
  12   │ guess = ""
  13   │ answer = ""
  14   │ while True:
  15   │     dec_flag.append(0x0)
  16   │     for i in range(start, end):
  17   │         cmp_offset = (dec_index + 1) * 2
  18   │         dec_flag[dec_index] = str(hex(i)[2:])
  19   │         guess = ''.join(dec_flag)
  20   │
  21   │         ret_val = subprocess.run(f"echo {guess} | ./PES", shell=True, capture_output=True)
  22   │         ret_val = ret_val.stdout.decode('ascii').split("\n")[-1]
  23   │
  24   │         if enc_flag[:cmp_offset] == ret_val[:cmp_offset]:
  25   │             answer += str(chr(i))
  26   │             print(answer)
  27   │             break
  28   │
  29   │     if ''.join(dec_flag) == enc_flag:
  30   │         break
  31   │
  32   │     dec_index += 1
```

Is this beautiful? No... but did it get us to solve a 973 point challenge that only 50 other folks solved without having to open the binary in a decompiler or a debugger? Yes!

Let's go through it!

Line 5 is just the flag we were given and line 6 is a var we use later.

8 and 9 are the start and end of the ASCII printable characters in decimal and up until line 14, we just declare some more variables.

Line 15 might seem strange, but we have to populate our testable range with something to avoid an out-of-index error. This is part of the algorithm that is ugly and results in us having to manually exit the script (yeah, yeah, I didn't fix it. fite me).

We start a for loop to test each printable ASCII character, and, as pseudocode, our algorithm does this:

```
set offset for two-byte chars 
answer_arr[i] = current_ascii_chr // we strip the "0x" with [2:]
answer_str = "".join(answer_arr)

echo answer_str | ./PES

if flag[num_bytes_to_compare] == answer_str:
  num_bytes_to_compare++
  print(answer_str)
```

It really is that simple, but I had to do some subprocess magic to get it to work. Also, like I said before, I have not debugged the reason why the script doesn't exit, and I am assuming it is because I automatically append an additional byte to the end of the answer array. 

This is easily fixable, but this very short script automagically pooped out the answer for me:

```
>> ./solve.py
u
ut
utf
utfl
utfla
utflag
utflag{
utflag{i
utflag{i_
utflag{i_g
utflag{i_go
utflag{i_got
utflag{i_got_
utflag{i_got_t
utflag{i_got_th
utflag{i_got_the
utflag{i_got_the_
utflag{i_got_the_n
utflag{i_got_the_ne
utflag{i_got_the_nee
utflag{i_got_the_need
utflag{i_got_the_need_
utflag{i_got_the_need_f
utflag{i_got_the_need_fo
utflag{i_got_the_need_for
utflag{i_got_the_need_for_
utflag{i_got_the_need_for_a
utflag{i_got_the_need_for_am
utflag{i_got_the_need_for_amd
utflag{i_got_the_need_for_amda
utflag{i_got_the_need_for_amdah
utflag{i_got_the_need_for_amdahl
utflag{i_got_the_need_for_amdahls
utflag{i_got_the_need_for_amdahls_
utflag{i_got_the_need_for_amdahls_l
utflag{i_got_the_need_for_amdahls_la
utflag{i_got_the_need_for_amdahls_law
utflag{i_got_the_need_for_amdahls_law}
```

After the closing "}", I just manually exited the program (lol). 

Also, I have no idea what amdahl's law is and it obviously wasn't required to solve this challenge (unless I invented it again just now). In fact, not even a decompiler or debugger were required! All we needed to see was that we had a limited key space and that there was only one correct byte based on the previous byte and the first byte always matched the first byte entered! 

