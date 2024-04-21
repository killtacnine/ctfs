# Prompt 

Come one, come all! For a limited time only, The Magic Conch is answering your most pressing queries! Fun and knowledge will collide as you learn the deepest secrets of the unvierse! If your queries are thought-provoking enough, The Magic Conch may even present you with the flag! (Please keep your queries to 32 bytes or less; The Magic Conch does not have the patience for yappers)

Files:

    magic_conch

nc magic-conch.ctf.umasscybersec.org 1337 

# Solve 

This is an RE challenge, so we first run the program, then open the binary in Ghidra. 

Running the program shows: 

```
ERROR: Environment variable FLAG not set
```

If we pass in a FLAG variable, we see the same for a PORT variable. Once we enter that, we get a server listening at our port. 

The binary returns some hex-like data depending on what we enter, but our entries return the same result every time, sort of like a hash. We've seen a lot of challenge like this, so it's probably a "reverse the algorithm" binary. Let's open it up and see.

## Weird Binary 

What's immediately interesting about this binary is that we can't find the strings or the commands we would expect for a challenge like this. How can this be? How can I binary listen on a port without any socket commands?

I cleaned up the binary to be pretty neat and tidy, which results in this pretty easy-to-follow code:

![cleaned up code](./media/cleaned_up_code.png)

Let's walk through what's happening here at a high level:

1. A global data blob of ~16,000 bytes (I've marked it encrypted_elf) is grabbed and converted to raw bytes 
2. This string of bytes is then decrypted on line 21, followed by a free of the encrypted_bytes
3. We then create a memory-only file descriptor which is difficult to interface with from user space. memfds are very annoying. They can store data that never touches disk, and is therefore ephemeral.
4. The decrypted bytes are written to the memory file descriptor 
5. The file descriptor is opened and the address of the symbol "EntryPoint" is loaded
6. If everything has gone well, the address of "EntryPoint" is called a function 

## Decrypting The Bytes 

So, it seems pretty straight forward: whatever code is being executed as `addr_of_entry` must be where the actual "magic" lives. But, how do we grab it? 

I noticed in the `decrypt_payload` function that the decryption seemed pretty straightforward. If you want to test some of your reversing chops, try to identify the initialization vector for the decryption code. One way to solve this challenge must be to actually decrypt the bytes, because the author of the challenge used fairly easy to identify "seeds" for the encryption. If you use the same library the author does to decrypt the bytes, you can just do it yourself! 

Alas, I am lazy... 

So, imagine how happy I was when it occurred to I could just set a breakpoint at the `write` call from line 32 (whichonlyoccurredtomeafterireversedthedecryptionmechanismlollmao). If you completed the sidequest for this challenge, and you know what "YELLOW SUBMARINE" and "*CHICKEN NUGGET*" means... congrats...

So, I set a breakpoint to just before the `write` call and I checked its parameters. This revealed that we were going to write 168000 bytes to some memory address (because this executable is PIE, the value is different every time).

No matter where the address is, once you get it from the `write` call, you can use the handy-dandy `dump` feature of `gdb` to dump the decrypted bytes to disk:

```
gef> dump binary memory magic_conch_part_2 <start addr> <start addr + 168000>
```

We now have a new elf! However, we can't run it without segfaulting... so, let's open it in Ghidra!

## Solving The challenge 

We see why the program segfaults... it doesn't have a `main`! But, we remember from the previous reversing that we loaded a symbol named `EntryPoint`. Sure enough, that symbol does exist; but, the function itself is super boring. It just does the socket listen. 

We see that the function we *really* want is `thread_start`!

Sure enough, in this function we see the strings we expect, the calls we expect, etc.

Again, clean the function up and get something like this: 

![cleaned up code 2](./media/cleaned_up_part_2.png)

You notice I cut the function off at line 90, but that's only because the remaining code doesn't matter. All you need to know is that if comparison on line 89 is of two equal values, then we pass the check on line 90 and the flag is printed for us. The actual algorithm is what is pictured here. 

Reading Ghidra can be a daunting task, but if you follow along, you can effectively see that we have a recv call that gets our first "query". Our entered value is run through a custom function named `HASH` which does some calculations on the input and then returns the `sha256` checksum of the calculated input.

This process is repeated again for a second `recv` call so long as no errors occur... Then things get interesting... 

On line 83, our recv buffers are compared and if they are the same, the program exits. This means we can't enter the same value twice. Why that is interesting is because the comparison onl in 89 is for the calculated values of our input. This means that we must enter two *different* values that, when caluclated by the `HASH` function return the same result. 

![hash algorithm](./media/hash.png)

This function is very simple. I have no clue what the decompilation is trying to tell us on lines 15 and 17, but lines 16 and 18 tells me that we are splitting our 32 byte input (the `read` calls were only for 32 bytes -- well, 33, but the newline is removed) into 2 16 byte values which are XOR-ed together. Those XOR-ed values are `sha256` checksummed. 

*Voila!* We need the first 16 bytes to be the second 16 bytes in our second call, and the second 16 bytes to be the first 16 bytes in our second call. 

This could look like this: 

`AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB`

and 

`BBBBBBBBBBBBBBBBAAAAAAAAAAAAAAAA`

There are like... millions of possible ways to do this. So long as the values don't match but we use the same set of 16 bytes twice, we can get the flag!

UMASS{dYN4M1C_an4ly$1s_4_Th3_w1n}
