# Prompt 

If you want the flag, command me to give it to you. 

# Solve 

In `checksec`, we see we have a canary, but no PIE, which is nice...

We also have the source code and it is only 23 lines, which is even nicer!

On initial inspection, we can see this is just a simple ROP challenge to jump to the `give_flag` function.

## Blazing The Trail

The buffer we need to overwrite is 16 bytes and using `nm the_voice | grep give_flag` we see the addres of the function we care about:

```
>> nm the_voice | grep -i give_flag
00000000004011f6 T give_flag
```

This binary seems extremely straightforwad with one simple hiccup...

The only line that is odd to us is line 22. Here it is with its context:

```
     4 __thread long long g[10] // Global var
       ...
       ...
    21    gets(command);
    22    g[atoi(command)] = 10191;
```

Why this matters is because we have a global variable we can assign some value to and the *cookie itself* is a global variable. In assembly, this looks like the following:

```
mov    QWORD PTR fs:[rax*8-0x50], 0x27cf // Moving the value 10191 into the global variable
...
...
mov    rdx, QWORD PTR [rbp-0x8]          // Pulling the cookie from the stack
sub    rdx, QWORD PTR fs:0x28            // Subtracting it from the global value to check integrity
```

We control `rax` from the first line of the previous assembly block. This means, that if we can solve some equation such as `(x * 8) - 0x50 = 0x28` and `x` doesn't cause a segfault, we can just use the value of 0x27cf as our "cookie" and the `sub` check will pass (if you aren't aware of how cookie works in `gcc`, the result of the subtraction must be `0` or the code exits -- not all cookies work this way, though).

Spoilers: we *can* solve the equation and it does not crash the code. The value we must pass in is `0xf`, but because `atoi` is used, we just use the string "15"!

## Another Problem 

I hit a problem I have hit before so frequently that you would think I would have learned better... 

I jumped to the the *start* of the address of the `give_flag` function which uses the basic function preamble to preserve and set the local stack. 

This is a major problem because we are corrupting the stack... In fact, we are corrupting the stack so brutally that `malloc` was broken (which is called from within `fopen` in `give_flag`).

The way to get around this is to *totally control the stack* by jumping just pass the function preamble! We just had to change our rop from the start of `give_flag` to 0x4011fb (a few bytes past the start).

UMDCTF{pwn_g3ss3r1t_sk1ll5_d0nt_tak3_a5_many_y3ar5_t0_l3arn_pau1}
