# Prompt
Can you help me fix my code?

Files:

    wrapper.c
    wrapper
    chall
    chall.c

nc mitigations-are-awesome.ctf.umasscybersec.org 1337 

# Solve

We are given two files:
  - a wrapper
  - a challenge file

We get the source code and the binaries, which is great. 

Checksec shows:

```
[*] '/root/workbench/umassctf_2024/pwn/mitigations_are_awesome/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/root/workbench/umassctf_2024/pwn/mitigations_are_awesome/wrappper'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

What's interesting is that `chall` (which is the only binary we can interface with, it seems) does not have PIE enabled. The `wrapper` does not have a canary, which is also interesting. Worth noting as well is that the `chall` binary only has partial RELRO. That may not matter, but it is a difference. But then... things got interesting... 

## What Happened To This Challenge?

The authors of the ctf did a fantastic job, but as someone who has self-hosted many a ctf, I know from experience that things go wrong at the worst possible time. I have no clue at all what the point of the `wrapper` binary and source code was, but I get the vibe that whatever was going on there was abandoned due to issues during the ctf (we will see later that the flag actually helps us confirm this).

That being said, for those following along at home, we can just ignore anything with `wrapper` in its name going forward. 

## The Heap

We have a `win` function! This is indicative of a ROP or UAF challenge. That narrows things down a bit. 

If we run the challenge, we see the following: 

```
>> ./chall
+=========:[ Menu ]:========+
| [1] Make Allocation       |
| [2] Resize Allocation     |
| [3] Edit Allocation       |
| [4] Retrieve Flag         |
| [5] Exit Shop             |
+===========================+

 > What action do you want to take?
```

I won't even show any decompilation in this writeup because the functions behind these menu items aren't playing any tricks on us. They really are just making allocations with `malloc`, resizing allocations with `realloc`, writing data to allocated areas, and then calling the `win` function if a heap block we can't seem to control contains the string `Ez W` (called with option "[4] Retrieve Flag").

There *are* two things you need to know from the decompilation though...

1. The "Edit Allocation" option uses `gets`, so we can overflow our heap buffers 
2. The "Retrieve Flag" option calls `malloc(32)`, which is relevant for the condition mentioned above

Excellent! This must be a UAF challenge! This means we will have to do something like `allocate`, then `realloc` and try to trick the heap manager into using different memory instead of just extending the same memory region. 

Per the `realloc` man pages: 

```
  void *realloc(void *ptr, size_t size); 

  The realloc() function changes the size of the memory block  pointed
  to  by  ptr  to  size  bytes.  The contents will be unchanged in the
  range from the start of the region up to the minimum of the old  and
  new  sizes.   If the new size is larger than the old size, the added
  memory will not be initialized.  If ptr is NULL, then  the  call  is
  equivalent to malloc(size), for all values of size; if size is equal
  to zero, and ptr is  not  NULL,  then  the  call  is  equivalent  to
  free(ptr).   Unless  ptr  is  NULL, it must have been returned by an
  earlier call to malloc(),  calloc(),  or  realloc().   If  the  area
  pointed to was moved, a free(ptr) is done.
```
So, it doesn't mention anything about what causes the memory region to be `freed`. But, we do see that we can `free` a region by entering a new size of `0`. However, I tried that, and the code blocks us from using `0` when we want to allocate or reallocate memory. 

## What Else To Try? 

I did a heap spray... That is what the `input.txt` and `gdb.script` files are doing in this repo, but don't bother using them... This didn't work, and it was a bad idea. 

## So, How Do We Actually Solve?

So, we can use `gef` to do some heap analysis and some rudimentary inspection (which is all we need). All we care about is:

1. Can we use `realloc` to actually "move" to a new memory region instead of just expanding or shrinking the same region?
2. If we do "move" to new memory, can we reuse the old memory deterministically? 
3. Can we either control the data in that region after it is "moved" away from or confirm that the data we entered there is not altered after we "move"?

We can easily disprove the second part of number 3, because we fairly trivially proved number 1! We can indeed move to a new memory region if we just put the memory in a small enough hole that it can't expand without moving! 

To test this, I made 3 allocations:

```
gef➤  heap chunk 0x10717a0
Chunk(addr=0x10717a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Chunk size: 32 (0x20)
Usable size: 24 (0x18)
Previous chunk size: 0 (0x0)
PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA

gef➤  heap chunk 0x10717c0
Chunk(addr=0x10717c0, size=0x30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Chunk size: 48 (0x30)
Usable size: 40 (0x28)
Previous chunk size: 0 (0x0)
PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA

gef➤  heap chunk 0x10717f0
Chunk(addr=0x10717f0, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Chunk size: 1040 (0x410)
Usable size: 1032 (0x408)
Previous chunk size: 0 (0x0)
PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA
```

So, in reverse order, the last allocation is at 0x10717f0, the one before is at 0x10717c0, and the earliest is at 0x10717a0. Some basic math shows the allocations 1 and 2 are 32 bytes apart and 2 and 3 are 48 bytes apart. In text, this looks something like this:

```
  32 bytes    48 bytes        1040 bytes
|-----------|---------------|-----------------------------------|
```

The reason I created such a small allocation first (I only asked for 4 bytes) was to demonstrate that the heap only allocates in certain size chunks at a time. In this case, it is 32 bytes that is the smallest amount we can allocate. But, it isn't actually 32 bytes of *data*. The chunk in its entirety is 32 bytes. There are 8 bytes of metadata in the chunk that isn't the `data` portion of the chunk. So, you notice I allocated 32 bytes in the second allocation, but the chunk is 48 bytes? This is why (well, that and because the heap manager rounded up the data allocated to 40 bytes instead of 32)! 

This matters because the value we need to be free is one large enough to hold 32 bytes of *data* (since the check to send us to `win` requests a 32 byte large memory region for data). The minimum amount we need is 48 bytes. So, how do we make those 48 bytes there free? 

Let's try a `realloc`! 

If we `realloc` the second region (index "1") to `1024` bytes (other values will work, so long as it is larger than 48 bytes) we do, in fact, move our new region to 0x1071800, which is very far from where we were before. So, now, the heap looks like this:

```
  32 bytes    48 free bytes   1040 bytes
|-----------|---------------|-----------------------------------|

```

Inspecting the free bytes indicates the data there was overwritten with new heap data, so filling the memory region with repeated `Ez W`s before moving the region won't work!

## The Overwrite

The final stage of this solve was to use the `gets` overflow we talked about earlier!

We mentioned that our data in the prior-to-`realloc` region is overwritten after the move. But, we *can* write to it afterwards prior to getting the heap allocator to give it back to us! 

Let's walk through what we are doing so far: 

1. Allocate 4 bytes (or whatever)
2. Allocate 32 bytes 
3. Allocate 1024 bytes (also doesn't really matter)
4. Re-alloc the 32-byte chunk to 1024 bytes 

We now have our 48 byte "hole" which will be picked up the next time the allocator is asked for 32 bytes.

If we want to write into that "hole" after it has been freed for us after `realloc`, we have to write 36 bytes to the *first* memory region (which is why we had to allocate an arbitrary region before our "hole" instead of the first region being the "hole").

Remember, there are 8 bytes of metadata in the chunk and the smallest size of a region we could allocate was 32 bytes. This means there are 24 bytes of `data` available. 

So, why do we want to write 36 bytes? Because we overwrite the 24 bytes of data in our region, the 8 bytes of metadata in the next usable chunk, and then we write 4 bytes into the `data` region of the next chunk! 

So, we continue our alrogithm: 

5. Edit chunk at index 0 and write 36 bytes, such as: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEz W"
6. Call the "Retrieve Flag" option
7. `malloc(32)` is made and uses the chunk with a data section reading `Ez W`

UMASS{$0m3on3!_g37z_4ng$ty_wh3n_ptr4c3_w0rkz!!!}

# Conclusion 

You can see that the flag indicates I should've cared about `ptrace`. The `wrapper` source code indicated this too... But, like I said before, I just ignored `wrapper` (and `ptrace`, for that matter). 

This could be an artifact of the original challenge going wrong? Either way, it was a fun challenge, just not sure what `wrapper` was for and why `ptrace` was mentioned...
