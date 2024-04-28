# Prompt 

Thufir Hawat is ready to answer any and all questions you have. Unless it's not about division...

nc challs.umdctf.io 32300 

# Solve

We get source and binary together again, which is fantastic. We also don't have any stack canaries, per `checksec`, which is great as well.

Opening that source code shows us the following logic in a nutshell:

1. We must enter "Division" first. No exceptions
2. We are asked to choose two numbers to divide together, and the denominator can not be 0 
3. This math is calculated and returned *or*
4. If our denominator is less than 1, we hit extra logic 
5. Either way, so long as our result returns 0, we have the option to divide more numbers

## The Secret Sauce 

The "secret sauce" of this challenge is in number "4" above. The extra logic we can hit if our denominator is less than 1 includes two critical bugs: A print format string (info leak) and a call to `gets` (stack overflow).

We don't have any cookies, but we do have an unused function named `secret` which drops us to a shell. So, the information must be used for this since PIE is enabled.

The first hurdle is to get past the "less than 1" check. 

Why?

Well, if you remember number "2" from above, there is a check to make sure our denominator is not "0". Additionally, we can't use negative numbers because our entry gets type-promoted to an unisnged int.

So... we are stuck.... *except* that the check for "0" is on the *entered value* and *not* the result of `atoi`! 

What does this mean? Well, if `atoi` immediatley encounters an unknwon character, it returns 0 (hilarious, I know)! So, let's say we enter somethinb like `AA`... what will happen?

Sure enough, our buffer contains the strings `AA` (not `0`) and `atoi` returns `0` as well.

This means we can now hit the "extra logic" in the code!

## Extra Stuff 

This is the code that includes a bof and an info leak. The only catch for the info leak is that our buffer must begin with the characters `Yes` to work (check the code for details on this as there is no reason to harp on it further).

Inspecting the stack with `telescope` while debugging this process, we see we have a consistent address that is 3728 bytes *ahead* of the `secret` function we need. Well, not *technically*, but because we are corrupting the stack, we skip the preamble of the `secret` function and just jump to the good stuff.

This leak is near the top of the stack, so, if we get to the extra logic and are met with the `Would you like to try again?` prompt, we just have to enter `Yes %1$p` to get our leak (see the solution for more details).

To finally solve this problem, we need to -- once again -- go through the division problem `0/AA`, and once we hit the extra logic we just have to enter data into the `gets` call enough to overwrite the return address with our desired address from above.

I solved this by padding my payload starting with `Yes`, just as before; however, to be honest, I am not sure if that is necessary since the `gets` call is prior to the check for `Yes`. However, this still worked

UMDCTF{3_6u1ld_n4v16470r5_4_7074l_0f_1.46_m1ll10n_62_50l4r15_r0und_7r1p}
