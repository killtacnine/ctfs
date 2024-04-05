# PROMPT

I've heard that everyone just uses dcode.fr to solve all of their crypto problems. Shameful, really.

This is really just a basic Caesar cipher, with a few extra random characters on either side of the flag. Dcode can handle that, right? >:)

The '{', '}', and _ characters aren't part of the Caesar cipher, just a-z. As a reminder, all flags start with "utflag{".

By Khael (Malfuncti0nal on Discord).

# SOLUTION 

I have no idea what the reference to dcode.fr is. In fact, that doesn't even sound like English to me. 

All I know is that the prompt gives us the following information:

- They probably don't want us to use dcode.fr (why would we...)
- The data is shifted by some unknown number, but this number must be 25 or less
- The previous point is know-able because they tell us the flag alphabet is only a-z (no uppercase or numbers)
- They strongly hint that we will know we have hit the correct shift if the file includes the string "utflag{"

This is very straightforward. In fact, I literally solved it by guessing the shift. 

*However*, that isn't fun, so let's solve it the intended way! 

Python is illegal and for nerds, so we are going to use Bash for two reasons: 

1. I love how unreadable properly de-globbed Bash is. It makes it so you really have to read it and see what's going on. (this is a joke... or is it?)
2. I am often in situations where I only have Bash available (as opposed to Python), so using correctly formatted Bash can not hurt me. 

## Shifting

The standardized way to do caesar-esque alphabet shifts using the linux coreutils is to use the `tr` command. 

It works like this (we are only demonstrating a-z as an alphabet, but you can use numbers and upper case as well):

```
echo "the quick brown fox jumps over the lazy dog" | tr '[a-z]' '[n-za-m]' # encode
echo "gur dhvpx oebja sbk whzcf bire gur ynml qbt" | tr '[n-za-m]' '[a-z]' # decode
```

The above code will do a shift-by-13 (known as rot13, colloquially) on the alphabet, followed by a reverse-shift-by-13. 

We know we only care about the reverse-shift-by-X formula, so how can we generalize this?

The basic format for decrypting a shift cypher is that the final argument of `tr` will always be '[a-z]', "za" must always be in the "middle" of the first argument, and the number on the end must always be the character directly before the character on the right ("m" and "n" on the right and left respectively in the above example).

Remember, you can use `tr` to abuse text, so this formula isn't "the only and correct way" to do rotations, but, for this challenge, there is no need to get further into the weeds. 

## Scripting

I know you are now thinking, "So, I just write a bash script that does each shift? like 1 line for `tr '[n-za-m]' '[a-z]'`, another for `tr '[o-za-n]' '[a-z]'`, `tr '[p-za-o]' '[a-z]'`, and so on...?"

*NO*! We automate everything, you fools...

Here is the script we developed with explanations for everything to follow:

```
  1   │ #!/bin/bash
  2   │
  3   │ printf "Let's do this 😎\n"
  4   │
  5   │ FILE="LoooongCaesarCipher.txt"
  6   │ OUTPUT="deciphered.txt"
  7   │ REGEX="utflag{."
  8   │
  9   │ ALPH=(a b c d e f g h i j k l m n o p q r s t u v w x y z)
 10   │ ALPH_LEN="${#ALPH[@]}"
 11   │ INDEX=0
 12   │
 13   │ # Model is 'tr "[<LETTER1>-za-<LETTER2>]" "[a-z]"'
 14   │ for _ in "${ALPH[@]}"; do
 15   │   LETTER1="${ALPH[""$(( ${INDEX} % "$(( ${ALPH_LEN} ))" ))""]}"
 16   │   LETTER2="${ALPH[""$(( (${INDEX} - 1) % "$(( ${ALPH_LEN} ))" ))""]}"
 17   │
 18   │   cat "${FILE}" | tr "["${LETTER1}"-za-"${LETTER2}"]" "[a-z]" > "${OUTPUT}"
 19   │
 20   │   FLAG="$(grep -E -o "${REGEX}" ""${OUTPUT}"")"
 21   │   if [[ "$?" == "0" ]]; then
 22   │     printf "You found the right shift 😮\n"
 23   │     while [[ "${FLAG:0-1}" != "}" ]]; do # Closing char of flag
 24   │       REGEX="${REGEX}""."
 25   │       FLAG="$(grep -E -o ""${REGEX}"" ""${OUTPUT}"")"
 26   │     done
 27   │
 28   │     printf "You found the right shift 🤐\n"
 29   │     printf "Flag: %s\n" "${FLAG}"
 30   │
 31   │     exit 0;
 32   │   fi
 33   │
 34   │   INDEX="$(( $INDEX + 1 ))"
 35   │ done
 36   │
 37   │ exit 1
```

I told you properly de-globbed Bash is hard to read...

Line 5 is a variable holding the encrypted text. We *never* write to this as it is required to solve the challenge. We just read it
Line 6 is an output file for our possible solutions to be stored on disk. 
Line 7 is regex we will use later...

Line 9 is where is gets interesting. This is a Bash array, which is a beautifully underused artifact in Bash. 
The following line uses Bash variable expansion (also criminally underused) to grab the length of the array (this feels like a challenge they will add capital letters and numbers to next year, so let's make it easy to change in the future). 
Then on line 11, we have another var we will get to later. 

Starting on line 14, we begin our algorithm. Remember, we only need to calculate two letters: some letter at some index, and the letter either directly ahead or behind that one in the array. I chose to pick a letter and grab the one behind it (possible in Bash, as well, given that we can reference array indices in the negative, like with other languages). 

The de-globbing using quotation marks makes it difficult to read, but all that is happening on lines 15 and 16 is we are declaring variables that hold alphabet[index % 26] and alphabet[(index - 1) % 26]. Nothing more, nothing less.

On line 18, we can *not* use single-quotes in `tr` as per the previous example. Why? Because single-quotes are special characters in bash (and other shells) intended to prevent the expansion of variables into their definitions in case you need the *literal characters* that might represent a variable. So, on line 18, we are calling `tr`, but replacing LETTER1 and LETTER2 with out pre-defined letters. Try it with single-quotes to see what happens.

On line 20, we use our regex variable from before (we still won't explain it quite yet) and on line 21 we check the return value of that command ("$?"). If $? is 0, grep found something!. 

If grep did *not* find something, we just increment the index on line 34 and continue. 

Assuming we did find something with grep, then we take our regex variable and update it. Why do we do this? Because there are no new-lines in the file we were given, grep fundamentally breaks. grep doesn't *depend* on new lines, but it does use them when we are trying to tell grep to use regex. 

Let's break down our grep command found on lines 20 and 25:

```
grep -E -o "${REGEX}" "${OUTPUT}" # Remember that REGEX represents "utflag{." for the moment and OUTPUT is just the file we want to read
# -E means "use regex". So, our search won't search for exact text.
#    our regex is 'utflag{.' and the "." in this context means "any single character". So, this regex will retern "utflag{<first character of flag"
# -o means return "o"nly the values you find. If we don't include this, grep will print the entire line it found the match on
#    since we don't have any new lines... a success means grep will print the entire file...
```

You'll notice on line 23 we are checking if our regex's final character is "}" and, if not, it adds more "."s to the regex search. 

This was the best way I could figure to do this, but I would love to see other ideas.

That being said, this challenge does strongly feel like a challenge that will be re-used/updated to be more difficult next year, and I love writing Bash, so this 20 minute solve was fairly satisfying.

```
>> ./solve.sh
Let's do this 😎
You found the right shift 😮
You found the right shift 🤐
Flag: utflag{rip_dcode}
```

