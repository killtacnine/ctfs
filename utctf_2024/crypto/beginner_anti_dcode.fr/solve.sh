#!/bin/bash 

printf "Let's do this 😎\n"

FILE="LoooongCaesarCipher.txt"
OUTPUT="deciphered.txt"
REGEX="utflag{."

ALPH=(a b c d e f g h i j k l m n o p q r s t u v w x y z)
ALPH_LEN="${#ALPH[@]}"
INDEX=0

# Model is 'tr "[<LETTER1>-za-<LETTER2>]" "[a-z]"'
for _ in "${ALPH[@]}"; do
  LETTER1="${ALPH[""$(( ${INDEX} % "$(( ${ALPH_LEN} ))" ))""]}"
  LETTER2="${ALPH[""$(( (${INDEX} - 1) % "$(( ${ALPH_LEN} ))" ))""]}"

  cat "${FILE}" | tr "["${LETTER1}"-za-"${LETTER2}"]" "[a-z]" > "${OUTPUT}"

  FLAG="$(grep -E -o "${REGEX}" ""${OUTPUT}"")"
  if [[ "$?" == "0" ]]; then
    printf "You found the right shift 😮\n"
    while [[ "${FLAG:0-1}" != "}" ]]; do # Closing char of flag
      REGEX="${REGEX}""."
      FLAG="$(grep -E -o ""${REGEX}"" ""${OUTPUT}"")"
    done

    printf "You found the right shift 🤐\n"
    printf "Flag: %s\n" "${FLAG}"

    exit 0;
  fi

  INDEX="$(( $INDEX + 1 ))"
done

exit 1
