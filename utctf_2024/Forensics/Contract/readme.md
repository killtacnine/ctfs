10 0011 10 10 1

# Challenge Name: <br>
  Contracts
    
# Challenge Description: <br>
  Magical contracts are hard. Occasionally, you sign with the flag instead of your name. It happens.
  
# Challenge Author: <br>
  Samintell (@samintell on discord)

# Solution: <br>
  I initally examied the pdf in my browser to get a hint at what I need to be looking for. Taking in to         account the Challenge Description "Occasionally, you sign with the flag instead of your name" I was           thinking the flag was going to be some kind of pdf layer trick, however there are few free tools to examine   pdf layers so I quickly crossed that option out. 

  Next step was to examine the pdf document in my FlareVM using the following tools (pfid, pdf-parser, 
  PDFStreamDump). I was unable to find any interesting 
  information that might point me in a different direction (JS streams).

  Using the tool pdfimages via SIFT wsl I was able to extract all images embedded indside the pdf file. 1 of 
  the 8-10 images extracted from the PDF was a 
  photo of the flag.
  
  ![Capture](https://github.com/vr0n/utctf_2024/assets/48105639/4667947a-34dc-4217-a78c-3497decad757)
