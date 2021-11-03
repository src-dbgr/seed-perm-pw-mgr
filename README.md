# Interactive PRNG Seed Permutation PW Manager

- Simple password generation and PW retrieval manager.
- Pseudo Random PW generation based on custom chosen secret permutation seed number and custom chosen secret pin number.
- With each PW the generator creates encrypted token - These token need to be stored somewhere since they are crutial for PW retrieval.
- PW retrieval happens by passing the token in combination with the secret permutation seed and the secret pin number.
- No memorization of multiple passwords, simply store the resulted token somewhere and memorize your secret seed + secret pin
- Max PW length 60 characters
- Recommendation to use PWs with length > 20 characters
- Recommendation to run the batch script from within Windows PowerShell since PowerShell provides all mechanisms for obfuscation
- Multiple PW generation and retrieval options available
- Everything runs on your local machine

## Prerequisites

- Maven
- Java v11
- Windows Terminal (recommended)
- Powershell (recommended)
- GitBash (recommended)

#### Build Run:

mvn clean install

#### Execute securely in PowerShell

- I noticed that my desired behaviour worked so far when I open Powershell from Windows Terminal
- Open PowerShell
- Navigate to `<your local path>\manager`
- Type: `./run.bat` into your PowerShell and press Enter
- Follow Options provided

#### Alternative - Run directly from within CMD / Bash

##### Attention - some features, such as color change of output text, do not work within CMD prompt (Vulnerable to screen shot hacks)

- Execute `run.bat` or `run.sh`
- Or alternatively
  Then navigate to:
  `<your drive path>\manager\target`

Execute in PowerShell:
`java -cp manager-0.0.1-SNAPSHOT.jar com.sam.key.manager.Generator`

# The following Example is deprecated and will be updated soon since the retrieval mechanism has been changed to a token based approach

## (DEPRECATED) Example PW Generation with Custom Seed Number & Custom PIN

![Index Generation](/misc/00_pw_generation.jpg "Masked PW and Index Generation")

## (DEPRECATED) Copy & Paste Content into Text Editor

![Index Generation](/misc/01_pw_unmasked.jpg "Copy and Paste Content into Text Editor")

## (DEPRECATED) Retrieve PW With Indexes Array & Custom Seed Number & Custom PIN (Seed and PIN need to be the Same as have been used for Creation)

![Index Generation](/misc/02_pw_retrieve.jpg "Copy and Paste Content into Text Editor")
