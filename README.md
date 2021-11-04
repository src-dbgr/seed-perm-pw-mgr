![Index Generation](/misc/logo.jpg "Masked PW and Index Generation")
# Interactive PRNG Seed Permutation PW Manager

- Simple password generation and PW retrieval manager.
- Pseudo Random PW generation based on custom chosen secret permutation seed number and custom chosen secret pin number.
- With each PW the generator creates encrypted token - These token need to be stored somewhere since they are crutial for PW retrieval.
- PW retrieval happens by passing the token in combination with the secret permutation seed and the secret pin number.
- No memorization of multiple passwords, simply store the resulted token somewhere and memorize your secret seed + secret pin
- Max PW length 62 characters
- Recommendation to use PWs with length > 20 characters
- Recommendation to run the batch script from within Windows PowerShell since PowerShell provides all mechanisms for obfuscation
- Multiple PW generation and retrieval options available
- Everything runs on your local machine

## Prerequisites

- Maven
- Java v11
- Windows Terminal (recommended)

#### Build Run:

mvn clean install

##### Attention - some features, such as color change of output text, do not work within CMD prompt (Vulnerable to screen shot hacks)

- Execute `run.bat` or `run.sh`
- Or alternatively
  Then navigate to:
  `<your drive path>\manager\target`

Execute in PowerShell:
`java -cp manager-0.0.1-SNAPSHOT.jar com.sam.key.manager.Generator`

## Example PW Generation with Custom Seed Number & Custom PIN
Execute `run.bat` within project by double click on it, this will open the following terminal.
![Menu](/misc/01_pw_generation_token_menu.jpg "Menu")

>Note: Choose strong secret Seed and Pin numerical values for good protection

![Menu](/misc/02_pw_generation_token.jpg "Menu")

## Memorize the given Seed number and Pin number, choose a numerical value
- Note down the Token!
  >NOTE: The value can be signed!
  
  Pass an integer without comma `,` or dot `.`

- **Max Value** for the Seed and Pin is: `9,223,372,036,854,775,807`

- **MIN Value** for the Seed and Pin is: `-9,223,372,036,854,775,808`

## Retrieve PW With Indexes Array & Custom Seed Number & Custom PIN (Seed and PIN need to be the Same as have been used for the PW / Token generation)

![Index Generation](/misc/03_pw_retrieve_token.jpg "Copy and Paste Content into Text Editor")
