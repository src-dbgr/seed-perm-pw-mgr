# Interactive Seed Permutation PW Manager
- Simple password generation and PW retrieval manager.
- Random PW generation based on custom chosen secret permutation seed number and custom chosen secret pin number.
- PW retrieval by passing the permutation array in combination with the secret permutation seed and the secret pin number.
- No memorization of multiple passwords, simply store the resulted permutation array somewhere and memorize your secret seed + secret pin
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