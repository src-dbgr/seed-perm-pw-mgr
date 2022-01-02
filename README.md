![Index Generation](/misc/logo.jpg "Masked PW and Index Generation")

# Interactive Permutation PW Manager

> ## The current version is in a beta phase, but the basic functionality is in place, feel free to test it. I am happy about any feedback

Since I was annoyed of constant PW changes and maintenance, I was pointed towards PW managers. However, in many cases, I simply do not understand what these PW Managers are doing exactly and where my PWs are actually stored and how secure it is to pass my passwords to some external host. I decided to try to build something myself to have an idea about the combinatorics involved. I came up with the following project.

- Simple password generation and PW retrieval manager.
- Passwords are randomly generated with CSPRNG within a provided length range.
- PW encryption based on AES 256 GCM cipher. Internal chained alphabet permutation of distinct and separate seed values.
- With each PW the generator creates encrypted token - These token need to be stored somewhere since they are crutial for PW retrieval.
- PW retrieval happens by passing the token in combination with the secret permutation seed and the secret pin number.
- No memorization of multiple passwords, simply store the resulted token somewhere and memorize your secret seed + secret pin
- Max PW length 62 characters
- Recommendation to use PWs with length > 20 characters
- Multiple PW generation and retrieval options available
- Everything runs on your local machine

## Prerequisites

- Maven
- Java v11

#### Execute Clean Build:

> `mvn clean install`

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

> Note: Choose strong secret Password [Chars and numbers] and Pin [numbers] values for good protection

![Menu](/misc/02_pw_generation_token.jpg "Menu")

## Memorize the given Password and Pin number.

- Note down the Token! (In later implementations this could be improved to be stored in a local db or csv etc.)

  > NOTE: The value can be signed!

  Pass an integer without comma `,` or dot `.`

- **Max Value** for the Seed and Pin is: `9,223,372,036,854,775,807`

- **MIN Value** for the Seed and Pin is: `-9,223,372,036,854,775,808`

## Retrieve PW With Indexes Array & Custom Password & Custom PIN (Password and PIN need to be the Same as have been used for the PW / Token generation)

![Index Generation](/misc/03_pw_retrieve_token.jpg "Copy and Paste Content into Text Editor")

## Run SonarQube local analysis
- start a local SonarQube, a Docker container for instance
- `mvn clean verify sonar:sonar   -Dsonar.projectKey=<project key>    -Dsonar.host.url=http://localhost:9000   -Dsonar.login=<login-token> -DskipTests`