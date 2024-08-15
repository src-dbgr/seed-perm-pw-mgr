package com.sam.key.manager;

import com.sam.key.cipher.AesGcmPw;
import org.apache.commons.math3.random.MersenneTwister;
import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.AnsiConsole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.fusesource.jansi.Ansi.Color.*;
import static org.fusesource.jansi.Ansi.ansi;

/**
 * Interactive CSPRNG / PRNG Password Manager.
 * <p>
 * This class implements a secure password management system with the following features:
 * <ul>
 *   <li>Password encryption/decryption using AES 256 GCM cipher.</li>
 *   <li>Password and PIN-based chaining permutations using different seed values.</li>
 *   <li>Generation of a seed-dependent surjection along with modulus circulation.</li>
 * </ul>
 * <p>
 * Key aspects of the implementation:
 * <ul>
 *   <li>Password randomization/generation utilizes a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).</li>
 *   <li>Alphabet permutation is performed using the Mersenne Twister (MT) PRNG for seed-deterministic behavior,
 *       chosen over Linear Congruential Generator (LCG) for improved randomness.</li>
 *   <li>Token reversal security: Combinatorically set to 2^128 permutations in worst case (WC)
 *       and 2^127 in average case (AVGC).</li>
 *   <li>Enhanced security option: An initial randomization of the reference alphabet can be applied,
 *       raising the permutation complexity to 2^192 WC and 2^191 AVGC, provided this randomization remains secret.</li>
 * </ul>
 * <p>
 *
 * @author src-dbgr
 * @version 2.0
 */
public class Generator {

    private static final Logger log = LoggerFactory.getLogger(Generator.class);

    // Constants
    public static final int OBFUSCATION_OFFSET = 20;
    public static final int MIN_PADDING_LENGTH = 5;
    public static final int MAX_PADDING_LENGTH = 20;
    public static final int RESERVED_ARRAY_INDEXES = 2;
    public static final String ENTER_PIN = "Enter Pin:";
    static final int OBFUSCATION_ARRAY_SIZE = 100;
    private static final int SHUFFLE_THRESHOLD = 5;
    private static final String DEFAULT_ERR = "An issue occurred";
    private static final String CONTINUE_WITH_DEFAULT_INVOCATION = "Masking input not supported. Continuing with default invocation";
    private static final int BYTE_SIZE = 8;
    private static final String TEST = "test";
    private static final String CREATE_PASSWORDS = " - Create Passwords - ";
    private static final String RETRIEVE_PASSWORD = " - Retrieve Password ";

    // ASCII art for password manager
    static final String PASSWORD_MANAGER_ASCII = "\n" +
            "                                                                                        \n" +
            " _____ _____ _____ ____     _____ _____ _____ _____    _____ _ _ _    _____ _____ _____ \n" +
            "|   __|   __|   __|    \\   |  _  |   __| __  |     |  |  _  | | | |  |     |   __| __  |\n" +
            "|__   |   __|   __|  |  |  |   __|   __|    -| | | |  |   __| | | |  | | | |  |  |    -|\n" +
            "|_____|_____|_____|____/   |__|  |_____|__|__|_|_|_|  |__|  |_____|  |_|_|_|_____|__|__|\n" +
            "                                                                                        \n";

    final Decoder decoder;
    final Encoder encoder;
    private final SecureRandom secureRandom;
    private MessageDigest sha3Instance;
    char[] alphabet;
    char[] referenceAlphabet;
    private boolean randomized = false;

    /**
     * Constructs a Generator with custom filtered characters.
     *
     * @param filteredCharacters Characters to be filtered from the alphabet
     */
    public Generator(String filteredCharacters) {
        this.decoder = Base64.getDecoder();
        this.encoder = Base64.getEncoder();
        this.secureRandom = new SecureRandom();
        this.referenceAlphabet = initializeAlphabet(filteredCharacters);
    }

    /**
     * Default constructor for Generator.
     */
    public Generator() {
        this("");
    }

    /**
     * Initializes the alphabet with filtered characters.
     *
     * @param filteredCharacters Characters to be filtered out
     * @return Initialized alphabet as char array
     */
    private char[] initializeAlphabet(String filteredCharacters) {
        char[] initialAlphabet = {'i', 'g', 'r', '.', 'u', '$', '&', 'G', '+', 'W', '9', 'C', 'Q', ':', 'w', 'o', 'j', 'L', 'y', 'A', 'O', 'v', 'U', 'Y', 'S', 'z', 'E', 'f', '*', '2', '=', '4', '%', 'B', 'K', 'T', 'm', '@', '!', 'h', 'V', '/', '1', 'l', 'X', '(', '_', 'J', ')', '5', 'a', 'q', 'k', '[', '?', '=', '-', 'n', 'P', 's', '3', 'Z', 'N', 'M', '#', 'R', 'p', ']', '0', '7', 'D', 'x', '8', 't', '6', 'e', 'H', ';', 'I', 'F', 'd', 'b', 'c'};
        List<Character> characters = new String(initialAlphabet)
                .chars()
                .mapToObj(c -> Character.valueOf((char) c))
                .collect(Collectors.toList());
        List<String> removeChars = Arrays.asList(filteredCharacters.split(""));
        List<Character> filteredChars = characters.stream()
                .filter(c -> !removeChars.contains(c.toString()))
                .collect(Collectors.toList());
        return toCharArray(filteredChars);
    }

    /**
     * Main method to run the password manager.
     *
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        Generator generator = new Generator();
        AnsiConsole.systemInstall();
        generator.printAnsi(ansi().eraseScreen().bg(GREEN).fg(WHITE).a(PASSWORD_MANAGER_ASCII).reset());
        generator.printAnsi(ansi().eraseScreen().bg(GREEN).fg(WHITE).a(PASSWORD_MANAGER_ASCII).reset());
        generator.printCLICommands();

        try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
            int option = generator.readOption(args.length > 0 && args[0] != null && args[0].equals(TEST) ? null : br);
            ConsoleReader cr = new ConsoleReader();
            generator.callToAction(br, cr, option);
        } catch (IOException e) {
            log.error("Error reading from console", e);
        }
    }

    /**
     * Provides a token and password pair.
     *
     * @param length       Length of the password
     * @param pin          PIN for randomization
     * @param encryptionPw Encryption password
     * @return Map containing the token and password
     */
    public Map<String, String> provideTokenAndPw(int length, long pin, String encryptionPw) {
        shuffleAlphabetByPin(String.valueOf(pin).toCharArray());
        alphabet = randomizeAlphabet(pin, referenceAlphabet);
        int[] indexes = generateIndexes(length, pin);
        String token = provideObfuscatedEncodedIndexes(encoder, indexes, pin, encryptionPw);
        try {
            token = AesGcmPw.encrypt(token.getBytes(AesGcmPw.UTF_8), encryptionPw);
        } catch (Exception e) {
            log.error("Error generating encrypted password: ", e);
            throw new RuntimeException("Failed to encrypt token", e);
        }
        StringBuilder pw = new StringBuilder();
        for (int index : indexes) {
            pw.append(alphabet[index]);
        }
        return Map.of("token", token, "pw", pw.toString());
    }

    /**
     * Retrieves a password from a token.
     *
     * @param pass  Encryption password
     * @param pin   PIN for randomization
     * @param token Encrypted token
     * @return Decrypted password
     */
    public String getPWfromToken(String pass, long pin, String token) {
        return providePwFromToken(pass, pin, token, null);
    }

    /**
     * Converts a list of Characters to a char array.
     *
     * @param list List of Characters
     * @return char array
     */
    char[] toCharArray(List<Character> list) {
        return list.stream()
                .map(Character::charValue)
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString()
                .toCharArray();
    }

    /**
     * Reads an option from the user input.
     *
     * @param br BufferedReader for input
     * @return The selected option as an integer
     */
    int readOption(BufferedReader br) {
        try {
            String input = br.readLine();
            input = input.trim();
            if (!input.matches("\\d+")) {
                throw new IllegalArgumentException("Input is not a valid integer: " + input);
            }
            return Integer.parseInt(input);
        } catch (IOException e) {
            log.error("Could not process input", e);
        }
        return -1;
    }

    /**
     * Performs the action based on the user's choice.
     *
     * @param br     BufferedReader for input
     * @param cr     ConsoleReader for password input
     * @param option User's chosen option
     */
    void callToAction(BufferedReader br, ConsoleReader cr, int option) {
        switch (option) {
            case 0 -> interactiveTokenGenerationHidden(br, cr);
            case 1 -> interactiveTokenGenerationVisible(br, cr);
            case 2 -> interactivePWGenerationHidden(br, cr);
            case 3 -> interactivePWGenerationVisible(br, cr);
            case 4 -> interactivePWRetrieve(true, cr, br);
            case 5 -> interactivePWRetrieve(false, cr, br);
            default -> printAnsi(ansi().fg(RED).a("This option is not available. Choose a listed option.").reset());
        }
    }

    /**
     * Retrieves a password from user input.
     *
     * @param cr ConsoleReader for password input
     * @return char array containing the password
     */
    char[] retrievePwd(ConsoleReader cr) {
        char[] pw = null;
        try {
            printAnsi(ansi().fg(GREEN).a("Enter PW:").reset());
            pw = cr.readPassword();
            if (pw == null) {
                throw new IllegalArgumentException("PW is null");
            }
        } catch (IOError e) {
            log.error(DEFAULT_ERR, e);
        }
        return pw;
    }

    /**
     * Prints the CLI commands for user interaction.
     */
    void printCLICommands() {
        printAnsi(ansi().fg(GREEN).a("Choose what you want to do:").reset());
        printAnsi(ansi().fg(GREEN).a("0").fg(YELLOW).a(CREATE_PASSWORDS + "Show only Token (Hidden)").reset());
        printAnsi(ansi().fg(GREEN).a("1").fg(YELLOW).a(CREATE_PASSWORDS + "Show only Token (Visible)").reset());
        printAnsi(ansi().fg(GREEN).a("2").fg(YELLOW).a(CREATE_PASSWORDS + "Show PWs and Token (Hidden)").reset());
        printAnsi(ansi().fg(GREEN).a("3").fg(YELLOW).a(CREATE_PASSWORDS + "Show PWs and Token (Visible)").reset());
        printAnsi(ansi().fg(GREEN).a("4").fg(YELLOW).a(RETRIEVE_PASSWORD + "(Hidden)").reset());
        printAnsi(ansi().fg(GREEN).a("5").fg(YELLOW).a(RETRIEVE_PASSWORD + "(Visible)").reset());
    }

    /**
     * Converts a char array to a long value.
     *
     * @param pwd char array to convert
     * @return converted long value
     */
    public long convertCharToLong(char[] pwd) {
        return new String(pwd).chars()
                .mapToLong(ch -> Character.getNumericValue((char) ch))
                .reduce(0L, (a, b) -> (a + b) * (a + b));
    }

    public char[] getReferenceAlphabet() {
        return this.referenceAlphabet;
    }

    public Generator setReferenceAlphabet(char[] referenceAlphabet) {
        this.referenceAlphabet = referenceAlphabet;
        return this;
    }

    /**
     * Requests a seed for alphabet shuffling.
     *
     * @param br  BufferedReader for input
     * @param pin PIN for randomization
     */
    void alphabetSeedRequest(BufferedReader br, char[] pin) {
        if (pin == null && br != null) {
            log.info(CONTINUE_WITH_DEFAULT_INVOCATION);
            alphabetSeedRequestOnNull(br);
        }
        shuffleAlphabetByPin(pin);
    }

    private void shuffleAlphabetByPin(char[] pin) {
        long seed = convertCharToLong(pin);
        if (!randomized) {
            referenceAlphabet = randomizeAlphabet(seed, referenceAlphabet);
            randomized = true;
        }
    }

    void alphabetSeedRequestOnNull(BufferedReader br) {
        try {
            printAnsi(ansi().fg(GREEN).a("Enter Seed: ").reset());
            String seedS = br.readLine();
            long seed = Long.parseLong(seedS);
            referenceAlphabet = randomizeAlphabet(seed, referenceAlphabet);
        } catch (IOException e) {
            log.error(DEFAULT_ERR, e);
        }
    }

    /**
     * Interactively retrieves a password based on user input.
     *
     * @param hidden Whether to hide the output
     * @param cr     ConsoleReader for secure password input
     * @param br     BufferedReader for general input
     */
    void interactivePWRetrieve(boolean hidden, ConsoleReader cr, BufferedReader br) {
        char[] pwd = retrievePwd(cr);
        String pass = new String(pwd);
        char[] readPin = null;
        String token = null;
        try {
            printAnsi(ansi().fg(GREEN).a("Enter Token:").reset());
            token = br.readLine();
            printAnsi(ansi().fg(GREEN).a(ENTER_PIN).reset());
            readPin = cr.readPassword();
            long pin = Long.parseLong(new String(readPin));
            if (hidden) {
                printHidden(providePwFromToken(pass, pin, token, br));
            } else {
                printNormal(providePwFromToken(pass, pin, token, br));
            }
        } catch (Exception e) {
            if (e instanceof NullPointerException && readPin == null) {
                log.info(CONTINUE_WITH_DEFAULT_INVOCATION);
                interactivePWRetrieveOnNull(br, hidden, token);
            } else {
                log.error(DEFAULT_ERR + " on retrieving PW. Make sure your token is correct, has no line breaks or empty space. Check Stack Trace for Details: ", e);
                throw new RuntimeException("Failed to retrieve password", e);
            }
        } finally {
            // Clear sensitive data from memory
            if (pwd != null) Arrays.fill(pwd, '\0');
            if (readPin != null) Arrays.fill(readPin, '\0');
        }
    }

    /**
     * Provides a password from a token.
     *
     * @param encryptionPw Encryption password
     * @param pin          PIN for randomization
     * @param token        Encrypted token
     * @param br           BufferedReader for input (can be null)
     * @return Decrypted password
     */
    String providePwFromToken(String encryptionPw, long pin, String token, BufferedReader br) {
        String pw = "";
        try {
            char[] pinArr = Long.toString(pin).toCharArray();
            token = AesGcmPw.decrypt(token, encryptionPw);
            alphabetSeedRequest(br, pinArr);
            int[] indexes = provideClearDecodedIndexes(decoder, token, pin, encryptionPw);
            pw = generateByIndexes(indexes, pin);
        } catch (Exception e) {
            log.error("Error providing password from token", e);
        }
        return pw;
    }

    /**
     * Interactively retrieves a password when pin input is null.
     *
     * @param br     BufferedReader for input
     * @param hidden Whether to hide the output
     * @param token  Encrypted token
     */
    void interactivePWRetrieveOnNull(BufferedReader br, boolean hidden, String token) {
        try {
            printAnsi(ansi().fg(GREEN).a(ENTER_PIN).reset());
            String pin = br.readLine();
            long seed = Long.parseLong(pin);
            int[] indexes = provideClearDecodedIndexes(decoder, token, seed);
            if (hidden) {
                printHidden(generateByIndexes(indexes, seed));
            } else {
                printNormal(generateByIndexes(indexes, seed));
            }
        } catch (IOException e) {
            log.error(DEFAULT_ERR, e);
        }
    }

    /**
     * Interactively generates a hidden token.
     *
     * @param br BufferedReader for input
     * @param cr ConsoleReader for password input
     */
    void interactiveTokenGenerationHidden(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(true, true, br, cr);
    }

    /**
     * Interactively generates a hidden password.
     *
     * @param br BufferedReader for input
     * @param cr ConsoleReader for password input
     */
    void interactivePWGenerationHidden(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(false, true, br, cr);
    }

    /**
     * Interactively generates a visible token.
     *
     * @param br BufferedReader for input
     * @param cr ConsoleReader for password input
     */
    void interactiveTokenGenerationVisible(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(true, false, br, cr);
    }

    /**
     * Interactively generates a visible password.
     *
     * @param br BufferedReader for input
     * @param cr ConsoleReader for password input
     */
    void interactivePWGenerationVisible(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(false, false, br, cr);
    }

    /**
     * Core method for interactive password/token generation.
     *
     * @param anonymous Whether to generate only the token
     * @param hidden    Whether to hide the output
     * @param br        BufferedReader for input
     * @param cr        ConsoleReader for password input
     */
    void interactiveGenerator(boolean anonymous, boolean hidden, BufferedReader br, ConsoleReader cr) {
        char[] pwd = retrievePwd(cr);
        String encryptionPw = new String(pwd);
        char[] readPin = null;
        int min = -1;
        int max = -1;
        int numPws = -1;
        try {
            printAnsi(ansi().fg(GREEN).a("Enter minimal PW character length:").reset());
            min = Integer.parseInt(br.readLine());
            printAnsi(ansi().fg(GREEN).a("Enter max PW character length:").reset());
            max = Integer.parseInt(br.readLine());
            printAnsi(ansi().fg(GREEN).a("Enter number of Passwords to be created:").reset());
            numPws = Integer.parseInt(br.readLine());
            printAnsi(ansi().fg(GREEN).a(ENTER_PIN).reset());
            readPin = cr.readPassword();
            alphabetSeedRequest(br, readPin);
            long pin = Long.parseLong(new String(readPin));
            printMultipleRandomPWs(min, max, numPws, pin, anonymous, hidden, encryptionPw);
        } catch (Exception e) {
            if (e instanceof NullPointerException && readPin == null) {
                log.info(CONTINUE_WITH_DEFAULT_INVOCATION);
                interactiveGeneratorOnNull(br, min, max, numPws, anonymous, hidden, encryptionPw);
            } else {
                log.error("Error occurred on interactive PW generation", e);
            }
        }
    }

    /**
     * Handles interactive generation when pin input is null.
     *
     * @param br           BufferedReader for input
     * @param min          Minimum password length
     * @param max          Maximum password length
     * @param numPws       Number of passwords to generate
     * @param anonymous    Whether to generate only the token
     * @param hidden       Whether to hide the output
     * @param encryptionPw Encryption password
     */
    void interactiveGeneratorOnNull(BufferedReader br, int min, int max, int numPws, boolean anonymous, boolean hidden, String encryptionPw) {
        try {
            printAnsi(ansi().fg(GREEN).a(ENTER_PIN).reset());
            String pin = br.readLine();
            long seed = Long.parseLong(pin);
            printMultipleRandomPWs(min, max, numPws, seed, anonymous, hidden, encryptionPw);
        } catch (IOException e) {
            log.error(DEFAULT_ERR, e);
        }
    }

    /**
     * Parses a string of integers into an int array.
     *
     * @param word String representation of integers
     * @return Array of integers
     */
    int[] parseStringToIntArr(String word) {
        return Arrays.stream(word.replaceAll("[^0-9,]", "").split(","))
                .mapToInt(Integer::parseInt)
                .toArray();
    }

    /**
     * Randomizes the alphabet using a seed.
     *
     * @param seed     Seed for randomization
     * @param alphabet Alphabet to randomize
     * @return Randomized alphabet
     */
    char[] randomizeAlphabet(long seed, char[] alphabet) {
        List<Character> tempList = new ArrayList<>(alphabet.length);
        for (char c : alphabet) {
            tempList.add(c);
        }
        shuffle(tempList, new MersenneTwister(seed));
        return tempList.stream()
                .map(String::valueOf)
                .collect(Collectors.joining())
                .toCharArray();
    }

    /**
     * Provides a Mersenne Twister PRNG long value.
     *
     * @param seed Seed for the PRNG
     * @return Generated long value
     */
    long provideMersenneTwisterPRNGLong(long seed) {
        return new MersenneTwister(seed).nextLong();
    }

    /**
     * Generates a random number within a range.
     *
     * @param min Minimum value (inclusive)
     * @param max Maximum value (exclusive)
     * @return Random number within the range
     */
    int generateRandomNumber(int min, int max) {
        return secureRandom.nextInt(max - min) + min;
    }

    /**
     * Generates an array of random indexes.
     *
     * @param length Length of the array
     * @param pin    PIN for randomization
     * @return Array of random indexes
     */
    int[] generateIndexes(int length, long pin) {
        if (alphabet == null) {
            alphabet = randomizeAlphabet(pin, referenceAlphabet);
        }
        return secureRandom.ints(length, 0, alphabet.length).toArray();
    }

    /**
     * Generates a password based on provided indexes.
     *
     * @param indexes Array of indexes
     * @param pin     PIN for randomization
     * @return Generated password
     */
    String generateByIndexes(int[] indexes, long pin) {
        alphabet = randomizeAlphabet(pin, referenceAlphabet);
        StringBuilder pw = new StringBuilder();
        for (int index : indexes) {
            pw.append(alphabet[index]);
        }
        printAnsi(ansi().fg(GREEN).a("\nPW: ").reset());
        return pw.toString();
    }

    /**
     * Converts a char array to a string representation and logs it.
     *
     * @param arr The char array to be converted and logged
     * @throws IllegalArgumentException if the passed array is null
     */
    void printCharArrayToString(char[] arr) {
        if (arr == null) {
            throw new IllegalArgumentException("Passed Array is null.");
        }
        String result = "alphabet: {" +
                String.join(", ", IntStream.range(0, arr.length)
                        .mapToObj(i -> "'" + arr[i] + "'")
                        .collect(Collectors.toList())) +
                "}";
        log.info(result);
    }

    /**
     * Prints multiple random passwords.
     *
     * @param rangeMin     Minimum password length
     * @param rangeMax     Maximum password length
     * @param numOfPWs     Number of passwords to generate
     * @param pin          PIN for randomization
     * @param anonymous    Whether to generate only the token
     * @param hidden       Whether to hide the output
     * @param encryptionPw Encryption password
     */
    public void printMultipleRandomPWs(int rangeMin, int rangeMax, int numOfPWs, long pin, boolean anonymous, boolean hidden, String encryptionPw) {
        for (int i = 0; i < numOfPWs; i++) {
            printAnsi(ansi().fg(GREEN).a("\n----------------PW NO:" + String.format("%02d", i + 1) + "-----------------").reset());
            int rand = generateRandomNumber(rangeMin, rangeMax);
            if (anonymous) {
                generatePw(rand, pin, hidden, true, encryptionPw);
            } else if (hidden) {
                printHidden(generatePw(rand, pin, true, false, encryptionPw));
            } else {
                printNormal(generatePw(rand, pin, false, false, encryptionPw));
            }
            printAnsi(ansi().fg(GREEN).a("-----------------------------------------").reset());
        }
    }

    /**
     * Provides obfuscated and encoded indexes.
     *
     * @param e            Base64.Encoder
     * @param indexes      Array of indexes
     * @param pin          PIN for randomization
     * @param encryptionPw Encryption password
     * @return Obfuscated and encoded indexes as a string
     */
    String provideObfuscatedEncodedIndexes(Encoder e, int[] indexes, long pin, String encryptionPw) {
        int[] obfuscatedIndexes = obfuscateIndexes(indexes, pin, encryptionPw);
        return base64Encoding(obfuscatedIndexes, e);
    }

    /**
     * Provides clear decoded indexes from an encoded string.
     *
     * @param d            Base64.Decoder
     * @param encodedIndexes Encoded indexes as a string
     * @param pin          PIN for randomization
     * @param encryptionPw Encryption password
     * @return Array of clear decoded indexes
     */
    int[] provideClearDecodedIndexes(Decoder d, String encodedIndexes, long pin, String encryptionPw) {
        int[] obfuscatedIndexes = base64Decoding(encodedIndexes, d);
        return clearObfuscatedIndexes(obfuscatedIndexes, pin, encryptionPw);
    }

    /**
     * Provides clear decoded indexes from an encoded string.
     *
     * @param d               Base64.Decoder
     * @param encodedIndexes  Encoded indexes as a string
     * @param pin             PIN for randomization
     * @return Array of clear decoded indexes
     */
    int[] provideClearDecodedIndexes(Decoder d, String encodedIndexes, long pin) {
        int[] obfuscatedIndexes = base64Decoding(encodedIndexes, d);
        return clearObfuscatedIndexes(obfuscatedIndexes, pin, null);
    }

    /**
     * Prints a hidden message.
     *
     * @param message Message to be hidden
     */
    void printHidden(String message) {
        message = padWithEmptyString() + message + padWithEmptyString();
        printAnsi(ansi().fg(BLACK).bg(BLACK).a(message).reset());
    }

    /**
     * Prints a normal (visible) message.
     *
     * @param message Message to be printed
     */
    void printNormal(String message) {
        printAnsi(ansi().fg(MAGENTA).a(message).reset());
    }

    /**
     * Provides a shift value based on the PIN.
     *
     * @param pin PIN for shift calculation
     * @return Calculated shift value
     */
    int provideShiftValue(long pin) {
        int cycles = sumDigits(pin);
        long maskNumber = -1;
        for (int i = 0; i < cycles; i++) {
            maskNumber = Math.abs(provideMersenneTwisterPRNGLong(pin));
        }
        double p = ((double) maskNumber / (double) Long.MAX_VALUE);
        return (int) Math.ceil(OBFUSCATION_ARRAY_SIZE * p);
    }

    /**
     * Calculates the sum of digits in a number.
     *
     * @param num Number to sum digits from
     * @return Sum of digits
     */
    int sumDigits(long num) {
        return String.valueOf(Math.abs(num))
                .chars()
                .map(Character::getNumericValue)
                .sum();
    }

    /**
     * Provides a secure random integer within a range.
     *
     * @param min Minimum value (inclusive)
     * @param max Maximum value (inclusive)
     * @return Random integer within the range
     */
    int provideSecureRandomInteger(int min, int max) {
        return secureRandom.nextInt(max - min + 1) + min;
    }

    /**
     * Obfuscates an array of indexes.
     *
     * @param indexes      Array of indexes to obfuscate
     * @param pin          PIN for randomization
     * @param encryptionPw Encryption password
     * @return Obfuscated array of indexes
     */
    int[] obfuscateIndexes(int[] indexes, long pin, String encryptionPw) {
        int pwLength = indexes.length;
        int[] obfuscatedIndexes = new int[OBFUSCATION_ARRAY_SIZE];
        int min = RESERVED_ARRAY_INDEXES;
        int max = OBFUSCATION_ARRAY_SIZE - pwLength;
        int shiftValue = provideShiftValue(pin + transformPwToHashedLong(encryptionPw));

        if ((OBFUSCATION_ARRAY_SIZE - (pwLength + 1)) <= OBFUSCATION_OFFSET || max <= min) {
            throw new IllegalArgumentException("Password too long, lower password max-length to max: " + (OBFUSCATION_ARRAY_SIZE - (OBFUSCATION_OFFSET + 2)));
        }

        int arrayStartIndex = provideSecureRandomInteger(min, max);
        obfuscatedIndexes[1] = arrayStartIndex;
        System.arraycopy(indexes, 0, obfuscatedIndexes, arrayStartIndex, indexes.length);
        int[] remainingIndexes = provideRemainingIndexes(arrayStartIndex, pwLength);
        int random = provideSecureRandomInteger(0, remainingIndexes.length - 1);
        obfuscatedIndexes[0] = remainingIndexes[random];
        obfuscatedIndexes[obfuscatedIndexes[0]] = pwLength;
        obfuscatedIndexes = fillEmptySpotsInObfuscatedArray(obfuscatedIndexes, remainingIndexes, referenceAlphabet.length);

        for (int i = 0; i < obfuscatedIndexes.length; i++) {
            obfuscatedIndexes[i] = shiftValue(obfuscatedIndexes[i], shiftValue);
        }
        return obfuscatedIndexes;
    }

    /**
     * Clears obfuscated indexes.
     *
     * @param obfuscatedIndexes Array of obfuscated indexes
     * @param pin               PIN for randomization
     * @param encryptionPw      Encryption password
     * @return Array of clear indexes
     */
    int[] clearObfuscatedIndexes(int[] obfuscatedIndexes, long pin, String encryptionPw) {
        try {
            int shiftValue = provideShiftValue(pin + (encryptionPw != null ? transformPwToHashedLong(encryptionPw) : 0));
            int lengthIndex = unShiftValue(obfuscatedIndexes[0], shiftValue);
            int length = unShiftValue(obfuscatedIndexes[lengthIndex], shiftValue);
            int start = unShiftValue(obfuscatedIndexes[1], shiftValue);
            int[] clearIndexes = new int[length];
            for (int i = 0; i < clearIndexes.length; i++) {
                clearIndexes[i] = unShiftValue(obfuscatedIndexes[(i + start)], shiftValue);
            }
            return clearIndexes;
        } catch (Exception e) {
            log.error("Issue clearing obfuscated Indexes ", e);
        }
        return new int[0];
    }

    /**
     * Provides remaining indexes for obfuscation.
     *
     * @param pwStartIndex Start index of the password
     * @param pwLength     Length of the password
     * @return Array of remaining indexes
     */
    int[] provideRemainingIndexes(int pwStartIndex, int pwLength) {
        int beforePwMinIndex = pwStartIndex > RESERVED_ARRAY_INDEXES ? RESERVED_ARRAY_INDEXES : -1;
        int beforePwMaxIndex = pwStartIndex > RESERVED_ARRAY_INDEXES ? pwStartIndex : -1;
        int afterPwMinIndex = (pwStartIndex + pwLength) >= OBFUSCATION_ARRAY_SIZE - 1 ? -1 : (pwStartIndex + pwLength);
        int afterPwMaxIndex = (pwStartIndex + pwLength) >= OBFUSCATION_ARRAY_SIZE - 1 ? -1 : OBFUSCATION_ARRAY_SIZE - 1;

        int remainingIndexesLength = 0;
        if (beforePwMaxIndex > 0) {
            remainingIndexesLength += beforePwMaxIndex - beforePwMinIndex;
        }
        if (afterPwMaxIndex > 0) {
            remainingIndexesLength += afterPwMaxIndex - afterPwMinIndex + 1;
        }

        int[] remainingIndexes = new int[remainingIndexesLength];
        int currentIndex = 0;

        if (beforePwMaxIndex > 0) {
            for (int i = beforePwMinIndex; i < beforePwMaxIndex; i++) {
                remainingIndexes[currentIndex++] = i;
            }
        }
        if (afterPwMaxIndex > 0) {
            for (int i = afterPwMinIndex; i <= afterPwMaxIndex; i++) {
                remainingIndexes[currentIndex++] = i;
            }
        }
        return remainingIndexes;
    }

    /**
     * Fills empty spots in the obfuscated array with random values.
     *
     * @param obfuscatedArray  Partially filled obfuscated array
     * @param remainingIndexes Array of remaining indexes
     * @param alphabetLength   Length of the alphabet
     * @return Fully filled obfuscated array
     */
    int[] fillEmptySpotsInObfuscatedArray(int[] obfuscatedArray, int[] remainingIndexes, int alphabetLength) {
        int pwLengthIndex = obfuscatedArray[0];
        if (pwLengthIndex == 0) {
            throw new IllegalStateException("Pw Length not yet assigned to obfuscated Array");
        }
        for (int remainingIndex : remainingIndexes) {
            if (remainingIndex != pwLengthIndex) {
                obfuscatedArray[remainingIndex] = provideSecureRandomInteger(0, alphabetLength - 1);
            }
        }
        return obfuscatedArray;
    }

    /**
     * Shifts a value by a given amount.
     *
     * @param value      Value to shift
     * @param shiftValue Amount to shift by
     * @return Shifted value
     */
    int shiftValue(int value, int shiftValue) {
        return (value + shiftValue) % OBFUSCATION_ARRAY_SIZE;
    }

    /**
     * Unshifts a value by a given amount.
     *
     * @param value      Value to unshift
     * @param shiftValue Amount to unshift by
     * @return Unshifted value
     */
    int unShiftValue(int value, int shiftValue) {
        int tempIndex = (value - shiftValue) % OBFUSCATION_ARRAY_SIZE;
        return tempIndex < 0 ? tempIndex + OBFUSCATION_ARRAY_SIZE : tempIndex;
    }

    /**
     * Encodes an array of integers to a Base64 string.
     *
     * @param indexes Array of integers to encode
     * @param e       Base64.Encoder
     * @return Base64 encoded string
     */
    String base64Encoding(int[] indexes, Encoder e) {
        String string = Arrays.toString(indexes);
        byte[] bytes = string.getBytes();
        return e.encodeToString(bytes);
    }

    /**
     * Decodes a Base64 string to an array of integers.
     *
     * @param indexes Base64 encoded string
     * @param d       Base64.Decoder
     * @return Decoded array of integers
     */
    int[] base64Decoding(String indexes, Decoder d) {
        byte[] decodedBytes = d.decode(indexes);
        String decodedString = new String(decodedBytes);
        return parseStringToIntArr(decodedString);
    }

    /**
     * Shuffles a list using the Fisher-Yates algorithm.
     *
     * @param list List to shuffle
     * @param rnd  Random number generator
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    public void shuffle(List<?> list, MersenneTwister rnd) {
        int size = list.size();
        if (size < SHUFFLE_THRESHOLD || list instanceof RandomAccess) {
            for (int i = size; i > 1; i--)
                swap(list, i - 1, rnd.nextInt(i));
        } else {
            Object[] arr = list.toArray();

            for (int i = size; i > 1; i--)
                swap(arr, i - 1, rnd.nextInt(i));

            ListIterator it = list.listIterator();
            for (Object e : arr) {
                it.next();
                it.set(e);
            }
        }
    }

    /**
     * Swaps two elements in a list.
     *
     * @param list List containing the elements
     * @param i    Index of the first element
     * @param j    Index of the second element
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    public void swap(List<?> list, int i, int j) {
        ((List) list).set(i, ((List) list).set(j, ((List) list).get(i)));
    }

    /**
     * Swaps two elements in an array.
     *
     * @param arr Array containing the elements
     * @param i   Index of the first element
     * @param j   Index of the second element
     */
    private void swap(Object[] arr, int i, int j) {
        Object tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }

    /**
     * Prints an Ansi-formatted message.
     *
     * @param msg Ansi message to print
     */
    private void printAnsi(Ansi msg) {
        System.out.println(msg);
    }

    /**
     * Transforms a password into a hashed long value.
     *
     * @param encryptionPw Password to hash
     * @return Hashed long value
     */
    long transformPwToHashedLong(String encryptionPw) {
        return bytesToLong(getSha3Instance().digest(encryptionPw.getBytes(UTF_8)));
    }

    /**
     * Converts the first 8 bytes of a byte array to a long value.
     *
     * @param bytes Byte array to convert
     * @return Converted long value
     */
    long bytesToLong(byte[] bytes) {
        long bytesInLong = 0;
        for (int i = 0; i < BYTE_SIZE; i++) {
            bytesInLong <<= BYTE_SIZE;
            bytesInLong |= (bytes[i] & 0xFF);
        }
        return bytesInLong;
    }

    /**
     * Gets or creates a SHA3-512 MessageDigest instance.
     *
     * @return SHA3-512 MessageDigest instance
     */
    MessageDigest getSha3Instance() {
        if (sha3Instance == null) {
            try {
                sha3Instance = MessageDigest.getInstance("SHA3-512");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("SHA3-512 algorithm not available", e);
            }
        }
        return sha3Instance;
    }

    /**
     * Generates a password with specified parameters.
     *
     * @param length       Length of the password
     * @param pin          PIN for randomization
     * @param hidden       Whether to hide the output
     * @param anonymous    Whether to generate only the token
     * @param encryptionPw Encryption password
     * @return Generated password or token
     */
    String generatePw(int length, long pin, boolean hidden, boolean anonymous, String encryptionPw) {
        alphabet = randomizeAlphabet(pin, referenceAlphabet);
        StringBuilder pw = new StringBuilder();
        int[] indexes = generateIndexes(length, pin);
        printAnsi(ansi().fg(GREEN).a("Token:").reset());
        String token = provideObfuscatedEncodedIndexes(encoder, indexes, pin, encryptionPw);
        try {
            token = AesGcmPw.encrypt(token.getBytes(AesGcmPw.UTF_8), encryptionPw);
        } catch (Exception e) {
            log.error("Error generating encrypted Pw: ", e);
        }
        if (hidden) {
            printHidden(token);
        } else {
            printNormal(token);
        }
        for (int index : indexes) {
            pw.append(alphabet[index]);
        }
        if (!anonymous) {
            printAnsi(ansi().fg(GREEN).a("\nPW: ").reset());
        }
        pw.append(padWithEmptyString());
        return pw.toString();
    }

    /**
     * Generates a random padding string.
     *
     * @return Random padding string
     */
    String padWithEmptyString() {
        int length = generateRandomNumber(MIN_PADDING_LENGTH, MAX_PADDING_LENGTH);
        return String.format("%1$" + length + "s", "");
    }

    // ConsoleReader inner class
    static class ConsoleReader {
        private final Console c;

        ConsoleReader(Console c) {
            this.c = c;
        }

        public ConsoleReader() {
            this(System.console());
        }

        public char[] readPassword() {
            return c.readPassword();
        }

        public char[] readPassword(String msg) {
            return c.readPassword(msg);
        }
    }
}