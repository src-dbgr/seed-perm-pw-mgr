package com.sam.key.manager;

import com.sam.key.cipher.AesGcmPw;
import org.apache.commons.math3.random.MersenneTwister;
import org.fusesource.jansi.AnsiConsole;
import org.fusesource.jansi.Ansi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import static org.fusesource.jansi.Ansi.Color.YELLOW;
import static org.fusesource.jansi.Ansi.Color.BLACK;
import static org.fusesource.jansi.Ansi.Color.GREEN;
import static org.fusesource.jansi.Ansi.Color.MAGENTA;
import static org.fusesource.jansi.Ansi.Color.WHITE;
import static org.fusesource.jansi.Ansi.Color.RED;
import static org.fusesource.jansi.Ansi.ansi;

/**
 * Interactive CSPRNG / PRNG PW Manager. Password encryption/description happens
 * by application of AES 256 GCM cipher. Further password and pin based chaining
 * permutations based on different seed values and generation of a seed
 * dependent surjection along with modulus circulation.
 * <p>
 * Password randomization/generation happens via CSPRNG
 * <p>
 * Alphabet permutation happens via Mersenne Twister (MT) PRNG for seed
 * deterministic behaviour instead of LCG. Token reversal is combinatorically
 * set to 2^128 permutations in worst case (WC) and in average case (AVGC)
 * 2^127. To further improve security an initial randomization of the reference
 * alphabet may be considered. This raises the permutation to 2^192 WC and 2^191
 * AVGC, as long as this randomization is kept secret.
 * <p>
 *
 * @author src-dbgr
 */
public class Generator {

    /**
     * Determines Max PW length and determines combinatorial search space for random
     * index assignment for PW length
     * <p>
     * MAX PW LENGTH = ALPHABET_SIZE * MIN_OBFUSCATION_OFFSET
     * <p>
     * MAX PW LENGTH = ALPHABET_SIZE - MIN_OBFUSCATION_OFFSET
     * <p>
     * Should not be smaller than 20 to keep combinatorial search space large enough
     */
    public static final int OBFUSCATION_OFFSET = 20;
    public static final int MIN_PADDING_LENGTH = 5;
    public static final int MAX_PADDING_LENGTH = 20;
    public static final int RESERVED_ARRAY_INDEXES = 2;
    public static final String ENTER_PIN = "Enter Pin:";
    private static final int SHUFFLE_THRESHOLD = 5;
    private static final String DEFAULT_ERR = "Issue occurred";
    public static final String CONTINUE_WITH_DEFAULT_INVOCATION = "Masking input not supported.. Continue with default Invocation";

    Decoder decoder = Base64.getDecoder();
    Encoder encoder = Base64.getEncoder();

    char[] alphabet;

    char[] referenceAlphabet = {'i', 'g', 'r', '.', 'u', '$', '&', 'G', '+', 'W', '9', 'C', 'Q', ':', 'w', 'o', 'j', 'L', 'y', 'A', 'O', 'v', 'U', 'Y', 'S', 'z', 'E', 'f', '*', '2', '=', '4', '%', 'B', 'K', 'T', 'm', '@', '!', 'h', 'V', '/', '1', 'l', 'X', '(', '_', 'J', ')', '5', 'a', 'q', 'k', '[', '?', '=', '-', 'n', 'P', 's', '3', 'Z', 'N', 'M', '#', 'R', 'p', ']', '0', '7', 'D', 'x', '8', 't', '6', 'e', 'H', ';', 'I', 'F', 'd', 'b', 'c'};

    static String pwMgr = "\n" + "                                                                                        \n" + " _____ _____ _____ ____     _____ _____ _____ _____    _____ _ _ _    _____ _____ _____ \n" + "|   __|   __|   __|    \\   |  _  |   __| __  |     |  |  _  | | | |  |     |   __| __  |\n" + "|__   |   __|   __|  |  |  |   __|   __|    -| | | |  |   __| | | |  | | | |  |  |    -|\n" + "|_____|_____|_____|____/   |__|  |_____|__|__|_|_|_|  |__|  |_____|  |_|_|_|_____|__|__|\n" + "                                                                                        \n" + "";

    static Logger log;
    private boolean randomized = false;

    public static void main(String[] args) {
        Generator g = new Generator();
        AnsiConsole.systemInstall();
        g.printAnsi(ansi().eraseScreen().bg(GREEN).fg(WHITE).a(pwMgr).reset());
        System.setProperty("log4j.configurationFile", "./src/main/resources/log4j2.properties");
        log = LoggerFactory.getLogger(Generator.class);
        g.printAnsi(ansi().eraseScreen().bg(GREEN).fg(WHITE).a(pwMgr).reset());
        g.printCLICommands();
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        int option = g.readOption(br);
        ConsoleReader cr = new ConsoleReader();
        g.callToAction(br, cr, option);
    }

    int readOption(BufferedReader br) {
        int option = -1;
        try {
            option = Integer.parseInt(br.readLine());
        } catch (Exception e) {
            log.error(DEFAULT_ERR + " , please choose one of the available options.", e);
            System.exit(-1);
        }
        return option;
    }

    void callToAction(BufferedReader br, ConsoleReader cr, int option) {
        switch (option) {
            case 0:
                interactiveTokenGenerationHidden(br, cr);
                break;
            case 1:
                interactiveTokenGenerationVisible(br, cr);
                break;
            case 2:
                interactivePWGenerationHidden(br, cr);
                break;
            case 3:
                interactivePWGenerationVisible(br, cr);
                break;
            case 4:
                interactivePWRetrieve(true, cr, br);
                break;
            case 5:
                interactivePWRetrieve(false, cr, br);
                break;
            default:
                printAnsi(ansi().fg(RED).a("This option is not available. Choose a listed option.").reset());
                break;
        }
    }

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

    void printCLICommands() {
        printAnsi(ansi().fg(GREEN).a("Choose what you want to do:").reset());
        printAnsi(ansi().fg(GREEN).a("0").fg(YELLOW).a(" - Create Passwords - Show only Token (Hidden)").reset());
        printAnsi(ansi().fg(GREEN).a("1").fg(YELLOW).a(" - Create Passwords - Show only Token (Visible)").reset());
        printAnsi(ansi().fg(GREEN).a("2").fg(YELLOW).a(" - Create Passwords - Show PWs and Token (Hidden)").reset());
        printAnsi(ansi().fg(GREEN).a("3").fg(YELLOW).a(" - Create Passwords - Show PWs and Token (Visible)").reset());
        printAnsi(ansi().fg(GREEN).a("4").fg(YELLOW).a(" - Retrieve Password (Hidden)").reset());
        printAnsi(ansi().fg(GREEN).a("5").fg(YELLOW).a(" - Retrieve Password (Visible)").reset());
    }

    public long convertCharToLong(char[] pwd) {
        long pwdConverted = 0;
        for (char c : pwd) {
            pwdConverted += Character.getNumericValue(c);
            pwdConverted *= pwdConverted;
        }
        return pwdConverted;
    }

    void alphabetSeedRequest(BufferedReader br, char[] pin) {
        try {
            shuffleAlphabetByPin(pin);
        } catch (Exception e) {
            if (e instanceof NullPointerException && pin == null && br != null) {
                log.info(CONTINUE_WITH_DEFAULT_INVOCATION);
                alphabetSeedRequestOnNull(br);
            } else {
                log.error(DEFAULT_ERR, e);
            }
        }
    }

    private void shuffleAlphabetByPin(char[] pin) {
        long seed = convertCharToLong(pin);
        if (!randomized) {
            referenceAlphabet = randomizeAlphabet(seed, referenceAlphabet);
            randomized = !randomized;
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

    void interactivePWRetrieve(boolean hidden, ConsoleReader cr, BufferedReader br) {
        char[] pwd = retrievePwd(cr);
        String pass = String.valueOf(pwd);
        char[] readPin = null;
        String token = null;
        try {
            printAnsi(ansi().fg(GREEN).a("Enter Token:").reset());
            token = br.readLine();
            printAnsi(ansi().fg(GREEN).a(ENTER_PIN).reset());
            readPin = cr.readPassword();
            long pin = Long.parseLong(new String(readPin));
            if (hidden) {
                printHidden(getPWfromToken(pass, pin, token, br));
            } else {
                printNormal(getPWfromToken(pass, pin, token, br));
            }
        } catch (Exception e) {
            if (e instanceof NullPointerException && readPin == null) {
                log.info(CONTINUE_WITH_DEFAULT_INVOCATION);
                interactivePWRetrieveOnNull(br, hidden, token);
            } else {
                log.error(DEFAULT_ERR + " on retrieving PW. Make sure your token is correct, has no line breaks or empty space. Check Stack Trace for Details: ", e);
                System.exit(-1);
            }
        }
    }

    String getPWfromToken(String pass, long pin, String token, BufferedReader br) {
        String pw = "";
        try {
            char[] pinArr = Long.toString(pin).toCharArray();
            token = AesGcmPw.decrypt(token, pass);
            alphabetSeedRequest(br, pinArr);
            int[] indexes = provideClearDecodedIndexes(decoder, token, pin);
            pw = generateByIndexes(indexes, pin);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pw;
    }

    public String getPWfromToken(String pass, long pin, String token) {
        return getPWfromToken(pass, pin, token, null);
    }

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

    void interactiveTokenGenerationHidden(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(true, true, br, cr);
    }

    void interactivePWGenerationHidden(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(false, true, br, cr);
    }

    void interactiveTokenGenerationVisible(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(true, false, br, cr);
    }

    void interactivePWGenerationVisible(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(false, false, br, cr);
    }

    void interactiveGenerator(boolean anonymous, boolean hidden, BufferedReader br, ConsoleReader cr) {
        char[] pwd = retrievePwd(cr);
        String encryptionPw = String.valueOf(pwd);
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
                log.error("Error occurred on interactive PW generation, check Stack Trace for Details: ", e);
                System.exit(-1);
            }
        }
    }

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

    int[] parseStringToIntArr(String word) {
        String[] stringIndexes = word.replace("{", "").replace("}", "").replace("[", "").replace("]", "").replace(" ", "").split(",");
        int[] indexes = new int[stringIndexes.length];

        for (int i = 0; i < indexes.length; i++) {
            indexes[i] = Integer.parseInt(stringIndexes[i]);
        }
        return indexes;
    }

    char[] randomizeAlphabet(long seed, char[] alphabet) {
        char[] arr = alphabet;
        List<Character> tempList = new ArrayList<>();
        for (char c : arr) {
            tempList.add(c);
        }
        shuffle(tempList, new MersenneTwister(seed));
        String str = tempList.toString().replace(",", "");
        arr = str.substring(1, str.length() - 1).replace(" ", "").toCharArray();
        return arr;
    }

    long provideMersenneTwisterPRNGLong(long seed) {
        return new MersenneTwister(seed).nextLong();
    }

    // handles only positive integers
    int generateRandomNumber(int min, int max) {
        int rand = -1;
        try {
            rand = SecureRandom.getInstanceStrong().nextInt(max - min) + min;
        } catch (NoSuchAlgorithmException e) {
            log.error(DEFAULT_ERR + " generating random numbers: ", e);
        }
        if (rand == -1) {
            throw new IllegalStateException(DEFAULT_ERR + " generating random numbers, random value is -1");
        }
        return rand;
    }

    int[] generateIndexes(int length, long pin) {
        if (alphabet == null) {
            alphabet = randomizeAlphabet(pin, referenceAlphabet);
        }
        int[] indexes = new int[length];

        for (int i = 0; i < length; i++) {
            indexes[i] = generateRandomNumber(0, alphabet.length);
        }
        return indexes;
    }

    public Map<String, String> provideTokenAndPw(int length, long pin, String encryptionPw) {
        shuffleAlphabetByPin(String.valueOf(pin).toCharArray());
        alphabet = randomizeAlphabet(pin, referenceAlphabet);
        int[] indexes = generateIndexes(length, pin);
        String token = provideObfuscatedEncodedIndexes(encoder, indexes, pin);
        try {
            token = AesGcmPw.encrypt(token.getBytes(AesGcmPw.UTF_8), encryptionPw);
        } catch (Exception e) {
            log.error(DEFAULT_ERR + " generating encrypted Pw: ", e);
        }
        StringBuilder pw = new StringBuilder();
        for (int index : indexes) {
            pw.append(alphabet[index]);
        }
        return Map.of("token", token, "pw", pw.toString());
    }

    public String provideToken(int length, long pin, String encryptionPw) {
        return provideTokenAndPw(length, pin, encryptionPw).get("token");
    }

    String generatePw(int length, long pin, boolean hidden, boolean anonymous, String encryptionPw) {
        alphabet = randomizeAlphabet(pin, referenceAlphabet);
        StringBuilder pw = new StringBuilder();
        int[] indexes = generateIndexes(length, pin);
        printAnsi(ansi().fg(GREEN).a("Token:").reset());
        String token = provideObfuscatedEncodedIndexes(encoder, indexes, pin);
        try {
            token = AesGcmPw.encrypt(token.getBytes(AesGcmPw.UTF_8), encryptionPw);
        } catch (Exception e) {
            log.error(DEFAULT_ERR + " generating encrypted Pw: ", e);
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
        pw.append(padWithEmtpyString());
        return pw.toString();
    }

    String padWithEmtpyString() {
        int length = generateRandomNumber(MIN_PADDING_LENGTH, MAX_PADDING_LENGTH);
        return String.format("%1$" + length + "s", ""); //NOSONAR
    }

    // pass your indexes to retrieve your pwd.
    String generateByIndexes(int[] indexes, long pin) {
        alphabet = randomizeAlphabet(pin, referenceAlphabet);
        StringBuilder pw = new StringBuilder();
        for (int index : indexes) {
            pw.append(alphabet[index]);
        }
        printAnsi(ansi().fg(GREEN).a("\nPW: ").reset());
        return pw.toString();
    }

    void printCharArrayToString(char[] arr) {
        if (arr == null) {
            throw new IllegalArgumentException("Passed Array is null.");
        }
        StringBuilder str = new StringBuilder("alphabet: {");
        for (int i = 0; i < arr.length; i++) {
            str.append("'").append(arr[i]).append("'");
            str.append((i == arr.length - 1) ? "}" : ", ");
        }
        log.info(str.toString()); //NOSONAR
    }

    public void printMultipleRandomPWs(int rangeMin, int rangeMax, int numOfPWs, long pin, boolean anonymous, boolean hidden, String encryptionPw) {
        for (int i = 0; i < numOfPWs; i++) {
            printAnsi(ansi().fg(GREEN).a("\n----------------PW NO:" + ((i + 1) < 10 ? "0" + (i + 1) : (i + 1)) + "-----------------").reset());
            int rand = generateRandomNumber(rangeMin, rangeMax);
            if (anonymous) {
                generatePw(rand, pin, hidden, true, encryptionPw);
            } else if (hidden) {
                printHidden(generatePw(rand, pin, true, false, encryptionPw));
            } else {
                printNormal(generatePw(rand, pin, false, false, encryptionPw));
            }
            printAnsi(ansi().fg(GREEN).a("-----------------------------------------").reset()); //NOSONAR
        }
    }

    String provideObfuscatedEncodedIndexes(Encoder e, int[] indexes, long pin) {
        int[] obfuscatedIndexes = obfuscateIndexes(indexes, referenceAlphabet.length, pin);
        return base64Encoding(obfuscatedIndexes, e);
    }

    int[] provideClearDecodedIndexes(Decoder d, String encodedIndexes, long pin) {
        int[] obfuscatedIndexes = base64Decoding(encodedIndexes, d);
        return clearObfuscatedIndexes(obfuscatedIndexes, referenceAlphabet.length, pin);
    }

    void printHidden(String message) {
        message = padWithEmtpyString() + message + padWithEmtpyString();
        printAnsi(ansi().fg(BLACK).bg(BLACK).a(message).reset()); //NOSONAR
    }

    void printNormal(String message) {
        printAnsi(ansi().fg(MAGENTA).a(message).reset()); //NOSONAR
    }

    // applies surjection with sumDigits
    int provideShiftValue(long pin, int alphabetLength) {
        int cycles = sumDigits(pin);
        long maskNumber = -1;
        for (int i = 0; i < cycles; i++) {
            maskNumber = Math.abs(provideMersenneTwisterPRNGLong(pin));
        }
        double p = ((double) maskNumber / (double) Long.MAX_VALUE);
        return (int) Math.ceil(alphabetLength * p);
    }

    int sumDigits(long num) {
        num = Math.abs(num);
        long sum = 0;
        while (num > 0) {
            sum = sum + num % 10;
            num = num / 10;
        }
        return (int) sum;
    }

    // only deals with positive integers
    int provideSecureRandomInteger(int min, int max) {
        int n = -1;
        try {
            n = SecureRandom.getInstanceStrong().nextInt(max - min + 1) + min;
        } catch (NoSuchAlgorithmException e) {
            log.error(DEFAULT_ERR, e);
        }
        if (n == -1) {
            throw new IllegalStateException(DEFAULT_ERR + " assigning random number. Random number is -1");
        }
        return n;
    }

    int[] obfuscateIndexes(int[] indexes, int alphabetLength, long pin) {
        int pwLength = indexes.length;
        int[] obfuscatedIndexes = new int[alphabetLength];
        int min = RESERVED_ARRAY_INDEXES;
        int max = alphabetLength - pwLength;
        int shiftValue = provideShiftValue(pin, alphabetLength);
        boolean obfuscationOffsetTooLong = (alphabetLength - (indexes.length + 1)) <= OBFUSCATION_OFFSET;
        boolean alphabetPWLengthCritical = max <= min;
        if (obfuscationOffsetTooLong || alphabetPWLengthCritical) {
            throw new IllegalArgumentException("Password too long, lower password max-length to max: " + (alphabetLength - (OBFUSCATION_OFFSET + 2)));
        }

        int arrayStartIndex = provideSecureRandomInteger(min, max);
        obfuscatedIndexes[1] = arrayStartIndex;
        System.arraycopy(indexes, 0, obfuscatedIndexes, arrayStartIndex, indexes.length + arrayStartIndex - arrayStartIndex);
        int[] remainingIndexes = provideRemainingIndexes(arrayStartIndex, pwLength, alphabetLength);
        int random = provideSecureRandomInteger(0, remainingIndexes.length - 1);
        obfuscatedIndexes[0] = remainingIndexes[random];
        obfuscatedIndexes[obfuscatedIndexes[0]] = pwLength;
        obfuscatedIndexes = fillEmptySpotsInObfuscatedArray(obfuscatedIndexes, remainingIndexes, alphabetLength);
        for (int i = 0; i < obfuscatedIndexes.length; i++) {
            obfuscatedIndexes[i] = shiftValue(obfuscatedIndexes[i], shiftValue, alphabetLength);
        }
        return obfuscatedIndexes;
    }

    int[] clearObfuscatedIndexes(int[] obfuscatedIndexes, int alphabetLength, long pin) {
        int shiftValue = provideShiftValue(pin, alphabetLength);
        int lengthIndex = unShiftValue(obfuscatedIndexes[0], shiftValue, alphabetLength);
        int length = unShiftValue(obfuscatedIndexes[lengthIndex], shiftValue, alphabetLength);
        int start = unShiftValue(obfuscatedIndexes[1], shiftValue, alphabetLength);
        int[] clearIndexes = new int[length];
        for (int i = 0; i < clearIndexes.length; i++) {
            clearIndexes[i] = unShiftValue(obfuscatedIndexes[i + start], shiftValue, alphabetLength);
        }
        return clearIndexes;
    }

    int[] provideRemainingIndexes(int pwStartIndex, int pwLength, int alphabetLength) {
        int beforePwMinIndex = pwStartIndex > RESERVED_ARRAY_INDEXES ? RESERVED_ARRAY_INDEXES : -1;
        int beforePwMaxIndex = pwStartIndex > RESERVED_ARRAY_INDEXES ? pwStartIndex : -1;
        int afterPwMinIndex = (pwStartIndex + pwLength) >= alphabetLength - 1 ? -1 : (pwStartIndex + pwLength);
        int afterPwMaxIndex = (pwStartIndex + pwLength) >= alphabetLength - 1 ? -1 : alphabetLength - 1;

        int remainingIndexesLength = (Math.max(beforePwMaxIndex, 0)) + ((pwStartIndex + pwLength) < (alphabetLength - 1) ? (alphabetLength) - (pwStartIndex + pwLength) : 0) - RESERVED_ARRAY_INDEXES;

        int[] remainingIndexes = new int[remainingIndexesLength];
        if (beforePwMaxIndex > 0) {
            for (int i = 0; i < (beforePwMaxIndex - beforePwMinIndex); i++) {
                remainingIndexes[i] = beforePwMinIndex + i;
            }
        }
        if (afterPwMaxIndex > 0) {
            for (int i = (beforePwMaxIndex - beforePwMinIndex); i < remainingIndexes.length; i++) {
                remainingIndexes[i] = afterPwMinIndex + (i - (beforePwMaxIndex - beforePwMinIndex));
            }
        }
        return remainingIndexes;
    }

    int[] fillEmptySpotsInObfuscatedArray(int[] obfuscatedArray, int[] remainingIndexes, int alphabetLength) {
        int pwLengthIndex = obfuscatedArray[0];
        if (pwLengthIndex == 0) {
            throw new IllegalStateException("Pw Length not yet assigned to obfuscated Array");
        }
        for (int remainingIndex : remainingIndexes) {
            if (remainingIndex == pwLengthIndex) {
                continue;
            }
            obfuscatedArray[remainingIndex] = provideSecureRandomInteger(0, alphabetLength);
        }
        return obfuscatedArray;
    }

    int shiftValue(int value, int shiftValue, int alphabetLength) {
        return (value + shiftValue) % alphabetLength;
    }

    int unShiftValue(int value, int shiftValue, int alphabetLength) {
        int tempIndex = (value - shiftValue) % alphabetLength;
        return tempIndex < 0 ? tempIndex + alphabetLength : tempIndex;
    }

    String base64Encoding(int[] indexes, Encoder e) {
        String string = Arrays.toString(indexes);
        byte[] bytes = string.getBytes();
        return e.encodeToString(bytes);
    }

    int[] base64Decoding(String indexes, Decoder d) {
        byte[] decodedBytes = d.decode(indexes);
        String decodedString = new String(decodedBytes);
        return parseStringToIntArr(decodedString);
    }

    // Wrap Console in order to ease testing and for separation of concerns
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

    @SuppressWarnings({"rawtypes", "unchecked"})
    public void shuffle(List<?> list, MersenneTwister rnd) {
        int size = list.size();
        if (size < SHUFFLE_THRESHOLD || list instanceof RandomAccess) {
            for (int i = size; i > 1; i--)
                swap(list, i - 1, rnd.nextInt(i));
        } else {
            Object[] arr = list.toArray();

            // Shuffle array
            for (int i = size; i > 1; i--)
                swap(arr, i - 1, rnd.nextInt(i));

            // Dump array back into list
            // instead of using a raw type here, it's possible to capture
            // the wildcard, but it will require a call to a supplementary
            // private method
            ListIterator it = list.listIterator();
            for (Object e : arr) {
                it.next();
                it.set(e);
            }
        }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public void swap(List<?> list, int i, int j) {
        // instead of using a raw type here, it's possible to capture
        // the wildcard, but it will require a call to a supplementary
        // private method
        ((List) list).set(i, ((List) list).set(j, ((List) list).get(i)));
    }

    private void swap(Object[] arr, int i, int j) {
        Object tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }

    private void printAnsi(Ansi msg) {
        System.out.println(msg); //NOSONAR
    }
}