package com.sam.key.manager;

import com.sam.key.cipher.AesGcmPw;
import org.apache.commons.math3.random.MersenneTwister;
import org.fusesource.jansi.AnsiConsole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import static org.fusesource.jansi.Ansi.Color.*;
import static org.fusesource.jansi.Ansi.ansi;

/**
 * Interactive CSPRNG / PRNG PW Manager. Password encryption/decription happens
 * by application of AES 256 GCM cipher. Further password and pin based chaining
 * permutations based on different seed values and generation of a seed
 * dependend surjection along with modulus circulation.
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
    private static final int SHUFFLE_THRESHOLD = 5;
    private static final String DEFAULT_ERR = "Issue occured";

    static Decoder decoder = Base64.getDecoder();
    static Encoder encoder = Base64.getEncoder();

    static char[] alphabet;

    static char[] referenceAlphabet = {'i', 'g', 'r', '.', 'u', '$', '&', 'G', '+', 'W', '9', 'C', 'Q', ':', 'w', 'o',
            'j', 'L', 'y', 'A', 'O', 'v', 'U', 'Y', 'S', 'z', 'E', 'f', '*', '2', '=', '4', '%', 'B', 'K', 'T', 'm',
            '@', '!', 'h', 'V', '/', '1', 'l', 'X', '(', '_', 'J', ')', '5', 'a', 'q', 'k', '[', '?', '=', '-', 'n',
            'P', 's', '3', 'Z', 'N', 'M', '#', 'R', 'p', ']', '0', '7', 'D', 'x', '8', 't', '6', 'e', 'H', ';', 'I',
            'F', 'd', 'b', 'c'};

    static String pwMgr = "\n"
            + "                                                                                        \n"
            + " _____ _____ _____ ____     _____ _____ _____ _____    _____ _ _ _    _____ _____ _____ \n"
            + "|   __|   __|   __|    \\   |  _  |   __| __  |     |  |  _  | | | |  |     |   __| __  |\n"
            + "|__   |   __|   __|  |  |  |   __|   __|    -| | | |  |   __| | | |  | | | |  |  |    -|\n"
            + "|_____|_____|_____|____/   |__|  |_____|__|__|_|_|_|  |__|  |_____|  |_|_|_|_____|__|__|\n"
            + "                                                                                        \n" + "";

    private static Logger log = LoggerFactory.getLogger(Generator.class);

    public static void main(String[] args) {
        AnsiConsole.systemInstall();
        System.out.println(ansi().eraseScreen().bg(GREEN).fg(WHITE).a(pwMgr).reset());
        printCLICommands();
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        int option = readOption(br);
        ConsoleReader cr = new ConsoleReader();
        callToAction(br, cr, option);
    }

    static int readOption(BufferedReader br) {
        int option = -1;
        try {
            option = Integer.parseInt(br.readLine());
        } catch (Exception e) {
            log.error("DEFAULT_ERR, please choose one of the available options.", e);
            System.exit(-1);
        }
        return option;
    }

    static void callToAction(BufferedReader br, ConsoleReader cr, int option) {
        switch (option) {
            case 0:
                interactiveIndexesGenerationHidden(br, cr);
                break;
            case 1:
                interactiveIndexesGenerationVisible(br, cr);
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
                System.out.println(ansi().fg(RED).a("This option is not available. Choose a listed option.").reset());
                break;
        }
    }

    //	static String retrievePwd(BufferedReader br, ConsoleReader cr) {
    static char[] retrievePwd(ConsoleReader cr) {
//		String pw = null;
        char[] pw = null;
        try {
            System.out.println(ansi().fg(GREEN).a("Enter PW:").reset());
            pw = cr.readPassword();
//			pw = br.readLine();
            if (pw == null) {
                throw new Error("PW is null");
            }
        } catch (IOError e) {
            log.error("DEFAULT_ERR.", e);
        }
        return pw;
    }

    static void printCLICommands() {
        System.out.println(ansi().fg(GREEN).a("Choose what you want to do:").reset());
        System.out.println(
                ansi().fg(GREEN).a("0").fg(YELLOW).a(" - Create Passwords - Show only Token (Hidden)").reset());
        System.out.println(
                ansi().fg(GREEN).a("1").fg(YELLOW).a(" - Create Passwords - Show only Token (Visible)").reset());
        System.out.println(
                ansi().fg(GREEN).a("2").fg(YELLOW).a(" - Create Passwords - Show PWs and Token (Hidden)").reset());
        System.out.println(
                ansi().fg(GREEN).a("3").fg(YELLOW).a(" - Create Passwords - Show PWs and Token (Visible)").reset());
        System.out.println(ansi().fg(GREEN).a("4").fg(YELLOW).a(" - Retrieve Password (Hidden)").reset());
        System.out.println(ansi().fg(GREEN).a("5").fg(YELLOW).a(" - Retrieve Password (Visible)").reset());
    }

    public static long convertCharToLong(char[] pwd) {
        long pwdConverted = 0;
        for (int i = 0; i < pwd.length; i++) {
            pwdConverted += Character.getNumericValue(pwd[i]);
            pwdConverted *= pwdConverted;
        }
        return pwdConverted;
    }

    static void alphabetSeedRequest(ConsoleReader cr, BufferedReader br, char[] pin) {
//		char[] seedC = null;
        try {
//			System.out.println(ansi().fg(GREEN).a("Enter Seed:").reset());
//			seedC = cr.readPassword();
            long seed = convertCharToLong(pin);
//			long seed = Long.parseLong(new String(pwd));
            referenceAlphabet = randomizeAlphabet(seed, referenceAlphabet);
        } catch (Exception e) {
            if (e instanceof NullPointerException && pin == null) {
                System.out.println("Masking input not supported.. Continue with default Invocation");
                alphabetSeedRequestOnNull(br);
            } else {
                log.error(DEFAULT_ERR, e);
            }
        }
    }

    static void alphabetSeedRequestOnNull(BufferedReader br) {
        try {
            System.out.println(ansi().fg(GREEN).a("Enter Seed: ").reset());
            String seedS = br.readLine();
            long seed = Long.parseLong(seedS);
            referenceAlphabet = randomizeAlphabet(seed, referenceAlphabet);
        } catch (IOException e) {
            log.error(DEFAULT_ERR, e);
        }
    }

    static void interactivePWRetrieve(boolean hidden, ConsoleReader cr, BufferedReader br) {
        char[] pwd = retrievePwd(cr);
        String pass = String.valueOf(pwd);
        char[] readPin = null;
        int[] indexes = null;
        String token = null;
        try {
            System.out.println(ansi().fg(GREEN).a("Enter Token:").reset());
            token = br.readLine();
            token = AesGcmPw.decrypt(token, pass);
            System.out.println(ansi().fg(GREEN).a("Enter Pin:").reset());
            readPin = cr.readPassword();
            alphabetSeedRequest(cr, br, readPin);
            long pin = Long.parseLong(new String(readPin));
            indexes = provideClearDecodedIndexes(decoder, token, pin);
            if (hidden) {
                printHidden(generateByIndexes(indexes, pin, hidden));
            } else {
                printNormal(generateByIndexes(indexes, pin, hidden));
            }
        } catch (Exception e) {
            if (e instanceof NullPointerException && readPin == null) {
                System.out.println("Masking input not supported.. Continue with default Invocation");
                interactivePWRetrieveOnNull(br, hidden, token);
            } else {
                log.error(DEFAULT_ERR + " on retrieving PW, check Stack Trace for Details: ", e);
                System.exit(-1);
            }
            return;
        }
    }

    static void interactivePWRetrieveOnNull(BufferedReader br, boolean hidden, String token) {
        try {
            System.out.println(ansi().fg(GREEN).a("Enter Pin:").reset());
            String pin = br.readLine();
            long seed = Long.parseLong(pin);
            int[] indexes = provideClearDecodedIndexes(decoder, token, seed);
            if (hidden) {
                printHidden(generateByIndexes(indexes, seed, hidden));
            } else {
                printNormal(generateByIndexes(indexes, seed, hidden));
            }
        } catch (IOException e) {
            log.error(DEFAULT_ERR, e);
        }
    }

    static void interactiveIndexesGenerationHidden(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(true, true, br, cr);
    }

    static void interactivePWGenerationHidden(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(false, true, br, cr);
    }

    static void interactiveIndexesGenerationVisible(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(true, false, br, cr);
    }

    static void interactivePWGenerationVisible(BufferedReader br, ConsoleReader cr) {
        interactiveGenerator(false, false, br, cr);
    }

    static void interactiveGenerator(boolean anonymous, boolean hidden, BufferedReader br, ConsoleReader cr) {
        char[] pwd = retrievePwd(cr);
        String encryptionPw = String.valueOf(pwd);
        char[] readPin = null;
        int min = -1;
        int max = -1;
        int numPws = -1;
        try {
            System.out.println(ansi().fg(GREEN).a("Enter minimal PW character length:").reset());
            min = Integer.parseInt(br.readLine());
            System.out.println(ansi().fg(GREEN).a("Enter max PW character length:").reset());
            max = Integer.parseInt(br.readLine());
            System.out.println(ansi().fg(GREEN).a("Enter number of Passwords to be created:").reset());
            numPws = Integer.parseInt(br.readLine());
            System.out.println(ansi().fg(GREEN).a("Enter Pin:").reset());
            readPin = cr.readPassword();
            alphabetSeedRequest(cr, br, readPin);
            long pin = Long.parseLong(new String(readPin));
            printMultipleRandomPWs(min, max, numPws, pin, anonymous, hidden, encryptionPw);
        } catch (Exception e) {
            if (e instanceof NullPointerException && readPin == null) {
                System.out.println("Masking input not supported.. Continue with default Invocation");
                interactiveGeneratorOnNull(br, min, max, numPws, anonymous, hidden, encryptionPw);
            } else {
                log.error("Error occured on interactive PW generation, check Stack Trace for Details: ", e);
                System.exit(-1);
            }
            return;
        }
    }

    static void interactiveGeneratorOnNull(BufferedReader br, int min, int max, int numPws, boolean anonymous,
                                           boolean hidden, String encryptionPw) {
        try {
            System.out.println(ansi().fg(GREEN).a("Enter Pin:").reset());
            String pin = br.readLine();
            long seed = Long.parseLong(pin);
            printMultipleRandomPWs(min, max, numPws, seed, anonymous, hidden, encryptionPw);
        } catch (IOException e) {
            log.error(DEFAULT_ERR, e);
        }
    }

    static int[] parseStringToIntArr(String word) {
        String[] stringIndexes = word.replaceAll("\\{", "").replaceAll("\\}", "").replaceAll("\\[", "")
                .replaceAll("\\]", "").replaceAll("\\s", "").split(",");
        int[] indexes = new int[stringIndexes.length];

        for (int i = 0; i < indexes.length; i++) {
            indexes[i] = Integer.parseInt(stringIndexes[i]);
        }
        return indexes;
    }

    static char[] randomizeAlphabet(long seed, char[] alphabet) {
        char[] arr = alphabet;
        List<Character> tempList = new ArrayList<>();
        for (char c : arr) {
            tempList.add(c);
        }
        shuffle(tempList, new MersenneTwister(seed));
        String str = tempList.toString().replaceAll(",", "");
        arr = str.substring(1, str.length() - 1).replaceAll(" ", "").toCharArray();
        return arr;
    }

    static long provideMersenneTWisterPRNGLong(long seed) {
        return new MersenneTwister(seed).nextLong();
    }

    // handles only positive integers
    static int generateRandomNumber(int min, int max) {
        int rand = -1;
        try {
            rand = SecureRandom.getInstanceStrong().nextInt(max - min) + min;
        } catch (NoSuchAlgorithmException e) {
            log.error(DEFAULT_ERR + " generating random numbers: ", e);
        }
        if (rand == -1) {
            throw new Error(DEFAULT_ERR + " generating random numbers");
        }
        return rand;
    }

    static int[] generateIndexes(int length, long pin) {
        if (alphabet == null) {
            alphabet = randomizeAlphabet(pin, referenceAlphabet);
        }
        int[] indexes = new int[length];

        for (int i = 0; i < length; i++) {
            indexes[i] = generateRandomNumber(0, alphabet.length);
        }
        return indexes;
    }

    static String generatePw(int length, long pin, boolean hidden, boolean anonymous, String encryptionPw) {
        alphabet = randomizeAlphabet(pin, referenceAlphabet);
        String pw = "";
        int[] indexes = generateIndexes(length, pin);
        System.out.println(ansi().fg(GREEN).a("Token:").reset());
        String token = provideObfuscatedEncodedIndexes(encoder, indexes, pin);
        try {
            token = AesGcmPw.encrypt(token.getBytes(AesGcmPw.UTF_8), encryptionPw);
//			System.out.println(encryptedPw);
        } catch (Exception e) {
            log.error(DEFAULT_ERR + " generating encrypted Pw: ", e);
        }
        if (hidden) {
            printHidden(token);
        } else {
            printNormal(token);
        }
        for (int i = 0; i < indexes.length; i++) {
            pw += alphabet[indexes[i]];
        }
        if (!anonymous) {
            System.out.println(ansi().fg(GREEN).a("\nPW: ").reset());
        }
        pw += padWithEmtpyString();
        return pw;
    }

    static String padWithEmtpyString() {
        int length = generateRandomNumber(MIN_PADDING_LENGTH, MAX_PADDING_LENGTH);
        return String.format("%1$" + length + "s", "");
    }

    // pass your indexes to retrieve your pwd.
    static String generateByIndexes(int[] indexes, long pin, boolean hidden) {
        alphabet = randomizeAlphabet(pin, referenceAlphabet);
        String pw = "";
        for (int i = 0; i < indexes.length; i++) {
            pw += alphabet[indexes[i]];
        }
        System.out.println(ansi().fg(GREEN).a("\nPW: ").reset());
        return pw;
    }

    static void printCharArrayToString(char[] arr) throws Exception {
        if (arr == null) {
            throw new Exception("Passed Array is null.");
        }
        String str = "alphabet: {";
        for (int i = 0; i < arr.length; i++) {
            str += "'" + Character.toString(arr[i]) + "'";
            str += (i == arr.length - 1) ? "}" : ", ";
        }
        System.out.println(str);
    }

    static void printMultipleRandomPWs(int rangeMin, int rangeMax, int numOfPWs, long pin, boolean anonymous,
                                       boolean hidden, String encryptionPw) {
        for (int i = 0; i < numOfPWs; i++) {
            System.out.println(ansi().fg(GREEN)
                    .a("\n----------------PW NO:" + ((i + 1) < 10 ? "0" + (i + 1) : (i + 1)) + "-----------------")
                    .reset());
            int rand = generateRandomNumber(rangeMin, rangeMax);
            if (anonymous) {
                generatePw(rand, pin, hidden, anonymous, encryptionPw);
            } else if (hidden) {
                printHidden(generatePw(rand, pin, hidden, anonymous, encryptionPw));
            } else {
                printNormal(generatePw(rand, pin, hidden, anonymous, encryptionPw));
            }
            System.out.println(ansi().fg(GREEN).a("-----------------------------------------").reset());
        }
    }

    static String provideObfuscatedEncodedIndexes(Encoder e, int[] indexes, long pin) {
        int[] obfuscatedIndexes = obfuscateIndexes(indexes, referenceAlphabet.length, pin);
        String base64EncodedArray = base64Encoding(obfuscatedIndexes, e);
        return base64EncodedArray;
    }

    static int[] provideClearDecodedIndexes(Decoder d, String encodedIndexes, long pin) {
        int[] obfuscatedIndexes = base64Decoding(encodedIndexes, d);
        int[] clearIndexes = clearObfuscatedIndexes(obfuscatedIndexes, referenceAlphabet.length, pin);
        return clearIndexes;
    }

    static void printHidden(String message) {
        message = padWithEmtpyString() + message + padWithEmtpyString();
        System.out.println(ansi().fg(BLACK).bg(BLACK).a(message).reset());
    }

    static void printNormal(String message) {
        System.out.println(ansi().fg(MAGENTA).a(message).reset());
    }

    // applies surjection with sumDigits
    static int provideShiftValue(long pin, int alphabetLength) {
        int cycles = sumDigits(pin);
        long maskNumber = -1;
        for (int i = 0; i < cycles; i++) {
            maskNumber = Math.abs(provideMersenneTWisterPRNGLong(pin));
        }
        double p = ((double) maskNumber / (double) Long.MAX_VALUE);
        int shiftValue = (int) Math.ceil(alphabetLength * p);
        return shiftValue;
    }

    static int sumDigits(long num) {
        num = Math.abs(num);
        long sum = 0;
        while (num > 0) {
            sum = sum + num % 10;
            num = num / 10;
        }
        return (int) sum;
    }

    // only deals with positive integers
    static int provideSecureRandomInteger(int min, int max) {
        int n = -1;
        try {
            n = SecureRandom.getInstanceStrong().nextInt(max - min + 1) + min;
        } catch (NoSuchAlgorithmException e) {
            log.error(DEFAULT_ERR, e);
        }
        if (n == -1) {
            throw new Error(DEFAULT_ERR + " assigning random number");
        }
        return n;
    }

    static int[] obfuscateIndexes(int[] indexes, int alphabetLength, long pin) {
        int pwLength = indexes.length;
        int[] obfuscatedIndexes = new int[alphabetLength];
        int min = RESERVED_ARRAY_INDEXES;
        if ((alphabetLength - (indexes.length + 1)) <= OBFUSCATION_OFFSET) {
            throw new Error("Password too long, lower password max-length to max: "
                    + (alphabetLength - (OBFUSCATION_OFFSET + 1)));
        }
        int max = (alphabetLength) - pwLength;
        int shiftValue = provideShiftValue(pin, alphabetLength);
        if (max <= min) {
            throw new Error("PW too long");
        }

        int arrayStartIndex = provideSecureRandomInteger(min, max);
        obfuscatedIndexes[1] = arrayStartIndex;
        for (int i = arrayStartIndex; i < (indexes.length + arrayStartIndex); i++) {
            obfuscatedIndexes[i] = indexes[i - arrayStartIndex];
        }
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

    static int[] clearObfuscatedIndexes(int[] obfuscatedIndexes, int alphabetLength, long pin) {
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

    static int[] provideRemainingIndexes(int pwStartIndex, int pwLength, int alphabetLength) {
        int beforePwMinIndex = pwStartIndex > RESERVED_ARRAY_INDEXES ? RESERVED_ARRAY_INDEXES : -1;
        int beforePwMaxIndex = pwStartIndex > RESERVED_ARRAY_INDEXES ? pwStartIndex : -1;
        int afterPwMinIndex = (pwStartIndex + pwLength) >= alphabetLength - 1 ? -1 : (pwStartIndex + pwLength);
        int afterPwMaxIndex = (pwStartIndex + pwLength) >= alphabetLength - 1 ? -1 : alphabetLength - 1;

        int remainingIndexesLength = (beforePwMaxIndex > 0 ? beforePwMaxIndex : 0)
                + ((pwStartIndex + pwLength) < (alphabetLength - 1) ? (alphabetLength) - (pwStartIndex + pwLength) : 0)
                - RESERVED_ARRAY_INDEXES;

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

    static int[] fillEmptySpotsInObfuscatedArray(int[] obfuscatedArray, int[] remainingIndexes, int alphabetLength) {
        int pwLengthIndex = obfuscatedArray[0];
        if (pwLengthIndex == 0) {
            throw new Error("Pw Length not yet assigned to obfuscated Array");
        }
        for (int i = 0; i < remainingIndexes.length; i++) {
            if (remainingIndexes[i] == pwLengthIndex) {
                continue;
            }
            obfuscatedArray[remainingIndexes[i]] = provideSecureRandomInteger(0, alphabetLength);
        }
        return obfuscatedArray;
    }

    static int shiftValue(int value, int shiftValue, int alphabetLength) {
        return (value + shiftValue) % alphabetLength;
    }

    static int unShiftValue(int value, int shiftValue, int alphabetLength) {
        int tempIndex = (int) (value - shiftValue) % alphabetLength;
        int actualIndex = tempIndex < 0 ? tempIndex + alphabetLength : tempIndex;
        return actualIndex;
    }

    static String base64Encoding(int[] indexes, Encoder e) {
        String string = Arrays.toString(indexes);
        byte[] bytes = string.getBytes();
        String encodedIndexes = e.encodeToString(bytes);
        return encodedIndexes;
    }

    static int[] base64Decoding(String indexes, Decoder d) {
        byte[] decodedBytes = d.decode(indexes);
        String decodedString = new String(decodedBytes);
        int[] decodedIndexes = parseStringToIntArr(decodedString);
        return decodedIndexes;
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
    public static void shuffle(List<?> list, MersenneTwister rnd) {
        int size = list.size();
        if (size < SHUFFLE_THRESHOLD || list instanceof RandomAccess) {
            for (int i = size; i > 1; i--)
                swap(list, i - 1, rnd.nextInt(i));
        } else {
            Object arr[] = list.toArray();

            // Shuffle array
            for (int i = size; i > 1; i--)
                swap(arr, i - 1, rnd.nextInt(i));

            // Dump array back into list
            // instead of using a raw type here, it's possible to capture
            // the wildcard but it will require a call to a supplementary
            // private method
            ListIterator it = list.listIterator();
            for (Object e : arr) {
                it.next();
                it.set(e);
            }
        }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public static void swap(List<?> list, int i, int j) {
        // instead of using a raw type here, it's possible to capture
        // the wildcard but it will require a call to a supplementary
        // private method
        final List l = list;
        l.set(i, l.set(j, l.get(i)));
    }

    private static void swap(Object[] arr, int i, int j) {
        Object tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}