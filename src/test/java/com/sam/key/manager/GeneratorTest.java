package com.sam.key.manager;

import com.sam.key.manager.Generator.ConsoleReader;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.math3.random.MersenneTwister;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.sam.key.manager.Generator.OBFUSCATION_ARRAY_SIZE;
import static org.junit.jupiter.api.Assertions.*;

public class GeneratorTest {

    static final int PERMUTATION_SEED = 1;
    static final int PIN = 12345;
    static final int NO_PWS = 10;
    static final int MIN_PW_LENGTH = 20;
    static final int MAX_PW_LENGTH = 30;
    public static final char[] UTILIZED_REFERENCE_ALPHABET = {'i', 'g', 'r', '.', 'u', '$', '&', 'G', '+', 'W', '9', 'C', 'Q', ':', 'w', 'o', 'j', 'L', 'y', 'A', 'O', 'v', 'U', 'Y', 'S', 'z', 'E', 'f', '*', '2', '=', '4', '%', 'B', 'K', 'T', 'm', '@', '!', 'h', 'V', '/', '1', 'l', 'X', '(', '_', 'J', ')', '5', 'a', 'q', 'k', '[', '?', '=', '-', 'n', 'P', 's', '3', 'Z', 'N', 'M', '#', 'R', 'p', ']', '0', '7', 'D', 'x', '8', 't', '6', 'e', 'H', ';', 'I', 'F', 'd', 'b', 'c'};

    Generator g;

    @BeforeAll
    public static void init() {
        System.setProperty("log4j.configurationFile", "./src/main/resources/log4j2.properties");
        Generator.log = LoggerFactory.getLogger(GeneratorTest.class);
    }

    @BeforeEach
    public void reassign() {
        g = new Generator();
    }

    @Test
    void parseStringToIntArrTest() {
        String indexes = "{21,79,57,0,6,5,39,32,29,69,29,65,72,39,28,44,0,71,10,14,21,53,16,7,3,28}";
        int[] parseStringToIntArr = g.parseStringToIntArr(indexes);
        assertEquals(26, parseStringToIntArr.length);

        indexes = "{21,79,57,0,6}";
        parseStringToIntArr = g.parseStringToIntArr(indexes);
        assertEquals(5, parseStringToIntArr.length);
        assertEquals(57, parseStringToIntArr[2]);

        indexes = "21,79, 57,2,6";
        parseStringToIntArr = g.parseStringToIntArr(indexes);
        assertEquals(5, parseStringToIntArr.length);
        assertEquals(2, parseStringToIntArr[3]);
        assertEquals(6, parseStringToIntArr[4]);
    }

    @Test
    void parseStringToIntArrExceptionTest() {
        String indexes = "{21,79,57, abc,0,6}";
        Exception exception = assertThrows(NumberFormatException.class, () -> g.parseStringToIntArr(indexes));

        String expectedMessage = "For input string: \"abc\"";
        assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    void randomizeAlphabetTest() {
        char[] testAlphabet = g.referenceAlphabet;
        assertNotEquals(g.alphabet, g.referenceAlphabet);
        long seed = PERMUTATION_SEED;
        char[] randomizedAlphabet = g.randomizeAlphabet(seed, g.referenceAlphabet);
        assertNotNull(randomizedAlphabet);
        assertNotEquals(randomizedAlphabet, testAlphabet);
        List<Character> testList = new ArrayList<>();
        for (char c : testAlphabet) {
            testList.add(c);
        }
        g.shuffle(testList, new MersenneTwister(seed));
        String str = testList.toString().replaceAll(",", "");
        testAlphabet = str.substring(1, str.length() - 1).replaceAll(" ", "").toCharArray();
        assertEquals(testAlphabet.length, randomizedAlphabet.length);
        for (int i = 0; i < randomizedAlphabet.length; i++) {
            assertEquals(testAlphabet[i], randomizedAlphabet[i]);
        }
    }

    @Test
    void generateRandomNumberTest() {
        for (int i = 0; i < 100; i++) {
            int rand = g.generateRandomNumber(i, (i + 1) * 10);
            assertTrue(rand <= ((i + 1) * 10) && rand >= i);
        }
        int rand = (int) (Math.random() * 1000);
        Exception exception = assertThrows(IllegalArgumentException.class, () -> g.generateRandomNumber(rand, rand));
        String expectedMessage = "bound must be positive";
        assertEquals(expectedMessage, exception.getMessage());

    }

    @Test
    void generateIndexesTest() {
        int length = (int) (Math.random() * 100);
        long pin = (long) (Math.random() * 1_000_000);
        int[] generateIndexes = g.generateIndexes(length, pin);
        assertEquals(generateIndexes.length, length);
        g.randomizeAlphabet(pin, g.referenceAlphabet);
        generateIndexes = g.generateIndexes(length, pin);
        assertEquals(generateIndexes.length, length);
    }

    @Test
    void generatePwTest() {
        int length = (int) (Math.random() * 60);
        long pin = (long) (Math.random() * 1_000_000);
        String pwd = "test";
        String generatedPw = g.generatePw(length, pin, true, false, pwd);
        assertNotEquals(generatedPw.length(), length);
        assertTrue(generatedPw.length() >= length + Generator.MIN_PADDING_LENGTH);
        assertTrue(generatedPw.length() <= length + Generator.MAX_PADDING_LENGTH);
        char[] generatedPwCharArray = generatedPw.toCharArray();
        // check that only reference alphabet chars are considered
        pwContainsCheck(generatedPwCharArray);

        generatedPw = g.generatePw(length, pin, false, false, pwd);
        assertNotEquals(generatedPw.length(), length);
        assertTrue(generatedPw.length() >= length + Generator.MIN_PADDING_LENGTH);
        assertTrue(generatedPw.length() <= length + Generator.MAX_PADDING_LENGTH);
        char[] generatedPwCharArray2 = generatedPw.toCharArray();
        pwContainsCheck(generatedPwCharArray2);
    }

    private void pwContainsCheck(char[] generatedPw) {
        boolean contained;
        for (char c : generatedPw) {
            if (c == ' ') {
                continue;
            }
            contained = false;
            for (int j = 0; j < g.referenceAlphabet.length; j++) {
                contained = c == g.referenceAlphabet[j];
                if (contained) {
                    break;
                }
            }
            assertTrue(contained);
        }
    }

    @Test
    void padWithEmptyStringTest() {
        String emptyString = g.padWithEmtpyString();
        assertTrue(emptyString.length() >= Generator.MIN_PADDING_LENGTH);
        assertTrue(emptyString.length() <= Generator.MAX_PADDING_LENGTH);
    }

    @Test
    void generateByIndexesTest() {
        int[] indexes = {47, 41, 12, 1, 28, 57, 7, 44, 67, 43, 46, 73, 67, 51, 82, 10, 43, 53, 42, 53, 20, 73, 65, 48, 35, 65, 9, 14, 61, 38, 43, 57, 56, 30, 80, 76, 22, 56, 18, 11, 35, 16, 14, 9, 37, 16, 49, 51, 43, 30, 80, 77, 61, 40, 79, 30, 6, 37, 22, 10, 30, 3, 41, 21, 15, 69, 57, 51, 32, 45, 36, 75, 54, 68, 45, 53, 9, 59, 56, 16, 47, 3};
        String expectedPw = "S=KGe1:aC$_fC[yV$rMrYfR&gR*lmd$1xEB@(xL0g-l*P-5[$EBumJ.EWP(VEo=ZHI1[QAwNp;Ar*Tx-So";
        char[] referenceAlphabetInitial = g.getReferenceAlphabet();
        String generatePwByIndexes = g.setReferenceAlphabet(UTILIZED_REFERENCE_ALPHABET).generateByIndexes(indexes, PIN);
        assertEquals(expectedPw, generatePwByIndexes);

        generatePwByIndexes = g.generateByIndexes(indexes, PIN);
        assertEquals(expectedPw, generatePwByIndexes);

        int[] indexes2 = {4, 10, 50, 22, 5, 45, 19, 81, 73, 35, 23, 62, 2, 53, 0, 39, 11, 2, 75, 13, 73, 36, 72, 35, 70, 49, 6, 29, 52, 42, 24, 62, 57, 71, 0, 73, 26, 77, 17, 42, 29, 22, 5, 0, 70, 32, 38, 17, 15, 45, 59, 67, 20, 49, 82, 79, 82, 31, 30, 77, 28, 37, 49, 60, 73, 1, 16, 27, 73, 73, 61, 21, 74, 19, 35, 40, 13, 33, 78, 6, 42, 81};

        expectedPw = "UV](sA9#fgv6brnj0bNDfwOgt5Wz)M?614nf2u/Mz(sntQd/HATCY5y.y8EueP5hfG-qffmZk9gJDX3WM#";
        generatePwByIndexes = g.generateByIndexes(indexes2, PIN);
        assertEquals(expectedPw, generatePwByIndexes);
        g.setReferenceAlphabet(referenceAlphabetInitial);
    }

    @Test
    void interactiveIndexesGenerationHiddenTest() throws IOException {
        char[] initialAlphabetState = g.referenceAlphabet;
        assertEquals(initialAlphabetState, g.referenceAlphabet);
        BufferedReader br = provideBufferedReaderMock();
        ConsoleReader cr = provideConsoleReaderMock();
        g.interactiveTokenGenerationHidden(br, cr);
        assertNotEquals(initialAlphabetState, g.referenceAlphabet);
    }

    @Test
    void interactivePWGenerationHiddenTest() throws IOException {
        char[] initialAlphabetState = g.referenceAlphabet;
        assertEquals(initialAlphabetState, g.referenceAlphabet);
        BufferedReader br = provideBufferedReaderMock();
        ConsoleReader cr = provideConsoleReaderMock();
        g.interactivePWGenerationHidden(br, cr);
        assertNotEquals(initialAlphabetState, g.referenceAlphabet);
    }

    @Test
    void interactivePWGenerationVisibleTest() throws IOException {
        char[] initialAlphabetState = g.referenceAlphabet;
        assertEquals(initialAlphabetState, g.referenceAlphabet);
        BufferedReader br = provideBufferedReaderMock();
        ConsoleReader cr = provideConsoleReaderMock();
        g.interactivePWGenerationVisible(br, cr);
        assertNotEquals(initialAlphabetState, g.referenceAlphabet);
    }

    @Test
    void alphabetSeedRequestExceptionTest() throws IOException {
        char[] initialAlphabetState = g.referenceAlphabet;
        assertEquals(initialAlphabetState, g.referenceAlphabet);
        BufferedReader br = provideBufferedReaderMock();
        char[] pwd = {'a', 'b', 'c', 'd'};
        g.alphabetSeedRequest(br, pwd);
        assertNotEquals(initialAlphabetState, g.referenceAlphabet);
    }

    @Test
    void alphabetSeedRequestNullTest() throws IOException {
        char[] initialAlphabetState = g.referenceAlphabet;
        assertEquals(initialAlphabetState, g.referenceAlphabet);
        BufferedReader br = provideBufferedReaderMock();
        char[] pwd = {'a', 'b', 'c', 'd'};
        g.alphabetSeedRequest(br, pwd);
        assertNotEquals(initialAlphabetState, g.referenceAlphabet);
    }

    @Test
    void alphabetSeedRequestOnNullExceptionTest() throws IOException {
        char[] initialAlphabetState = g.referenceAlphabet;
        assertEquals(initialAlphabetState, g.referenceAlphabet);
        BufferedReader br = provideBufferedReaderExceptionMock();
        g.alphabetSeedRequestOnNull(br);
        assertEquals(initialAlphabetState, g.referenceAlphabet);
    }

    @Test
    void interactiveGeneratorNullTest() throws IOException {
        char[] initialAlphabetState = g.referenceAlphabet;
        assertEquals(initialAlphabetState, g.referenceAlphabet);
        BufferedReader br = provideBufferedReaderLongMock();
        ConsoleReader cr = provideConsoleReaderNullMock();
        g.interactiveGenerator(false, false, br, cr);
        assertNotEquals(initialAlphabetState, g.referenceAlphabet);
    }

    @Test
    void interactiveIndexesGenerationVisibleTest() throws IOException {
        char[] initialAlphabetState = g.referenceAlphabet;
        assertEquals(initialAlphabetState, g.referenceAlphabet);
        g.printCLICommands();
        BufferedReader br = provideBufferedReaderMock();
        ConsoleReader cr = provideConsoleReaderMock();
        g.interactiveTokenGenerationVisible(br, cr);
        assertNotEquals(initialAlphabetState, g.referenceAlphabet);
    }

    @Test
    void interactivePWRetrieveHiddenTest() throws IOException {
        char[] referenceAlphabetBackup = g.referenceAlphabet;
        g.setReferenceAlphabet(UTILIZED_REFERENCE_ALPHABET);

        char[] initialAlphabetState = g.referenceAlphabet;
        assertEquals(initialAlphabetState, g.referenceAlphabet);
        BufferedReader br = provideBufferedReaderTokenMock();
        ConsoleReader cr = provideConsoleReaderMock();
        g.interactivePWRetrieve(true, cr, br);
        assertNotEquals(initialAlphabetState, g.referenceAlphabet);

        g.referenceAlphabet = referenceAlphabetBackup;
    }

    @Test
    void interactivePWRetrieveVisibleTest() throws IOException {
        char[] referenceAlphabetBackup = g.referenceAlphabet;
        g.setReferenceAlphabet(UTILIZED_REFERENCE_ALPHABET);

        char[] initialAlphabetState = g.referenceAlphabet;
        assertEquals(initialAlphabetState, g.referenceAlphabet);
        BufferedReader br = provideBufferedReaderTokenMock();
        ConsoleReader cr = provideConsoleReaderMock();
        g.interactivePWRetrieve(false, cr, br);
        assertNotEquals(initialAlphabetState, g.referenceAlphabet);

        g.referenceAlphabet = referenceAlphabetBackup;
    }

    @Test
    void interactivePWRetrieveExceptionTest() throws Exception {
        char[] referenceAlphabetBackup = g.referenceAlphabet;
        g.setReferenceAlphabet(UTILIZED_REFERENCE_ALPHABET);

        char[] initialAlphabetState = g.referenceAlphabet;
        assertEquals(initialAlphabetState, g.referenceAlphabet);
        BufferedReader br = provideBufferedReaderNullTokenMock();
        ConsoleReader cr = provideConsoleReaderNullMock();
        g.interactivePWRetrieve(false, cr, br);
        assertNotEquals(initialAlphabetState, g.referenceAlphabet);
        g.referenceAlphabet = referenceAlphabetBackup;
    }

    @Test
    void printCharArrayNullTest() {
        Exception exception = assertThrows(Exception.class, () -> g.printCharArrayToString(null));
        String expectedMessage = "Passed Array is null.";
        assertEquals(expectedMessage, exception.getMessage());
        g.printCharArrayToString("{48,13,73,7,64,78,11,77,27,54,38,56,71,72,43,67,28,30,67,19,46,28,5,37,2,65,79,43,32,12,17,4}".toCharArray());
    }

    @Test
    void testPwGenerationAndRetieval() throws NoSuchAlgorithmException {
        for (int j = 0; j < 100; j++) {
            long tempPin = SecureRandom.getInstanceStrong().nextLong();
            int tempPWLength = (int) Math.ceil((OBFUSCATION_ARRAY_SIZE - 22) * Math.random());
            g.alphabet = g.randomizeAlphabet(tempPin, g.referenceAlphabet);
            int[] indexes = g.generateIndexes(tempPWLength, tempPin);
            String encryptionPW = provideMockPassword();
            String token = g.provideObfuscatedEncodedIndexes(g.encoder, indexes, tempPin, encryptionPW);
            StringBuilder encodedPW = new StringBuilder();
            for (int index : indexes) {
                encodedPW.append(g.alphabet[index]);
            }
            int[] resultIndexes = g.provideClearDecodedIndexes(g.decoder, token, tempPin, encryptionPW);
            String decodedPW = g.generateByIndexes(resultIndexes, tempPin);
            assertEquals(encodedPW.toString(), decodedPW);
        }
    }

    @Test
    void provideTokenAndPwTest() {
        long pin = (long) (Long.MAX_VALUE * Math.random());
        String encryptionPw = provideMockPassword();
        Map<String, String> stringStringMap = g.provideTokenAndPw(78, pin, encryptionPw);
        assertTrue(stringStringMap.containsKey("token"));
        assertTrue(stringStringMap.containsKey("pw"));
        String token = stringStringMap.get("token");
        String pw = stringStringMap.get("pw");
        String decryptedPw = g.providePwFromToken(encryptionPw, pin, token, null);
        assertEquals(pw, decryptedPw);
    }

    private BufferedReader provideBufferedReaderMock() throws IOException {
        BufferedReader brMock = Mockito.mock(BufferedReader.class);
        Mockito.when(brMock.readLine()).thenReturn(Integer.toString(PERMUTATION_SEED), Integer.toString(MIN_PW_LENGTH), Integer.toString(MAX_PW_LENGTH), Integer.toString(NO_PWS));
        return brMock;
    }

    private BufferedReader provideBufferedReaderTokenMock() throws IOException {
        BufferedReader brMock = Mockito.mock(BufferedReader.class);
        String mockToken = "SkZlAQLxqELWuJxMrojtHYagiomXsKsKMVZRtYscjtCdaRWt0zvZPZa8yIN3KEZhQblVdyHzJYHhlr9hRtAYMSpBG48n6v809dLdTq75Vxo3sWQqqIHUIllkdbyK6z5t6VSUM6LtBV1E3Wa2BAcMjHJnfTHPKoTskP6msxeWZvy2ZUKwV2zJEIfGvDPm32UQDZW6fqeW7miZQdwzVsosNVvMq0AsKhHAe1EQ8ti+thqK4MC1rr4ppJoIGVudcfAl4vsXD/X4rmvypQdw+nXYqi2MnsGN+CL79vo5qzFgbDX72r9tHolGlWRgr6l3KcdAn8ivkQDRN1NQsOSvQmQDvYaaUWoegNMpE95GMZ691alMJhmC1AQb6P8zbYyn0b/LNMgMzslakyl/nJNimzvuofvgkc3jEWQTnQnBNLdtU5Ctzxt1k89qSryloi6T00gxerULdDO37sh8dcDoQgN5ITFD2cDLuzd6zyw4yGWcuzphX/drrxa95y2QIAzibJTIKMiBo77a9FvYXfuFzvXmMdluDYmJAEi6f9W3uYmtRmOFEUVEcqOg+3JilmDSoDFnW1RCoaUcYTLFMM2U2PPuifRCx2462UN9W9g11jnOPNrCJSVdRdQ1QD6kehJOMCm4IPx7wE0Yxl3/Niy4G/UcEwiv1SaJOMYckeHNaUfjOA33YijxXqO4Kw0rbi0p9HdOCu6a21EJ7fShWHlnFIo6NKI7CRyFm+XToOBZ9XyU9kMVW9e8q/Rft49dIJUu2yxsA1LnaFQolp0Pav+vttJjCRzlKXeUn0aCh97HC+Y0/oFcUKc/F9uqws7RijGK5XDOSJqKvzgbZGXKygzCwQGbKFTbjnc=";
        Mockito.when(brMock.readLine()).thenReturn(mockToken, Integer.toString(PERMUTATION_SEED), Integer.toString(MIN_PW_LENGTH), Integer.toString(MAX_PW_LENGTH), Integer.toString(NO_PWS));
        return brMock;
    }

    private BufferedReader provideBufferedReaderNullTokenMock() throws IOException {
        BufferedReader brMock = Mockito.mock(BufferedReader.class);
        String mockToken = "SkZlAQLxqELWuJxMrojtHYagiomXsKsKMVZRtYscjtCdaRWt0zvZPZa8yIN3KEZhQblVdyHzJYHhlr9hRtAYMSpBG48n6v809dLdTq75Vxo3sWQqqIHUIllkdbyK6z5t6VSUM6LtBV1E3Wa2BAcMjHJnfTHPKoTskP6msxeWZvy2ZUKwV2zJEIfGvDPm32UQDZW6fqeW7miZQdwzVsosNVvMq0AsKhHAe1EQ8ti+thqK4MC1rr4ppJoIGVudcfAl4vsXD/X4rmvypQdw+nXYqi2MnsGN+CL79vo5qzFgbDX72r9tHolGlWRgr6l3KcdAn8ivkQDRN1NQsOSvQmQDvYaaUWoegNMpE95GMZ691alMJhmC1AQb6P8zbYyn0b/LNMgMzslakyl/nJNimzvuofvgkc3jEWQTnQnBNLdtU5Ctzxt1k89qSryloi6T00gxerULdDO37sh8dcDoQgN5ITFD2cDLuzd6zyw4yGWcuzphX/drrxa95y2QIAzibJTIKMiBo77a9FvYXfuFzvXmMdluDYmJAEi6f9W3uYmtRmOFEUVEcqOg+3JilmDSoDFnW1RCoaUcYTLFMM2U2PPuifRCx2462UN9W9g11jnOPNrCJSVdRdQ1QD6kehJOMCm4IPx7wE0Yxl3/Niy4G/UcEwiv1SaJOMYckeHNaUfjOA33YijxXqO4Kw0rbi0p9HdOCu6a21EJ7fShWHlnFIo6NKI7CRyFm+XToOBZ9XyU9kMVW9e8q/Rft49dIJUu2yxsA1LnaFQolp0Pav+vttJjCRzlKXeUn0aCh97HC+Y0/oFcUKc/F9uqws7RijGK5XDOSJqKvzgbZGXKygzCwQGbKFTbjnc=";
        Mockito.when(brMock.readLine()).thenReturn(mockToken, Integer.toString(PERMUTATION_SEED), Integer.toString(PERMUTATION_SEED), Integer.toString(MIN_PW_LENGTH), Integer.toString(MAX_PW_LENGTH), Integer.toString(NO_PWS));
        return brMock;
    }

    private BufferedReader provideBufferedReaderExceptionMock() throws IOException {
        BufferedReader brMock = Mockito.mock(BufferedReader.class);
        Mockito.when(brMock.readLine()).thenThrow(IOException.class);
        return brMock;
    }

    private BufferedReader provideBufferedReaderLongMock() throws IOException {
        BufferedReader brMock = Mockito.mock(BufferedReader.class);
        Mockito.when(brMock.readLine()).thenReturn("10", "15", "20", "25", "30", "35", "40", "45", "50", "55", "60");
        return brMock;
    }

    private ConsoleReader provideConsoleReaderMock() {
        ConsoleReader consoleReaderMock = Mockito.mock(ConsoleReader.class);
        Mockito.when(consoleReaderMock.readPassword()).thenReturn(Integer.toString(PERMUTATION_SEED).toCharArray(), Integer.toString(PIN).toCharArray());
        Mockito.when(consoleReaderMock.readPassword(Mockito.anyString())).thenReturn(Integer.toString(PERMUTATION_SEED).toCharArray(), Integer.toString(PIN).toCharArray());
        return consoleReaderMock;
    }

    private ConsoleReader provideConsoleReaderNullMock() {
        ConsoleReader consoleReaderMock = Mockito.mock(ConsoleReader.class);
        Mockito.when(consoleReaderMock.readPassword()).thenReturn(Integer.toString(PERMUTATION_SEED).toCharArray(), Integer.toString(PIN).toCharArray());
        Mockito.when(consoleReaderMock.readPassword(Mockito.anyString())).thenReturn(null);
        return consoleReaderMock;
    }

    private String provideMockPassword() {
        return RandomStringUtils.randomAlphanumeric((int) (Math.random() * 100));
    }

}
