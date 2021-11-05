package com.sam.key.manager;

import static com.sam.key.manager.Generator.MAX_PADDING_LENGTH;
import static com.sam.key.manager.Generator.MIN_PADDING_LENGTH;
import static com.sam.key.manager.Generator.alphabet;
import static com.sam.key.manager.Generator.alphabetSeedRequest;
import static com.sam.key.manager.Generator.alphabetSeedRequestOnNull;
import static com.sam.key.manager.Generator.generateByIndexes;
import static com.sam.key.manager.Generator.generateIndexes;
import static com.sam.key.manager.Generator.generatePw;
import static com.sam.key.manager.Generator.generateRandomNumber;
import static com.sam.key.manager.Generator.interactiveGenerator;
import static com.sam.key.manager.Generator.interactiveIndexesGenerationHidden;
import static com.sam.key.manager.Generator.interactiveIndexesGenerationVisible;
import static com.sam.key.manager.Generator.interactivePWGenerationHidden;
import static com.sam.key.manager.Generator.interactivePWGenerationVisible;
import static com.sam.key.manager.Generator.interactivePWRetrieve;
import static com.sam.key.manager.Generator.padWithEmtpyString;
import static com.sam.key.manager.Generator.parseStringToIntArr;
import static com.sam.key.manager.Generator.printCLICommands;
import static com.sam.key.manager.Generator.printCharArrayToString;
import static com.sam.key.manager.Generator.randomizeAlphabet;
import static com.sam.key.manager.Generator.referenceAlphabet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.sam.key.manager.Generator.ConsoleReader;

public class GeneratorTest {

	static final int PERMUTATION_SEED = 1;
	static final int PIN = 12345;
	static final int NO_PWS = 10;
	static final int MIN_PW_LENGTH = 20;
	static final int MAX_PW_LENGTH = 30;

	@Test
	public void parseStringToIntArrTest() {
		String indexes = "{21,79,57,0,6,5,39,32,29,69,29,65,72,39,28,44,0,71,10,14,21,53,16,7,3,28}";
		int[] parseStringToIntArr = parseStringToIntArr(indexes);
		assertEquals(26, parseStringToIntArr.length);

		indexes = "{21,79,57,0,6}";
		parseStringToIntArr = parseStringToIntArr(indexes);
		assertEquals(5, parseStringToIntArr.length);
		assertEquals(57, parseStringToIntArr[2]);

		indexes = "21,79, 57,2,6";
		parseStringToIntArr = parseStringToIntArr(indexes);
		assertEquals(5, parseStringToIntArr.length);
		assertEquals(2, parseStringToIntArr[3]);
		assertEquals(6, parseStringToIntArr[4]);
	}

	@Test
	public void parseStringToIntArrExceptionTest() {
		String indexes = "{21,79,57, abc,0,6}";
		Exception exception = assertThrows(NumberFormatException.class, () -> {
			parseStringToIntArr(indexes);
		});

		String expectedMessage = "For input string: \"abc\"";
		assertEquals(expectedMessage, exception.getMessage());
	}

	@Test
	public void randomizeAlphabetTest() {
		char[] testAlphabet = referenceAlphabet;
		assertNotEquals(alphabet, referenceAlphabet);
		char[] randomizedAlphabet = randomizeAlphabet(PERMUTATION_SEED, referenceAlphabet);
		assertNotNull(randomizedAlphabet);
		assertNotEquals(randomizedAlphabet, testAlphabet);
		List<Character> testList = new ArrayList<>();
		for (char c : testAlphabet) {
			testList.add(c);
		}
		Collections.shuffle(testList, new Random(PERMUTATION_SEED));
		String str = testList.toString().replaceAll(",", "");
		testAlphabet = str.substring(1, str.length() - 1).replaceAll(" ", "").toCharArray();
		assertEquals(testAlphabet.length, randomizedAlphabet.length);
		for (int i = 0; i < randomizedAlphabet.length; i++) {
			assertEquals(testAlphabet[i], randomizedAlphabet[i]);
		}
	}

	@Test
	public void generateRandomNumberTest() {
		for (int i = 0; i < 100; i++) {
			int rand = generateRandomNumber(i, (i + 1) * 10);
			assertTrue(rand <= ((i + 1) * 10) && rand >= i);
		}
		int rand = (int) (Math.random() * 1000);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> {
			generateRandomNumber(rand, rand);
		});
		String expectedMessage = "bound must be positive";
		assertEquals(expectedMessage, exception.getMessage());

	}

	@Test
	public void generateIndexesTest() {
		int length = (int) (Math.random() * 100);
		long pin = (long) (Math.random() * 1_000_000);
		int[] generateIndexes = generateIndexes(length, pin);
		assertTrue(generateIndexes.length == length);
		randomizeAlphabet(pin, referenceAlphabet);
		generateIndexes = generateIndexes(length, pin);
		assertTrue(generateIndexes.length == length);
	}

	@Test
	public void generatePwTest() {
		int length = (int) (Math.random() * 60);
		long pin = (long) (Math.random() * 1_000_000);
		String generatedPw = generatePw(length, pin, true, false);
		assertFalse(generatedPw.length() == length);
		assertTrue(generatedPw.length() >= length + MIN_PADDING_LENGTH);
		assertTrue(generatedPw.length() <= length + MAX_PADDING_LENGTH);
		char[] generatedPwCharArray = generatedPw.toCharArray();
		// check that only reference alphabet chars are considered
		pwContainsCheck(generatedPwCharArray);

		generatedPw = generatePw(length, pin, false, false);
		assertFalse(generatedPw.length() == length);
		assertTrue(generatedPw.length() >= length + MIN_PADDING_LENGTH);
		assertTrue(generatedPw.length() <= length + MAX_PADDING_LENGTH);
		char[] generatedPwCharArray2 = generatedPw.toCharArray();
		pwContainsCheck(generatedPwCharArray2);
	}

	private void pwContainsCheck(char[] generatedPw) {
		boolean contained = false;
		for (int i = 0; i < generatedPw.length; i++) {
			if (generatedPw[i] == ' ') {
				continue;
			}
			contained = false;
			for (int j = 0; j < referenceAlphabet.length; j++) {
				contained = generatedPw[i] == referenceAlphabet[j];
				if (contained) {
					break;
				}
			}
			assertTrue(contained);
		}
	}

	@Test
	public void padWithEmptyStringTest() {
		String emptyString = padWithEmtpyString();
		assertTrue(emptyString.length() >= MIN_PADDING_LENGTH);
		assertTrue(emptyString.length() <= MAX_PADDING_LENGTH);
	}

	@Test
	public void generateByIndexesTest() {
		int[] indexes = { 47, 41, 12, 1, 28, 57, 7, 44, 67, 43, 46, 73, 67, 51, 82, 10, 43, 53, 42, 53, 20, 73, 65, 48,
				35, 65, 9, 14, 61, 38, 43, 57, 56, 30, 80, 76, 22, 56, 18, 11, 35, 16, 14, 9, 37, 16, 49, 51, 43, 30,
				80, 77, 61, 40, 79, 30, 6, 37, 22, 10, 30, 3, 41, 21, 15, 69, 57, 51, 32, 45, 36, 75, 54, 68, 45, 53, 9,
				59, 56, 16, 47, 3 };
		String expectedPw = "CUl=V#a5-%xo-LwQ%8_8so49n4/DNr%#XbSqeX.0nPD/=PzL%bSjN(*bE=eQbTU]?;#L12+KR$28/MXPCT";
		String generatePwByIndexes = generateByIndexes(indexes, PIN, true);
		assertEquals(expectedPw, generatePwByIndexes);

		generatePwByIndexes = generateByIndexes(indexes, PIN, false);
		assertEquals(expectedPw, generatePwByIndexes);

		int[] indexes2 = { 4, 10, 50, 22, 5, 45, 19, 81, 73, 35, 23, 62, 2, 53, 0, 39, 11, 2, 75, 13, 73, 36, 72, 35,
				70, 49, 6, 29, 52, 42, 24, 62, 57, 71, 0, 73, 26, 77, 17, 42, 29, 22, 5, 0, 70, 32, 38, 17, 15, 45, 59,
				67, 20, 49, 82, 79, 82, 31, 30, 77, 28, 37, 49, 60, 73, 1, 16, 27, 73, 73, 61, 21, 74, 19, 35, 40, 13,
				33, 78, 6, 42, 81 };

		expectedPw = "hQdeu2IkonWJ38m!03Kvo+fnBzEF:_[J#&moYj@_FeumB1r@?2M-szw*wpbjV=zco=PAooN]gIn(viyE_k";
		generatePwByIndexes = generateByIndexes(indexes2, PIN, true);
		assertEquals(expectedPw, generatePwByIndexes);
	}

	@Test
	public void interactiveIndexesGenerationHiddenTest() throws IOException {
		char[] initialAlphabetState = referenceAlphabet;
		assertEquals(initialAlphabetState, referenceAlphabet);
		BufferedReader br = provideBufferedReaderMock();
		ConsoleReader cr = provideConsoleReaderMock();
		interactiveIndexesGenerationHidden(br, cr);
		assertNotEquals(initialAlphabetState, referenceAlphabet);
	}

	@Test
	public void interactivePWGenerationHiddenTest() throws IOException {
		char[] initialAlphabetState = referenceAlphabet;
		assertEquals(initialAlphabetState, referenceAlphabet);
		BufferedReader br = provideBufferedReaderMock();
		ConsoleReader cr = provideConsoleReaderMock();
		interactivePWGenerationHidden(br, cr);
		assertNotEquals(initialAlphabetState, referenceAlphabet);
	}

	@Test
	public void interactivePWGenerationVisibleTest() throws IOException {
		char[] initialAlphabetState = referenceAlphabet;
		assertEquals(initialAlphabetState, referenceAlphabet);
		BufferedReader br = provideBufferedReaderMock();
		ConsoleReader cr = provideConsoleReaderMock();
		interactivePWGenerationVisible(br, cr);
		assertNotEquals(initialAlphabetState, referenceAlphabet);
	}

	@Test
	public void alphabetSeedRequestExceptionTest() throws IOException {
		char[] initialAlphabetState = referenceAlphabet;
		assertEquals(initialAlphabetState, referenceAlphabet);
		BufferedReader br = provideBufferedReaderMock();
		ConsoleReader cr = provideConsoleReaderExceptionMock();
		alphabetSeedRequest(cr, br);
		assertNotEquals(initialAlphabetState, referenceAlphabet);
	}

	@Test
	public void alphabetSeedRequestNullTest() throws IOException {
		char[] initialAlphabetState = referenceAlphabet;
		assertEquals(initialAlphabetState, referenceAlphabet);
		BufferedReader br = provideBufferedReaderMock();
		ConsoleReader cr = provideConsoleReaderNullMock();
		alphabetSeedRequest(cr, br);
		assertNotEquals(initialAlphabetState, referenceAlphabet);
	}

	@Test
	public void alphabetSeedRequestOnNullExceptionTest() throws IOException {
		char[] initialAlphabetState = referenceAlphabet;
		assertEquals(initialAlphabetState, referenceAlphabet);
		BufferedReader br = provideBufferedReaderExceptionMock();
		alphabetSeedRequestOnNull(br);
		assertEquals(initialAlphabetState, referenceAlphabet);
	}

	@Test
	public void interactiveGeneratorNullTest() throws IOException {
		char[] initialAlphabetState = referenceAlphabet;
		assertEquals(initialAlphabetState, referenceAlphabet);
		BufferedReader br = provideBufferedReaderLongMock();
		ConsoleReader cr = provideConsoleReaderNullMock();
		interactiveGenerator(false, false, br, cr);
		assertNotEquals(initialAlphabetState, referenceAlphabet);
	}

	@Test
	public void interactiveIndexesGenerationVisibleTest() throws IOException {
		char[] initialAlphabetState = referenceAlphabet;
		assertEquals(initialAlphabetState, referenceAlphabet);
		printCLICommands();
		BufferedReader br = provideBufferedReaderMock();
		ConsoleReader cr = provideConsoleReaderMock();
		interactiveIndexesGenerationVisible(br, cr);
		assertNotEquals(initialAlphabetState, referenceAlphabet);
	}

	@Test
	public void interactivePWRetrieveBlackedTest() throws IOException {
		char[] referenceAlphabetBackup = referenceAlphabet;

		char[] initialAlphabetState = referenceAlphabet;
		assertEquals(initialAlphabetState, referenceAlphabet);
		BufferedReader br = provideBufferedReaderTokenMock();
		ConsoleReader cr = provideConsoleReaderMock();
		interactivePWRetrieve(true, cr, br);
		assertNotEquals(initialAlphabetState, referenceAlphabet);

		referenceAlphabet = referenceAlphabetBackup;
	}

	@Test
	public void interactivePWRetrieveVisibleTest() throws IOException {
		char[] referenceAlphabetBackup = referenceAlphabet;

		char[] initialAlphabetState = referenceAlphabet;
		assertEquals(initialAlphabetState, referenceAlphabet);
		BufferedReader br = provideBufferedReaderTokenMock();
		ConsoleReader cr = provideConsoleReaderMock();
		interactivePWRetrieve(false, cr, br);
		assertNotEquals(initialAlphabetState, referenceAlphabet);

		referenceAlphabet = referenceAlphabetBackup;
	}

	@Test
	public void interactivePWRetrieveExceptionTest() throws Exception {
		char[] referenceAlphabetBackup = referenceAlphabet;

		char[] initialAlphabetState = referenceAlphabet;
		assertEquals(initialAlphabetState, referenceAlphabet);
		BufferedReader br = provideBufferedReaderNullTokenMock();
		ConsoleReader cr = provideConsoleReaderNullMock();
		interactivePWRetrieve(false, cr, br);
		assertNotEquals(initialAlphabetState, referenceAlphabet);
		referenceAlphabet = referenceAlphabetBackup;
	}

	@Test
	public void printCharArrayNullTest() throws Exception {
		Exception exception = assertThrows(Exception.class, () -> {
			printCharArrayToString(null);
		});
		String expectedMessage = "Passed Array is null.";
		assertEquals(expectedMessage, exception.getMessage());
		printCharArrayToString(
				"{48,13,73,7,64,78,11,77,27,54,38,56,71,72,43,67,28,30,67,19,46,28,5,37,2,65,79,43,32,12,17,4}"
						.toCharArray());
	}

	@Test
	public void testPwGenerationAndRetieval() throws NoSuchAlgorithmException {
		for (int j = 0; j < 100; j++) {
			long tempPin = SecureRandom.getInstanceStrong().nextLong();
			int tempPWLength = (int) Math.ceil((referenceAlphabet.length - 22) * Math.random());
			alphabet = randomizeAlphabet(tempPin, referenceAlphabet);
			int[] indexes = generateIndexes(tempPWLength, tempPin);
			String token = Generator.provideObfuscatedEncodedIndexes(Generator.encoder, indexes, tempPin);
			String encodedPW = "";
			for (int i = 0; i < indexes.length; i++) {
				encodedPW += alphabet[indexes[i]];
			}
			int[] resultIndexes = Generator.provideClearDecodedIndexes(Generator.decoder, token, tempPin);
			String decodedPW = Generator.generateByIndexes(resultIndexes, tempPin, false);
			assertEquals(encodedPW, decodedPW);
		}

	}

	private BufferedReader provideBufferedReaderMock() throws IOException {
		BufferedReader brMock = Mockito.mock(BufferedReader.class);
		Mockito.when(brMock.readLine()).thenReturn(Integer.toString(PERMUTATION_SEED), Integer.toString(MIN_PW_LENGTH),
				Integer.toString(MAX_PW_LENGTH), Integer.toString(NO_PWS));
		return brMock;
	}

	private BufferedReader provideBufferedReaderTokenMock() throws IOException {
		BufferedReader brMock = Mockito.mock(BufferedReader.class);
		String mockToken = "WzIyLCAzNiwgNTEsIDMxLCA2LCA0OSwgNzUsIDQ5LCA4MCwgNzQsIDAsIDIyLCA0NiwgNzEsIDczLCA3MCwgMTYsIDExLCA4MiwgNjEsIDI5LCAzNywgMjAsIDMzLCA0MSwgNzcsIDU0LCAyMiwgMzEsIDM4LCAyOSwgNzAsIDQzLCA2OSwgNzcsIDcyLCA0LCA2MSwgNzUsIDc3LCA0OCwgNzksIDAsIDM4LCA0OSwgNTIsIDU4LCAzNiwgMjIsIDgyLCA2MiwgNTQsIDc1LCAxOCwgODIsIDQxLCA3NSwgMjgsIDQzLCAyOSwgMTksIDUzLCAzMiwgNzQsIDEyLCA1OCwgNDksIDM4LCAyNCwgNDYsIDM5LCAyNSwgNDcsIDcxLCAxNCwgMzMsIDc2LCA0OSwgMzEsIDIyLCA3NiwgNTQsIDI1XQ==";
		Mockito.when(brMock.readLine()).thenReturn(mockToken, Integer.toString(PERMUTATION_SEED),
				Integer.toString(MIN_PW_LENGTH), Integer.toString(MAX_PW_LENGTH), Integer.toString(NO_PWS));
		return brMock;
	}

	private BufferedReader provideBufferedReaderNullTokenMock() throws IOException {
		BufferedReader brMock = Mockito.mock(BufferedReader.class);
		String mockToken = "WzIyLCAzNiwgNTEsIDMxLCA2LCA0OSwgNzUsIDQ5LCA4MCwgNzQsIDAsIDIyLCA0NiwgNzEsIDczLCA3MCwgMTYsIDExLCA4MiwgNjEsIDI5LCAzNywgMjAsIDMzLCA0MSwgNzcsIDU0LCAyMiwgMzEsIDM4LCAyOSwgNzAsIDQzLCA2OSwgNzcsIDcyLCA0LCA2MSwgNzUsIDc3LCA0OCwgNzksIDAsIDM4LCA0OSwgNTIsIDU4LCAzNiwgMjIsIDgyLCA2MiwgNTQsIDc1LCAxOCwgODIsIDQxLCA3NSwgMjgsIDQzLCAyOSwgMTksIDUzLCAzMiwgNzQsIDEyLCA1OCwgNDksIDM4LCAyNCwgNDYsIDM5LCAyNSwgNDcsIDcxLCAxNCwgMzMsIDc2LCA0OSwgMzEsIDIyLCA3NiwgNTQsIDI1XQ==";
		Mockito.when(brMock.readLine()).thenReturn(mockToken, Integer.toString(PERMUTATION_SEED),
				Integer.toString(PERMUTATION_SEED), Integer.toString(MIN_PW_LENGTH), Integer.toString(MAX_PW_LENGTH),
				Integer.toString(NO_PWS));
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

	private ConsoleReader provideConsoleReaderMock() throws IOException {
		ConsoleReader consoleReaderMock = Mockito.mock(ConsoleReader.class);
		Mockito.when(consoleReaderMock.readPassword()).thenReturn(Integer.toString(PERMUTATION_SEED).toCharArray(),
				Integer.toString(PIN).toCharArray());
		Mockito.when(consoleReaderMock.readPassword(Mockito.anyString()))
				.thenReturn(Integer.toString(PERMUTATION_SEED).toCharArray(), Integer.toString(PIN).toCharArray());
		return consoleReaderMock;
	}

	private ConsoleReader provideConsoleReaderNullMock() throws IOException {
		ConsoleReader consoleReaderMock = Mockito.mock(ConsoleReader.class);
		Mockito.when(consoleReaderMock.readPassword()).thenReturn(Integer.toString(PERMUTATION_SEED).toCharArray(),
				Integer.toString(PIN).toCharArray());
		Mockito.when(consoleReaderMock.readPassword(Mockito.anyString())).thenReturn(null);
		return consoleReaderMock;
	}

	private ConsoleReader provideConsoleReaderExceptionMock() throws IOException {
		ConsoleReader consoleReaderMock = Mockito.mock(ConsoleReader.class);
		Mockito.when(consoleReaderMock.readPassword()).thenReturn(Integer.toString(PERMUTATION_SEED).toCharArray(),
				Integer.toString(PIN).toCharArray());
		Mockito.when(consoleReaderMock.readPassword(Mockito.anyString())).thenThrow(NullPointerException.class);
		return consoleReaderMock;
	}

}
