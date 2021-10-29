package com.sam.key.manager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

public class GeneratorTest {

	static final int PERMUTATION_SEED = 1;
	static final int PIN = 12345;
	static final int NO_PWS = 10;
	static final int MIN_PW_LENGTH = 20;
	static final int MAX_PW_LENGTH = 30;

	@Test
	public void parseStringToIntArrTest() {
		String indices = "{21,79,57,0,6,5,39,32,29,69,29,65,72,39,28,44,0,71,10,14,21,53,16,7,3,28}";
		int[] parseStringToIntArr = Generator.parseStringToIntArr(indices);
		assertEquals(26, parseStringToIntArr.length);

		indices = "{21,79,57,0,6}";
		parseStringToIntArr = Generator.parseStringToIntArr(indices);
		assertEquals(5, parseStringToIntArr.length);
		assertEquals(57, parseStringToIntArr[2]);

		indices = "21,79, 57,2,6";
		parseStringToIntArr = Generator.parseStringToIntArr(indices);
		assertEquals(5, parseStringToIntArr.length);
		assertEquals(2, parseStringToIntArr[3]);
		assertEquals(6, parseStringToIntArr[4]);
	}

	@Test
	public void parseStringToIntArrExceptionTest() {
		String indices = "{21,79,57, abc,0,6}";
		Exception exception = assertThrows(NumberFormatException.class, () -> {
			Generator.parseStringToIntArr(indices);
		});

		String expectedMessage = "For input string: \"abc\"";
		assertEquals(expectedMessage, exception.getMessage());
	}

	@Test
	public void randomizeAlphabetTest() {
		char[] testAlphabet = Generator.referenceAlphabet;
		assertNotEquals(Generator.alphabet, Generator.referenceAlphabet);
		char[] randomizedAlphabet = Generator.randomizeAlphabet(PERMUTATION_SEED, Generator.referenceAlphabet);
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

}
