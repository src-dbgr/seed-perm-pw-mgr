package com.sam.key.manager;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.concurrent.ThreadLocalRandom;

public class Generator {
	// Custom ANSI color declaration
	public static final String ANSI_YELLOW = "\u001B[33m";
	public static final String ANSI_BLACK = "\u001B[30m";
	public static final String ANSI_BLACK_BACKGROUND = "\u001B[40m";
	// Declaring ANSI_RESET so that we can reset the color
	public static final String ANSI_RESET = "\u001B[0m";

	public static final int MIN_PADDING_LENGTH = 5;
	public static final int MAX_PADDING_LENGTH = 20;

	// Determines Max PW length and determines combinatorial search space for
	// random index assignment for PW length
	// MAX PW LENGTH = ALPHABET_SIZE - MIN_OBFUSCATION_OFFSET
	// Should not be smaller than 20 to keep combinatorial search space large enough
	public static final int OBFUSCATION_OFFSET = 20;

	static Decoder decoder = Base64.getDecoder();
	static Encoder encoder = Base64.getEncoder();

	static char[] alphabet;

	static char[] referenceAlphabet = { 'i', 'g', 'r', '.', 'u', '$', '&', 'G', '+', 'W', '9', 'C', 'Q', ':', 'w', 'o',
			'j', 'L', 'y', 'A', 'O', 'v', 'U', 'Y', 'S', 'z', 'E', 'f', '*', '2', '=', '4', '%', 'B', 'K', 'T', 'm',
			'@', '!', 'h', 'V', '/', '1', 'l', 'X', '(', '_', 'J', ')', '5', 'a', 'q', 'k', '[', '?', '=', '-', 'n',
			'P', 's', '3', 'Z', 'N', 'M', '#', 'R', 'p', ']', '0', '7', 'D', 'x', '8', 't', '6', 'e', 'H', ';', 'I',
			'F', 'd', 'b', 'c' };

	public static void main(String[] args) {
		printCLICommands();
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		int option = -1;
		try {
			option = Integer.parseInt(br.readLine());
		} catch (Exception e) {
			System.out.println("Issue occured, please choose one of the available options.");
			e.printStackTrace();
			System.exit(-1);
		}
		ConsoleReader cr = new ConsoleReader();
		switch (option) {
		case 0:
			interactiveIndexesGenerationBlacked(br, cr);
			break;
		case 1:
			interactiveIndexesGenerationVisible(br, cr);
			break;
		case 2:
			interactivePWGenerationBlacked(br, cr);
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
			System.out.println("This option is not available. Choose a listed option.");
			break;
		}
	}

	static void printCLICommands() {
		System.out.println("Choose what you want to do:");
		System.out.println("0 - Create Passwords - Show only Token (Blacked)");
		System.out.println("1 - Create Passwords - Show only Token (Visible)");
		System.out.println("2 - Create Passwords - Show PWs and Token (Blacked)");
		System.out.println("3 - Create Passwords - Show PWs and Token (Visible)");
		System.out.println("4 - Retrieve Password (Blacked)");
		System.out.println("5 - Retrieve Password (Visible)");
	}

	static void alphabetSeedRequest(ConsoleReader cr, BufferedReader br) {
		char[] seedC = null;
		try {
			seedC = cr.readPassword("Enter Alphabet Permutation Seed: \n");
			long seed = Long.parseLong(new String(seedC));
			referenceAlphabet = randomizeAlphabet(seed, referenceAlphabet);
		} catch (Exception e) {
			if (e instanceof NullPointerException && seedC == null) {
				System.out.println("Masking input not supported.. Continue with default Invocation");
				alphabetSeedRequestOnNull(br);
			} else {
				e.printStackTrace();
			}
		}
	}

	static byte[] longToBytes(long x) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(x);
		return buffer.array();
	}

	static void alphabetSeedRequestOnNull(BufferedReader br) {
		try {
			System.out.println("Enter Alphabet Permutation Seed: ");
			String seedS = br.readLine();
			long seed = Long.parseLong(seedS);
			referenceAlphabet = randomizeAlphabet(seed, referenceAlphabet);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}

	static void interactivePWRetrieve(boolean blacked, ConsoleReader cr, BufferedReader br) {
		alphabetSeedRequest(cr, br);
		char[] readPin = null;
		int[] indexes = null;
		String token = null;
		try {
			System.out.print("Enter Token:\n");
			token = br.readLine();
			readPin = cr.readPassword("Enter Pin:\n");
			long pin = Long.parseLong(new String(readPin));
			indexes = provideClearDecodedIndexes(decoder, token, pin);
			if (blacked) {
				printBlacked(generateByIndexes(indexes, pin, blacked));
			} else {
				printNormal(generateByIndexes(indexes, pin, blacked));
			}
		} catch (Exception e) {
			if (e instanceof NullPointerException && readPin == null) {
				System.out.println("Masking input not supported.. Continue with default Invocation");
				interactivePWRetrieveOnNull(br, blacked, token);
			} else {
				System.out.println("Error occured on retrieving PW, check Stack Trace for Details");
				e.printStackTrace();
				System.exit(-1);
			}
			return;
		}
	}

	static void interactivePWRetrieveOnNull(BufferedReader br, boolean blacked, String token) {
		try {
			System.out.println("Enter Pin:");
			String pin = br.readLine();
			long seed = Long.parseLong(pin);
			int[] indexes = provideClearDecodedIndexes(decoder, token, seed);
			if (blacked) {
				printBlacked(generateByIndexes(indexes, seed, blacked));
			} else {
				printNormal(generateByIndexes(indexes, seed, blacked));
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}

	static void interactiveIndexesGenerationBlacked(BufferedReader br, ConsoleReader cr) {
		interactiveGenerator(true, true, br, cr);
	}

	static void interactivePWGenerationBlacked(BufferedReader br, ConsoleReader cr) {
		interactiveGenerator(false, true, br, cr);
	}

	static void interactiveIndexesGenerationVisible(BufferedReader br, ConsoleReader cr) {
		interactiveGenerator(true, false, br, cr);
	}

	static void interactivePWGenerationVisible(BufferedReader br, ConsoleReader cr) {
		interactiveGenerator(false, false, br, cr);
	}

	static void interactiveGenerator(boolean anonymous, boolean blacked, BufferedReader br, ConsoleReader cr) {
		alphabetSeedRequest(cr, br);
		char[] readPin = null;
		int min = -1;
		int max = -1;
		int numPws = -1;
		try {
			System.out.print("Enter minimal PW character length:\n");
			min = Integer.parseInt(br.readLine());
			System.out.print("Enter max PW character length:\n");
			max = Integer.parseInt(br.readLine());
			System.out.print("Enter number of Passwords to be created:\n");
			numPws = Integer.parseInt(br.readLine());
			readPin = cr.readPassword("Enter Pin:\n");
			long pin = Long.parseLong(new String(readPin));
			printMultipleRandomPWs(min, max, numPws, pin, anonymous, blacked);
		} catch (Exception e) {
			if (e instanceof NullPointerException && readPin == null) {
				System.out.println("Masking input not supported.. Continue with default Invocation");
				interactiveGeneratorOnNull(br, min, max, numPws, anonymous, blacked);
			} else {
				System.out.println("Error occured on interactive PW generation, check Stack Trace for Details");
				e.printStackTrace();
				System.exit(-1);
			}
			return;
		}
	}

	static void interactiveGeneratorOnNull(BufferedReader br, int min, int max, int numPws, boolean anonymous,
			boolean blacked) {
		try {
			System.out.println("Enter Pin");
			String pin = br.readLine();
			long seed = Long.parseLong(pin);
			printMultipleRandomPWs(min, max, numPws, seed, anonymous, blacked);
		} catch (IOException e1) {
			e1.printStackTrace();
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
		Collections.shuffle(tempList, new Random(seed));
		String str = tempList.toString().replaceAll(",", "");
		arr = str.substring(1, str.length() - 1).replaceAll(" ", "").toCharArray();
		return arr;
	}

	static int generateRandomNumber(int min, int max) {
		return ThreadLocalRandom.current().nextInt(min, max);
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

	static String generatePw(int length, long pin, boolean blacked, boolean anonymous) {
		alphabet = randomizeAlphabet(pin, referenceAlphabet);
		String pw = "";
		int[] indexes = generateIndexes(length, pin);
		System.out.println("Token:");
		String encodedIndexes = provideObfuscatedEncodedIndexes(encoder, indexes, pin);
		if (blacked) {
			printBlacked(encodedIndexes);
		} else {
			printNormal(encodedIndexes);
		}
		for (int i = 0; i < indexes.length; i++) {
			pw += alphabet[indexes[i]];
		}
		if (!anonymous) {
			System.out.print("PW: ");
		}
		pw += padWithEmtpyString();
		return pw;
	}

	static String padWithEmtpyString() {
		int length = generateRandomNumber(MIN_PADDING_LENGTH, MAX_PADDING_LENGTH);
		return String.format("%1$" + length + "s", "");
	}

	// pass your indexes to retrieve your pwd.
	static String generateByIndexes(int[] indexes, long pin, boolean blacked) {
		alphabet = randomizeAlphabet(pin, referenceAlphabet);
		String pw = "";
		for (int i = 0; i < indexes.length; i++) {
			pw += alphabet[indexes[i]];
		}
		System.out.print("PW: ");
		return pw;
	}

	static void printIntArrayToString(int[] arr, boolean blacked) {
		String indexes = "{";
		for (int i = 0; i < arr.length; i++) {
			indexes += Integer.toString(arr[i]);
			indexes += (i == arr.length - 1) ? "}" : ",";
		}
		System.out.print("INDEXES: ");
		if (blacked) {
			printBlacked(indexes);
		} else {
			printNormal(indexes);
		}
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
			boolean blacked) {
		for (int i = 0; i < numOfPWs; i++) {
			int rand = generateRandomNumber(rangeMin, rangeMax);
			System.out.println();
			if (anonymous) {
				generatePw(rand, pin, blacked, anonymous);
			} else if (blacked) {
				printBlacked(generatePw(rand, pin, blacked, anonymous));
			} else {
				printNormal(generatePw(rand, pin, blacked, anonymous));
			}
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

	static void printBlacked(String message) {
		message = padWithEmtpyString() + message + padWithEmtpyString();
		System.out.println(ANSI_BLACK_BACKGROUND + ANSI_BLACK + message + ANSI_RESET);
	}

	static void printNormal(String message) {
		System.out.println(message);
	}

	// applies surjection with sumDigits
	static int provideShiftValue(long pin, int alphabetLength) {
		Random r = new Random(pin);
		int cycles = sumDigits(pin);
		long maskNumber = -1;
		for (int i = 0; i < cycles; i++) {
			maskNumber = Math.abs(r.nextLong());
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

	static int[] obfuscateIndexes(int[] indexes, int alphabetLength, long pin) {
		int[] obfuscatedIndexes = new int[alphabetLength];
		int shiftValue = provideShiftValue(pin, alphabetLength);
		int arrayLenghtShifted = shiftValue(indexes.length, shiftValue, alphabetLength);
		int min = indexes.length + 1;
		if ((alphabetLength - min) <= OBFUSCATION_OFFSET) {
			throw new Error("Password too long, lower password max-length to max: "
					+ (alphabetLength - (OBFUSCATION_OFFSET + 1)));
		}
		int indexArrayLengthShifted = generateRandomNumber(min, alphabetLength);
		obfuscatedIndexes[0] = shiftValue(indexArrayLengthShifted, shiftValue, alphabetLength);
		for (int i = 0; i < indexes.length; i++) {
			obfuscatedIndexes[i + 1] = shiftValue(indexes[i], shiftValue, alphabetLength);
		}
		for (int i = (indexes.length + 1); i < alphabetLength; i++) {
			if (i == indexArrayLengthShifted) {
				obfuscatedIndexes[i] = arrayLenghtShifted;
				continue;
			}
			obfuscatedIndexes[i] = (int) (Math.floor(Math.random() * (alphabetLength + 1)));
		}
		return obfuscatedIndexes;
	}

	static int[] clearObfuscatedIndexes(int[] obfuscatedIndexes, int alphabetLength, long pin) {
		int shiftValue = provideShiftValue(pin, alphabetLength);
		int lengthIndex = unShiftValue(obfuscatedIndexes[0], shiftValue, alphabetLength);
		int length = unShiftValue(obfuscatedIndexes[lengthIndex], shiftValue, alphabetLength);
		int[] clearIndexes = new int[length];
		for (int i = 0; i < clearIndexes.length; i++) {
			clearIndexes[i] = unShiftValue(obfuscatedIndexes[i + 1], shiftValue, alphabetLength);
		}
		return clearIndexes;
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

}
