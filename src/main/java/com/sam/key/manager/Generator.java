package com.sam.key.manager;

import static org.fusesource.jansi.Ansi.ansi;
import static org.fusesource.jansi.Ansi.Color.BLACK;
import static org.fusesource.jansi.Ansi.Color.GREEN;
import static org.fusesource.jansi.Ansi.Color.MAGENTA;
import static org.fusesource.jansi.Ansi.Color.RED;
import static org.fusesource.jansi.Ansi.Color.WHITE;
import static org.fusesource.jansi.Ansi.Color.YELLOW;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import org.fusesource.jansi.AnsiConsole;

public class Generator {
	// Custom ANSI color declaration
	public static final String ANSI_YELLOW = "\u001B[33m";
	public static final String ANSI_BLACK = "\u001B[30m";
	public static final String ANSI_BLACK_BACKGROUND = "\u001B[40m";
	// Declaring ANSI_RESET so that we can reset the color
	public static final String ANSI_RESET = "\u001B[0m";

	public static final int MIN_PADDING_LENGTH = 5;
	public static final int MAX_PADDING_LENGTH = 20;
	public static final int RESERVED_ARRAY_INDEXES = 2;

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

	static String pwMgr = "\n"
			+ "                                                                                        \n"
			+ " _____ _____ _____ ____     _____ _____ _____ _____    _____ _ _ _    _____ _____ _____ \n"
			+ "|   __|   __|   __|    \\   |  _  |   __| __  |     |  |  _  | | | |  |     |   __| __  |\n"
			+ "|__   |   __|   __|  |  |  |   __|   __|    -| | | |  |   __| | | |  | | | |  |  |    -|\n"
			+ "|_____|_____|_____|____/   |__|  |_____|__|__|_|_|_|  |__|  |_____|  |_|_|_|_____|__|__|\n"
			+ "                                                                                        \n" + "";

	public static void main(String[] args) {
		AnsiConsole.systemInstall();
		System.out.println(ansi().eraseScreen().bg(GREEN).fg(WHITE).a(pwMgr).reset());
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

	static void alphabetSeedRequest(ConsoleReader cr, BufferedReader br) {
		char[] seedC = null;
		try {
			System.out.println(ansi().fg(GREEN).a("Enter Seed:").reset());
			seedC = cr.readPassword();
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
			System.out.println(ansi().fg(GREEN).a("Enter Seed: ").reset());
			String seedS = br.readLine();
			long seed = Long.parseLong(seedS);
			referenceAlphabet = randomizeAlphabet(seed, referenceAlphabet);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}

	static void interactivePWRetrieve(boolean hidden, ConsoleReader cr, BufferedReader br) {
		alphabetSeedRequest(cr, br);
		char[] readPin = null;
		int[] indexes = null;
		String token = null;
		try {
			System.out.println(ansi().fg(GREEN).a("Enter Token:").reset());
			token = br.readLine();
			System.out.println(ansi().fg(GREEN).a("Enter Pin:").reset());
			readPin = cr.readPassword();
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
				System.out.println("Error occured on retrieving PW, check Stack Trace for Details");
				e.printStackTrace();
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
		} catch (IOException e1) {
			e1.printStackTrace();
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
		alphabetSeedRequest(cr, br);
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
			long pin = Long.parseLong(new String(readPin));
			printMultipleRandomPWs(min, max, numPws, pin, anonymous, hidden);
		} catch (Exception e) {
			if (e instanceof NullPointerException && readPin == null) {
				System.out.println("Masking input not supported.. Continue with default Invocation");
				interactiveGeneratorOnNull(br, min, max, numPws, anonymous, hidden);
			} else {
				System.out.println("Error occured on interactive PW generation, check Stack Trace for Details");
				e.printStackTrace();
				System.exit(-1);
			}
			return;
		}
	}

	static void interactiveGeneratorOnNull(BufferedReader br, int min, int max, int numPws, boolean anonymous,
			boolean hidden) {
		try {
			System.out.println(ansi().fg(GREEN).a("Enter Pin:").reset());
			String pin = br.readLine();
			long seed = Long.parseLong(pin);
			printMultipleRandomPWs(min, max, numPws, seed, anonymous, hidden);
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
		int rand = -1;
		try {
			rand = SecureRandom.getInstanceStrong().nextInt(max - min) + min;
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Issue occured generating random numbers");
			e.printStackTrace();
		}
		if (rand == -1) {
			throw new Error("Issue occured generating random numbers");
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

	static String generatePw(int length, long pin, boolean hidden, boolean anonymous) {
		alphabet = randomizeAlphabet(pin, referenceAlphabet);
		String pw = "";
		int[] indexes = generateIndexes(length, pin);
		System.out.println(ansi().fg(GREEN).a("Token:").reset());
		String token = provideObfuscatedEncodedIndexes(encoder, indexes, pin);
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

	static void printIntArrayToString(int[] arr, boolean hidden) {
		String indexes = "{";
		for (int i = 0; i < arr.length; i++) {
			indexes += Integer.toString(arr[i]);
			indexes += (i == arr.length - 1) ? "}" : ",";
		}
		System.out.print("INDEXES: ");
		if (hidden) {
			printHidden(indexes);
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
			boolean hidden) {
		for (int i = 0; i < numOfPWs; i++) {
			System.out.println(ansi().fg(GREEN)
					.a("\n----------------PW NO:" + ((i + 1) < 10 ? "0" + (i + 1) : (i + 1)) + "-----------------")
					.reset());
			int rand = generateRandomNumber(rangeMin, rangeMax);
			if (anonymous) {
				generatePw(rand, pin, hidden, anonymous);
			} else if (hidden) {
				printHidden(generatePw(rand, pin, hidden, anonymous));
			} else {
				printNormal(generatePw(rand, pin, hidden, anonymous));
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

	// only deals with positive integers
	static int provideSecureRandomInteger(int min, int max) {
		int n = -1;
		try {
			n = SecureRandom.getInstanceStrong().nextInt(max - min + 1) + min;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		if (n == -1) {
			throw new Error("Issue occured assigning random number");
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

}
