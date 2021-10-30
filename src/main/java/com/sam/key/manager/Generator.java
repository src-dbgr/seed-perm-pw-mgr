package com.sam.key.manager;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class Generator {
	// Declaring the color
	// Custom declaration
	public static final String ANSI_YELLOW = "\u001B[33m";
	public static final String ANSI_BLACK = "\u001B[30m";
	public static final String ANSI_BLACK_BACKGROUND = "\u001B[40m";
	// Declaring ANSI_RESET so that we can reset the color
	public static final String ANSI_RESET = "\u001B[0m";

	public static final int MIN_PADDING_LENGTH = 5;
	public static final int MAX_PADDING_LENGTH = 20;

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
			return;
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
		System.out.println("0 - Create Passwords - Show only indexes (Blacked)");
		System.out.println("1 - Create Passwords - Show only indexes (Visible)");
		System.out.println("2 - Create Passwords - Show PWs and indexes (Blacked)");
		System.out.println("3 - Create Passwords - Show PWs and indexes (Visible)");
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
		try {
			System.out.print("Enter Indexes Array:\n");
			String indexesString = br.readLine();
			indexes = parseStringToIntArr(indexesString);
			printIntArrayToString(indexes, blacked);
			readPin = cr.readPassword("Enter Pin:\n");
			long pin = Long.parseLong(new String(readPin));
			if (blacked) {
				printBlacked(generateByIndexes(indexes, pin, blacked));
			} else {
				printNormal(generateByIndexes(indexes, pin, blacked));
			}
		} catch (Exception e) {
			if (e instanceof NullPointerException && readPin == null) {
				System.out.println("Masking input not supported.. Continue with default Invocation");
				interactivePWRetrieveOnNull(br, blacked, indexes);
			} else {
				System.out.println("Error occured on retrieving PW, check Stack Trace for Details");
				e.printStackTrace();
				System.exit(-1);
			}
			return;
		}
	}

	static void interactivePWRetrieveOnNull(BufferedReader br, boolean blacked, int[] indexes) {
		try {
			System.out.println("Enter Pin:");
			String pin = br.readLine();
			long seed = Long.parseLong(pin);
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

	static String generatePw(int length, long pin, boolean blacked) {
		alphabet = randomizeAlphabet(pin, referenceAlphabet);
		System.out.print("PW Length: ");
		if (blacked) {
			printBlacked(Long.toString(length));
		} else {
			printNormal(Long.toString(length));
		}
		String pw = "";
		int[] indexes = generateIndexes(length, pin);
		printIntArrayToString(indexes, blacked);
		for (int i = 0; i < indexes.length; i++) {
			pw += alphabet[indexes[i]];
		}
		System.out.print("PW: ");
		pw += padWithEmtpyString();
		return pw;
	}

	static String padWithEmtpyString() {
		int length = generateRandomNumber(MIN_PADDING_LENGTH, MAX_PADDING_LENGTH);
		return String.format("%1$" + length + "s", "");
	}

	// pass your indeces to retrieve your pwd.
	static String generateByIndexes(int[] indexes, long pin, boolean blacked) {
		alphabet = randomizeAlphabet(pin, referenceAlphabet);
		System.out.print("PW Length: ");
		if (blacked) {
			printBlacked(Integer.toString(indexes.length));
		} else {
			printNormal(Integer.toString(indexes.length));
		}
		String pw = "";
		printIntArrayToString(indexes, blacked);
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
				generatePw(rand, pin, blacked);
			} else if (blacked) {
				printBlacked(generatePw(rand, pin, blacked));
			} else {
				printNormal(generatePw(rand, pin, blacked));
			}
		}
	}

	static void printBlacked(String message) {
		message = padWithEmtpyString() + message + padWithEmtpyString();
		System.out.println(ANSI_BLACK_BACKGROUND + ANSI_BLACK + message + ANSI_RESET);
	}

	static void printNormal(String message) {
//		message = padWithEmtpyString() + message + padWithEmtpyString();
		System.out.println(message);
	}

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
