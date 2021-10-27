package com.sam.key.manager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class Generator {

	// Declaring ANSI_RESET so that we can reset the color
	public static final String ANSI_RESET = "\u001B[0m";

	// Declaring the color
	// Custom declaration
	public static final String ANSI_YELLOW = "\u001B[33m";
	public static final String ANSI_BLACK = "\u001B[30m";
	public static final String ANSI_BLACK_BACKGROUND = "\u001B[40m";

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
		switch (option) {
		case 0:
			interactiveIndicesGenerationBlacked();
			break;
		case 1:
			interactiveIndicesGenerationVisible();
			break;
		case 2:
			interactivePWGenerationBlacked();
			break;
		case 3:
			interactivePWGenerationVisible();
			break;
		case 4:
			interactivePWRetrieve(true);
			break;
		case 5:
			interactivePWRetrieve(false);
			break;
		default:
			System.out.println("This option is not available. Choose a listed option.");
			break;
		}
	}

	static void printCLICommands() {
		System.out.println("Choose what you want to do:");
		System.out.println("0 - Create Passwords - Show only indices (Blacked)");
		System.out.println("1 - Create Passwords - Show only indices (Visible)");
		System.out.println("2 - Create Passwords - Show PWs and Indices (Blacked)");
		System.out.println("3 - Create Passwords - Show PWs and Indices (Visible)");
		System.out.println("4 - Retrieve Password (Blacked)");
		System.out.println("5 - Retrieve Password (Visible)");
	}

	static void alphabetSeedRequest() {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		char[] seedC = null;
		try {
			seedC = System.console().readPassword("Enter Alphabet Permutation Seed: \n");
			long seed = Long.parseLong(new String(seedC));
			randomizeReferenceAlphabet(seed);
		} catch (Exception e) {
			if (e instanceof NullPointerException) {
				System.out.println("Masking input not supported.. Continue with default Invocation");
			} else {
				e.printStackTrace();
			}
			if (seedC == null) {
				try {
					System.out.println("Enter Alphabet Permutation Seed: ");
					String seedS = br.readLine();
					long seed = Long.parseLong(seedS);
					randomizeReferenceAlphabet(seed);
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
		}
	}

	static void interactivePWRetrieve(boolean blacked) {
		alphabetSeedRequest();
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		char[] readPin = null;
		int[] indices = null;
		try {
			System.out.print("Enter Indices Array:\n");
			String indicesString = br.readLine();
			indices = parseStringToIntArr(indicesString);
			printIntArrayToString(indices, blacked);
			readPin = System.console().readPassword("Enter Pin:\n");
			long pin = Long.parseLong(new String(readPin));
			if (blacked) {
				printBlacked(generateByIndices(indices, pin, blacked));
			} else {
				printNormal(generateByIndices(indices, pin, blacked));
			}
		} catch (Exception e) {
			if (e instanceof NullPointerException) {
				System.out.println("Masking input not supported.. Continue with default Invocation");
			} else {
				System.out.println("Error occured on retrieving PW, check Stack Trace for Details");
				e.printStackTrace();
			}
			if (readPin == null) {
				try {
					System.out.println("Enter Pin:");
					String pin = br.readLine();
					long seed = Long.parseLong(pin);
					if (blacked) {
						printBlacked(generateByIndices(indices, seed, blacked));
					} else {
						printNormal(generateByIndices(indices, seed, blacked));
					}
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
			System.exit(-1);
		}
	}

	static void interactiveIndicesGenerationBlacked() {
		interactiveGenerator(true, true);
	}

	static void interactivePWGenerationBlacked() {
		interactiveGenerator(false, true);
	}

	static void interactiveIndicesGenerationVisible() {
		interactiveGenerator(true, false);
	}

	static void interactivePWGenerationVisible() {
		interactiveGenerator(false, false);
	}

	static void interactiveGenerator(boolean anonymous, boolean blacked) {
		alphabetSeedRequest();
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
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
			readPin = System.console().readPassword("Enter Pin:\n");
			long pin = Long.parseLong(new String(readPin));
			printMultipleRandomPWs(min, max, numPws, pin, anonymous, blacked);
		} catch (Exception e) {
			if (e instanceof NullPointerException) {
				System.out.println("Masking input not supported.. Continue with default Invocation");
			} else {
				System.out.println("Error occured on interactive PW generation, check Stack Trace for Details");
				e.printStackTrace();
			}
			if (readPin == null) {
				try {
					System.out.println("Enter Pin");
					String pin = br.readLine();
					long seed = Long.parseLong(pin);
					printMultipleRandomPWs(min, max, numPws, seed, anonymous, blacked);
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
			System.exit(-1);
		}
	}

	static int[] parseStringToIntArr(String word) {
		String[] stringIndices = word.replaceAll("\\{", "").replaceAll("\\}", "").replaceAll("\\s", "").split(",");
		int[] indices = new int[stringIndices.length];

		for (int i = 0; i < indices.length; i++) {
			try {
				indices[i] = Integer.parseInt(stringIndices[i]);
			} catch (NumberFormatException nfe) {
				nfe.printStackTrace();
			}
		}
		return indices;
	}

	// helper to randomize Alphabet
	// Prints a shuffled Alphabet
	static void randomizeAlphabet(long seed) {
		alphabet = referenceAlphabet;
		List<Character> listC = new ArrayList<>();
		for (char c : alphabet) {
			listC.add(c);
		}
		Collections.shuffle(listC, new Random(seed));
		String str = listC.toString().replaceAll(",", "");
		alphabet = str.substring(1, str.length() - 1).replaceAll(" ", "").toCharArray();
//		System.out.println("SIZE: " + alphabet.length);
//		printCharArrayToString(alphabet);
	}

	// Randomizes reference Alphabet
	static void randomizeReferenceAlphabet(long seed) {
		List<Character> listC = new ArrayList<>();
		for (char c : referenceAlphabet) {
			listC.add(c);
		}
		Collections.shuffle(listC, new Random(seed));
		String str = listC.toString().replaceAll(",", "");
		referenceAlphabet = str.substring(1, str.length() - 1).replaceAll(" ", "").toCharArray();
	}

	static int generateRandomNumber(int min, int max) {
		return ThreadLocalRandom.current().nextInt(min, max);
	}

	static int[] generateIndices(int length) {
		int[] indices = new int[length];
		for (int i = 0; i < length; i++) {
			indices[i] = generateRandomNumber(0, alphabet.length);
		}
		return indices;
	}

	static String generatePw(int length, long pin, boolean blacked) {
		randomizeAlphabet(pin);
		System.out.print("PW Length: ");
		if (blacked) {
			printBlacked(Long.toString(length));
		} else {
			printNormal(Long.toString(length));
		}
		String pw = "";
		int[] indices = generateIndices(length);
		printIntArrayToString(indices, blacked);
		for (int i = 0; i < indices.length; i++) {
			pw += alphabet[indices[i]];
		}
		System.out.print("PW: ");
		pw += padWithEmtpyString();
		return pw;
	}

	static String padWithEmtpyString() {
		int length = generateRandomNumber(5, 20);
		return String.format("%1$" + length + "s", "");
	}

	// pass your indeces to retrieve your pwd.
	static String generateByIndices(int[] indices, long pin, boolean blacked) {
		randomizeAlphabet(pin);
		System.out.print("PW Length: ");
		if (blacked) {
			printBlacked(Integer.toString(indices.length));
		} else {
			printNormal(Integer.toString(indices.length));
		}
		String pw = "";
		printIntArrayToString(indices, blacked);
		for (int i = 0; i < indices.length; i++) {
			pw += alphabet[indices[i]];
		}
		System.out.print("PW: ");
		return pw;
	}

	static void printIntArrayToString(int[] arr, boolean blacked) {
		String indices = "{";
		for (int i = 0; i < arr.length; i++) {
			indices += Integer.toString(arr[i]);
			indices += (i == arr.length - 1) ? "}" : ",";
		}
		System.out.print("INDICES: ");
		if (blacked) {
			printBlacked(indices);
		} else {
			printNormal(indices);
		}
	}

	static void printCharArrayToString(char[] arr) {
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
}
