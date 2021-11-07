package com.sam.key.cipher;
public enum Nonce {
	SMALL(12), MEDIUM(16), LARGE(96);

	private int size;

	private Nonce(int size) {
		this.size = size;
	}

	public int getSize() {
		return this.size;
	}
}