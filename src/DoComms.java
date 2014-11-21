import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

class DoComms implements Runnable {
	private Socket clientSocket;

	PrintWriter out;
	BufferedReader in;
	private KeyPair keyPair;
	private SecretKey sessionKey;
	Cipher sessionEncryptCipher;
	Cipher sessionDecryptCipher;

	DoComms(Socket server, KeyPair keyPair) {
		this.clientSocket = server;
		this.keyPair = keyPair;
	}

	private void createCiphers() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		byte[] iv = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		IvParameterSpec ips = new IvParameterSpec(iv);
		sessionEncryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		sessionEncryptCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ips);
		sessionDecryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		sessionDecryptCipher.init(Cipher.DECRYPT_MODE, sessionKey, ips);
	}

	public String encrypt(String input) throws IllegalBlockSizeException, BadPaddingException {
		byte[] inputInByteArray = input.getBytes();
		byte[] encryptedInput = sessionEncryptCipher.doFinal(inputInByteArray);
		return DatatypeConverter.printBase64Binary(encryptedInput);
	}

	public String decrypt(String input) throws IllegalBlockSizeException, BadPaddingException {
		byte[] inputInByteArray = DatatypeConverter.parseBase64Binary(input);
		byte[] decryptedInput = sessionDecryptCipher.doFinal(inputInByteArray);
		return new String(decryptedInput);
	}

	public void run() {
		try {
			String inputLine;
			out = new PrintWriter(clientSocket.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			out.println(keyPair.getPublic());
			out.println("end key");
			try {
				while ((inputLine = in.readLine()) != null) {
					if (inputLine.equalsIgnoreCase("end key")) {
						break;
					} else {
						byte[] encryptedKey = DatatypeConverter.parseBase64Binary(inputLine);
						Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
						cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
						byte[] decryptedKey = cipher.doFinal(encryptedKey);
						sessionKey = new SecretKeySpec(decryptedKey, "AES");
						createCiphers();
						out.println(encrypt(clientSocket.toString()));
					}
				}
				while (true) {
					if (in.ready()) {
						inputLine = in.readLine();
						System.out.println("Received:" + inputLine);
						String decryptedMessage = decrypt(inputLine);
						System.out.println("Decrypted:" + decryptedMessage);
						if (decryptedMessage.equalsIgnoreCase("Bye.")) {
							break;
						}

					}
					if (stdIn.ready()) {
						String fromOwner = stdIn.readLine();
						String encryptedMessage = encrypt(fromOwner);
						System.out.println("Encrypted Message Sent: " + encryptedMessage);
						out.println(encryptedMessage);
						if (fromOwner.equalsIgnoreCase("Bye.")) {
							break;
						}

					}
				}
			} catch (IOException ioe) {
				System.out.println("IOException on while listening on socket: " + ioe);
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				clientSocket.close();
			}
		} catch (IOException ioe) {
			System.out.println("IOException on socket listen: " + ioe);
			// ioe.printStackTrace();
		}
	}
}
