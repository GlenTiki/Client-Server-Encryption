import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class DoComms implements Runnable {
	private Socket clientSocket;

	private PrintWriter out;
	private BufferedReader in;
	private KeyPair keyPair;
	private SecretKey sessionKey;
	private Cipher sessionEncryptCipher;
	private Cipher sessionDecryptCipher;

	// Initialize the server communication protocol
	DoComms(Socket server, KeyPair keyPair) {
		this.clientSocket = server;
		this.keyPair = keyPair;
	}

	// Create decryption and encryption ciphers
	private void createCiphers() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		byte[] iv = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		IvParameterSpec ips = new IvParameterSpec(iv);
		sessionEncryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		sessionEncryptCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ips);
		sessionDecryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		sessionDecryptCipher.init(Cipher.DECRYPT_MODE, sessionKey, ips);
	}

	public void sendBytes(byte[] myByteArray, int start, int len) throws IOException {
		if (len < 0)
			throw new IllegalArgumentException("Negative length not allowed");
		if (start < 0 || start >= myByteArray.length)
			throw new IndexOutOfBoundsException("Out of bounds: " + start);
		// Other checks if needed.

		// May be better to save the streams in the support class;
		// just like the socket variable.
		OutputStream out = clientSocket.getOutputStream();
		DataOutputStream dos = new DataOutputStream(out);

		dos.writeInt(len);
		if (len > 0) {
			dos.write(myByteArray, start, len);
		}
	}

	public void run() {
		try {
			// Initialize the IO from client
			String inputLine;
			OutputStream out = clientSocket.getOutputStream();
			DataOutputStream dos = new DataOutputStream(out);
			InputStream in = clientSocket.getInputStream();
			DataInputStream dis = new DataInputStream(in);
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

			String info = keyPair.getPublic().toString();
			String[] kk = info.split("\n");
			for(String k: kk){
				sendBytes(k.getBytes(), 0, k.getBytes().length);
			}
			
			
			
			// Send the RSA public key
			//sendBytes(keyPair.getPublic().toString().getBytes(), 0, keyPair.getPublic().toString().getBytes().length);

			String endKey = "end key";

			sendBytes(endKey.getBytes(), 0, endKey.getBytes().length);
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");

				// Read the encrypted AES session key from the client.
				// The session key is received in the format:
				//
				// sessionKey
				// "end key"
				//
				int len;
				while ((len = dis.readInt()) != 0) {
					byte[] data = new byte[len];
					if (len > 0) {
						dis.readFully(data);
					}
					inputLine = new String(data);

					if (inputLine.equalsIgnoreCase("end key")) {
						break;
					} else {
						// Key was received, the server can rebuild the
						// decrypted AES session key using the private RSA key.

						// The line below turns the stringified encrpyted
						// session key back into a byte array
						byte[] encryptedKey = inputLine.getBytes();

						// Initialize a cipher decrypter
						Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
						cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

						// Decrypted key
						byte[] decryptedKey = cipher.doFinal(encryptedKey);

						// Build decrypted AES key, and store it.
						sessionKey = new SecretKeySpec(decryptedKey, "AES");
						createCiphers();

						// Send client first message, a toString of the socket
						// it is connected on
						byte[] inputInByteArray = clientSocket.toString().getBytes();
						byte[] encryptedInput = sessionEncryptCipher.doFinal(inputInByteArray);
						
						sendBytes(encryptedInput, 0, encryptedInput.length);

						// Build and send hash
						byte[] messageHash = new byte[inputInByteArray.length + sessionKey.getEncoded().length];
						System.arraycopy(inputInByteArray, 0, messageHash, 0, inputInByteArray.length);
						System.arraycopy(sessionKey.getEncoded(), 0, messageHash, inputInByteArray.length, sessionKey.getEncoded().length);

						byte outputHash[] = md.digest(messageHash);

						sendBytes(outputHash, 0, outputHash.length);
					}
				}

				// Read input from user (server administrator), and input from
				// connected client
				while (true) {
					if (in.available() != 0) {
						
						len = dis.readInt();
					    byte[] inputInByteArray = new byte[len];
					    if (len > 0) {
					        dis.readFully(inputInByteArray);
					    }

						len = dis.readInt();
					    byte[] hash = new byte[len];
					    if (len > 0) {
					        dis.readFully(hash);
					    }
						
						inputLine = new String(inputInByteArray);
						System.out.println("Received:" + inputLine);
						System.out.println("hash:" + hash);

						// Decrypting message
						byte[] decryptedInput = sessionDecryptCipher.doFinal(inputInByteArray);

						String decryptedMessage = new String(decryptedInput);

						// Rebuilding hash
						byte[] rebuiltHash = new byte[decryptedInput.length + sessionKey.getEncoded().length];
						System.arraycopy(decryptedInput, 0, rebuiltHash, 0, decryptedInput.length);
						System.arraycopy(sessionKey.getEncoded(), 0, rebuiltHash, decryptedInput.length, sessionKey.getEncoded().length);

						byte outputHash[] = md.digest(rebuiltHash);

						// Validating hash
						if (Arrays.equals(hash, outputHash)) {
							System.out.println("Hash match!");
						} else {
							System.out.println("Hashes do not match! Decrypted message may be garbled and/or tempered with.");
						}

						// Displaying message
						System.out.println("Decrypted:" + decryptedMessage);

						if (decryptedMessage.equalsIgnoreCase("Bye.")) {
							break;
						}

					}

					// Reading input from server console and encrypting it
					if (stdIn.ready()) {
						String fromOwner = stdIn.readLine();
						byte[] inputInByteArray = fromOwner.getBytes();
						byte[] encryptedInput = sessionEncryptCipher.doFinal(inputInByteArray);
						String encryptedMessage = new String(encryptedInput);

						// Building hash
						byte[] messageHash = new byte[inputInByteArray.length + sessionKey.getEncoded().length];
						System.arraycopy(inputInByteArray, 0, messageHash, 0, inputInByteArray.length);
						System.arraycopy(sessionKey.getEncoded(), 0, messageHash, inputInByteArray.length, sessionKey.getEncoded().length);

						byte outputHash[] = md.digest(messageHash);

						// Sending and displaying message
						System.out.println("Encrypted Message Sent: " + encryptedMessage);
						sendBytes(encryptedInput, 0, encryptedInput.length);

						System.out.println("hash:" + new String(outputHash));
						sendBytes(outputHash, 0, outputHash.length);

						if (fromOwner.equalsIgnoreCase("Bye.")) {
							break;
						}

					}
				}
				// Catching exceptions
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
