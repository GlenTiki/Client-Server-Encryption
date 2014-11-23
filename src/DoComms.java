import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

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

	//Initialize the server communication protocol
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
	
	public void run() {
		try {
			//connection initialise, initialize the IO from client
			String inputLine;
			out = new PrintWriter(clientSocket.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			//send the RSA public key
			out.println(keyPair.getPublic());
			out.println("end key");
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				
				//read the encrypted AES session key from the client.
				//The session key is received in the format:
				//sessionKey
				//end key
				while ((inputLine = in.readLine()) != null) {
					if (inputLine.equalsIgnoreCase("end key")) {
						break;
					} else {
						//Key was received, the server can rebuild the decrypted AES session key using the private RSA key.
						
						//the line below turns the stringified encrpyted session key back into a byte array
						byte[] encryptedKey = DatatypeConverter.parseBase64Binary(inputLine);
						//Initialize a cipher decrypter
						Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
						cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
						//decrypted key
						byte[] decryptedKey = cipher.doFinal(encryptedKey);
						
						//build decrypted AES key, and store it.
						sessionKey = new SecretKeySpec(decryptedKey, "AES");
						createCiphers();
						//send client first message, a toString of the socket it is connected on

						byte[] inputInByteArray = clientSocket.toString().getBytes();
						byte[] encryptedInput = sessionEncryptCipher.doFinal(inputInByteArray);
						String encryptedMessage = DatatypeConverter.printBase64Binary(encryptedInput);
						out.println(encryptedMessage);
						
						byte[] messageHash = new byte[inputInByteArray.length + sessionKey.getEncoded().length];
						System.arraycopy(inputInByteArray, 0, messageHash, 0, inputInByteArray.length);
						System.arraycopy(sessionKey.getEncoded(), 0, messageHash, inputInByteArray.length, sessionKey.getEncoded().length);
						
						byte outputHash[] = md.digest(messageHash);
						
						out.println(new String(outputHash));
					}
				}
				
				
				
				//read input from user (server administrator), and input from connected client
				while (true) {
					if (in.ready()) {
						inputLine = in.readLine();
						String hash = in.readLine();
						System.out.println("Received:" + inputLine);
						System.out.println("hash:" + hash);
						byte[] inputInByteArray = DatatypeConverter.parseBase64Binary(inputLine);
						byte[] decryptedInput = sessionDecryptCipher.doFinal(inputInByteArray);
						
						String decryptedMessage = new String(decryptedInput);
						
						byte[] rebuiltHash = new byte[decryptedInput.length + sessionKey.getEncoded().length];
						System.arraycopy(decryptedInput, 0, rebuiltHash, 0, decryptedInput.length);
						System.arraycopy(sessionKey.getEncoded(), 0, rebuiltHash, decryptedInput.length, sessionKey.getEncoded().length);
						
						byte outputHash[] = md.digest(rebuiltHash);

						if (Arrays.equals(hash.getBytes(), outputHash)){
							System.out.println("Hash match!");
						} else {
							System.out.println("Hashes do not match! Decrypted message may be garbled and/or tempered with.");
						}

						System.out.println("Decrypted:" + decryptedMessage);
						
						if (decryptedMessage.equalsIgnoreCase("Bye.")) {
							break;
						}

					}
					if (stdIn.ready()) {
						String fromOwner = stdIn.readLine();
						byte[] inputInByteArray = fromOwner.getBytes();
						byte[] encryptedInput = sessionEncryptCipher.doFinal(inputInByteArray);
						String encryptedMessage = DatatypeConverter.printBase64Binary(encryptedInput);
						
						byte[] messageHash = new byte[inputInByteArray.length + sessionKey.getEncoded().length];
						System.arraycopy(inputInByteArray, 0, messageHash, 0, inputInByteArray.length);
						System.arraycopy(sessionKey.getEncoded(), 0, messageHash, inputInByteArray.length, sessionKey.getEncoded().length);
						
						byte outputHash[] = md.digest(messageHash);
						
						System.out.println("Encrypted Message Sent: " + encryptedMessage);
						out.println(encryptedMessage);

						System.out.println("hash:" + new String(outputHash));
						out.println(new String(outputHash));
						
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
