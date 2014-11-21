import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

public class Client {

	private SecretKey sessionKey;
	private Cipher sessionEncryptCipher;
	private Cipher sessionDecryptCipher;

	public Client(SecretKey sessionKey) {
		this.sessionKey = sessionKey;
		try {
			createCiphers();
		} catch (Exception e) {
			e.printStackTrace();
		}
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

	public static void main(String[] args) throws IOException {
		String hostName = "127.0.0.1";
		int portNumber = 4000;

		try (Socket socket = new Socket(hostName, portNumber);
				PrintWriter clientOut = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader clientIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));) {
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

			// generate aes session key
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			SecretKey sessionKey = keygen.generateKey();

			Client client = new Client(sessionKey);

			String fromServer;
			String fromUser;
			BigInteger modulus = new BigInteger("123");
			BigInteger exponent = new BigInteger("123");
			while ((fromServer = clientIn.readLine()) != null) {
				if (fromServer.contains("modulus:")) {
					modulus = new BigInteger(fromServer.split(":")[1].trim());
				} else if (fromServer.contains("public exponent:")) {
					exponent = new BigInteger(fromServer.split(":")[1].trim());
				}
				if (fromServer.equals("end key"))
					break;
			}

			// rebuild servers public RSA key from data received
			RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			PublicKey pub = factory.generatePublic(spec);

			// encrypt the aes session key with the rsa public key
			Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipher.init(Cipher.ENCRYPT_MODE, pub);
			byte[] encryptedSessionKey = rsaCipher.doFinal(sessionKey.getEncoded());

			String stringifiedEncryptedSessionKey = DatatypeConverter.printBase64Binary(encryptedSessionKey);

			clientOut.println(stringifiedEncryptedSessionKey);
			clientOut.println("end key");
			while (true) {
				if (clientIn.ready()) {
					fromServer = clientIn.readLine();
					System.out.println("Received Encrypted Message:" + fromServer);
					String decryptedMessage = client.decrypt(fromServer);
					System.out.println("Decrypted:" + decryptedMessage);
					if (decryptedMessage.equalsIgnoreCase("Bye."))
						break;
				}
				if (stdIn.ready()) {
					fromUser = stdIn.readLine();
					String encryptedMessage = client.encrypt(fromUser);
					System.out.println("Encrypted Message Sent: " + encryptedMessage);
					clientOut.println(encryptedMessage);
					if (fromUser.equalsIgnoreCase("Bye."))
						break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}