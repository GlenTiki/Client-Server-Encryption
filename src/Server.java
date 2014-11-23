import java.io.*;
import java.security.*;
import java.net.*;

public class Server {
	public static void main(String[] args) throws IOException {

		int portNumber = 4000;
		int maxConnections = 5;
		int i = 0;
		
		//Server initializes the socket it must listen on
		try (ServerSocket serverSocket = new ServerSocket(portNumber);) {
			//generate RSA keypair
			KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
			
			//THREADING FOR MULTIPLE CONNECTIONS
			while ((i++ < maxConnections) || (maxConnections == 0)) {
				Socket clientSocket = serverSocket.accept();//wait for connection...
				DoComms conn_c = new DoComms(clientSocket, keyPair); //initialize the communication protocol for the server,
																	//pass it the RSA keypair.
				
				//run the communication protocol
				Thread t = new Thread(conn_c);
				t.start();
			}
		} catch (IOException e) {
			System.out.println("Exception caught when trying to listen on port " + portNumber + " or listening for a connection");
			System.out.println(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Exception caught when trying to generate RSA keypair");
		}
	}
}
