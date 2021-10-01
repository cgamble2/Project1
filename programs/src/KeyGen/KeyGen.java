package KeyGen;

import java.io.*;
import java.util.Scanner;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;

import java.math.BigInteger;

public class KeyGen {
	public static void main(String[] args) throws Exception {
		
		//Generate a pair of keys
		SecureRandom random = new SecureRandom();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024, random);  //1024: key size in bits
		//when key size of RSA is 1024 bits, the RSA Plaintext block
		//size needs to be <= 117 bytes; and the RSA Cyphertext
		//block is always 128 Bytes (1024 bits) long.
		KeyPair xPair = generator.generateKeyPair();
		KeyPair yPair = generator.generateKeyPair();
		
		// x pair
		Key xPubKey = xPair.getPublic();
		Key xPrivKey = xPair.getPrivate();
		
		// y pair
		Key yPubKey = yPair.getPublic();
		Key yPrivKey = yPair.getPrivate();

    /* next, store the keys to files, read them back from files,
       and then, encrypt & decrypt using the keys from files. */
		
		//get the parameters of the keys: modulus and exponet
		KeyFactory factory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec xPubKSpec = factory.getKeySpec(xPubKey,
				RSAPublicKeySpec.class);
		RSAPrivateKeySpec xPrivKSpec = factory.getKeySpec(xPrivKey,
				RSAPrivateKeySpec.class);
		
		RSAPublicKeySpec yPubKSpec = factory.getKeySpec(yPubKey,
				RSAPublicKeySpec.class);
		RSAPrivateKeySpec yPrivKSpec = factory.getKeySpec(yPrivKey,
				RSAPrivateKeySpec.class);
		
		//save the parameters of the keys to the files
		saveToFile("XPublic.key", xPubKSpec.getModulus(),
				xPubKSpec.getPublicExponent());
		saveToFile("XPrivate.key", xPrivKSpec.getModulus(),
				xPrivKSpec.getPrivateExponent());
		
		saveToFile("YPublic.key", yPubKSpec.getModulus(),
				yPubKSpec.getPublicExponent());
		saveToFile("YPrivate.key", yPrivKSpec.getModulus(),
				yPrivKSpec.getPrivateExponent());
		
		Scanner sc = new Scanner(System.in);
		String input = "";
		while (input.length() != 16) {
			System.out.println("Enter a 16-character string: ");
			input = sc.nextLine();
		}
		File symmetricKey = new File("symmetric.key");
		PrintWriter pw = new PrintWriter(symmetricKey);
		pw.println(input);
		pw.close();
	
	}
	//save the prameters of the public and private keys to file
	public static void saveToFile(String fileName,
	                              BigInteger mod, BigInteger exp) throws IOException {
		
		System.out.println("Write to " + fileName + ": modulus = " +
		                   mod.toString() + ", exponent = " + exp.toString() + "\n");
		
		ObjectOutputStream oout = new ObjectOutputStream(
				new BufferedOutputStream(new FileOutputStream(fileName)));
		
		try {
			oout.writeObject(mod);
			oout.writeObject(exp);
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}
	
	
	//read key parameters from a file and generate the public key
	public static PublicKey readPubKeyFromFile(String keyFileName)
			throws IOException {
		
		InputStream in =
				KeyGen.class.getResourceAsStream(keyFileName);
		ObjectInputStream oin =
				new ObjectInputStream(new BufferedInputStream(in));
		
		try {
			BigInteger m = (BigInteger) oin.readObject();
			BigInteger e = (BigInteger) oin.readObject();
			
			System.out.println("Read from " + keyFileName + ": modulus = " +
			                   m.toString() + ", exponent = " + e.toString() + "\n");
			
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			PublicKey key = factory.generatePublic(keySpec);
			
			return key;
		} catch (Exception e) {
			throw new RuntimeException("Spurious serialisation error", e);
		} finally {
			oin.close();
		}
	}
	
	
	//read key parameters from a file and generate the private key
	public static PrivateKey readPrivKeyFromFile(String keyFileName)
			throws IOException {
		
		InputStream in =
				KeyGen.class.getResourceAsStream(keyFileName);
		ObjectInputStream oin =
				new ObjectInputStream(new BufferedInputStream(in));
		
		try {
			BigInteger m = (BigInteger) oin.readObject();
			BigInteger e = (BigInteger) oin.readObject();
			
			System.out.println("Read from " + keyFileName + ": modulus = " +
			                   m.toString() + ", exponent = " + e.toString() + "\n");
			
			RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			PrivateKey key = factory.generatePrivate(keySpec);
			
			return key;
		} catch (Exception e) {
			throw new RuntimeException("Spurious serialisation error", e);
		} finally {
			oin.close();
		}
	}
}

