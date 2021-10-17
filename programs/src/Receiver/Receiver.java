import java.io.*;
import java.security.DigestInputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;

import java.math.BigInteger;
import java.nio.file.Files;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.print.event.PrintEvent;

import java.nio.Buffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;
import java.util.Scanner;

public class Receiver {
	
	public static void main(String[] args) throws Exception{
		// main method
		
		// init cipher
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		// read keys back from files
		System.out.println("Reading in Private Key");
		PrivateKey privKeyY = readPrivKeyFromFile("YPrivate.key");
		
		// read in the symmetric key for later use in AES;
		System.out.println("Reading in symmetric Key");
		Scanner symmetricScanner = new Scanner(new FileReader("symmetric.key"));
		String symmetricKey = symmetricScanner.nextLine();
		
		// get file name to save the decrypted message from
		Scanner scnr = new Scanner(System.in);
		System.out.println("Input the name of the message file");
		String fileName = scnr.nextLine();
		
		// read from file the text to decrypt with private key
		String encryptedFile = "message.rsacipher";
		
		File file = new File(encryptedFile);
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		System.out.println("message.rsacipher size: " + file.length());
		
		int piece;
		byte[] buffer;
		byte[] decrypted;
		final int PIECE_SIZE = 128;
		
		cipher.init(Cipher.DECRYPT_MODE, privKeyY);
		
		File messageds = new File("message.add-msg");
		FileOutputStream fos = new FileOutputStream(messageds);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		System.out.println("Beginning loop for RSA Decryption");
		do {
			buffer = new byte[PIECE_SIZE];
			piece = bis.read(buffer, 0, PIECE_SIZE);
			
			if (piece > 0) {
				System.out.println("buffer content: " + Arrays.toString(buffer));
				decrypted = cipher.doFinal(buffer, 0, PIECE_SIZE);
				System.out.println("Decrypted:" + Arrays.toString(decrypted));
				System.out.println("Size of decrypted: " + decrypted.length);
				bos.write(decrypted);
			}
			System.out.println("Piece size: " + piece);
		} while (piece == PIECE_SIZE);

		
		fis.close();
		bis.close();
		bis.close();
		bos.close();
		
		System.out.println("Finished with loop for RSA Decryption");
		// open file that we saved the rsa decryption to
		String decodedString = "message.add-msg";
		
		File messageadd = new File(decodedString);
		fis = new FileInputStream(messageadd);
		bis = new BufferedInputStream(fis);
		
		// get digest from first 32 bytes
		
		byte[] adigitalDigest = new byte[32];
		
		int messageLength = (int)messageadd.length() - 32;
		
		byte[] message = new byte[messageLength];
		
		bis.read(adigitalDigest, 0, 32);
		// read remaining bytes of message M into the with a name of fileName from user
		bis.read(message, 0, messageLength);
		
		
		// save message into file with name filename
		
		File userFile = new File(fileName);
		fos = new FileOutputStream(userFile);
		bos = new BufferedOutputStream(fos);
		bos.write(message);
		
		
		
		// do AES decryption of digital signature to determine if its genuine use symmetric key pubkeyXY
		
		Cipher cipherAES = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes(StandardCharsets.UTF_8), "AES");
		cipherAES.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16]));
		byte[] unencryptedDD = cipherAES.doFinal(adigitalDigest);
		
		
		// save the digital digest into a file named message.dd and print it in hexadecimal
		
		bos.close();
		
		File messagedd = new File("message.dd");
		fos = new FileOutputStream(messagedd);
		bos = new BufferedOutputStream(fos);
		bos.write(unencryptedDD);
		
		
		// display in hexadecimal
		System.out.println("digital digest (hash value): ");
		for (int k = 0, j = 0; k < unencryptedDD.length; k++, j++){
			System.out.format("%2X ", unencryptedDD[k]);
			if (j >= 15) {
				System.out.println();
				j = -1;
			}
		}
		
		// read the message from the file
		
		bis.close();
		
		fis = new FileInputStream(userFile);
		bis = new BufferedInputStream(fis);
		
		
		// calc sha256(m) using pubkeyXY which is in symmetric.key
		
		final int BUFFER_SIZE = 32 * 1024;
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		DigestInputStream in = new DigestInputStream(bis, md);
		
		int i;
		byte[] finalbuffer = new byte[BUFFER_SIZE];
		
		do {
			i = in.read(finalbuffer, 0, BUFFER_SIZE);
		} while(i == BUFFER_SIZE);
		
		md = in.getMessageDigest();
		in.close();
		byte[] hash = md.digest();
		
		// compare hash to unencrypted dd
		System.out.println("new digital digest of M  (hash value): ");
		for (int k = 0, j = 0; k < hash.length; k++, j++){
			System.out.format("%2X ", hash[k]);
			if (j >= 15) {
				System.out.println();
				j = -1;
			}
		}
		
		// Check if the values are equal
		if (Arrays.equals(hash, unencryptedDD)) {
			System.out.println("Successful");
		} else {
			System.out.println("Didnt match, message was altered");
		}
		
		
		// close all documents and scanners
		scnr.close();
		bis.close();
		bos.close();
	}
	
	
	public static String readFileAsString(String fileName) throws Exception{
		String data = "";
		data = new String(Files.readAllBytes(Paths.get(fileName)));
		return data;
	}
	
	
	// read key params and generate public from file
	public static PublicKey readPubKeyFromFile(String keyFileName) throws IOException {
		InputStream in = Receiver.class.getResourceAsStream(keyFileName);
		ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
		
		try {
			BigInteger m = (BigInteger) oin.readObject();
			BigInteger e = (BigInteger) oin.readObject();
			
			System.out.println("Read from " + keyFileName +
			                   ": modulus = " + m.toString() + ", exponent = " + e.toString() + "\n");
			
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m,e);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			PublicKey key = factory.generatePublic(keySpec);
			
			return key;
		} catch (Exception e) {
			throw new RuntimeException("Spurious serialisation error", e);
		} finally {
			oin.close();
		}
	}
	
	public static PrivateKey readPrivKeyFromFile(String keyFileName) throws IOException {
		
		InputStream in = Receiver.class.getResourceAsStream(keyFileName);
		ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
		
		try {
			BigInteger m = (BigInteger) oin.readObject();
			BigInteger e = (BigInteger) oin.readObject();
			
			System.out.println("Read from " + keyFileName +
			                   ": modulus = " + m.toString() + ", exponent = " + e.toString() + "\n");
			
			RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m,e);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			PrivateKey key = factory.generatePrivate(keySpec);
			
			return key;
		} catch (Exception e) {
			throw new RuntimeException("Spurious serialisation error", e);
		} finally {
			oin.close();
		}
	}
	
	// this is a class
}

