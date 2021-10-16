//package Sender;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Sender {
	
	//read key parameters from a file and generate the public key
	public static PublicKey readPubKeyFromFile(String keyFileName)
			throws IOException {
		
		InputStream in =
				Sender.class.getResourceAsStream(keyFileName);
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
	
	public static String getFileNameFromUser() {
		Scanner sc = new Scanner(System.in);
		System.out.print("Input the name of the message file: ");
		return sc.nextLine();
	}
	
	public static void createFile(String fileName) {
		try {
			File file = new File(fileName);
			if (file.createNewFile()) {
				System.out.println("File created: " + file.getName());
			} else {
				System.out.println("File already exists.");
			}
		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
	}
	
	public static void writeToFile(String file) {
		try {
			Scanner sc = new Scanner(System.in);
			System.out.print("Super secret message (M): ");
			PrintWriter pw = new PrintWriter(file);
			pw.println(sc.nextLine());
			pw.close();
			
		} catch (FileNotFoundException ex) {
			System.out.println(ex.getMessage());
		}
	}
	
	public static byte[] md(String f) throws Exception {
		final int BUFFER_SIZE = 32 * 1024;
		BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		DigestInputStream in = new DigestInputStream(file, md);
		int i;
		byte[] buffer = new byte[BUFFER_SIZE];
		do {
			i = in.read(buffer, 0, BUFFER_SIZE);
		} while (i == BUFFER_SIZE);
		md = in.getMessageDigest();
		in.close();
		byte[] hash = md.digest();
		
		Scanner sc = new Scanner(System.in);
		System.out.print("Do you want to invert the 1st byte in SHA256(M)? (Y or N) ");
		if (sc.nextLine().equalsIgnoreCase("Y"))
			hash[0] = (byte)~hash[0];
		System.out.println();
		
		System.out.println("digit digest (hash value):");
		for (int k = 0, j = 0; k < hash.length; k++, j++) {
			System.out.format("%2X ", hash[k]);
			if (j >= 15) {
				System.out.println();
				j = -1;
			}
		}
		System.out.println();
		
		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.dd"));
		bos.write(hash);
		bos.close();
		return hash;
	}
	
	public static void encryptAES(byte[] hash, String f) throws Exception {
		File file = new File(f);
		Scanner sk = new Scanner(new FileReader("symmetric.key"));
		String symmetricKey = sk.nextLine();
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes(StandardCharsets.UTF_8), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encrypted = cipher.doFinal(hash);
		
		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.add-msg"));
		bos.write(encrypted);
		// append message "piece by piece"?
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		DataInputStream dis = new DataInputStream(bis);
		while (dis.available() > 0)
			bos.write(dis.readNBytes(16));
		fis.close();
		bis.close();
		dis.close();
		bos.close();
		
		System.out.println("encrypted digit digest (hash value):");
		for (int k = 0, j = 0; k < encrypted.length; k++, j++) {
			System.out.format("%2X ", encrypted[k]);
			if (j >= 15) {
				System.out.println();
				j = -1;
			}
		}
		System.out.println();
		
		//return encrypted;
	}
	
	public static void encryptRSA(String f) throws Exception {
		File file = new File(f);
		final int BUFFER_SIZE = 117;
		Key key = readPubKeyFromFile("YPublic.key");
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, new SecureRandom());
		
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		DataInputStream dis = new DataInputStream(bis);
		
		
		FileOutputStream fos = new FileOutputStream("message.rsacipher");
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		int piece;
		byte[] buffer;
		byte[] leftOverBuffer;
		byte[] encrypted;
		do {
			buffer = new byte[BUFFER_SIZE];
			piece = dis.read(buffer, 0, BUFFER_SIZE);
			if (piece == BUFFER_SIZE) {
				encrypted = cipher.doFinal(buffer, 0, piece);
				System.out.println("encrypted size: " + encrypted.length);
				bos.write(encrypted);
			}
			else if (piece < BUFFER_SIZE && piece > 0) {
				System.out.println("starting if piece size: " + piece);
				leftOverBuffer = new byte[piece];
				piece = dis.read(leftOverBuffer, 0, leftOverBuffer.length);
				encrypted = cipher.doFinal(leftOverBuffer);
				bos.write(encrypted);
				System.out.println("left over piece size: " + piece);
			}
		} while (piece == BUFFER_SIZE);
		System.out.println("final piece size: " + piece + " bytes");
		
		fis.close();
		bis.close();
		dis.close();
		bos.close();
		
	}
	
	public static void main(String[] args) throws Exception {
		String msgFile = getFileNameFromUser();
		createFile(msgFile);
		writeToFile(msgFile);
		byte[] md = md(msgFile);
		encryptAES(md, msgFile);
		encryptRSA(msgFile);
		
	}
}
