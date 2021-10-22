import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
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
		byte[] iv = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
		byte[] encrypted = cipher.doFinal(hash);
		
		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.add-msg"));
		bos.write(encrypted);

		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		while (bis.available() > 0)
			bos.write(bis.readNBytes(16));
		fis.close();
		bis.close();
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
	}
	
	public static void encryptRSA() throws Exception {
		final int BUFFER_SIZE = 117;
		Key key = readPubKeyFromFile("YPublic.key");
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, new SecureRandom());
		
		FileInputStream fis = new FileInputStream("message.add-msg");
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		FileOutputStream fos = new FileOutputStream("message.rsacipher");
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		int piece;
		byte[] buffer;
		byte[] encrypted;
		do {
			buffer = new byte[BUFFER_SIZE];
			piece = bis.read(buffer, 0, BUFFER_SIZE);
			if (piece > 0) {
				encrypted = cipher.doFinal(buffer, 0, piece);
				bos.write(encrypted);
			}
		} while (piece == BUFFER_SIZE);
		
		fis.close();
		bis.close();
		bos.close();
		
	}
	
	public static void main(String[] args) throws Exception {
		String msgFile = getFileNameFromUser();
		byte[] md = md(msgFile);
		encryptAES(md, msgFile);
		encryptRSA();
		
	}
}
