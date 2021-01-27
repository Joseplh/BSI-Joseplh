package encrpytion;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class encryption {
	/**salt used for encryption purposes*/
	private final static String salt="r4nd0m94r649373x7u53df0r7";
	/**public key*/
	private PublicKey publicKey;
	/**private key*/
	private PrivateKey privateKey;
	/** basic constructor: https://www.devglan.com/java8/rsa-encryption-decryption-java
	 * <br> Constructor generates a keypair with a public and private key*/
	public encryption() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }
	/**return private RSA key*/
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	/**return public RSA key*/
	public PublicKey getPublicKey() {
		return publicKey;
	}
	/**return private RSA key as String variable*/
	public String getPrivateKeyStr() {
		return privateKey.toString();
	}
	/**return public RSA key as String variable*/
	public String getPublicKeyStr() {
		return publicKey.toString();
	}
	/**writes to a provided location the key provided in a byte[].
	 * <br>Acceptable paths include general and absolute pathing
	 * <br>Example of the byte[] key is encryption.getPublicKey().getEncoded() */
	public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }
	/** encrypt takes in a string of any size and prints out coded text
	 * @throws Exception 
	 * <br> Source: https://www.adeveloperdiary.com/java/how-to-easily-encrypt-and-decrypt-text-in-java*/
	public String encrypt(String plainText) throws Exception {
		String strData="";
		
		try {
			String strKey = salt;
			SecretKeySpec skeyspec=new SecretKeySpec(strKey.getBytes(), "Blowfish");
			Cipher cipher=Cipher.getInstance("Blowfish");
			cipher.init(Cipher.ENCRYPT_MODE, skeyspec);
			byte[] encrypted=cipher.doFinal(plainText.getBytes());
			strData=new String(encrypted);
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e);
		}
		return strData;
	}
	/** decodes encoded text into plain text of any size
	 * @throws Exception 
	 * <br> Source: https://www.adeveloperdiary.com/java/how-to-easily-encrypt-and-decrypt-text-in-java*/
	public String decrypt(String codedText) throws Exception {
		String strData="";
		
		try {
			String strKey = salt;
			SecretKeySpec skeyspec=new SecretKeySpec(strKey .getBytes(), "Blowfish");
			Cipher cipher=Cipher.getInstance("Blowfish");
			cipher.init(Cipher.DECRYPT_MODE, skeyspec);
			byte[] decrypted=cipher.doFinal(codedText.getBytes());
			strData=new String(decrypted);
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e);
		}
		return strData;
	}
	/** One-way hash encryption, takes in String and outputs hash of 16 character length*/
	public static String makeHash(String password) {
		String hash = "";
		if(password == null)
			return null;

		password = password + salt;
		try {
			MessageDigest digest = MessageDigest.getInstance("MD5");
			digest.update(password.getBytes(), 0, password.length());
			hash = new BigInteger(1, digest.digest()).toString(16);
		} catch (NoSuchAlgorithmException err) {
			err.printStackTrace();
		}
		return hash;
	}
}
