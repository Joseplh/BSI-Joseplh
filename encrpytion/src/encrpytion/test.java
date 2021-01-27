package encrpytion;

import java.util.Scanner;

public class test {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		encryption crypt = new encryption();
		Scanner input = new Scanner(System.in);
		System.out.println(crypt.getPublicKeyStr());
		System.out.println(crypt.getPrivateKeyStr());
		System.out.print("Text to encode: ");
		String plainText = input.nextLine();
		System.out.println("Text recieved: " + plainText);
		System.out.println("Text encoded: " + crypt.encrypt(plainText));
		System.out.println("Text decoded: " + crypt.decrypt(crypt.encrypt(plainText)));
		input.close();
	}

}
