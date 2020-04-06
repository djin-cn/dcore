package me.djin.dcore.util;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * 
 * @author djin
 *
 */
public class RsaUtils {
	private static final String ALGORITHM="RSA";
	/**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;
    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;
    
	/**
	 * 生成公私密钥对
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static void generateKeys(String publicKeyFile, String privateKeyFile) throws NoSuchAlgorithmException, IOException {
		// RSA算法要求有一个可信任的随机数源
		SecureRandom secureRandom = new SecureRandom();
		// 为RSA算法创建一个KeyPairGenerator对象
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
		// 利用上面的随机数据源初始化这个KeyPairGenerator对象
		keyPairGenerator.initialize(1024, secureRandom);
		// 生成密匙对
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		// 得到公钥
		java.security.Key publicKey = keyPair.getPublic();
		// 得到私钥
		java.security.Key privateKey = keyPair.getPrivate();

		// 对象流形式写入公钥
		ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
		outputStream.writeObject(publicKey);
		outputStream.flush();
		outputStream.close();

		// 对象流形式写入私钥
		ObjectOutputStream outputStream1 = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
		outputStream1.writeObject(privateKey);
		outputStream1.flush();
		outputStream1.close();
	}
	
	/**
	 * 加密
	 * @param securityKeyFile 公钥或者私钥文件路径
	 * @param str  待加密数据
	 * @return        加密后的数据
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encrypt(String securityKeyFile, String str) throws ClassNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		ObjectInputStream objectInputStream=new ObjectInputStream(new FileInputStream(securityKeyFile));
		java.security.Key publicKey= (java.security.Key)objectInputStream.readObject();
		objectInputStream.close();
		//得到Cipher对象来实现对源数据的RSA加密
		Cipher cipher=Cipher.getInstance(publicKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		
 
		byte[] encryptedData=str.getBytes();
		int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密  doFinal
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedDatas = out.toByteArray();
        out.close();
        
		return encryptedDatas;
	}
	
	/**
	 * 加密
	 * @param securityKeyFile 公钥或者私钥文件路径
	 * @param str  待加密数据
	 * @return        加密后的数据
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static String encryptToString(String securityKeyFile, String str) throws ClassNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		byte[] data=encrypt(securityKeyFile, str);
		return Base64.getEncoder().encodeToString(data);
	}
	
	/**
	 * 解密
	 * @param securityKeyFile 公钥或者私钥文件路径
	 * @param encryString 加密后的数据
	 * @return                    解密后数据
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decrypt(String securityKeyFile, byte[] encryString) throws FileNotFoundException, IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		ObjectInputStream objectInputStream=new ObjectInputStream(new FileInputStream(securityKeyFile));
		java.security.Key privatekey= (java.security.Key)objectInputStream.readObject();
		objectInputStream.close();
		
		Cipher cipher=Cipher.getInstance(privatekey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privatekey);
		
		int inputLen = encryString.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryString, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryString, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedDatas = out.toByteArray();
        out.close();
		
	    return decryptedDatas;
	}
	
	/**
	 * 解密
	 * @param securityKeyFile 公钥或者私钥文件路径
	 * @param encryString 加密后的数据
	 * @return                    解密后数据
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static String decryptToString(String securityKeyFile, String str) throws ClassNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		byte[] strByte = Base64.getDecoder().decode(str);
		byte[] data=decrypt(securityKeyFile, strByte);
		return new String(data);
	}
	
	/**
	 * 获取公钥或者私钥的字符串
	 * @param keyFile 公钥或者私钥文件
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public static String getStringKey(String keyFile) throws FileNotFoundException, IOException, ClassNotFoundException {
		ObjectInputStream objectInputStream=new ObjectInputStream(new FileInputStream(keyFile));
		java.security.Key key= (java.security.Key)objectInputStream.readObject();
		objectInputStream.close();
		return Base64.getEncoder().encodeToString(key.getEncoded());
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		String publicKeyFile = "/publicKeyFile.key";
		String privateKeyFile = "/privateKeyFile.key";
		String text = "15687asdf*&(^23";
//		String text = "你是RSA吗？";
		RsaUtils.generateKeys(publicKeyFile, privateKeyFile);
		
		
		byte[] a = RsaUtils.encrypt(publicKeyFile, text);
		String aString = Base64.getEncoder().encodeToString(a);
		System.out.println("加密");
		System.out.println(aString);
		
		byte[] b = RsaUtils.decrypt(privateKeyFile, a);
		String bString = new String(b);
		System.out.println("解密");
		System.out.println(bString);
	}
}
