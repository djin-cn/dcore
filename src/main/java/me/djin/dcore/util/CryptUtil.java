package me.djin.dcore.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * 加密、解密工具类 包装cipher对象的操作
 * 基于javax.crypto.*、java.security.*、org.apache.commons.codec.binary.Base64实现
 * 解密、加密包装。该工具类仅仅是对底层方法的包装，提供更友好的API使用，本身不包含任何加密、解密 算法；所有加密、解密算法均依赖于JDK提供的包实现；
 * 
 * @author djin
 */
public class CryptUtil {
	/**
	 * 单态实例对象
	 */
	private static final CryptUtil INSTANCE = new CryptUtil();

	/**
	 * 密码类型
	 * 
	 * @author djin
	 *
	 */
	public enum CipherType {
		// AES加密
		AES
	}

	/**
	 * 私有构造函数，避免被外部实例化
	 */
	private CryptUtil() {
	};

	/**
	 * 获取单态实例对象
	 * 
	 * @return
	 */
	public static CryptUtil getInstance() {
		return INSTANCE;
	}

	/**
	 * 产生随机的密钥 例如：“xjPk2rOSU1n5v70a84M+vw==”
	 * 
	 * @return 随机密钥
	 */
	public String generateRandomKeyStr(CipherType type) {
		SecretKey key;
		try {
			key = KeyGenerator.getInstance(type.toString()).generateKey();
			return new String(Base64.encodeBase64(key.getEncoded()));
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}

	/**
	 * 加密文本
	 * 
	 * @param str
	 *            明文
	 * @param password
	 *            密钥
	 * @param type
	 *            密码类型
	 * @return 密文
	 */
	public String encrypt(String str, String password, CipherType type) {
		try {
			Key key = initKey(type.toString(), password);
			// 创建密码器
			Cipher cipher = Cipher.getInstance(type.toString());
			byte[] byteContent = str.getBytes("utf-8");
			// 初始化
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] result = cipher.doFinal(byteContent);
			String strResult = new String(Base64.encodeBase64(result));
			return strResult;
		} catch (IOException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 解密
	 * 
	 * @param str
	 *            密文
	 * @param password
	 *            密钥
	 * @param type
	 *            密码算法
	 * @return 明文
	 */
	public String decrypt(String str, String password, CipherType type) {
		try {
			Key key = initKey(type.toString(), password);
			// 创建密码器
			Cipher cipher = Cipher.getInstance(type.toString());
			// 初始化
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] result = cipher.doFinal(Base64.decodeBase64(str.getBytes()));
			String strResult = new String(result, "utf-8");
			return strResult;
		} catch (IOException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 初始化密钥
	 * 
	 * @param cryptType
	 *            加密算法类型
	 * @param key
	 *            密钥
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private Key initKey(String cryptType, String password) throws NoSuchAlgorithmException {
		KeyGenerator kgen = KeyGenerator.getInstance(cryptType);
		switch (cryptType) {
		case "AES":
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(password.getBytes());
			kgen.init(256, random);
			break;
		case "DES":
			kgen.init(56, new SecureRandom(password.getBytes()));
			break;
		default:
			break;
		}
		SecretKey secretKey = kgen.generateKey();
		byte[] enCodeFormat = secretKey.getEncoded();
		SecretKeySpec key = new SecretKeySpec(enCodeFormat, cryptType);
		return key;
	}

	public static void main(String[] args) {
		String randomKey = "|5d~k.aEq!W!!D$lL5k2N.unfW@Wn\"O+";
		System.out.println("randomKey:" + randomKey);
		String message = "2017032016@&]JLg[4L5TWqX`ME_2e('tyo2T^?I8d  (";
		System.out.println("加密前明文:" + message);
		String s1 = CryptUtil.getInstance().encrypt(message, randomKey, CipherType.AES);
		System.out.println("加密后的信息：" + s1);
		String s2 = CryptUtil.getInstance().decrypt(s1, randomKey, CipherType.AES);
		System.out.println("解密后的信息：" + s2);
		System.out.println("");
		message = "{\"status\":true,\"data\":{\"id\":\"accountaccountaccountaccountaccoaccountaccountaccountaccountacco\",\"account\":\"accountaccountaccountaccountacco\",\"loginName\":\"accountaccountaccountaccountacco,accountaccountaccountaccountacco,ididididididididid,accountaccountaccountaccountacco\"}}";
		String s3 = CryptUtil.getInstance().encrypt(message, randomKey, CipherType.AES);
		System.out.println("加密后的信息：" + s3);
		String s4 = CryptUtil.getInstance().decrypt(s3, randomKey, CipherType.AES);
		System.out.println("解密后的信息：" + s4);
		System.out.println("");
		String secureText = "mqvkvU4Uj6mNNYEzfgQLWRNO+iwm/wK6BFSbmXYqW0wuDiYQaEFuc/QmYWWDeqXv";
		String password = "2018011715MR98T]o99/nAkpUM'1veo\\v2T@;_z@S5";
		String s5 = CryptUtil.getInstance().decrypt(secureText, randomKey, CipherType.AES);
		System.out.println("s5解密后信息：" + s5);
	}
}
