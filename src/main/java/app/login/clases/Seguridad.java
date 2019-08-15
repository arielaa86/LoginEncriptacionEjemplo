/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package app.login.clases;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author ariel
 */
public class Seguridad {

    public static String getSimplePassword(String passwordToHash) {

        String generatedPassword = null;
        try {
            
            
            //Tanto algoritmo MD5 como SHA-512 son vulnerables a ataques de fuerza bruta, 
            //por lo que hay métodos más seguros

            MessageDigest md = MessageDigest.getInstance("MD5");

             //Puedes utilizar SHA-512 para dar más seguridad 
//            MessageDigest md = MessageDigest.getInstance("SHA-512");

            md.update(passwordToHash.getBytes());

            byte[] bytes = md.digest();

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }

            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return generatedPassword;

    }

    public static String getSecurePassword(String passwordToHash) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        String generatedPassword = null;

        
        //utilizando algoritmo PBKDF2WithHmacSHA1 
        // El terccer parametro es la cantidad de iteraciones
        //que el algoritmo tomará para generar le hash. 
        // cámbialo de acuerdo a las caracteristicas de la máquina donde correrá.
        
        KeySpec spec = new PBEKeySpec(passwordToHash.toCharArray(), passwordToHash.getBytes(), 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = factory.generateSecret(spec).getEncoded();

        try {

            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(hash);

            byte[] bytes = md.digest(passwordToHash.getBytes());

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }

            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return generatedPassword;
    }

    private static byte[] getSalt() throws NoSuchAlgorithmException, NoSuchProviderException {

        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        return salt;
    }

}
