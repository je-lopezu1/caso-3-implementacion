package Servidor;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class KeyGenerator {

    public static PublicKey publicKey = null;
    public static PrivateKey privateKey = null;

    // Método para generar y almacenar las llaves asimétricas
    public static void generateAndStoreKeys() {
        try {
            // Generador de pares de llaves
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(1024); // Longitud de llave de 1024 bits
            
            // Generación del par de llaves
            KeyPair keyPair = keyPairGen.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();

            // Convertir las llaves a formato String (Base64)
            String publicKeyEncoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            String privateKeyEncoded = Base64.getEncoder().encodeToString(privateKey.getEncoded());

            // Guardar las llaves en archivos separados
            try (FileWriter publicFileWriter = new FileWriter("src/Cliente/publicKeys.txt", false);
                 FileWriter privateFileWriter = new FileWriter("src/Servidor/privateKeys.txt", false)) {
                 
                // Escribir ID de sesión y llave en cada archivo
                publicFileWriter.write(publicKeyEncoded);
                privateFileWriter.write(privateKeyEncoded);


            }

            System.out.println("Llaves generadas y almacenadas para la sesión");

        } catch (Exception e) {
            System.err.println("Error al generar o almacenar llaves: " + e.getMessage());
        }
    }

    // Método para obtener la llave pública
    public static PublicKey getPublicKey() {
        return publicKey;
    }

    // Método para obtener la llave privada
    public static PrivateKey getPrivateKey() {
        return privateKey;
    }
    
}
