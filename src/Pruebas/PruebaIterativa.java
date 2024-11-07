package Pruebas;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PruebaIterativa {

    public static void pruebaverificar() {
        try {
        
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(1024); // Longitud de la clave RSA
            KeyPair keyPair = keyPairGen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();

            // Mensaje a cifrar
            String mensaje = "Mensaje secreto";
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] mensajeCifrado = cipher.doFinal(mensaje.getBytes());
            System.out.println("Mensaje cifrado (Base64): " + Base64.getEncoder().encodeToString(mensajeCifrado));

            
            long startTime = System.nanoTime();

            for (int i = 0; i < 32; i++) {
                // Inicializar el cifrador en modo de descifrado para cada iteración
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] mensajeDescifrado = cipher.doFinal(mensajeCifrado);

            }

           
            long endTime = System.nanoTime();

            // Cálculo del tiempo transcurrido en milisegundos
            long durationInMillis = (endTime - startTime) / 1_000_000;
            System.out.println("Tiempo total de descifrado para 32 mensajes: " + durationInMillis + " ms");

            // Cálculo del tiempo promedio por mensaje en milisegundos
            double averageTimePerMessage = durationInMillis / 32.0;
            System.out.println("Tiempo promedio de descifrado por mensaje: " + averageTimePerMessage + " ms");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void pruebaValores() {
        // Parámetros de Diffie-Hellman
        int bitLength = 1024; // Longitud de los valores de P y G en bits
        SecureRandom random = new SecureRandom();

        // Medición de tiempo para la generación de P, G y G^x en 32 iteraciones
        long startTime = System.nanoTime();

        for (int i = 0; i < 32; i++) {
           try {
            // Ejecutar el comando openssl para generar P y G
            @SuppressWarnings("deprecation")
                    Process process = Runtime.getRuntime().exec("openssl dhparam -text 1024");

                    // Lee la salida del comando
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String line;
                    StringBuilder output = new StringBuilder();

                    // Almacena toda la salida para procesarla después
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                    }
                    reader.close();
                    process.waitFor();

                    // Convertir la salida completa en un String
                    String opensslOutput = output.toString();

                    // Expresiones regulares para capturar los valores de P y G
                    Pattern pPattern = Pattern.compile("P:\\s+((?:[0-9a-f]{2}:)+[0-9a-f]{2})", Pattern.CASE_INSENSITIVE);
                    Pattern gPattern = Pattern.compile("G:\\s+(\\d+)", Pattern.CASE_INSENSITIVE);

                    // Buscar el valor de P
                    Matcher pMatcher = pPattern.matcher(opensslOutput);
                    StringBuilder pHex = new StringBuilder();
                    if (pMatcher.find()) {
                        pHex.append(pMatcher.group(1).replace(":", ""));
                    }

                    // Buscar el valor de G
                    Matcher gMatcher = gPattern.matcher(opensslOutput);
                    String gValue = null;
                    if (gMatcher.find()) {
                        gValue = gMatcher.group(1);
                    }

                    // Convertir P y G a BigInteger
                    BigInteger P = new BigInteger(pHex.toString(), 16);
                    BigInteger G = new BigInteger(gValue);

                    // Imprimir los valores de P y G
                    System.out.println("Valor de P: " + P);
                    System.out.println("Valor de G: " + G);

                    // Generar un valor aleatorio x y calcular G^x mod P
                    BigInteger x = new BigInteger(1024, new java.security.SecureRandom());
                    BigInteger Gx = G.modPow(x, P);
                    System.out.println("Valor de G^x mod P: " + Gx);

        } catch (Exception e) {
            System.err.println("Error en el thread " + e.getMessage());
        }
        }

        // Finalizar medición de tiempo
        long endTime = System.nanoTime();

        // Calcular tiempo total y promedio en milisegundos
        long durationInMillis = (endTime - startTime) / 1_000_000;
        double averageTimePerIteration = durationInMillis / 32.0;

        System.out.println("Tiempo total para generar P, G y G^x en 32 iteraciones: " + durationInMillis + " ms");
        System.out.println("Tiempo promedio por iteración: " + averageTimePerIteration + " ms");
    }


    public static void pruebaConsulta() {
        try {
            // Inicializar claves de cifrado y HMAC
            byte[] K_AB1_bytes = new byte[32]; // Clave simétrica para cifrado de usuario y paquete
            byte[] K_AB2_bytes = new byte[32]; // Clave simétrica para HMAC
            SecureRandom random = new SecureRandom();
            random.nextBytes(K_AB1_bytes);
            random.nextBytes(K_AB2_bytes);

            SecretKey K_AB1 = new SecretKeySpec(K_AB1_bytes, "AES");
            SecretKey K_AB2 = new SecretKeySpec(K_AB2_bytes, "HmacSHA384");

            // Mensajes de ejemplo
            String idUsuario = "user12345";
            String idPaquete = "package123";

            // Generar IV
            IvParameterSpec ivSpec = generateIV();

            // Cifrar el id del usuario
            String encryptedIdUsuario = encryptWithSymmetricKey(idUsuario, K_AB1, ivSpec);
            String hmacIdUsuario = generateHmac(idUsuario, K_AB2);

            // Cifrar el id del paquete
            String encryptedIdPaquete = encryptWithSymmetricKey(idPaquete, K_AB1, ivSpec);
            String hmacIdPaquete = generateHmac(idPaquete, K_AB2);

            // Medir tiempo de verificación de 32 consultas
            long startTime = System.nanoTime();

            for (int i = 0; i < 32; i++) {
                // Descifrar y verificar el id de usuario
                String decryptedIdUsuario = decryptWithSymmetricKey(encryptedIdUsuario, K_AB1, ivSpec);
                boolean isHmacUsuarioValid = verifyHmac(decryptedIdUsuario, hmacIdUsuario, K_AB2);

                // Descifrar y verificar el id de paquete
                String decryptedIdPaquete = decryptWithSymmetricKey(encryptedIdPaquete, K_AB1, ivSpec);
                boolean isHmacPaqueteValid = verifyHmac(decryptedIdPaquete, hmacIdPaquete, K_AB2);

                // Verificar que ambos HMAC sean válidos
                if (!isHmacUsuarioValid || !isHmacPaqueteValid) {
                    System.out.println("Consulta no válida en la iteración " + i);
                }
            }

            long endTime = System.nanoTime();

            // Calcular tiempo total y promedio en milisegundos
            long durationInMillis = (endTime - startTime) / 1_000_000;
            double averageTimePerIteration = durationInMillis / 32.0;

            System.out.println("Tiempo total de verificación para 32 consultas: " + durationInMillis + " ms");
            System.out.println("Tiempo promedio por consulta: " + averageTimePerIteration + " ms");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Método para generar un IV de 16 bytes
    private static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Método para cifrar un mensaje con una clave simétrica y IV
    private static String encryptWithSymmetricKey(String message, SecretKey key, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Método para descifrar un mensaje con una clave simétrica y IV
    private static String decryptWithSymmetricKey(String encryptedMessage, SecretKey key, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }

    // Método para generar HMAC
    private static String generateHmac(String message, SecretKey key) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA384");
        hmac.init(key);
        byte[] hmacBytes = hmac.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    // Método para verificar HMAC
    private static boolean verifyHmac(String message, String hmacBase64, SecretKey key) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA384");
        hmac.init(key);
        byte[] computedHmac = hmac.doFinal(message.getBytes());
        byte[] receivedHmac = Base64.getDecoder().decode(hmacBase64);
        return MessageDigest.isEqual(computedHmac, receivedHmac);
    }

    public static void comparacionSimetricoAsimetrico() {
        try {
            // Estado del paquete a cifrar
            String estadoPaquete = "12"; // Ejemplo de estado

            // Claves para cifrado simétrico (AES)
            byte[] K_AB1_bytes = new byte[32];
            SecureRandom random = new SecureRandom();
            random.nextBytes(K_AB1_bytes);
            SecretKey K_AB1 = new SecretKeySpec(K_AB1_bytes, "AES");
            IvParameterSpec ivSpec = generateIV();

            // Par de claves para cifrado asimétrico (RSA)
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(1024);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Tiempo de cifrado simétrico en 32 iteraciones
            long startTimeSymmetric = System.nanoTime();
            for (int i = 0; i < 32; i++) {
                String encryptedEstadoSimetrico = encryptWithSymmetricKey(estadoPaquete, K_AB1, ivSpec);
               
               
            }
            long endTimeSymmetric = System.nanoTime();

            // Tiempo de cifrado asimétrico en n iteraciones
            long startTimeAsymmetric = System.nanoTime();
            for (int i = 0; i < 10000; i++) {
                String encryptedEstadoAsimetrico = encryptWithAsymmetricKey(estadoPaquete, publicKey);
               
               
            }
            long endTimeAsymmetric = System.nanoTime();

            // Cálculo de tiempos para cifrado simétrico
            long durationSymmetricMillis = (endTimeSymmetric - startTimeSymmetric) / 1_000_000;
            double averageSymmetricMillis = durationSymmetricMillis / 32.0;
            System.out.println("Tiempo total de cifrado simétrico (AES) en n iteraciones: " + durationSymmetricMillis + " ms");
            System.out.println("Tiempo promedio de cifrado simétrico por iteración: " + averageSymmetricMillis + " ms");

            // Cálculo de tiempos para cifrado asimétrico
            long durationAsymmetricMillis = (endTimeAsymmetric - startTimeAsymmetric) / 1_000_000;
            double averageAsymmetricMillis = durationAsymmetricMillis / 32.0;
            System.out.println("Tiempo total de cifrado asimétrico (RSA) en n iteraciones: " + durationAsymmetricMillis + " ms");
            System.out.println("Tiempo promedio de cifrado asimétrico por iteración: " + averageAsymmetricMillis + " ms");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }



    // Método para cifrar un mensaje con cifrado asimétrico (RSA)
    private static String encryptWithAsymmetricKey(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    public static void main(String[] args) 
    {
        pruebaverificar();
        pruebaValores();
        pruebaConsulta();
        comparacionSimetricoAsimetrico();

    }
    
}
