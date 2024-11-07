package Pruebas;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class TiempoVerificacionConsultaThreads {

    public static void main(String[] args) throws Exception {
        // Claves simétricas y IV para cifrado y HMAC
        byte[] K_AB1_bytes = new byte[32]; // Clave para cifrado de usuario y paquete
        byte[] K_AB2_bytes = new byte[32]; // Clave para HMAC
        SecureRandom random = new SecureRandom();
        random.nextBytes(K_AB1_bytes);
        random.nextBytes(K_AB2_bytes);

        SecretKey K_AB1 = new SecretKeySpec(K_AB1_bytes, "AES");
        SecretKey K_AB2 = new SecretKeySpec(K_AB2_bytes, "HmacSHA384");
        IvParameterSpec ivSpec = generateIV();

        // Mensajes de ejemplo
        String idUsuario = "user12345";
        String idPaquete = "package123";

        // Generar cifrado y HMAC para idUsuario
        String encryptedIdUsuario = encryptWithSymmetricKey(idUsuario, K_AB1, ivSpec);
        String hmacIdUsuario = generateHmac(idUsuario, K_AB2);

        // Generar cifrado y HMAC para idPaquete
        String encryptedIdPaquete = encryptWithSymmetricKey(idPaquete, K_AB1, ivSpec);
        String hmacIdPaquete = generateHmac(idPaquete, K_AB2);

        // Lista para almacenar los threads
        List<Thread> threads = new ArrayList<>();

        // Iniciar medición de tiempo
        long startTime = System.nanoTime();

        // Crear y ejecutar n threads para realizar la verificación
        for (int i = 0; i < 100; i++) {
            Thread thread = new Thread(new VerificacionConsultaTask(encryptedIdUsuario, hmacIdUsuario, encryptedIdPaquete, hmacIdPaquete, K_AB1, K_AB2, ivSpec, i));
            threads.add(thread);
            thread.start();
        }

        // Esperar a que todos los threads terminen
        for (Thread thread : threads) {
            thread.join();
        }

        // Fin de la medición de tiempo
        long endTime = System.nanoTime();

        // Calcular tiempo total en milisegundos
        long durationInMillis = (endTime - startTime) / 1_000_000;
        System.out.println("Tiempo total para verificar n consultas con threads: " + durationInMillis + " ms");
    }

    // Clase Runnable para verificar la consulta en un thread
    static class VerificacionConsultaTask implements Runnable {
        private final String encryptedIdUsuario;
        private final String hmacIdUsuario;
        private final String encryptedIdPaquete;
        private final String hmacIdPaquete;
        private final SecretKey K_AB1;
        private final SecretKey K_AB2;
        private final IvParameterSpec ivSpec;
        private final int threadId;

        public VerificacionConsultaTask(String encryptedIdUsuario, String hmacIdUsuario, String encryptedIdPaquete, String hmacIdPaquete, SecretKey K_AB1, SecretKey K_AB2, IvParameterSpec ivSpec, int threadId) {
            this.encryptedIdUsuario = encryptedIdUsuario;
            this.hmacIdUsuario = hmacIdUsuario;
            this.encryptedIdPaquete = encryptedIdPaquete;
            this.hmacIdPaquete = hmacIdPaquete;
            this.K_AB1 = K_AB1;
            this.K_AB2 = K_AB2;
            this.ivSpec = ivSpec;
            this.threadId = threadId;
        }

        @Override
        public void run() {
            try {
                // Descifrar el id de usuario y verificar el HMAC
                String decryptedIdUsuario = decryptWithSymmetricKey(encryptedIdUsuario, K_AB1, ivSpec);
                boolean isHmacUsuarioValid = verifyHmac(decryptedIdUsuario, hmacIdUsuario, K_AB2);

                // Descifrar el id de paquete y verificar el HMAC
                String decryptedIdPaquete = decryptWithSymmetricKey(encryptedIdPaquete, K_AB1, ivSpec);
                boolean isHmacPaqueteValid = verifyHmac(decryptedIdPaquete, hmacIdPaquete, K_AB2);

                // Verificación de la validez en cada thread
                if (isHmacUsuarioValid && isHmacPaqueteValid) {
                    System.out.println("Thread " + threadId + " - Consulta válida.");
                } else {
                    System.out.println("Thread " + threadId + " - Consulta no válida.");
                }
            } catch (Exception e) {
                System.err.println("Error en el thread " + threadId + ": " + e.getMessage());
            }
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
}
