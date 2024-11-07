package Pruebas;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class TiempoDescifradoAsimetricoThreads {

    public static void main(String[] args) throws Exception {
        // Generar un par de llaves RSA para el ejemplo
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024); // Longitud de la clave RSA
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        // Mensaje a cifrar (para descifrarlo en los threads)
        String mensaje = "Mensaje secreto";
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // Cifrar el mensaje una vez para simular 32 descifrados del mismo mensaje
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] mensajeCifrado = cipher.doFinal(mensaje.getBytes());
        System.out.println("Mensaje cifrado (Base64): " + Base64.getEncoder().encodeToString(mensajeCifrado));

        // Lista para almacenar los threads
        List<Thread> threads = new ArrayList<>();

        // Iniciar medición de tiempo
        long startTime = System.nanoTime();

        // Crear y ejecutar n threads
        for (int i = 0; i < 100; i++) {
            Thread thread = new Thread(new DescifradoAsimetricoTask(privateKey, mensajeCifrado, i));
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
        System.out.println("Tiempo total de descifrado con n threads: " + durationInMillis + " ms");
    }
}

// Clase Runnable para realizar el descifrado asimétrico en un thread
class DescifradoAsimetricoTask implements Runnable {
    private final PrivateKey privateKey;
    private final byte[] mensajeCifrado;
    private final int threadId;

    public DescifradoAsimetricoTask(PrivateKey privateKey, byte[] mensajeCifrado, int threadId) {
        this.privateKey = privateKey;
        this.mensajeCifrado = mensajeCifrado;
        this.threadId = threadId;
    }

    @Override
    public void run() {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] mensajeDescifrado = cipher.doFinal(mensajeCifrado);
            System.out.println("Thread " + threadId + " - Mensaje descifrado: " + new String(mensajeDescifrado));
        } catch (Exception e) {
            System.err.println("Error en el thread " + threadId + ": " + e.getMessage());
        }
    }
}
