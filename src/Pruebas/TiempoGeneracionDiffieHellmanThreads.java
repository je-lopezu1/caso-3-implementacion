package Pruebas;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TiempoGeneracionDiffieHellmanThreads {

    public static void main(String[] args) throws Exception {
        // Lista para almacenar los threads
        List<Thread> threads = new ArrayList<>();

        // Iniciar medición de tiempo
        long startTime = System.nanoTime();

        // Crear y ejecutar n threads
        for (int i = 0; i < 100; i++) {
            Thread thread = new Thread(new GeneracionPGxTask(i));
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
        System.out.println("Tiempo total para generar P, G y G^x con n threads: " + durationInMillis + " ms");
    }
}

// Clase Runnable para generar P, G y G^x en un thread
class GeneracionPGxTask implements Runnable {
    private final int threadId;

    public GeneracionPGxTask(int threadId) {
        this.threadId = threadId;
    }

    @Override
    public void run() {
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
            System.err.println("Error en el thread " + threadId + ": " + e.getMessage());
        }
    }

  
}
