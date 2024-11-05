import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import Cliente.Cliente;
import Servidor.Servidor;
import Servidor.KeyGenerator;

public class App {
   
    public static void main(String[] args) throws Exception {
        try {
            // Ejecuta el comando OpenSSL
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
            System.err.println("Error al ejecutar el comando o parsear la salida: " + e.getMessage());
        }
    }

    public static void opcion1() {
        KeyGenerator.generateAndStoreKeys();
    }
}
