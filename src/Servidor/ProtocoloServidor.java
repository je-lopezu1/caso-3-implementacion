package Servidor;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class ProtocoloServidor {
    public static void procesar(BufferedReader pIn, PrintWriter pOut, PrivateKey privateKey) throws IOException {
    String inputLine;
    String outputLine;
    int estado = 0;

    while (estado < 3 && (inputLine = pIn.readLine()) != null) {
        System.out.println("Entrada a procesar: " + inputLine);
        switch (estado) {
            case 0: //VERIFICACIÓN DEL RETO
                try{

                    byte[] mensaje = Base64.getDecoder().decode(inputLine);
                    BigInteger rta = desencriptarReto(mensaje, privateKey);
                    String rtaString = Base64.getEncoder().encodeToString(rta.toByteArray());
                    estado++;
                    outputLine = rtaString;
                } catch (Exception e) {
                    outputLine = "ERROR en argumento esperado";
                    estado = 0;
                }
                break;

            case 1: //GENERAR Y MANDAR FIRMA
                try {
                    // Ejecutar el comando OpenSSL para obtener G y P
                    
                    @SuppressWarnings("deprecation")
                    Process process = Runtime.getRuntime().exec("openssl dhparam -text 1024");
                    System.out.println(process);

                    // Leer la salida del comando
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String line;
                    StringBuilder gHex = new StringBuilder();
                    StringBuilder pHex = new StringBuilder();
                    boolean readingP = false, readingG = false;

                    // Procesar la salida para extraer G y P en formato hexadecimal
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (line.startsWith("prime")) {
                            readingP = true;
                            readingG = false;
                        } else if (line.startsWith("generator")) {
                            readingG = true;
                            readingP = false;
                        } else if (readingP && !line.isEmpty()) {
                            pHex.append(line);  // Concatenar cada línea de P
                        } else if (readingG && !line.isEmpty()) {
                            gHex.append(line);  // Concatenar cada línea de G
                        }
                    }

                    process.waitFor();  // Esperar a que el proceso termine

                    
                    // Convertir G y P a BigInteger
                    BigInteger G = new BigInteger(gHex.toString(), 16);
                    System.out.println(G);
                    BigInteger P = new BigInteger(pHex.toString(), 16);

                    // Generar un valor aleatorio para x
                    BigInteger x = new BigInteger(1024, new java.security.SecureRandom());

                    // Calcular G^x mod P
                    BigInteger Gx = G.modPow(x, P);
                    

                    // Puedes almacenar estos valores o enviarlos según lo que necesites en el caso 1
                    System.out.println("Valor de G: " + G);
                    System.out.println("Valor de P: " + P);
                    System.out.println("Valor de G^x mod P: " + Gx);
                    outputLine = "ADIOS";
                    // Incrementar el estado si todo se ejecuta correctamente
                    estado++;

                } catch (Exception e) {
                    outputLine = "ERROR en argumento esperado";
                    estado = 0;
                    System.err.println("Error en la generación de G, P o G^x: " + e.getMessage());
                }
                break;

            case 2:
                if (inputLine.equalsIgnoreCase("OK")) {
                    outputLine = "ADIOS";
                    estado++;
                } else {
                    outputLine = "ERROR. Esperaba OK";
                    estado = 0;
                }
                break;

            default:
                outputLine = "ERROR";
                estado = 0;
                break;
        }
        pOut.println(outputLine);
        }
    }

    // Método para descifrar un mensaje cifrado con la llave privada
    public static BigInteger desencriptarReto(byte[] encryptedMessage, PrivateKey privateKey) {
        try {
            // Configurar el cifrador con el algoritmo RSA y la llave privada
            System.out.println("Desencriptando mensaje");
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            System.out.println("Mensaje cifrado: " + encryptedMessage);
            // Descifrar el mensaje
            byte[] decryptedBytes = cipher.doFinal(encryptedMessage);

            System.out.println("Mensaje descifrado: " + decryptedBytes);
            // Convertir los bytes descifrados a BigInteger
            return new BigInteger(decryptedBytes);
        } catch (Exception e) {
            System.err.println("Error al descifrar el mensaje: " + e.getMessage());
            return null;
        }
    }

}
