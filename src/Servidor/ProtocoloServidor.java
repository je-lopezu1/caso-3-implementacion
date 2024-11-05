package Servidor;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;

public class ProtocoloServidor {
    public static void procesar(BufferedReader pIn, PrintWriter pOut, PrivateKey privateKey) throws IOException {
    String inputLine;
    String outputLine;
    int estado = 0;

    while (estado < 3 && (inputLine = pIn.readLine()) != null) { //TODO cambiar max estados
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

                    String Pstring = Base64.getEncoder().encodeToString(P.toByteArray());
                    String Gstring = Base64.getEncoder().encodeToString(G.toByteArray());
                    String GXstring = Base64.getEncoder().encodeToString(Gx.toByteArray());
                    //Mandar P,G y G^X
                    outputLine = Pstring;
                    pOut.println(outputLine);
                    outputLine = Gstring;
                    pOut.println(outputLine);
                    outputLine = GXstring;

                            // Convertir los valores de G, P, y Gx a bytes y concatenarlos
                    byte[] gBytes = G.toByteArray();
                    byte[] pBytes = P.toByteArray();
                    byte[] gxBytes = Gx.toByteArray();

                    // Concatenar todos los bytes en un solo arreglo
                    byte[] dataToSign = new byte[gBytes.length + pBytes.length + gxBytes.length];
                    System.arraycopy(gBytes, 0, dataToSign, 0, gBytes.length);
                    System.arraycopy(pBytes, 0, dataToSign, gBytes.length, pBytes.length);
                    System.arraycopy(gxBytes, 0, dataToSign, gBytes.length + pBytes.length, gxBytes.length);

                    // Configurar el objeto Signature con SHA1withRSA y la llave privada
                    Signature signature = Signature.getInstance("SHA1withRSA");
                    signature.initSign(privateKey);

                    // Firmar los datos
                    signature.update(dataToSign);
                    byte[] firmaBytes = signature.sign(); // Devuelve la firma como arreglo de bytes
                    BigInteger firma = new BigInteger(firmaBytes);
                    String firmaString = Base64.getEncoder().encodeToString(firma.toByteArray());
                    System.out.println(firmaBytes);
                    outputLine = firmaString;
                    pOut.println(outputLine);
                    estado++;

                } catch (Exception e) {
                    outputLine = "ERROR en argumento esperado";
                    System.err.println("Error al ejecutar el comando o parsear la salida o al procesar la firma: " + e.getMessage());
                    estado = 0;
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
