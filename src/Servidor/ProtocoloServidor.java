package Servidor;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.PrivateKey;

import javax.crypto.Cipher;

public class ProtocoloServidor {
    public static void procesar(BufferedReader pIn, PrintWriter pOut, PrivateKey privateKey) throws IOException {
    String inputLine;
    String outputLine;
    int estado = 0;

    while (estado < 3 && (inputLine = pIn.readLine()) != null) {
        System.out.println("Entrada a procesar: " + inputLine);
        switch (estado) {
            case 0:
                try{
                    byte[] mensaje = inputLine.getBytes();
                    BigInteger rta = desencriptarReto(mensaje, privateKey);
                    estado++;
                    outputLine = "R recibido";
                } catch (Exception e) {
                    outputLine = "ERROR en argumento esperado";
                    estado = 0;
                }
                break;

            case 1:
                try {
                    int val = Integer.parseInt(inputLine);
                    val--;
                    outputLine = "" + val;
                    estado++;
                } catch (Exception e) {
                    outputLine = "ERROR en argumento esperado";
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
