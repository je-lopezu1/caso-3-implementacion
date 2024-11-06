package Servidor;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ProtocoloServidor {
    private static BigInteger P;
    private static BigInteger x;
    private static SecretKey K_AB1;
    private static SecretKey K_AB2;
    private static IvParameterSpec vectorIV;

    public static void procesar(BufferedReader pIn, PrintWriter pOut, PrivateKey privateKey, BaseDatos baseDatos) throws Exception {
    String inputLine;
    String outputLine;
    int estado = 0;
    
    

    while (estado < 4 && (inputLine = pIn.readLine()) != null) { //TODO cambiar max estados
        System.out.println("Entrada a procesar: " + inputLine);
        switch (estado) {
            case 0: //VERIFICACIÓN DEL RETO
                try{

                    byte[] mensaje = Base64.getDecoder().decode(inputLine);
                    BigInteger rta = desencriptarReto(mensaje, privateKey);
                    String rtaString = Base64.getEncoder().encodeToString(rta.toByteArray());
                    estado++;
                    outputLine = rtaString;
                    pOut.println(outputLine);
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
                    P = new BigInteger(pHex.toString(), 16);
                    BigInteger G = new BigInteger(gValue);

                    // Imprimir los valores de P y G
                    System.out.println("Valor de P: " + P);
                    System.out.println("Valor de G: " + G);

                    // Generar un valor aleatorio x y calcular G^x mod P
                    x = new BigInteger(1024, new java.security.SecureRandom());
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
                    pOut.println(outputLine);

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
                    //String firmaString = signature.sign().toString();
                    String firmaString = Base64.getEncoder().encodeToString(firmaBytes);

                    //System.out.println(firmaBytes);
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
                String GYstring = pIn.readLine();
                byte[] GYbytes = Base64.getDecoder().decode(GYstring);
                BigInteger GY = new BigInteger(GYbytes);
                System.out.println("Valor de G^y: " + GY);
                //Calcular (G^y)^x mod P para obtener la misma clave compartida
                BigInteger sharedSecret = GY.modPow(x, P);
                System.out.println("Clave compartida (G^y)^x mod P: " + sharedSecret);

                //Derivar K_AB1 y K_AB2 a partir de la clave compartida
                byte[] sharedSecretBytes = sharedSecret.toByteArray();

                //Calcular K_AB1 y K_AB2 usando SHA-512 y dividir en dos mitades
                MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                byte[] hash = sha512.digest(sharedSecretBytes);
                
                // Dividir el hash en dos partes para obtener K_AB1 y K_AB2
                byte[] K_AB1bytes = new byte[32];
                byte[] K_AB2bytes = new byte[32];
                System.arraycopy(hash, 0, K_AB1bytes, 0, 32);
                System.arraycopy(hash, 32, K_AB2bytes, 0, 32);
                String K_AB1st = Base64.getEncoder().encodeToString(K_AB1bytes);
                String K_AB2st = Base64.getEncoder().encodeToString(K_AB2bytes);
                System.out.println("K_AB1: " + K_AB1st);
                System.out.println("K_AB2: " + K_AB2st);
                K_AB1 = new SecretKeySpec(K_AB1bytes, "AES");
                K_AB2 = new SecretKeySpec(K_AB2bytes, "HmacSHA384");
                // Crear un arreglo de 16 bytes para el IV
                byte[] iv = new byte[16];
                // Usar SecureRandom para llenar el arreglo con valores aleatorios
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(iv);
                vectorIV = new IvParameterSpec(iv);
                byte[] IVbytes = vectorIV.getIV();
                //String ivString = vectorIV.toString();
                String ivString = Base64.getEncoder().encodeToString(IVbytes);
                pOut.println(ivString);
                
                
                
                //System.out.println("iv: " + ivString);
                //System.out.println("iv: " + vectorIV);
                //mandar vector
                
                estado++;
                break;
            case 3:
                String id_cifrado_string = inputLine;
                System.out.println("id de usuario cifrado: " + id_cifrado_string);

                String id_hmac_string = pIn.readLine();
                System.out.println("id con hmac: " + id_hmac_string);

                String id_descifrado_string = desencriptarID(id_cifrado_string, K_AB1, vectorIV);
                System.out.println("id usuario decifrado: " + id_descifrado_string);

                boolean verificado = desencriptarHMAC(id_descifrado_string, id_hmac_string, K_AB2);
                System.out.println("verificación de integridad con hmac: " + verificado);

                String idpaquete_cifrado_String = pIn.readLine();
                System.out.println("id de paquete cifrado: " + idpaquete_cifrado_String);

                String idpaquete_hmac_string = pIn.readLine();
                System.out.println("id paquete con hmac: " + idpaquete_hmac_string);

                String idpaquete_descifrado_string = desencriptarID(idpaquete_cifrado_String, K_AB1, vectorIV);
                System.out.println("id paquete decifrado: " + idpaquete_descifrado_string);

                boolean verificadoPaquete = desencriptarHMAC(idpaquete_descifrado_string, idpaquete_hmac_string, K_AB2);
                System.out.println("verificación de integridad con hmac: " + verificadoPaquete);

                System.out.println("Consultando la base de datos...");
                String estadoPaquete = obtenerEstado(id_descifrado_string, idpaquete_descifrado_string, baseDatos);
                String estadoPaqueteCifrado = cifrarID(estadoPaquete, K_AB1, vectorIV);
                String estadoPaqueteHMAC = generarHMAC(estadoPaquete, K_AB2);
                pOut.println(estadoPaqueteCifrado);
                pOut.println(estadoPaqueteHMAC);
                System.out.println("Enviando estado de paquete al usuario...");
                estado++;



            default:
                outputLine = "ERROR";
                estado = 0;
                break;
        }
        //pOut.println(outputLine);
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

     // Método para descifrar el ID con la clave K_AB1 y el IV recibido
    public static String desencriptarID(String encryptedIdBase64, SecretKey K_AB1, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, K_AB1, ivSpec);
        byte[] decryptedIdBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedIdBase64));
        return new String(decryptedIdBytes); // Devuelve el ID descifrado como String
    }

     // Método para generar HMAC del ID con la clave K_AB2 y verificar con el HMAC recibido
    public static boolean desencriptarHMAC(String id, String hmacBase64, SecretKey K_AB2) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA384");
        hmac.init(K_AB2);
        byte[] computedHmac = hmac.doFinal(Base64.getDecoder().decode(id));

        // Decodificar el HMAC recibido en Base64 y compararlo con el HMAC calculado
        byte[] receivedHmac = Base64.getDecoder().decode(hmacBase64);
        return MessageDigest.isEqual(computedHmac, receivedHmac); // Compara ambos HMACs
    }

    public static String obtenerEstado(String id, String id_pedido, BaseDatos baseDatos)
    {
        return baseDatos.obtenerEstadoPaquete(id, id_pedido);
    }

      // Método para cifrar el ID con la clave K_AB1
      public static String cifrarID(String Id, SecretKey K_AB1, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, K_AB1, ivSpec);
        byte[] encryptedId = cipher.doFinal(Id.getBytes());
        return Base64.getEncoder().encodeToString(encryptedId);
    }

    // Método para generar HMAC del ID con la clave K_AB2
    public static String generarHMAC(String Id, SecretKey K_AB2) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA384");
        hmac.init(K_AB2);
        byte[] hmacBytes = hmac.doFinal(Base64.getDecoder().decode(Id));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }


}
