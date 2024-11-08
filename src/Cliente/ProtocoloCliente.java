package Cliente;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ProtocoloCliente {
    private static SecretKey K_AB1;
    private static SecretKey K_AB2;

    public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut, PublicKey publicKey) throws Exception {
        String fromServer;
        String fromUser;

        boolean ejecutar = true;

        while (ejecutar) {
            pOut.println("SECINIT");
            //VERIFICACIÓN DE RETO
            BigInteger reto = new BigInteger(256, new java.util.Random());
            byte[] retoCifrado = cifrarReto(reto, publicKey);
            String retoCifradoStr = Base64.getEncoder().encodeToString(retoCifrado);
            //manda mensaje cifrado al servidor
            fromUser = retoCifradoStr;
            pOut.println(fromUser);
            // lee la respuesta del servidor
            if ((fromServer = pIn.readLine()) != null) {
                System.out.println("Reto recibido: " + fromServer);
            }
            byte[] rtaBytes = Base64.getDecoder().decode(fromServer);
            BigInteger rtaConverted = new BigInteger(rtaBytes);
            boolean verificacion = reto.equals(rtaConverted);
            if (!verificacion)
            {
                fromUser = "ERROR";
                pOut.println(fromUser);
                break;
            }
            else
            {
                fromUser = "OK";
                pOut.println(fromUser);
            }
            //VERIFICACIÓN DE LA FIRMA
            String Pstring = pIn.readLine(); 
            byte[] Pbytes = Base64.getDecoder().decode(Pstring);
            BigInteger P = new BigInteger(Pbytes);
            String Gstring = pIn.readLine(); 
            byte[] Gbytes = Base64.getDecoder().decode(Gstring);
            BigInteger G = new BigInteger(Gbytes);
            String GXstring = pIn.readLine(); 
            byte[] GXbytes = Base64.getDecoder().decode(GXstring);
            BigInteger GX = new BigInteger(GXbytes);
            String firmaString = pIn.readLine(); 
            byte[] firma = Base64.getDecoder().decode(firmaString);
            //byte[] firma = firmaString.getBytes();
            System.out.println("Respuesta del Servidor: Valor de P: " + P);
            System.out.println("Respuesta del Servidor: Valor de G: " + G);
            System.out.println("Respuesta del Servidor: Valor de G^x: " + GX);
            System.out.println("Respuesta del Servidor: Firma obtenida: " + firma);
            try {
                // Convertir los valores de G, P, y Gx a bytes y concatenarlos
                byte[] gBytes = G.toByteArray();
                byte[] pBytes = P.toByteArray();
                byte[] gxBytes = GX.toByteArray();
    
                // Concatenar todos los bytes en un solo arreglo
                byte[] dataToVerify = new byte[gBytes.length + pBytes.length + gxBytes.length];
                System.arraycopy(gBytes, 0, dataToVerify, 0, gBytes.length);
                System.arraycopy(pBytes, 0, dataToVerify, gBytes.length, pBytes.length);
                System.arraycopy(gxBytes, 0, dataToVerify, gBytes.length + pBytes.length, gxBytes.length);
    
                // Configurar el objeto Signature con SHA1withRSA y la llave pública
                Signature signature = Signature.getInstance("SHA1withRSA");
                signature.initVerify(publicKey);
    
                // Actualizar el objeto Signature con los datos originales
                signature.update(dataToVerify);
                // Verificar la firma
                boolean verificacionFirma = signature.verify(firma);
                
                if (!verificacionFirma)
                {
                    fromUser = "ERROR";
                    pOut.println(fromUser);
                    break;
                }
                else
                {
                    fromUser = "OK";
                    pOut.println(fromUser);
                }
    
            } catch (Exception e) {
                System.err.println("Error al verificar la firma: " + e.getMessage());
                
            }

            //11a
            // Generar un valor aleatorio para y
            try {
            SecureRandom random = new SecureRandom();
            BigInteger y = new BigInteger(1024, random); // Genera un número de 1024 bits
            // Calcular G^y mod P
            BigInteger Gy = G.modPow(y, P);
            System.out.println("Valor de G^y: " + Gy);
             //mandar G^y
             String GYstring = Base64.getEncoder().encodeToString(Gy.toByteArray());
             pOut.println(GYstring);

            // Calcular (G^x)^y mod P para obtener la clave compartida
            BigInteger sharedSecret = GX.modPow(y, P);
            System.out.println("Clave compartida (G^x)^y mod P: " + sharedSecret);

            // Derivar K_AB1 y K_AB2 a partir de la clave compartida
            byte[] sharedSecretBytes = sharedSecret.toByteArray();
            //System.out.println("BYTES: " + sharedSecretBytes);
            // Calcular K_AB1 y K_AB2 usando SHA-512 y dividir en dos mitades
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hash = sha512.digest(sharedSecretBytes);
            
            // Dividir el hash en dos partes para obtener K_AB1 y K_AB2
            byte[] K_AB1bytes = new byte[32];
            byte[] K_AB2bytes = new byte[32];
            System.arraycopy(hash, 0, K_AB1bytes, 0, 32);
            System.arraycopy(hash, 32, K_AB2bytes, 0, 32);
            
            String K_AB1st = Base64.getEncoder().encodeToString(K_AB1bytes);
            String K_AB2st = Base64.getEncoder().encodeToString(K_AB2bytes);
            System.out.println("K_AB1 calculada: " + K_AB1st);
            System.out.println("K_AB2 calculada: " + K_AB2st);
            K_AB1 = new SecretKeySpec(K_AB1bytes, "AES");
            K_AB2 = new SecretKeySpec(K_AB2bytes, "HmacSHA384");

           
            }
            catch (Exception e) {
                System.err.println("Error en el proceso de creación de llaves simetricas: " + e.getMessage());
            }
            //recibir vector
            String ivString = pIn.readLine(); 
            //System.out.println("iv: " + ivString);
            byte[] ivBytes = Base64.getDecoder().decode(ivString);
            IvParameterSpec vectorIV = new IvParameterSpec(ivBytes);
            //byte[] iv = Base64.getDecoder().decode(ivString);
            //IvParameterSpec vectorIV = new IvParameterSpec(iv);
            //System.out.println("iv: " + vectorIV);
            boolean seguirConsulta = true;

            while(seguirConsulta){
            //Empezar consulta

            System.out.println("Ingrese el id del usuario: ");
            String idU = stdIn.readLine();
            String id_cifrado_string = cifrarID(idU, K_AB1, vectorIV);
            String id_hmac_string = generarHMAC(idU, K_AB2);
            pOut.println(id_cifrado_string);
            pOut.println(id_hmac_string);
            System.out.println("Ingrese el id del paquete: ");
            String idPaquete = stdIn.readLine();
            String idpaquete_cifrado_string = cifrarID(idPaquete, K_AB1, vectorIV);
            String idpaqeute_hmac_string = generarHMAC(idPaquete, K_AB2);
            pOut.println(idpaquete_cifrado_string);
            pOut.println(idpaqeute_hmac_string);
            
            String estadoPaqueteCifrado = pIn.readLine();
            System.out.println("ID Estado de paquete cifrado: " + estadoPaqueteCifrado);

            String estadoPaqueteHMAC = pIn.readLine();
            System.out.println("ID Estado de paquete con HMAC: " + estadoPaqueteHMAC);

            String IDestadoPaquete = desencriptarID(estadoPaqueteCifrado, K_AB1, vectorIV);
            System.out.println("ID Estado de paquete descifrado: " + IDestadoPaquete);

            boolean verificado = desencriptarHMAC(IDestadoPaquete, estadoPaqueteHMAC, K_AB2);
            System.out.println("verificación de integridad con hmac: " + verificado);

            String estadoPaquete = obtenerNombreEstado(IDestadoPaquete);
            System.out.println("Estado de paquete: " + estadoPaquete);

            System.out.println("Escriba TERMINAR si desea terminar la sesión.");
            System.out.println("Escriba CONTINUAR si desea hacer otra consulta.");
            fromUser = stdIn.readLine();
            if (fromUser.equalsIgnoreCase("TERMINAR")) {
                seguirConsulta = false;
            }
        }

           /*  fromUser = null;
            fromUser = stdIn.readLine();

            // si el usuario no ingresó null
            if (fromUser != null) {
                System.out.println("El usuario escribió: " + fromUser);
                
                // si el mensaje ingresado es "TERMINAR", detiene la ejecución
                if (fromUser.equalsIgnoreCase("TERMINAR")) {
                    ejecutar = false;
                }

                // envía el mensaje al servidor
                pOut.println(fromUser);
            }*/

            
            ejecutar = false;
        }
        }

    // Método para cifrar un BigInteger con la llave pública de un cliente
    public static byte[] cifrarReto(BigInteger message, PublicKey publicKey) {
        try {
            // Convertir el BigInteger a un arreglo de bytes
            byte[] messageBytes = message.toByteArray();

            // Configurar el cifrador con el algoritmo RSA y la llave pública
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Cifrar el mensaje
            byte[] encryptedBytes = cipher.doFinal(messageBytes);
            return encryptedBytes;
        } catch (Exception e) {
            System.err.println("Error al cifrar el mensaje: " + e.getMessage());
            return null;
        }
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

     // Método para convertir el estado del paquete de número a texto
     public static String obtenerNombreEstado(String estadoPaquete) {
        switch (estadoPaquete) {
            case "10":
                return "ENOFICINA";
            case "11":
                return "RECOGIDO";
            case "12":
                return "ENCLASIFICACION";
            case "13":
                return "DESPACHADO";
            case "14":
                return "ENENTREGA";
            case "15":
                return "ENTREGADO";
            case "16":
                return "DESCONOCIDO";
            default:
                return "ESTADO_INVALIDO"; // Retorna un valor en caso de que el estado no esté en el rango esperado
        }
    }
   
}

//TODO arreglar valores de 5 o 9 bytes

//TODO Crear cliente iterativo

//TODO SECINIT


//TODO terminar