import java.io.File;
import java.util.Scanner;
import Cliente.Cliente;
import Servidor.Servidor;
import Servidor.KeyGenerator;

public class App {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        int opcion;

        do {
            System.out.println("Menú de opciones:");
            System.out.println("1. Opción 1");
            System.out.println("2. Opción 2");
            System.out.println("0. Salir");
            System.out.print("Seleccione una opción: ");

            opcion = scanner.nextInt();

            switch (opcion) {
                case 1:
                    System.out.println("Has seleccionado Opción 1.");
                    // Lógica para la Opción 1
                    opcion1();
                    break;
                case 2:
                    System.out.println("Has seleccionado Opción 2.");
                    // Lógica para la Opción 2
                    break;
                case 0:
                    System.out.println("Saliendo del programa.");
                    break;
                default:
                    System.out.println("Opción no válida. Intente de nuevo.");
            }

            System.out.println(); // Espacio adicional para mejor legibilidad
        } while (opcion != 0);

        scanner.close();

        
        File publicKeysFile = new File("src/Cliente/publicKeys.txt");
            File privateKeysFile = new File("src/Servidor/privateKeys.txt");

            if (publicKeysFile.exists() && publicKeysFile.delete()) {
                System.out.println("Archivo de llaves públicas eliminado.");
            } else {
                System.err.println("No se pudo eliminar el archivo de llaves públicas.");
            }

            if (privateKeysFile.exists() && privateKeysFile.delete()) {
                System.out.println("Archivo de llaves privadas eliminado.");
            } else {
                System.err.println("No se pudo eliminar el archivo de llaves privadas.");
        }
    }

    public static void opcion1() {
        KeyGenerator.generateAndStoreKeys();
    }
}
