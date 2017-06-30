using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DemoCifradoAES
{
    class Program
    {
        public static void Main()
        {
            try
            {
                encriptarFrases();
                encriptarArchivos();
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
            finally
            {
                Console.ReadLine();
            }
        }

        private static void encriptarArchivos()
        {
            try
            {
                Console.WriteLine("===Encriptar Archivos===");

                string rutaOriginal = @"C:\Users\datasoft-edgardo\Desktop\pdf\12MB testing001.pdf";
                string rutaDestinoEnc = @"C:\Users\datasoft-edgardo\Desktop\160KB Prueba - Test Standard.AES256";
                string rutaDestinoDesEnc = @"C:\Users\datasoft-edgardo\Desktop\160KB Prueba - Test Standard DESCENC.pdf";


                AesEncryptDecrypt aesEncryptDecrypt = new AesEncryptDecrypt();

                byte[] archivoOriginal = File.ReadAllBytes(rutaOriginal);
                byte[] encrypted = aesEncryptDecrypt.Encrypt256(archivoOriginal);
                File.WriteAllBytes(rutaDestinoEnc, encrypted);

                byte[] archivoEncriptado = File.ReadAllBytes(rutaDestinoEnc);
                byte[] desencrypted = aesEncryptDecrypt.Decrypt256(archivoEncriptado);
                File.WriteAllBytes(rutaDestinoDesEnc, desencrypted);

                Console.WriteLine("Archivo Encriptado en: {0}", rutaDestinoEnc);
                Console.WriteLine("Archivo Desencriptado en: {0}", rutaDestinoDesEnc);
                Console.WriteLine("");
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
        }

        private static void encriptarFrases()
        {
            try
            {
                Console.WriteLine("===Encriptar Frases===");

                string original = "Here is some data to encrypt!";
                AesEncryptDecrypt a = new AesEncryptDecrypt();

                byte[] encrypted = a.Encrypt256(Encoding.ASCII.GetBytes(original));
                string b64Encrypted = AesEncryptDecrypt.byteArrayToB64(encrypted);
                string roundtrip = Encoding.ASCII.GetString(a.Decrypt256(encrypted));

                //Display the original data and the decrypted data.
                Console.WriteLine("Original:    {0}", original);
                Console.WriteLine("Encriptado:  {0}", b64Encrypted);
                Console.WriteLine("Descriptado: {0}", roundtrip);
                Console.WriteLine("");
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
        }
    }
}
