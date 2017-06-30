using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

/// <summary>
///AES, the Advanced Encryption Standard, defines in FIPS PUB 197 three symmetric block-ciphers: AES-128, AES-192 and AES-256. All three algorithms are defined by specific parameter-choices for the Rijndael algorithm.
///AES-128-encryption is a function(key, data) -> (encryption). Rijndael-encryption is a function(key, data, block-size, key-size) -> (encryption).
///AesCryptoServiceProvider uses the underlying Windows CryptoAPI to perform the encryption.AesManaged performs the encryption in pure managed code.RijndaelManaged supports the full range of parameter-choices (also in pure managed code).
///Advantages to using AesCryptoServiceProvider include potential for higher speed and the fact that CryptoAPI is FIPS certified(on certain versions of Windows).
///Advantages to AesManaged include portability(AesCryptoServiceProvider is not supported on all versions of Windows).
///The only advantage to RijndaelManaged is that it is supported in early versions of the.NET framework - I haven't ever seen anyone use the non-AES parameter-choices.
///Source: https://stackoverflow.com/questions/3683277/aes-encryption-and-c-sharp
/// </summary>

namespace DemoCifradoAES
{
    class AesEncryptDecrypt
    { 
        // AesCryptoServiceProvider
        private AesCryptoServiceProvider myAes = new AesCryptoServiceProvider();
        /// <summary>
        /// Vector de Inicializacion: No se puede encriptar sin él. Es de 16 bytes de longitud para el algoritmo de Rijndael. No es una 2ª llave, por lo tanto, no se trata de una dato que haya que esconder, únicamente hay que considerar que hay que usar el mismo IV para encriptar/desencriptar un mensaje concreto. Un error común es utilizar el mismo vector de inicialización en todas las encriptaciones. Utilizar siempre un mismo IV es equivalente en seguridad a no utilizar encriptación.
        /// </summary>
        private const string AesIV256 = @"!QAZ2WSX#EDC4RFV";//16
        /// <summary>
        /// Llave de encriptacion: Esta es la principal información para encriptar/desencriptar en los algoritmos simétricos. Toda la seguridad de un sistema simétrico depende de dónde esté esta llave, cómo esté compuesta y quién tiene acceso. Éste es un dato que debe conocerse única y exclusivamente por los interlocutores de la comunicación. De otra forma, la seguridad en la comunicación se vería comprometida.
        /// </summary>
        private const string AesKey256 = @"5TGB&YHN7UJM(IK<5TGB&YHN7UJM(IK<";//32
        /// <summary>
        /// Constructor default
        /// </summary>
        /// <param name="BlockSize"></param>
        /// <param name="KeySize"></param>
        /// <param name="cipherMode">Cipher Block Chaining Mode: Es una extensión de ECB que añade cierta seguridad (usa un vector de inicialización IV). Es el modo de cifrado por bloques más usado.</param>
        /// <param name="paddingMode">La cadena de relleno PKCS #7 consta de una secuencia de bytes, en la que cada byte es igual al número total de bytes de relleno agregados.</param>
        public AesEncryptDecrypt(int BlockSize = 128, int KeySize = 256, string IV = AesIV256, string Key = AesKey256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            myAes.BlockSize = BlockSize;
            myAes.KeySize = KeySize;
            myAes.IV = Encoding.UTF8.GetBytes(IV);
            myAes.Key = Encoding.UTF8.GetBytes(Key);
            myAes.Mode = cipherMode;
            myAes.Padding = paddingMode;
        }
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="myAes"></param>
        public AesEncryptDecrypt(AesCryptoServiceProvider myAes)
        {
            this.myAes = myAes;
        }
        /// <summary>
        /// AES encryption
        /// </summary>
        /// <param name="src"></param>
        /// <returns></returns>
        public byte[] Encrypt256(byte[] src)
        {
            try
            {
                // encryption
                using (ICryptoTransform encrypt = myAes.CreateEncryptor())
                {
                    return encrypt.TransformFinalBlock(src, 0, src.Length);
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
        }
        /// <summary>
        /// AES decryption
        /// </summary>
        public byte[] Decrypt256(byte[] src)
        {
            try
            {
                // decryption
                using (ICryptoTransform decrypt = myAes.CreateDecryptor())
                {
                    return decrypt.TransformFinalBlock(src, 0, src.Length);
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="src"></param>
        /// <returns></returns>
        public static string byteArrayToB64(byte[] src)
        {
            try
            {
                return Convert.ToBase64String(src);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="src"></param>
        /// <returns></returns>
        public static byte[] B64ToByteArray(string src)
        {
            try
            {
                return System.Convert.FromBase64String(src);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
        }
    }
}