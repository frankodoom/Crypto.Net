using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Cryptography
{
    class NidHeeshCrypto
    {

        /// <summary>
        /// This class provide static methods for encryption and decryption.
        /// </summary>
        public class DataEncryption
        {
            /// <summary>
            /// Method which does the encryption using Rijndeal algorithm
            /// </summary>
            /// <param name="InputText">Data to be encrypted</param>
            /// <param name="Password">The string to used for making the key.The same string
            /// should be used for making the decrpt key</param>
            /// <returns>Encrypted Data</returns>
            public static string EncryptString(string InputText, string Password)
            {
                RijndaelManaged RijndaelCipher = new RijndaelManaged();

                byte[] PlainText = System.Text.Encoding.Unicode.GetBytes(InputText);
                byte[] Salt = System.Text.Encoding.ASCII.GetBytes(Password.Length.ToString());

                //This class uses an extension of the PBKDF1 algorithm defined in the PKCS#5 v2.0 
                //standard to derive bytes suitable for use as key material from a password. 
                //The standard is documented in IETF RRC 2898.

                PasswordDeriveBytes SecretKey = new PasswordDeriveBytes(Password, Salt);
                //Creates a symmetric encryptor object. 
                ICryptoTransform Encryptor = RijndaelCipher.CreateEncryptor(SecretKey.GetBytes(32), SecretKey.GetBytes(16));
                System.IO.MemoryStream memoryStream = new System.IO.MemoryStream();
                //Defines a stream that links data streams to cryptographic transformations
                CryptoStream cryptoStream = new CryptoStream(memoryStream, Encryptor, CryptoStreamMode.Write);
                cryptoStream.Write(PlainText, 0, PlainText.Length);
                //Writes the final state and clears the buffer
                cryptoStream.FlushFinalBlock();
                byte[] CipherBytes = memoryStream.ToArray();
                memoryStream.Close();
                cryptoStream.Close();
                string EncryptedData = Convert.ToBase64String(CipherBytes);
                return EncryptedData;

            } //eof private static string EncryptString ( string InputText, string Password )

            /// <summary>
            /// Method which does the encryption using Rijndeal algorithm.This is for decrypting the data
            /// which has orginally being encrypted using the above method
            /// </summary>
            /// <param name="InputText">The encrypted data which has to be decrypted</param>
            /// <param name="Password">The string which has been used for encrypting.The same string
            /// should be used for making the decrypt key</param>
            /// <returns>Decrypted Data</returns>
            public static string DecryptString(string InputText, string Password)
            {

                RijndaelManaged RijndaelCipher = new RijndaelManaged();
                byte[] EncryptedData = Convert.FromBase64String(InputText);
                byte[] Salt = System.Text.Encoding.ASCII.GetBytes(Password.Length.ToString());
                //Making of the key for decryption
                PasswordDeriveBytes SecretKey = new PasswordDeriveBytes(Password, Salt);
                //Creates a symmetric Rijndael decryptor object.
                ICryptoTransform Decryptor = RijndaelCipher.CreateDecryptor(SecretKey.GetBytes(32), SecretKey.GetBytes(16));
                System.IO.MemoryStream memoryStream = new System.IO.MemoryStream(EncryptedData);
                //Defines the cryptographics stream for decryption.THe stream contains decrpted data
                CryptoStream cryptoStream = new CryptoStream(memoryStream, Decryptor, CryptoStreamMode.Read);
                byte[] PlainText = new byte[EncryptedData.Length];
                int DecryptedCount = cryptoStream.Read(PlainText, 0, PlainText.Length);
                memoryStream.Close();
                cryptoStream.Close();
                //Converting to string
                string DecryptedData = System.Text.Encoding.Unicode.GetString(PlainText, 0, DecryptedCount);
                return DecryptedData;

            } //eof private static string DecryptString (string InputText , string Password ) 

        } //eof class

    } //eof namespace Utils 
}

