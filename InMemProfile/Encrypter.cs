using System;
using System.Text;
using System.Configuration;
using System.Collections;
using System.Security.Cryptography;

namespace Rochas.InMemProfile.Security
{
	public class Encrypter : IDisposable
    {
        #region Declarations

        DESCryptoServiceProvider cryptoProvider;
        
        #endregion

        #region Constructors

        public Encrypter()
        {
            cryptoProvider = new DESCryptoServiceProvider();
            cryptoProvider.KeySize = 64;

            cryptoProvider.IV = Convert.FromBase64String(ConfigurationManager.AppSettings["RochasCriptoVetor"]);
            cryptoProvider.Key = Convert.FromBase64String(ConfigurationManager.AppSettings["RochasCriptoKey"]);
        }
        
        #endregion

        #region Public Methods

        public byte[] EncryptBinary(string text)
        {
            char[] contentToConvert = text.ToCharArray();
            byte[] convertedContent = new byte[contentToConvert.Length];

            int cont = 0;
            foreach (char token in contentToConvert)
            {
                convertedContent[cont] = Convert.ToByte(token);
                cont++;
            }

            return cryptoProvider.CreateEncryptor().TransformFinalBlock(convertedContent, 0, convertedContent.Length); 
        }

        public byte[] EncryptBinary(byte[] sourceArray)
        {
            byte[] convertedContent = new byte[sourceArray.Length];

            convertedContent = cryptoProvider.CreateEncryptor().TransformFinalBlock(sourceArray, 0, sourceArray.Length);

            return convertedContent;
        }

        public byte[] encryptBinary(BitArray sourceArray, int arraySize)
        {
            byte[] destinArray = new byte[arraySize];

            sourceArray.CopyTo(destinArray, 0);

            return cryptoProvider.CreateEncryptor().TransformFinalBlock(destinArray, 0, destinArray.Length);
        }

        public string EncryptBinary(ref BitArray sourceArray, int arraySize)
        {
            byte[] arrayToConvert = new byte[arraySize];
            byte[] encryptedArray = new byte[arraySize];

            sourceArray.CopyTo(arrayToConvert, 0);

            encryptedArray = cryptoProvider.CreateEncryptor().TransformFinalBlock(arrayToConvert, 0, arrayToConvert.Length);

            return Convert.ToBase64String(encryptedArray);
        }

        public string DecryptBinary(byte[] encryptedArray)
        {
            byte[] arrayToConvert = cryptoProvider.CreateDecryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length);
            StringBuilder destinText = new StringBuilder();

            foreach (byte token in arrayToConvert)
                destinText.Append(Convert.ToChar(token));

            return destinText.ToString();
        }

        public byte[] DecryptBinary(ref byte[] encryptedArray)
        {
            return cryptoProvider.CreateDecryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length);
        }

        public BitArray decryptBinary(byte[] encryptedArray, int tamanhoArray)
        {
            BitArray destinArray = new BitArray(cryptoProvider.CreateDecryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length));

            destinArray.Length = tamanhoArray;

            return destinArray;
        }

        public string EncryptText(string sourceText)
        {
            char[] arrayToConvert = sourceText.ToCharArray();
            byte[] encryptedArray = new byte[arrayToConvert.Length];

            int cont = 0;
            foreach (char token in arrayToConvert)
            {
                encryptedArray[cont] = Convert.ToByte(token);
                cont++;
            }

            byte[] destinArray = cryptoProvider.CreateEncryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length);

            return Convert.ToBase64String(destinArray);
        }

        public string DecryptText(string encryptedText)
        {
            byte[] encryptedArray = Convert.FromBase64String(encryptedText);

            byte[] arrayToConvert = cryptoProvider.CreateDecryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length);
            StringBuilder destinText = new StringBuilder();

            foreach (byte simbolo in arrayToConvert)
                destinText.Append(Convert.ToChar(simbolo));

            return destinText.ToString();
        }

        public byte[] DecryptText(ref string encryptedText)
        {
            byte[] encryptedArray = Convert.FromBase64String(encryptedText);

            byte[] destinArray = cryptoProvider.CreateDecryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length);

            return destinArray;
        }

        public void Dispose()
        {
            GC.ReRegisterForFinalize(this);
        }

        #endregion
	}
}
