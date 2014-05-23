using System;
using System.Text;
using System.ComponentModel;
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.Reflection;
using System.Linq;

namespace System.Security.InMemProfile
{
	public class AccessValidator
    {
        #region Declarations

        public const int ProfileKeySize = 1024; // 1024 bits
        public static int ConnectedUsers;

        #endregion

        #region Public Methods

        public static bool ValidatePassword(string cryptoPwd, string pwd)
        {
            Encrypter cripto = new Encrypter();

            return cryptoPwd.Equals(cripto.EncryptText(pwd));
        }

        public Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, List<string>>>>> ListFuncionalities(string assemblyPath, string profileKey)
        {
            Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, List<string>>>>> result =
                            new Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, List<string>>>>>();

            IEnumerable<Type> systemEntities = GetSystemEntities(assemblyPath);

            foreach (Type entity in systemEntities)
            {
                if (CheckPermission(entity, profileKey))
                {
                    var entityFuncionality = entity.GetCustomAttributes(true).
                                                    Where(ant => ant.GetType().
                                                    Name.Equals("Funcionality")).
                                                    FirstOrDefault();

                    string funcionalityGroup = entityFuncionality.GetType().GetField("FuncionalityGroup").
                                                                  GetValue(entityFuncionality).ToString();

                    string funcionalitySubGroup = entityFuncionality.GetType().GetField("FuncionalitySubGroup").
                                                                     GetValue(entityFuncionality).ToString();

                    List<string> attributeDescriptions = new List<string>();

                    if (!result.Keys.Any(key => key.Equals(funcionalityGroup)))
                        result.Add(funcionalityGroup, new Dictionary<string, Dictionary<string, Dictionary<string, List<string>>>>());

                    if (!result[funcionalityGroup].Any(sbg => sbg.Key.Equals(funcionalitySubGroup)))
                        result[funcionalityGroup].Add(funcionalitySubGroup, new Dictionary<string, Dictionary<string, List<string>>>());

                    var subGroups = result[funcionalityGroup];

                    var entityDisplayName = entity.GetCustomAttributes(true).
                                                   Where(ant => ant.GetType().
                                                   Name.Equals("DisplayName")).
                                                   FirstOrDefault();

                    string displayName = entityDisplayName.GetType().GetField("DisplayName").
                                                           GetValue(entityFuncionality).ToString();

                    if (!subGroups.Keys.Any(key => key.Equals(funcionalitySubGroup)))
                        subGroups.Add(funcionalitySubGroup, new Dictionary<string, Dictionary<string, List<string>>>());
                    
                    subGroups[funcionalitySubGroup].Add(displayName, new Dictionary<string, List<string>>());

                    var entityAttributes = entity.GetProperties().Where(ent => ent.GetCustomAttributes(true)
                                                                 .Any(atb => atb.GetType().Name.Contains("DisplayName")));

                    Dictionary<string, List<string>> funcionalityAttributes;
                    string funcionalityAccess = string.Empty;

                    funcionalityAttributes = subGroups[funcionalitySubGroup][displayName];

                    funcionalityAccess = entityFuncionality.
                                         GetType().GetField("FuncionalityAccess").
                                         GetValue(entityFuncionality).ToString();

                    if (entityAttributes.Count() > 0)
                    {
                        foreach (var attrib in entityAttributes)
                        {
                            string attribDescription = ((DisplayNameAttribute)attrib.GetCustomAttributes(true).
                                                                                     Where(atb => atb.GetType().
                                                                                     Name.Contains("DisplayName")).
                                                                                     FirstOrDefault()).DisplayName;
                            if (!attributeDescriptions.Contains(attribDescription))
                                attributeDescriptions.Add(attribDescription);
                        }

                        if (!funcionalityAttributes.Keys.Any(key => key.Equals(funcionalityAccess)))
                            funcionalityAttributes.Add(funcionalityAccess, attributeDescriptions);
                    }
                    else
                    {
                        if (!funcionalityAttributes.Keys.Any(key => key.Equals(funcionalityAccess)))
                            funcionalityAttributes.Add(funcionalityAccess, new List<string>(0));
                    }
                 }
            }

            return result;
        }

        public static bool CheckPermission(object entity, string profileKey)
        {
            return checkPermission(entity.GetType(), profileKey);
        }

        public static bool CheckPermission(int funcPosition, string profileKey)
        {
            return getBinaryProfileKey(profileKey)[funcPosition];
        }

        public static IEnumerable<Type> GetSystemEntities(string assemblyPath)
        {
            string libsPath = ConfigurationManager.AppSettings["BinPath"];

            Assembly entitiesLib = Assembly.LoadFrom(string.Concat(libsPath, assemblyPath));

            IEnumerable<Type> entities = entitiesLib.GetTypes()
                                          .Where(et => et.GetCustomAttributes(true)
                                          .Any(ant => ant.GetType().Name.Equals("Funcionality")));

            return entities;
        }

        #endregion

        #region Helper Methods

        internal static bool[] getBinaryProfileKey(string profileKey)
        {
            BitArray arrayDecryptedKey = null;
            byte[] preDecryptedKey = new byte[AccessValidator.ProfileKeySize];
            bool[] decryptedKey = new bool[AccessValidator.ProfileKeySize];

            Encrypter cripto = new Encrypter();

            preDecryptedKey = cripto.DecryptText(ref profileKey);

            arrayDecryptedKey = new BitArray(preDecryptedKey);
            arrayDecryptedKey.Length = AccessValidator.ProfileKeySize;

            arrayDecryptedKey.CopyTo(decryptedKey, 0);

            return decryptedKey;
        }

        internal static bool checkPermission(Type entityType, string profileKey)
        {
            bool verifyResult = false;
            bool[] decryptedProfileKey = getBinaryProfileKey(profileKey);

            foreach (object attrib in entityType.GetCustomAttributes(true))
                if (attrib.GetType().Name.Equals("AccessProfile"))
                {
                    int profileCode = int.Parse(attrib.GetType().GetField("ProfileCode")
                                                                .GetValue(attrib).ToString());

                    verifyResult = decryptedProfileKey[profileCode];
                    break;
                }

            return verifyResult;
        }

        #endregion
    }
}
