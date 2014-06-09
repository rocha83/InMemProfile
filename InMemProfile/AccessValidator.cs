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

        public static Dictionary<string, Dictionary<string, Dictionary<string, object>>> ListFuncionalities(string domainAssemblyPath, string controllerAssemblyPath, string profileKey)
        {
            Dictionary<string, Dictionary<string, Dictionary<string, object>>> result =
                            new Dictionary<string, Dictionary<string, Dictionary<string, object>>>();

            Assembly controllerAssembly;
            IEnumerable<Type> systemEntities = GetSystemEntities(domainAssemblyPath, out controllerAssembly);

            foreach (Type entity in systemEntities)
            {
                var ctrlAssemblyInstance = Assembly.LoadFrom(controllerAssemblyPath);

                if (CheckPermission(entity.Name, ctrlAssemblyInstance, profileKey))
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
                        result.Add(funcionalityGroup, new Dictionary<string, Dictionary<string, object>>());

                    if (!result[funcionalityGroup].Any(sbg => sbg.Key.Equals(funcionalitySubGroup)))
                        result[funcionalityGroup].Add(funcionalitySubGroup, new Dictionary<string, object>());

                    var subGroups = result[funcionalityGroup];

                    var entityDisplayName = entity.GetCustomAttributes(true).
                                                   Where(ant => ant.GetType().
                                                   Name.Equals("DisplayNameAttribute")).
                                                   FirstOrDefault();

                    string displayName = entityDisplayName.GetType().GetProperty("DisplayName").
                                                           GetValue(entityDisplayName, null).ToString();

                    if (!subGroups.Keys.Any(key => key.Equals(funcionalitySubGroup)))
                        subGroups.Add(funcionalitySubGroup, new Dictionary<string, object>());

                    var funcionalityAccess = entityFuncionality.
                                         GetType().GetField("FuncionalityAccess").
                                         GetValue(entityFuncionality).ToString();

                    var funcionalityActions = ctrlAssemblyInstance.CreateInstance(string.Concat("SGEv2.Controllers.", entity.Name, "Controller"))
                                                                  .GetType().GetMethods()
                                                                  .Where(mtd => new List<string>() { "Index", "Create", "Edit", "Delete", 
                                                                                                     "Approve", "Print", "Export" }.Contains(mtd.Name))
                                                                  .Select(mtd => string.Concat(displayName, "_", mtd.Name.Replace("Index", "View")))
                                                                  .Distinct().ToList();

                    subGroups[funcionalitySubGroup].Add(displayName, funcionalityAccess);

                    var funcActionsDict = new Dictionary<string, object>();
                    foreach (var act in funcionalityActions)
                        funcActionsDict.Add(act, null);
                    subGroups[funcionalitySubGroup].Add(string.Concat(displayName, "Act"), funcActionsDict);
                }
            }

            return result;
        }

        public static Dictionary<string, object> GetFuncionalitiesTree(Dictionary<string, Dictionary<string, Dictionary<string, object>>> funcList)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            Dictionary<string, object> resultSubGrp = new Dictionary<string, object>();
            Dictionary<string, object> resultItems = new Dictionary<string, object>();

            foreach (var funcGrp in funcList)
            {
                foreach (var subGrp in (Dictionary<string, Dictionary<string, object>>)funcGrp.Value)
                {
                    foreach (var item in subGrp.Value)
                        resultItems.Add(item.Key, item.Value);

                    resultSubGrp.Add(subGrp.Key, resultItems);
                }

                result.Add(funcGrp.Key, resultSubGrp);
            }

            return result;
        }

        public static Dictionary<string, object> GetFuncionalTreeCodes(Dictionary<string, object> funcTree, object entityAccessProfile, Dictionary<string, object> result)
        {
            if (result == null) result = new Dictionary<string, object>();

            foreach (var node in funcTree)
            {
                string nodeKey = string.Empty;
                if (!node.Key.Contains("_"))
                    nodeKey = node.Key;
                else
                    nodeKey = node.Key.Substring(node.Key.IndexOf("_") + 1);

                if (node.Value is Dictionary<string, object>)
                {
                    var childResult = new Dictionary<string, object>(); 
                    GetFuncionalTreeCodes(node.Value as Dictionary<string, object>, entityAccessProfile, childResult);
                    result.Add(nodeKey, childResult);
                }
                else
                {
                    var nodeCode = entityAccessProfile.GetType().GetField(node.Key)
                                                      .GetValue(entityAccessProfile).ToString();
                    result.Add(string.Concat(nodeKey, ".", nodeCode), node.Value);
                }
            }

            return result;
        }

        public static bool CheckPermission(string entityName, Assembly controllerAssembly, string profileKey)
        {
            return checkPermission(controllerAssembly, entityName, profileKey);
        }

        public static bool CheckPermission(int funcPosition, string profileKey)
        {
            return getBinaryProfileKey(profileKey)[funcPosition];
        }

        public static IEnumerable<Type> GetSystemEntities(string assemblyPath, out Assembly entitiesLib)
        {
            string libsPath = ConfigurationManager.AppSettings["BinPath"];

            entitiesLib = Assembly.LoadFrom(string.Concat(libsPath, assemblyPath));

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

        internal static bool checkPermission(Assembly controllerAssembly, string entityTypeName, string profileKey)
        {
            bool[] decryptedProfileKey = getBinaryProfileKey(profileKey);

            Type profileType = null;
            foreach (var fndType in controllerAssembly.GetTypes())
            {
                if (fndType.Name.Equals("EntityAccessProfile"))
                {
                    profileType = fndType;
                    break;
                }
            }

            var accessControl = Activator.CreateInstance(profileType);

            int profileCode = int.Parse(accessControl.GetType().GetField(entityTypeName)
                                        .GetValue(accessControl).ToString());

            return decryptedProfileKey[profileCode];
        }

        #endregion
    }
}
