using System;

namespace System.Security.InMemProfile
{
    public class Funcionality : Attribute
    {
        #region Declarations

        public string FuncionalityGroup = string.Empty;
        public string FuncionalitySubGroup = string.Empty;
        public string FuncionalityAccess = string.Empty;
        public bool UserAccess = true;
        public bool ShowResults = true;
        public bool WorkFlowParticipant = false;
        public bool PerformsIntegration = false;

        #endregion
    }
}