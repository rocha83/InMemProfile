﻿using System;

namespace Rochas.InMemProfile
{
    public class Funcionality : Attribute
    {
        #region Declarations

        public string FuncionalityGroup = string.Empty;
        public string FuncionalitySubGroup = string.Empty;
        public string DisplayName = string.Empty;
        public string FuncionalityAccess = string.Empty;
        public bool UserAccess = true;
        public bool ShowResults = true;
        public bool WorkFlowParticipant = false;
        public bool PerformsIntegration = false;

        #endregion
    }
}