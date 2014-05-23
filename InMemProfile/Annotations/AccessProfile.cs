using System;
using System.Collections.Generic;
using System.Linq;

namespace System.Security.InMemProfile.Annotations
{
    public class AccessProfile : Attribute
    {
        #region Declarations

        public int ProfileCode;
        public bool NeedsAutentication = true;

        #endregion

        #region Public Methods

        public int GetProfileCode()
        {
            return ProfileCode;
        }
        
        #endregion
    }
}
