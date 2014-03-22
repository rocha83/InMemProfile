using System;
using System.Collections.Generic;
using System.Linq;

namespace Rochas.InMemProfile
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
