using System;
using System.Xml;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Web.Security;
using System.Web.Hosting;
using System.Web.Management;
using System.Security.Permissions;
using System.Web;
using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Xml.Linq;
using System.Linq;
using System.IO;
using System.Web.Configuration;
using System.Text.RegularExpressions;

namespace Membership.Provider
{

    public class XmlMembershipProvider : MembershipProvider
    {
        private Dictionary<string, MembershipUser> _Users;
        private string _XmlFileName;
        private XDocument _Document;
        private string _hashAlgorithm;
        private string _validationKey;
        private MembershipPasswordFormat _passwordFormat;
        private int _maxInvalidPasswordAttempts;
        private int _passwordAttemptWindow;
        private int _minRequiredNonAlphanumericCharacters;
        private int _minRequiredPasswordLength;
        private string _passwordStrengthRegularExpression;
        private bool _enablePasswordReset;
        private bool _enablePasswordRetrieval;
        private bool _requiresQuestionAndAnswer;
        private bool _requiresUniqueEmail;

        #region Properties

        public string ProviderName { get; set; }

        #if DEBUG
        public XDocument XDocument { get { return _Document; } set { _Document = value; } }        
        #endif

        // MembershipProvider Properties
        public override string ApplicationName { get; set; }

        public override MembershipPasswordFormat PasswordFormat { get { return _passwordFormat; }  }

        public string XmlFileName { get { return _XmlFileName; } set { _XmlFileName = value; } }

        public override bool EnablePasswordRetrieval
        {
            get { return false; }
        }

        public override bool EnablePasswordReset
        {
            get { return false; }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { return 5; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return _minRequiredNonAlphanumericCharacters; }            
        }

        public override int MinRequiredPasswordLength
        {
            get { return 8; }
        }

        public override int PasswordAttemptWindow
        {
            get { throw new NotSupportedException(); }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { throw new NotSupportedException(); }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get { return false; }
        }

        public override bool RequiresUniqueEmail
        {
            get { return false; }
        }

        #endregion

        #region Supported methods

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("config");

            if (String.IsNullOrEmpty(name))
                name = "XmlMembershipProvider";

            this.ProviderName = name;

            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "XML membership provider");
            }

            if (string.IsNullOrEmpty(config["applicationName"]))
                ApplicationName = "/";

            InitConfigSettings(config);
            InitPasswordEncryptionSettings(config);

            base.Initialize(name, config);


            // Initialize _XmlFileName and make sure the path
            // is app-relative
            string path = config["xmlFileName"];

            if (string.IsNullOrEmpty(XmlFileName))
            {
                if (String.IsNullOrEmpty(path))
                    path = "~/App_Data/Membership.xml";

                

                if (!VirtualPathUtility.IsAppRelative(path))
                {
                    this.XmlFileName = Path.GetFullPath(path);
                }
                else
                {
                    string fullyQualifiedPath;
                    fullyQualifiedPath = VirtualPathUtility.Combine
                    (VirtualPathUtility.AppendTrailingSlash
                    (HttpRuntime.AppDomainAppVirtualPath), path);
                    this.XmlFileName = HostingEnvironment.MapPath(fullyQualifiedPath);
                }

                

                // Make sure we have permission to read the XML data source and
                // throw an exception if we don't
                FileIOPermission permission = new FileIOPermission(FileIOPermissionAccess.Write, this.XmlFileName);
                permission.Demand();
            }
            config.Remove("xmlFileName");


            if (!File.Exists(_XmlFileName))
            {
                File.AppendAllText(_XmlFileName, @"<XmlProvider>
  <Users>
    <User>
      <ApplicationId>MyApp</ApplicationId>
      <UserName>wilby</UserName>
      <PasswordSalt>KfONZg==</PasswordSalt>
      <Password>D4j8sWgqK0XpiPB4Szs0Cl41530=</Password>
      <Email>wilby@wcjj.net</Email>
      <PasswordQuestion>Mother's Maiden Name</PasswordQuestion>
      <PasswordAnswer>Smith</PasswordAnswer>
      <IsApproved>True</IsApproved>
      <IsLockedOut>False</IsLockedOut>
      <CreateDate>10/20/2012 9:16:03 AM</CreateDate>
      <LastLoginDate>10/20/2012 9:16:03 AM</LastLoginDate>
      <LastActivityDate>10/20/2012 9:16:03 AM</LastActivityDate>
      <LastPasswordChangeDate>10/20/2012 9:16:03 AM</LastPasswordChangeDate>
      <LastLockoutDate>10/20/2012 9:16:03 AM</LastLockoutDate>
      <FailedPasswordAttemptCount>0</FailedPasswordAttemptCount>
      <FailedPasswordAnswerAttemptCount>0</FailedPasswordAnswerAttemptCount>
      <Comment></Comment>
    </User>
  </Users>
  <Roles>
    <Role>
      <ApplicationId>/</ApplicationId>
      <RoleName></RoleName>
      <Description></Description>
    </Role>
  </Roles>
  <UserRoles>
    <UserName></UserName>
    <RoleName></RoleName>
  </UserRoles>
</XmlProvider>
");
            }


            // Throw an exception if unrecognized attributes remain
            //if (config.Count > 0)
            //{
            //    string attr = config.GetKey(0);
            //    if (!String.IsNullOrEmpty(attr))
            //        throw new ProviderException("Unrecognized attribute: " + attr);
            //}

            if(_Document == null) 
                _Document = XDocument.Load(_XmlFileName);
        }

        /// <summary>
        /// Returns true if the username and password match an exsisting user.
        /// </summary>
        public override bool ValidateUser(string username, string password)
        {
            if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password))
                return false;

            try
            {
                InitializeDataStore();

                // Validate the user name and password            
                XElement xUser = _Document.Descendants("User").Where(z => z.Element("UserName").Value == username.ToLower()).FirstOrDefault();

                if (xUser == null)
                    return false;

                MembershipUser user = MembershipUserFromXElement(xUser);

                string userHashedPassword = xUser.Descendants("Password").FirstOrDefault().Value ?? "";
                string passwordSalt = (xUser.Descendants("PasswordSalt").FirstOrDefault().Value ?? "").Trim();
                password = password.Trim();

                if (!string.IsNullOrEmpty(userHashedPassword) && !string.IsNullOrEmpty(passwordSalt) && userHashedPassword == EncodePassword(password, passwordSalt)) // Case-sensitive
                {
                    user.LastLoginDate = DateTime.Now;
                    user.LastActivityDate = DateTime.Now;                    
                    UpdateUser(user);

                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Membership.Provider.XmlMembershipProvider StackTrace: {0}", ex.StackTrace);
                return false;
            }
        }

        /// <summary>
        /// The GetUser method returns a MembershipUser object populated with current values from the data source for the specified user. 
        /// If the user name is not found in the data source, the GetUser method returns null (Nothing in Visual Basic)
        /// </summary>
        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            if (String.IsNullOrEmpty(username))
                return null;

            InitializeDataStore();

            MembershipUser user;
            var xUser = _Document.Descendants("User").Where(x => x.Element("UserName").Value == username.ToLower()).FirstOrDefault();

            if (xUser != null)
            {
                
                user = XElementToMembershipUser(xUser);
                if (user.IsOnline)
                {
                    var date = DateTime.Now;
                    user.LastActivityDate = date;
                    UpdateUser(user);
                }
                return user;
            }
            return null;
        }

        /// <summary>
        /// Get a user based on the username parameter.
        /// the userIsOnline parameter is ignored.
        /// </summary>
        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            string username = providerUserKey.ToString();
            return GetUser(username, userIsOnline);
        }

        /// <summary>
        /// Retrieves a collection of all the users.
        /// This implementation ignores pageIndex and pageSize,
        /// and it doesn't sort the MembershipUser objects returned.
        /// </summary>
        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            InitializeDataStore();

            int startIndex = pageIndex * pageSize;

            MembershipUserCollection users = new MembershipUserCollection();
            var xUsers = _Document.Descendants("User").Skip(pageIndex).Take(pageSize);
            foreach (XElement xuser in xUsers)
            {
                var muser = XElementToMembershipUser(xuser);
                users.Add(muser);
            }

            totalRecords = users.Count;
            return users;
        }

        /// <summary>
        /// Changes a users password.
        /// </summary>
        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(_XmlFileName);
            XmlNodeList nodes = doc.GetElementsByTagName("User");
            foreach (XmlNode node in nodes)
            {
                if (node["UserName"].InnerText.Equals(username, StringComparison.OrdinalIgnoreCase)
                  || node["Password"].InnerText.Equals(Encrypt(oldPassword), StringComparison.OrdinalIgnoreCase))
                {
                    node["Password"].InnerText = Encrypt(newPassword);
                    doc.Save(_XmlFileName);
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Creates a new user store he/she in the XML file
        /// </summary>
        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            string salt = PasswordUtil.CreateRandomSalt();
            string hashedPass = string.Empty;
            try
            {
                hashedPass = EncodePassword(password, salt);
            }
            catch (Exception ex)
            {
                throw new MembershipPasswordException("There was a problem with the given password", ex);
            }

            InitializeDataStore();            

            XElement xUser;

            xUser = _Document.Descendants("User").Where(x => x.Element("UserName").Value == username.ToLower()).FirstOrDefault();
            if (xUser != null)
            {
                status = MembershipCreateStatus.DuplicateUserName;
                return null;
            }

            xUser = _Document.Descendants("User").Where(x => x.Element("Email").Value == email.ToLower()).FirstOrDefault();
            if (xUser != null)
            {
                status = MembershipCreateStatus.DuplicateEmail;
                return null;
            }

            var nonAlphaNumericCharacters = password.Where(c => !char.IsLetterOrDigit(c)).SelectMany(x => x.ToString());
            if (password.Length < MinRequiredPasswordLength || nonAlphaNumericCharacters.Count() < MinRequiredNonAlphanumericCharacters)
            {
                status = MembershipCreateStatus.InvalidPassword;                
                return null;
            }


            //TODO: Check the Minimun Non AlpahNumeric Characters int the password.

            
            xUser = new XElement("User",
                    new XElement("ApplicationId", this.ApplicationName),
                    new XElement("UserName", username),
                    new XElement("PasswordSalt", salt),
                    new XElement("Password", hashedPass),
                    new XElement("Email", email),
                    new XElement("PasswordQuestion", passwordQuestion),
                    new XElement("PasswordAnswer", passwordAnswer),
                    new XElement("IsApproved", Convert.ToString(isApproved)),
                    new XElement("IsLockedOut", Convert.ToString(false)),
                    new XElement("CreateDate", Convert.ToString(DateTime.Now)),
                    new XElement("LastLoginDate", Convert.ToString(DateTime.MinValue)),
                    new XElement("LastActivityDate", Convert.ToString(DateTime.MinValue)),
                    new XElement("LastPasswordChangeDate", Convert.ToString(DateTime.MinValue)),
                    new XElement("LastLockoutDate", Convert.ToString(DateTime.MinValue)),
                    new XElement("FailedPasswordAttemptCount", Convert.ToString(0)),
                    new XElement("FailedPasswordAnswerAttemptCount", Convert.ToString(0)),
                    new XElement("Comment", "")
                    );

            _Document.Descendants("Users").FirstOrDefault().Add(xUser);
            _Document.Save(XmlFileName);

            var user = XElementToMembershipUser(xUser);
            status = MembershipCreateStatus.Success;
            return user;            
        }

        /// <summary>
        /// Deletes the user from the XML file and 
        /// removes him/her from the internal cache.
        /// </summary>
        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            InitializeDataStore();

            var user = _Document.Descendants("User").Where(x => x.Element("UserName").Value == username.ToLower()).FirstOrDefault();

            if (user != null)
            {
                user.Remove();
                _Document.Save(XmlFileName);

                if (deleteAllRelatedData)
                {
                    _Document.Descendants("UserRole").Where(x => x.Element("UserName").Value == username.ToLower()).Remove();
                }

                return true;
            }

            return false;
        }

        /// <summary>
        /// Retrieves a username based on a matching email.
        /// </summary>
        public override string GetUserNameByEmail(string email)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(_XmlFileName);

            foreach (XmlNode node in doc.GetElementsByTagName("User"))
            {
                if (node.ChildNodes[2].InnerText.Equals(email.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    return node.ChildNodes[0].InnerText;
                }
            }
            return null;
        }


        public MembershipUser MembershipUserFromXElement(XElement xUser)
        {
            MembershipUser user = new MembershipUser(this.Name,
                   xUser.Descendants("UserName").FirstOrDefault().Value ?? "",
                   xUser.Descendants("UserName").FirstOrDefault().Value ?? "",
                   xUser.Descendants("Email").FirstOrDefault().Value ?? "",
                   xUser.Descendants("PasswordQuestion").FirstOrDefault().Value ?? "",
                   xUser.Descendants("Comment").FirstOrDefault().Value ?? "",
                   Convert.ToBoolean(xUser.Descendants("IsApproved").FirstOrDefault().Value ?? "0"),
                   Convert.ToBoolean(xUser.Descendants("IsLockedOut").FirstOrDefault().Value ?? "0"),
                   Convert.ToDateTime(xUser.Descendants("CreateDate").FirstOrDefault().Value ?? DateTime.MinValue.ToString()),
                   Convert.ToDateTime(xUser.Descendants("LastLoginDate").FirstOrDefault().Value ?? DateTime.MinValue.ToString()),
                   Convert.ToDateTime(xUser.Descendants("LastActivityDate").FirstOrDefault().Value ?? DateTime.MinValue.ToString()),
                   Convert.ToDateTime(xUser.Descendants("LastPasswordChangeDate").FirstOrDefault().Value ?? DateTime.MinValue.ToString()),
                   Convert.ToDateTime(xUser.Descendants("LastLockoutDate").FirstOrDefault().Value ?? DateTime.MinValue.ToString()));

            return user;
        }


        /// <summary>
        /// Updates a user. The username will not be changed.
        /// </summary>
        public override void UpdateUser(MembershipUser user)
        {
            UpdateUser(user, null, null);
        }

        /// <summary>
        /// Updates a user. The username will not be changed.
        /// </summary>
        public void UpdateUser(MembershipUser user, string password)
        {
            UpdateUser(user, password, null);
        }

        /// <summary>
        /// Updates a user. The username will not be changed.
        /// </summary>
        public void UpdateUser(MembershipUser user, string password, string passwordQuestionAnswer)
        {
            InitializeDataStore();

            var xuser = _Document.Descendants("User").Where(x => x.Element("UserName").Value == user.UserName.ToLower()).FirstOrDefault();
            if (xuser == null)
                throw new NullReferenceException(string.Format("Cannot update user {0}. They don't exist in the data store.", user.UserName));

            if (!string.IsNullOrEmpty(password))
                xuser.Element("Password").Value = PasswordUtil.HashPassword(password, xuser.Element("PasswordSalt").Value, _hashAlgorithm, _validationKey);

            xuser.Element("Email").Value = user.Email;
            xuser.Element("PasswordQuestion").Value = user.PasswordQuestion;

            if (!string.IsNullOrEmpty(passwordQuestionAnswer))
                xuser.Element("PasswordAnswer").Value = passwordQuestionAnswer;

            xuser.Element("IsApproved").Value = Convert.ToString(user.IsApproved);
            xuser.Element("IsLockedOut").Value = Convert.ToString(user.IsLockedOut);
            xuser.Element("LastLoginDate").Value = Convert.ToString(user.LastLoginDate);
            xuser.Element("LastPasswordChangeDate").Value = Convert.ToString(user.LastPasswordChangedDate);
            xuser.Element("LastLockoutDate").Value  = Convert.ToString(user.LastLockoutDate);
            xuser.Element("Comment").Value = user.Comment;

            _Document.Save(_XmlFileName);
        }

        #endregion

        #region Helper methods

        /// <summary>
        /// Convert an XElement to a membership user.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private MembershipUser XElementToMembershipUser(XElement user)
        {
            return new MembershipUser(this.ProviderName,
                user.Element("UserName").Value,
                user.Element("UserName").Value,
                user.Element("Email").Value,
                user.Element("PasswordQuestion").Value ?? "",
                user.Element("Comment").Value ?? "",
                Convert.ToBoolean(user.Element("IsApproved").Value ?? "False"),
                Convert.ToBoolean(user.Element("IsLockedOut").Value ?? "False"),
                Convert.ToDateTime(user.Element("CreateDate").Value ?? DateTime.MinValue.ToLongDateString()),
                Convert.ToDateTime(user.Element("LastLoginDate").Value ?? DateTime.MinValue.ToLongDateString()),
                Convert.ToDateTime(user.Element("LastActivityDate").Value ?? DateTime.MinValue.ToLongDateString()),
                Convert.ToDateTime(user.Element("LastPasswordChangeDate").Value ?? DateTime.MinValue.ToLongDateString()),
                Convert.ToDateTime(user.Element("LastLockoutDate").Value ?? DateTime.MinValue.ToLongDateString()));
        }

        /// <summary>
        /// Builds the internal cache of users.
        /// </summary>
        /// 
        private void ReadMembershipDataStore() { }
        private void InitializeDataStore()
        {
            lock (this)
            {
                if (_Document == null)
                {
                    _Document = XDocument.Load(this.XmlFileName);                    
                }
            }
        }

        private string GetConfigValue(string value, string defaultValue)
        {
            if (string.IsNullOrEmpty(value))
                return defaultValue;
            return value;
        }

        private void InitConfigSettings(NameValueCollection config)
        {
            ApplicationName = GetConfigValue(config["applicationName"], System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            _maxInvalidPasswordAttempts = Convert.ToInt32(GetConfigValue(config["maxInvalidPasswordAttempts"], "5"));
            _passwordAttemptWindow = Convert.ToInt32(GetConfigValue(config["passwordAttemptWindow"], "10"));
            _minRequiredNonAlphanumericCharacters = Convert.ToInt32(GetConfigValue(config["minRequiredNonAlphaNumericCharacters"], "1"));
            _minRequiredPasswordLength = Convert.ToInt32(GetConfigValue(config["minRequiredPasswordLength"], "7"));
            _passwordStrengthRegularExpression = Convert.ToString(GetConfigValue(config["passwordStrengthRegularExpression"], String.Empty));
            _enablePasswordReset = Convert.ToBoolean(GetConfigValue(config["enablePasswordReset"], "true"));
            _enablePasswordRetrieval = Convert.ToBoolean(GetConfigValue(config["enablePasswordRetrieval"], "true"));
            _requiresQuestionAndAnswer = Convert.ToBoolean(GetConfigValue(config["requiresQuestionAndAnswer"], "false"));
            _requiresUniqueEmail = Convert.ToBoolean(GetConfigValue(config["requiresUniqueEmail"], "true"));            
        }

        private void InitPasswordEncryptionSettings(NameValueCollection config)
        {
            System.Configuration.Configuration cfg = WebConfigurationManager.OpenWebConfiguration(System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            MachineKeySection machineKey = cfg.GetSection("system.web/machineKey") as MachineKeySection;
            _hashAlgorithm = machineKey.ValidationAlgorithm;
            _validationKey = machineKey.ValidationKey;

            if (_validationKey.Contains("AutoGenerate"))
            {
                if (PasswordFormat != MembershipPasswordFormat.Clear)
                {
                    throw new ProviderException("Hashed or Encrypted passwords are not supported with auto-generated keys.");
                }
            }

            string passFormat = config["passwordFormat"];
            if (passFormat == null)
            {
                passFormat = "Hashed";
            }

            switch (passFormat)
            {
                case "Hashed":
                    _passwordFormat = MembershipPasswordFormat.Hashed;
                    break;
                case "Encrypted":
                    throw new ProviderException("Encrypted passwords are not secure, please use a hashing algorithm.");                    
                case "Clear":
                    throw new ProviderException("Clear passwords are not secure, please use a hashing algorithm.");                                        
                default:
                    throw new ProviderException("The password format from the custom provider is not supported.");
            }
        }

        /// <summary>
        /// Encode the password //Chris Pels
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        private string EncodePassword(string password, string salt)
        {
            string encodedPassword = password;

            switch (_passwordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    encodedPassword =
                      Convert.ToBase64String(EncryptPassword(Encoding.Unicode.GetBytes(password)));
                    break;
                case MembershipPasswordFormat.Hashed:
                    if (string.IsNullOrEmpty(salt))
                        throw new ProviderException("A random salt is required with hashed passwords.");
                    encodedPassword = PasswordUtil.HashPassword(password, salt, _hashAlgorithm, _validationKey);
                    break;
                default:
                    throw new ProviderException("Unsupported password format.");
            }
            return encodedPassword;
        }

        /// <summary>
        /// UnEncode the password //Chris Pels
        /// </summary>
        /// <param name="encodedPassword"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        private string UnEncodePassword(string encodedPassword, string salt)
        {
            string password = encodedPassword;

            switch (_passwordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    password =
                      Encoding.Unicode.GetString(DecryptPassword(Convert.FromBase64String(password)));
                    break;
                case MembershipPasswordFormat.Hashed:
                    throw new ProviderException("Hashed passwords do not require decoding, just compare hashes.");
                default:
                    throw new ProviderException("Unsupported password format.");
            }
            return password;
        }

        /// <summary>
        /// Encrypts a string using the SHA256 algorithm.
        /// </summary>
        private static string Encrypt(string plainMessage)
        {
            byte[] data = Encoding.UTF8.GetBytes(plainMessage);
            using (HashAlgorithm sha = new SHA256Managed())
            {
                byte[] encryptedBytes = sha.TransformFinalBlock(data, 0, data.Length);
                return Convert.ToBase64String(sha.Hash);
            }
        }

        #endregion

        #region Unsupported methods

        public override string ResetPassword(string username, string answer)
        {
            throw new NotSupportedException();
        }

        public override bool UnlockUser(string userName)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override int GetNumberOfUsersOnline()
        {
            throw new NotSupportedException();
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotSupportedException();
        }

        public override string GetPassword(string username, string answer)
        {
            throw new NotSupportedException();
        }

        #endregion
        
    }
}