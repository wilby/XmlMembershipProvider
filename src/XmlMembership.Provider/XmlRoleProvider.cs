using System;
using System.Collections.Generic;
using System.Configuration.Provider;
using System.IO;
using System.Linq;
using System.Security.Permissions;
using System.Text;
using System.Web;
using System.Web.Hosting;
using System.Web.Security;
using System.Xml.Linq;

namespace Wcjj.Providers
{
    public class XmlRoleProvider : RoleProvider
    {
        private XDocument _Document;

        /// <summary>
        /// Used in testing for access to the private _Document variable when compile in debug mode.
        /// </summary>
        #if DEBUG
        public XDocument XDocument { get { return _Document; } set { _Document = value; } }
        #endif

        public override string ApplicationName { get; set; }

        public string XmlFileName { get; set; }

        public override void Initialize(string name, System.Collections.Specialized.NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("There are no role provider configuration settings.");
            if (string.IsNullOrEmpty(name))
                name = "XmlRoleProvider";
            if (string.IsNullOrEmpty(config["description"]))
                config["description"] = "An Asp.Net Role provider for with an XML file backend.";            

            ApplicationName = string.IsNullOrEmpty(config["applicationName"]) ? System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath : config["applicationName"];

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


            if (!File.Exists(XmlFileName))
            {
                File.AppendAllText(XmlFileName, @"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""no"" ?>
<XmlProvider>
  <Users> 
    <!--
    <User>
      <ApplicationId>/</ApplicationId>
      <UserName></UserName>
      <PasswordSalt></PasswordSalt>
      <Password></Password>
      <Email></Email>
      <PasswordQuestion></PasswordQuestion>
      <PasswordAnswer></PasswordAnswer>
      <IsApproved></IsApproved>
      <IsLockedOut></IsLockedOut>
      <CreateDate></CreateDate>
      <LastLoginDate></LastLoginDate>
      <LastActivityDate></LastActivityDate>
      <LastPasswordChangeDate></LastPasswordChangeDate>
      <LastLockoutDate></LastLockoutDate>
      <FailedPasswordAttemptCount></FailedPasswordAttemptCount>
      <FailedPasswordAnswerAttemptCount></FailedPasswordAnswerAttemptCount>
      <Comment></Comment>
    </User>
    -->   
  </Users>
  <Roles>
    <!-- <Role>
      <ApplicationId>/</ApplicationId>
      <RoleName></RoleName>
      <Description></Description>
    </Role> -->
  </Roles>
  <UserRoles>
    <!-- <UserRole>
        <ApplicationId></ApplicationId>
        <UserName></UserName>
        <RoleName></RoleName>
    <UserRole> -->
  </UserRoles>
</XmlProvider>
");
            }

            base.Initialize(name, config);
        }

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            foreach (var user in usernames)
            {
                if (user == "")
                    throw new ArgumentException("Empty usernames are not allowed.");
                if (user == null)
                    throw new ArgumentNullException("Null values are not allowed for usernames.");

                var muser = _Document.Descendants("User").Where(x => x.Element("UserName").Value == user.ToLower() 
                    && x.Element("ApplicationId").Value == ApplicationName).FirstOrDefault();

                if (muser == null)
                    throw new ProviderException(string.Format("The user {0} does not exist.", user));
            }
            foreach (var role in roleNames)
            {
                if (role == "")
                    throw new ArgumentException("Empty roles are not allowed.");
                if(role == null)
                    throw new ArgumentNullException("Null values are not allowed for usernames.");

                var xRole = GetRole(role);

                if (xRole == null)
                    throw new ProviderException(string.Format("The role {0} does not exist.", role));
            }

            var xUserRoles = _Document.Descendants("UserRoles").FirstOrDefault();
            foreach (var role in roleNames)
            {
                foreach (var user in usernames)
                {
                    var xUserRole = new XElement("UserRole",
                        new XElement("ApplicationId", ApplicationName),
                        new XElement("RoleName", role),
                        new XElement("UserName", user));
                    xUserRoles.Add(xUserRole);
                }
            }
            _Document.Save(XmlFileName);
            
        }
        
        public override void CreateRole(string roleName)
        {
            ValidateParameter(roleName);
            
            var xRole = GetRole(roleName);
            if (xRole != null)
                throw new ProviderException(string.Format("The role {0} for application {1} already exists.", roleName, ApplicationName));

            xRole = new XElement("Role",
                new XElement("ApplicationId", ApplicationName),
                new XElement("RoleName", roleName)                
            );

            _Document.Descendants("Roles").FirstOrDefault().Add(xRole);
            _Document.Save(XmlFileName);
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            InitializeDataStore();

            ValidateParameter(roleName);
            var xUserRoles = _Document.Descendants("UserRole").Where(x => x.Element("RoleName").Value == roleName && x.Element("ApplicationId").Value == ApplicationName);

            if (xUserRoles.Count() > 0 && throwOnPopulatedRole)
                throw new ProviderException(string.Format("The role {0} is still in use.", roleName));

            try
            {
                xUserRoles.Remove();
                var xRole = _Document.Descendants("Role").Where(x => x.Element("RoleName").Value == roleName);
                xRole.Remove();
                _Document.Save(XmlFileName);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            var xRole = GetRole(roleName);
            if (xRole == null)
                throw new ProviderException(string.Format("The role {0} does not exist.", roleName));

            var matchedUserNames = _Document.Descendants("UserRole").Where(x => x.Element("RoleName").Value == roleName &&
                x.Element("UserName").IsMatch(usernameToMatch) && x.Element("ApplicationId").Value == ApplicationName).Select(y => y.Element("UserName").Value).OrderBy(z => z);

            if (matchedUserNames.Count() > 0)
                return matchedUserNames.ToArray<string>();

            return new string[0];
        }

        public override string[] GetAllRoles()
        {
            InitializeDataStore();

            var roles = _Document.Descendants("Role").Where(x => x.Element("ApplicationId").Value == ApplicationName).Select(y => y.Element("RoleName").Value);
            if (roles.Count() > 0)
                return roles.ToArray<string>();
            return new string[0];
        }

        public override string[] GetRolesForUser(string username)
        {
            InitializeDataStore();

            ValidateParameter(username);
            var roles = _Document.Descendants("UserRole").Where(x => x.Element("ApplicationId").Value == ApplicationName
                && x.Element("UserName").Value == username.ToLower()).Select(y => y.Element("RoleName").Value);

            if (roles.Count() > 0)
                return roles.ToArray<string>();

            return new string[0];
        }

        public override string[] GetUsersInRole(string roleName)
        {
            ValidateParameter(roleName);

            var xRole = GetRole(roleName);
            if (xRole == null)
                throw new ProviderException(string.Format("The role {0} does not exist.", roleName));

            var userNames = _Document.Descendants("UserRole").Where(x => x.Element("ApplicationId").Value == ApplicationName
                && x.Element("RoleName").Value == roleName).Select( y => y.Element("UserName").Value);

            if (userNames.Count() > 0)
                return userNames.ToArray<string>();

            return new string[0];
        }

        public override bool IsUserInRole(string username, string roleName)
        {
            ValidateParameter(username);
            ValidateParameter(roleName);

            var xRole = GetRole(roleName);
            if (xRole == null)
                throw new ProviderException(string.Format("The role {0} does not exist.", roleName));

            var xUser = GetRole(roleName);
            if (xUser == null)
                throw new ProviderException(string.Format("The user {0} does not exist.", username));

            var xUserRole = _Document.Descendants("UserRole").Where(x =>
                x.Element("ApplicationId").Value == ApplicationName
                && x.Element("RoleName").Value == roleName
                && x.Element("UserName").Value == username).FirstOrDefault();

            if (xUserRole != null)
                return true;
            return false;

        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            InitializeDataStore();

            foreach (var user in usernames)
            {
                ValidateParameter(user);
            }
            foreach (var role in roleNames)
            {
                ValidateParameter(role);
            }
            
            var users = _Document.Descendants("User").Where(x => usernames.Contains(x.Element("UserName").Value) && x.Element("ApplicationId").Value == ApplicationName).Select(y => y.Element("UserName").Value);
            var roles = _Document.Descendants("Role").Where(x => roleNames.Contains(x.Element("RoleName").Value) && x.Element("ApplicationId").Value == ApplicationName).Select(y => y.Element("RoleName").Value);

            foreach (var user in usernames)
            {
                if (!users.Contains(user))
                    throw new ProviderException(string.Format("The user {0} does not exist.", user));
            }

            foreach (var role in roleNames)
            {
                if(!roles.Contains(role))
                    throw new ProviderException(string.Format("The role {0} does not exist.", role));
            }

            var xUserRole = _Document.Descendants("UserRole").Where(x =>
               x.Element("ApplicationId").Value == ApplicationName
               && roleNames.Contains(x.Element("RoleName").Value)
               && usernames.Contains(x.Element("UserName").Value));

            xUserRole.Remove();
        }

        public override bool RoleExists(string roleName)
        {
            ValidateParameter(roleName);
            var exists = _Document.Descendants("Role").Any(x => x.Element("ApplicationId").Value == ApplicationName
                && x.Element("RoleName").Value == roleName);
            return exists;
        }

        #region Helper Methods

        private XElement GetRole(string roleName)
        {
            InitializeDataStore();

            return _Document.Descendants("Role").Where(x => x.Element("ApplicationId").Value == ApplicationName
                && x.Element("RoleName").Value == roleName).FirstOrDefault();
        }

        private void ValidateParameter(string roleName)
        {
            if (roleName == "")
                throw new ArgumentException("The parameter cannot be an empty string.");

            if (roleName == null)
                throw new ArgumentNullException("The parameter cannot be null");
        }

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

        #endregion

        
    }
}
