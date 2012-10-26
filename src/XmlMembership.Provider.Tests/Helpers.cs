using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Web.Security;
using System.Xml.Linq;
using Wcjj.Providers;

namespace Membership.Provider.Tests
{
    public static class Helpers
    {
       

        public static void AddTestUser(string _xmlFileName, string hashAlgorithm, string validationKey)
        {
            string password = FakesData.GoodPassword();
            string passwordQuestionAnswer = FakesData.GoodPasswordQuestionAnswer();
            string salt = PasswordUtil.CreateRandomSalt();

            var document = XDocument.Load(_xmlFileName);
            var user = document.Descendants("User").Where(x => x.Element("UserName").Value == FakesData.GoodUserName()).FirstOrDefault();

            if (user == null)
            {
                var xuser = new XElement("User",
                    new XElement("ApplicationId", "MyApp"),
                    new XElement("UserName", FakesData.GoodUserName()),
                    new XElement("PasswordSalt", salt),
                    new XElement("Password", PasswordUtil.HashPassword(password, salt, hashAlgorithm, validationKey)),
                    new XElement("Email", FakesData.GoodEmail()),
                    new XElement("PasswordQuestion", FakesData.GoodPasswordQuestion()),
                    new XElement("PasswordAnswer", passwordQuestionAnswer),
                    new XElement("IsApproved", Convert.ToString(true)),
                    new XElement("IsLockedOut", Convert.ToString(false)),
                    new XElement("CreateDate", Convert.ToString(DateTime.Now)),
                    new XElement("LastLoginDate", Convert.ToString(DateTime.Now)),
                    new XElement("LastActivityDate", Convert.ToString(DateTime.Now)),
                    new XElement("LastPasswordChangeDate", Convert.ToString(DateTime.Now)),
                    new XElement("LastLockoutDate", Convert.ToString(DateTime.Now)),
                    new XElement("FailedPasswordAttemptCount", Convert.ToString(0)),
                    new XElement("FailedPasswordAnswerAttemptCount", Convert.ToString(0)),
                    new XElement("Comment", "")
                    );


                var xusers = document.Descendants("Users").FirstOrDefault();
                xusers.AddFirst(xuser);
                document.Save(_xmlFileName);
            }

        }

        public static XElement GetGoodUser(string hashAlgorithm, string validationKey)
        {
            string password = FakesData.GoodPassword();
            string passwordQuestionAnswer = FakesData.GoodPasswordQuestionAnswer();
            string salt = PasswordUtil.CreateRandomSalt();
            var xuser = new XElement("User",
                    new XElement("ApplicationId", "MyApp"),
                    new XElement("UserName", FakesData.GoodUserName()),
                    new XElement("PasswordSalt", salt),
                    new XElement("Password", PasswordUtil.HashPassword(password, salt, hashAlgorithm, validationKey)),
                    new XElement("Email", FakesData.GoodEmail()),
                    new XElement("PasswordQuestion", FakesData.GoodPasswordQuestion()),
                    new XElement("PasswordAnswer", passwordQuestionAnswer),
                    new XElement("IsApproved", Convert.ToString(true)),
                    new XElement("IsLockedOut", Convert.ToString(false)),
                    new XElement("CreateDate", Convert.ToString(DateTime.Now)),
                    new XElement("LastLoginDate", Convert.ToString(DateTime.Now)),
                    new XElement("LastActivityDate", Convert.ToString(DateTime.Now)),
                    new XElement("LastPasswordChangeDate", Convert.ToString(DateTime.Now)),
                    new XElement("LastLockoutDate", Convert.ToString(DateTime.Now)),
                    new XElement("FailedPasswordAttemptCount", Convert.ToString(0)),
                    new XElement("FailedPasswordAnswerAttemptCount", Convert.ToString(0)),
                    new XElement("Comment", "")
                    );

            return xuser;
        }

        public static MembershipUser ConvertXElementToMembershipUser(XElement user)
        {
            return new MembershipUser("",
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

        public static NameValueCollection CreateMembershipConfigFake()
        {
            NameValueCollection config = new NameValueCollection();
            config.Add("name", "XmlMembershipProvider");
            config.Add("applicationName", "MyApp");
            config.Add("enablePasswordReset", "true");
            config.Add("enablePasswordRetrieval", "true");
            config.Add("maxInvalidPasswordAttempts", "5");
            config.Add("minRequiredAlphaNumericCharacters", "2");
            config.Add("minRequiredPasswordLength", "6");
            config.Add("requiresQuestionAndAnswer", "true");
            config.Add("requiresUniqueEmail", "true");
            config.Add("passwordAttemptWindow", "10");
            config.Add("passwordFormat", "Hashed");
            //config.Add("connectionStringName", "Server");            
            return config;
        }

        public  static NameValueCollection CreateRoleConfigFake()
        {
            NameValueCollection config = new NameValueCollection();
            config.Add("name", "XmlRoleProvider");
            config.Add("applicationName", "MyApp");
            //config.Add("enablePasswordReset", "true");
            //config.Add("enablePasswordRetrieval", "true");
            //config.Add("maxInvalidPasswordAttempts", "5");
            //config.Add("minRequiredAlphaNumericCharacters", "2");
            //config.Add("minRequiredPasswordLength", "6");
            //config.Add("requiresQuestionAndAnswer", "true");
            //config.Add("requiresUniqueEmail", "true");
            //config.Add("passwordAttemptWindow", "10");
            //config.Add("passwordFormat", "Hashed");
            //config.Add("connectionStringName", "Server");            
            return config;
        }

        public static void AddTestRoles(string xmlFileName)
        {
            var document = XDocument.Load(xmlFileName);

            var xRole = new XElement("Role",
                         new XElement("ApplicationId", "MyApp"),
                         new XElement("RoleName", "Admins"),
                         new XElement("Description", "Application Administrators Role"));

            var xRole2 = new XElement("Role",
                         new XElement("ApplicationId", "MyApp"),
                         new XElement("RoleName", "Users"),
                         new XElement("Description", "Application Regular User"));

            var xRole3 = new XElement("Role",
                         new XElement("ApplicationId", "MyApp"),
                         new XElement("RoleName", "Power Users"),
                         new XElement("Description", "Application Advanced Users"));

            var xRoles = document.Descendants("Roles").FirstOrDefault();
            xRoles.Add(xRole);
            xRoles.Add(xRole2);
            xRoles.Add(xRole3);

            document.Save(xmlFileName);

        }

        
    }
}
