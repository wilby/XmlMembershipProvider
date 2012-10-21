using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Membership.Provider.Tests.Fake;
using System.Xml.Linq;
using System.Linq;
using System.Configuration;
using System.Collections.Specialized;
using System.Web.Configuration;
using System.Text;
using System.Web.Security;

namespace Membership.Provider.Tests
{
    [TestClass]
    public class XmlMembershipProviderTests
    {
        public static XDocument _Document;
        public static string _hashAlgorithm;
        public static string _validationKey;
        public static string _xmlFileName = "Membership.xml";
        public static XmlMembershipProvider _provider;

        public XmlMembershipProviderTests()
        {
            System.Configuration.Configuration cfg = 
                WebConfigurationManager.OpenWebConfiguration(
                System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            MachineKeySection machineKey = cfg.GetSection("system.web/machineKey") as MachineKeySection;
            _hashAlgorithm = machineKey.ValidationAlgorithm;
            _validationKey = machineKey.ValidationKey;
        }

        [ClassInitialize]
        public static void Initialize(TestContext context)
        {            
            AddTestUser();

            _provider = new XmlMembershipProvider();
            _provider.XmlFileName = "Membership.xml";
            _provider.XDocument = _Document;
            _provider.Initialize("XmlMembershipProvider", CreateConfigFake());            
        }

        [ClassCleanup]
        public static void Teardown()
        {
            _Document.Descendants("User").Remove();
            _Document.Save(_xmlFileName);
        }

        [TestMethod]
        public void ValidateUser_returns_true_with_good_password()
        {   
         
            var result = _provider.ValidateUser(FakesData.GoodUserName(), FakesData.GoodPassword());

            Assert.IsTrue(result);
        }

        [TestMethod]
        public void ValidateUser_returns_false_with_bad_password()
        {
            var result = _provider.ValidateUser(FakesData.GoodUserName(), FakesData.BadPassword());

            Assert.IsFalse(result);
        }

        [TestMethod]
        public void GetUser_test_user_is_returned()
        {
            var user = _provider.GetUser(FakesData.GoodUserName(), userIsOnline: false);
            
            Assert.IsNotNull(user);
            Assert.AreEqual(user.UserName, FakesData.GoodUserName());
            Assert.AreEqual(user.Email, FakesData.GoodEmail());
        }

        [TestMethod]
        public void GetUser_returns_null_when_user_is_not_present()
        {
            var user = _provider.GetUser(FakesData.BadUserName(), userIsOnline: false);

            Assert.IsNull(user);            
        }

        [TestMethod]
        public void GetUser_Updates_LastActivity_when_userIsOnlineIsTrue()
        {
            var lastActivity = DateTime.Now;
            var user = _provider.GetUser(FakesData.GoodUserName(), userIsOnline: true);

            var ts = lastActivity.Subtract(user.LastActivityDate);
            Assert.IsTrue(ts.Minutes < 1);
        }

        [TestMethod]
        public void GetUser_ObjectParam_test_user_is_returned()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append(FakesData.GoodUserName());
            var user = _provider.GetUser(builder, userIsOnline: false);

            Assert.IsNotNull(user);
            Assert.AreEqual(user.UserName, FakesData.GoodUserName());
            Assert.AreEqual(user.Email, FakesData.GoodEmail());
        }

        [TestMethod]
        public void GetUser_ObjectParam_returns_null_when_user_is_not_present()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append(FakesData.BadUserName());
            var user = _provider.GetUser(builder, userIsOnline: false);

            Assert.IsNull(user);
        }

        [TestMethod]
        public void CreateUser_returns_null_and_status_when_duplicate_name()
        {
            MembershipCreateStatus status;
            var user = _provider.CreateUser(FakesData.GoodUserName(), FakesData.GoodPassword(), FakesData.GoodEmail(), null, null, false, null, out status);

            Assert.AreEqual(MembershipCreateStatus.DuplicateUserName, status);
            Assert.IsNull(user);
        }

        [TestMethod]
        public void CreateUser_returns_null_and_status_when_duplicate_email()
        {
            MembershipCreateStatus status;
            var user = _provider.CreateUser(FakesData.BadPassword(), FakesData.GoodPassword(), FakesData.GoodEmail(), null, null, false, null, out status);

            Assert.AreEqual(MembershipCreateStatus.DuplicateEmail, status);
            Assert.IsNull(user);
        }

        [TestMethod]
        public void CreateUser_returns_null_and_status_when_password_min_length_isnotmet()
        {
            MembershipCreateStatus status;
            var user = _provider.CreateUser(FakesData.BadPassword(), "pas", FakesData.BadEmail(), null, null, false, null, out status);

            Assert.AreEqual(MembershipCreateStatus.InvalidPassword, status);
            Assert.IsNull(user);
        }

        [TestMethod]
        public void CreateUser_returns_null_and_status_when_password_minnonalphanumeric_length_isnotmet()
        {
            MembershipCreateStatus status;
            var user = _provider.CreateUser(FakesData.BadPassword(), "password1", FakesData.BadEmail(), null, null, false, null, out status);

            Assert.AreEqual(MembershipCreateStatus.InvalidPassword, status);
            Assert.IsNull(user);
        }

        [TestMethod]
        public void CreateUser_returns_user_and_success_status()
        {
            MembershipCreateStatus status;
            var xuser = _provider.XDocument.Descendants("User").Where(x => x.Element("UserName").Value == FakesData.GoodUserName()).FirstOrDefault();
            xuser.Remove();

            var user = _provider.CreateUser(FakesData.GoodUserName(), FakesData.GoodPassword(), FakesData.GoodEmail(),
                FakesData.GoodPasswordQuestion(), FakesData.GoodPasswordQuestionAnswer(), 
                true, FakesData.GoodUserName(), out status);

            Assert.AreEqual(MembershipCreateStatus.Success, status);
            Assert.IsNotNull(user);
        }

        [TestMethod]
        public void UpdateUser_changes_values_and_saves_them_to_datastore()
        {
            var date = DateTime.Now;

            var user = _provider.GetUser(FakesData.GoodUserName(), false);
            user.Comment = "New Comment";
            user.Email = "wilby@wilby.com";
            user.LastLoginDate = date;

            _provider.UpdateUser(user);

            var userAfterChanges = _provider.GetUser(FakesData.GoodUserName(), false);

            Assert.AreEqual(user.Comment, userAfterChanges.Comment);
            Assert.AreEqual(user.Email, userAfterChanges.Email);
            Assert.AreEqual(user.LastLoginDate.ToLongDateString(), userAfterChanges.LastLoginDate.ToLongDateString());
        }

        [TestMethod]
        public void DeleteUser_deletes_user_from_datastore()
        {
            _provider.DeleteUser(FakesData.GoodUserName(), true);

            var xUser = _provider.XDocument.Descendants("User").Where(x => x.Element("UserName").Value == FakesData.GoodUserName()).FirstOrDefault();

            Assert.IsNull(xUser);

            AddTestUser();
        }

        [TestMethod]
        public void GetAllUsers()
        {
            var xUser = GetGoodUser();
            if(_provider.XDocument.Descendants("User").Count() == 0)
                _provider.XDocument.Descendants("Users").FirstOrDefault().Add(xUser);

            int total  = 0;
            var users = _provider.GetAllUsers(0, 4, out total);

            Assert.AreEqual(1, total);            
        }

        [TestMethod]
        public void GetNumberOfUsersOnline()
        {
            var userOnline = _provider.GetNumberOfUsersOnline();

            Assert.AreEqual(1, userOnline);
        }

        [TestMethod]
        public void ResetPassword()
        {
            var newPassword = _provider.ResetPassword(FakesData.GoodUserName(), FakesData.GoodPasswordQuestionAnswer());

            var xUser = XDocument.Load(_xmlFileName).Descendants("User").Where(x => x.Element("UserName").Value == FakesData.GoodUserName()).FirstOrDefault();

            Assert.AreEqual(xUser.Element("Password").Value, PasswordUtil.HashPassword(newPassword, xUser.Element("PasswordSalt").Value, _hashAlgorithm, _validationKey));
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void ResetPassword_thows_not_supported_when_enablePasswordReset_is_false()
        {
            _provider = new XmlMembershipProvider();
            _provider.XmlFileName = "Membership.xml";
            _provider.XDocument = _Document;
            var config = CreateConfigFake();
            config.Remove("enablePasswordReset");
            config.Add("enablePasswordReset", "false");
            _provider.Initialize("XmlMembershipProvider", config);
            var newPassword = _provider.ResetPassword(FakesData.GoodUserName(), FakesData.GoodPasswordQuestionAnswer());

        }

        [TestMethod]
        [ExpectedException(typeof(NullReferenceException))]
        public void ResetPassword_thows_NullReference_when_user_does_not_exist()
        {   
            //Reset Config from last test
            Initialize(null);

            var newPassword = _provider.ResetPassword(FakesData.BadUserName(), FakesData.GoodPasswordQuestionAnswer());
        }

        [TestMethod]
        [ExpectedException(typeof(MembershipPasswordException))]
        public void ResetPassword_thows_membershippassword_when_passwordquestionanser_is_wrong()
        {
            
            var newPassword = _provider.ResetPassword(FakesData.GoodUserName(), "");
        }

        [TestMethod]
        [ExpectedException(typeof(MembershipPasswordException))]
        public void GetPassword_thows_MembershipPasswordException_when_trying_to_retrieve_hashed_Passwords()
        {            
            var newPassword = _provider.GetPassword(FakesData.GoodUserName(), FakesData.GoodPasswordQuestionAnswer());

        }

        [TestMethod]
        public void GetUserNameByEmail()
        {
            string username = _provider.GetUserNameByEmail(FakesData.GoodEmail());

            Assert.AreEqual(FakesData.GoodUserName(), username);
        }


        //Helper Methods

        public static void AddTestUser()
        {
            string password = FakesData.GoodPassword();
            string passwordQuestionAnswer = FakesData.GoodPasswordQuestionAnswer();            
            string salt = PasswordUtil.CreateRandomSalt();

            _Document = XDocument.Load(_xmlFileName);
            var user = _Document.Descendants("User").Where(x => x.Element("UserName").Value == FakesData.GoodUserName()).FirstOrDefault();
            
            if (user == null)
            {
                var xuser = new XElement("User",
                    new XElement("ApplicationId", "MyApp"),
                    new XElement("UserName", FakesData.GoodUserName()),
                    new XElement("PasswordSalt", salt),
                    new XElement("Password", PasswordUtil.HashPassword(password, salt, _hashAlgorithm, _validationKey)),
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


                    var xusers = _Document.Descendants("Users").FirstOrDefault();
                    xusers.AddFirst(xuser);
                    _Document.Save(_xmlFileName);
            }
            
        }

        private static XElement GetGoodUser() {
            string password = FakesData.GoodPassword();
            string passwordQuestionAnswer = FakesData.GoodPasswordQuestionAnswer();            
            string salt = PasswordUtil.CreateRandomSalt();
            var xuser = new XElement("User",
                    new XElement("ApplicationId", "MyApp"),
                    new XElement("UserName", FakesData.GoodUserName()),
                    new XElement("PasswordSalt", salt),
                    new XElement("Password", PasswordUtil.HashPassword(password, salt, _hashAlgorithm, _validationKey)),
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

        private static MembershipUser GetGoodUser(XElement user)
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

        private static NameValueCollection CreateConfigFake()
        {
            NameValueCollection config = new NameValueCollection();
            config.Add("name", "XmlMembershipProvider");
            config.Add("applicationName", "TestApp");
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
    }
}
