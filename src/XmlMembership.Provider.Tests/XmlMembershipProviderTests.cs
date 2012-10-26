using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Xml.Linq;
using System.Linq;
using System.Configuration;
using System.Collections.Specialized;
using System.Web.Configuration;
using System.Text;
using System.Web.Security;
using System.IO;
using Wcjj.Providers;

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

        [TestInitialize]
        public void Initialize()
        {            
            Helpers.AddTestUser(_xmlFileName, _hashAlgorithm, _validationKey);

            _provider = new XmlMembershipProvider();
            _provider.XmlFileName = _xmlFileName;
            if (File.Exists(_xmlFileName))
                File.Delete(_xmlFileName);

            File.AppendAllText(_xmlFileName, @"<XmlProvider>
  <Users>    
  </Users>
  <Roles>
    <Role>
      <ApplicationId>/</ApplicationId>
      <RoleName></RoleName>
      <Description></Description>
    </Role>
  </Roles>
  <UserRoles>
    <UserRole>
        <ApplicationId></ApplicationId>
        <UserName></UserName>
        <RoleName></RoleName>
    </UserRole>
  </UserRoles>
</XmlProvider>
");         
            Helpers.AddTestUser(_xmlFileName, _hashAlgorithm, _validationKey);
            _Document = XDocument.Load(_xmlFileName);
            _provider.XDocument = _Document;
            _provider.Initialize("XmlMembershipProvider", Helpers.CreateMembershipConfigFake());            
        }

        [ClassCleanup]
        public static void Teardown()
        {
            //_Document.Descendants("User").Remove();
            //_Document.Save(_xmlFileName);
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

            Helpers.AddTestUser(_xmlFileName, _hashAlgorithm, _validationKey);
        }

        [TestMethod]
        public void GetAllUsers()
        {
            var xUser = Helpers.GetGoodUser(_hashAlgorithm, _validationKey);
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
            var config = Helpers.CreateMembershipConfigFake();
            config.Remove("enablePasswordReset");
            config.Add("enablePasswordReset", "false");
            _provider.Initialize("XmlMembershipProvider", config);
            var newPassword = _provider.ResetPassword(FakesData.GoodUserName(), FakesData.GoodPasswordQuestionAnswer());

        }

        [TestMethod]
        [ExpectedException(typeof(NullReferenceException))]
        public void ResetPassword_thows_NullReference_when_user_does_not_exist()
        {   
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

        [TestMethod]
        public void ChangePassword_returns_false_when_user_does_not_exist()
        {
            var changed = _provider.ChangePassword(FakesData.BadUserName(), FakesData.GoodPassword(), FakesData.GoodPassword());

            Assert.AreEqual(false, changed);
        }

        [TestMethod]
        public void ChangePassword_returns_false_when_old_pass_is_wrong()
        {
            var changed = _provider.ChangePassword(FakesData.GoodUserName(), "", FakesData.GoodPassword());

            Assert.AreEqual(false, changed);
        }

        [TestMethod]
        public void ChangePassword_returns_true_when_username_and_old_pass_are_correct()
        {   
            var changed = _provider.ChangePassword(FakesData.GoodUserName(), FakesData.GoodPassword(), FakesData.GoodPassword());

            Assert.AreEqual(true, changed);
        }

        [TestMethod]
        public void ChangePasswordQuestionAndAnswe_returns_false_when_user_does_not_exist()
        {
            var changed = _provider.ChangePasswordQuestionAndAnswer(FakesData.BadUserName(), FakesData.GoodPassword(), FakesData.GoodPasswordQuestion(), FakesData.GoodPasswordQuestionAnswer());

            Assert.AreEqual(false, changed);
        }

        [TestMethod]
        public void ChangePasswordQuestionAndAnswe_returns_false_when__pass_is_wrong()
        {
            var changed = _provider.ChangePasswordQuestionAndAnswer(FakesData.GoodUserName(), FakesData.BadPassword(), FakesData.GoodPasswordQuestion(), FakesData.GoodPasswordQuestionAnswer());

            Assert.AreEqual(false, changed);
        }

        [TestMethod]
        public void ChangePasswordQuestionAndAnswe_returns_true_when_username_and_old_pass_are_correct()
        {
            var changed = _provider.ChangePasswordQuestionAndAnswer(FakesData.GoodUserName(), FakesData.GoodPassword(), FakesData.GoodPasswordQuestion(), FakesData.GoodPasswordQuestionAnswer());

            Assert.AreEqual(true, changed);
        }

        [TestMethod]
        public void FindUsersByName()
        {
            int totalRecord = 0;

            var memUsers = _provider.FindUsersByName("w", 0, 10, out totalRecord);

            Assert.AreEqual(1, totalRecord);
            Assert.AreEqual(1, memUsers.Count);
        }

        [TestMethod]
        public void FindUsersByEmail()
        {
            int totalRecord = 0;

            var memUsers = _provider.FindUsersByName(FakesData.GoodEmail().Substring(0, 4), 0, 10, out totalRecord);

            Assert.AreEqual(1, totalRecord);
            Assert.AreEqual(1, memUsers.Count);
        }
    }
}
