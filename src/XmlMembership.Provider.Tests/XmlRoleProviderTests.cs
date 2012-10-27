using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Wcjj.Providers;
using System.Xml.Linq;
using System.Linq;
using System.IO;
using System.Web.Configuration;
using System.Configuration.Provider;

namespace Membership.Provider.Tests
{
    [TestClass]
    public class XmlRoleProviderTests
    {
        public static XDocument _Document;
        public static string _hashAlgorithm;
        public static string _validationKey;
        private static string _xmlFileName = "Membership.xml";
        private XmlRoleProvider _provider;

        public XmlRoleProviderTests()
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

            _provider = new XmlRoleProvider();
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
            Helpers.AddTestRoles(_xmlFileName);            

            _Document = XDocument.Load(_xmlFileName);
            _provider.XDocument = _Document;
            _provider.Initialize("XmlRoleProvider", Helpers.CreateRoleConfigFake());
        }

        [ClassCleanup]
        public static void Teardown()
        {
            //_Document.Descendants("User").Remove();
            //_Document.Save(_xmlFileName);
        }

        [TestMethod]
        public void AddUsersToRoles()
        {
            string[] usernames = { FakesData.GoodUserName() };
            string[] roleNames = { "Power Users", "Admins" };

            _provider.AddUsersToRoles(usernames, roleNames);

            var userRoles = _provider.XDocument.Descendants("UserRole").Where(x => x.Element("UserName").Value == FakesData.GoodUserName() 
                    &&  x.Element("RoleName").Value == "Power Users"
                    || x.Element("RoleName").Value == "Admins");

            Assert.AreEqual(2, userRoles.Count());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void AddUsersToRoles_throws_argrument_exception_when_empty_username()
        {
            string[] usernames = { "" };
            string[] roleNames = { "Power Users", "Admins" };

            _provider.AddUsersToRoles(usernames, roleNames);            
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void AddUsersToRoles_throws_argument_null_when_null_username()
        {
            string[] usernames = { null };
            string[] roleNames = { "Power Users", "Admins" };

            _provider.AddUsersToRoles(usernames, roleNames);
        }

        [TestMethod]
        [ExpectedException(typeof(ProviderException))]
        public void AddUsersToRoles_throws_provider_exception_when_user_does_not_exist()
        {
            string[] usernames = { FakesData.BadUserName() };
            string[] roleNames = { "Power Users", "Admins" };

            _provider.AddUsersToRoles(usernames, roleNames);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void AddUsersToRoles_throws_argrument_exception_when_empty_rolename()
        {
            string[] usernames = { FakesData.GoodUserName() };
            string[] roleNames = { "", "Admins" };

            _provider.AddUsersToRoles(usernames, roleNames);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void AddUsersToRoles_throws_argument_null_when_null_role()
        {
            string[] usernames = { FakesData.GoodUserName() };
            string[] roleNames = { null, "Admins" };

            _provider.AddUsersToRoles(usernames, roleNames);
        }

        [TestMethod]
        [ExpectedException(typeof(ProviderException))]
        public void AddUsersToRoles_throws_provider_exception_when_role_does_not_exist()
        {
            string[] usernames = { FakesData.BadUserName() };
            string[] roleNames = { "Bad Role", "Admins" };

            _provider.AddUsersToRoles(usernames, roleNames);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CreateRole_throws_argrument_exception_when_empty_rolename()
        {
            _provider.CreateRole("");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreateRole_throws_argument_null_when_null_role()
        {
            _provider.CreateRole(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ProviderException))]
        public void CreateRole_throws_provider_exception_when_role_already_exists()
        {
            _provider.CreateRole("Admins");
        }

        [TestMethod]        
        public void CreateRole_adds_to_datastore()
        {
            var role = "MyRole";
            _provider.CreateRole(role);

            var xRole = _provider.XDocument.Descendants("Role").Where(x => x.Element("RoleName").Value == role);

            Assert.AreEqual(1, xRole.Count());
        }

        [TestMethod]
        [ExpectedException(typeof(ProviderException))]
        public void DeleteRole_throws_provider_exception_user_is_in_role()
        {
            AddTestUserRole();            
            _provider.DeleteRole(FakesData.GoodRole(), true);
        }

        [TestMethod]        
        public void DeleteRole_does_not_throw_provider_exception__when_user_is_in_role_and_params_if_false()
        {
            AddTestUserRole();
            bool deleted = _provider.DeleteRole(FakesData.GoodRole(), false);
            Assert.IsTrue(deleted);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void DeleteRole_throws_argrument_exception_when_empty_rolename()
        {
            _provider.DeleteRole("", true);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DeleteRole_throws_argument_null_when_null_role()
        {
            _provider.DeleteRole(null, true);
        }

        [TestMethod]
        [ExpectedException(typeof(ProviderException))]
        public void FindUsersInRole_throws_exception_when_role_does_not_exist()
        {
            _provider.FindUsersInRole("NonRole", FakesData.GoodUserName());
        }

        [TestMethod]        
        public void FindUsersInRole()
        {
            AddTestUserRole();
            string[] usersInRole = _provider.FindUsersInRole(FakesData.GoodRole(), FakesData.GoodUserName());

            Assert.AreEqual(1, usersInRole.Count());
        }

        [TestMethod]
        public void GetAllRoles()
        {
            string[] roles = _provider.GetAllRoles();
            Assert.AreEqual(3, roles.Count());
        }

        [TestMethod]
        public void GetRolesForUser() {
            AddTestUserRole();
            var roles = _provider.GetRolesForUser(FakesData.GoodUserName());

            Assert.AreEqual(1, roles.Count());
        }

        [TestMethod]
        public void GetUsersInRole()
        {
            AddTestUserRole();
            var userNames = _provider.GetUsersInRole(FakesData.GoodRole());

            Assert.AreEqual(1, userNames.Count());
        }

        [TestMethod]
        public void IsUserInRole_is_true()
        {
            AddTestUserRole();
            var isInRole = _provider.IsUserInRole(FakesData.GoodUserName(), FakesData.GoodRole());

            Assert.IsTrue(isInRole);
        }

        [TestMethod]
        public void IsUserInRole_is_false()
        {            
            var isInRole = _provider.IsUserInRole(FakesData.GoodUserName(), FakesData.GoodRole());

            Assert.IsFalse(isInRole);
        }

        [TestMethod]
        public void RemoveUsersFromRoles()
        {
            AddTestUserRole();

            var userNames = new string[1] { FakesData.GoodUserName() };
            var roleNames = new string[1] { FakesData.GoodRole() };

            var userRole = _provider.XDocument.Descendants("UserRole").Where(x => x.Element("UserName").Value == FakesData.GoodUserName()
                && x.Element("RoleName").Value == FakesData.GoodRole());

            Assert.AreEqual(1, userRole.Count());
            _provider.RemoveUsersFromRoles(userNames, roleNames);
            var userRoleAfter = _provider.XDocument.Descendants("UserRole").Where(x => x.Element("UserName").Value == FakesData.GoodUserName()
                && x.Element("RoleName").Value == FakesData.GoodRole());
            Assert.AreEqual(0, userRoleAfter.Count());
        }

        [TestMethod]
        [ExpectedException(typeof(ProviderException))]
        public void RemoveUsersFromRoles_throws_exception_when_user_does_not_exist()
        {
            AddTestUserRole();

            var userNames = new string[1] { FakesData.BadUserName() };
            var roleNames = new string[1] { FakesData.GoodRole() };
                       
            _provider.RemoveUsersFromRoles(userNames, roleNames);
            
        }

        [TestMethod]
        public void RoleExists_true()
        {
            var exists = _provider.RoleExists(FakesData.GoodRole());
            Assert.IsTrue(exists);
        }

        [TestMethod]
        public void RoleExists_false()
        {
            var exists = _provider.RoleExists("NonRole");
            Assert.IsFalse(exists);
        }

        private void AddTestUserRole()
        {
            var xUserRole = new XElement("UserRole",
              new XElement("ApplicationId", "MyApp"),
              new XElement("UserName", FakesData.GoodUserName()),
              new XElement("RoleName", FakesData.GoodRole()));

            _provider.XDocument.Descendants("UserRoles").FirstOrDefault().Add(xUserRole);
        }

    }
}
