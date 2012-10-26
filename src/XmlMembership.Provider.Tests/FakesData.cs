using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Membership.Provider.Tests
{
    public static class FakesData
    {
        public static string GoodUserName() { return "wilby"; }
        public static string GoodPassword() { return "wilby1234@!"; }
        public static string GoodEmail() { return "wilby@wcjj.net"; }
        public static string GoodPasswordQuestion() { return "Mother's Maiden Name"; }
        public static string GoodPasswordQuestionAnswer() { return "Smith"; }

        public static string BadUserName() { return "test"; }
        public static string BadPassword() { return "test"; }
        public static string BadEmail() { return "test@test.com"; }

        public static string GoodRole() { return "Admins"; }
    }
}
