using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Wcjj.Providers
{
    public static class XExtentions
    {
        public static bool IsMatch(this XElement element, string stringToMatch)
        {
            string pattern = "^" + Regex.Escape(stringToMatch.ToLower()).Replace("\\*", ".*").Replace("\\?", ".") + "$";
            if (!pattern.Contains('*') && !pattern.Contains('.'))
                pattern = pattern.Replace("$", ".*$");

            Regex regex = new Regex(pattern);

            return regex.IsMatch(element.Value);
        }
    }
}
