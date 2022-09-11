using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace WmiSpawn.Library
{
    internal class Helpers
    {
        public static string GetActiveDirectoryDomainName()
        {
            string domainName;

            try
            {
                domainName = Domain.GetCurrentDomain().ToString();
            }
            catch (ActiveDirectoryOperationException)
            {
                domainName = null;
            }

            return domainName;
        }


        public static string[] LookupIpAddressByHostname(string hostname)
        {
            var results = new List<string>();
            IPAddress[] ipAddresses;

            try
            {
                ipAddresses = Dns.GetHostEntry(hostname).AddressList;

                for (var idx = 0; idx < ipAddresses.Length; idx++)
                {
                    results.Add(ipAddresses[idx].ToString());
                }

                return results.ToArray();
            }
            catch (ArgumentNullException)
            {
                return results.ToArray();
            }
            catch (ArgumentException)
            {
                return results.ToArray();
            }
            catch (SocketException)
            {
                return results.ToArray();
            }
        }


        public static bool IsValidDomainName(string domainname)
        {
            var regex = new Regex(
                string.Format(@"^{0}.\S+", domainname),
                RegexOptions.IgnoreCase);
            DomainCollection domains;

            try
            {
                domains = Forest.GetCurrentForest().Domains;

                foreach (var domain in domains)
                {
                    if (string.Compare(domain.ToString(), domainname, true) == 0)
                        return true;
                    else if (regex.IsMatch(domain.ToString()))
                        return true;
                }

                return false;
            }
            catch (ActiveDirectoryOperationException)
            {
                return false;
            }
        }


        public static bool IsValidIpAddress(string ipAddressString)
        {
            try
            {
                IPAddress.Parse(ipAddressString);

                return true;
            }
            catch (ArgumentNullException)
            {
                return false;
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }
}
