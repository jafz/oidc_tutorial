using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Principal;

namespace ConsoleApp1
{
    internal static class OAuthHelper
    {
        private static readonly ILogger Logger = NullLoggerProvider.Instance.CreateLogger("asdf");

        public static void LogDebug(string msg, params object[] args)
        {
            if (Logger == null)
                return;
            Logger.LogDebug(msg, args);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1804:RemoveUnusedLocals", MessageId = "si")]
        public static IList<DtoEnvironmentClaim> Verify(string user, string password)
        {
            if (string.IsNullOrEmpty(user))
            {
                throw new ArgumentNullException(nameof(user));
            }
            IList<DtoEnvironmentClaim> result = null;

            if (IsLocalAccount(user))
            {
                result = GetMachineGroups(user, password);
            }
            else
            {
                //TODO: Find a way around this known issue http://stackoverflow.com/questions/12608971/net-4-5-bug-in-userprincipal-findbyidentity-system-directoryservices-accountma?rq=1
                result = GetDomainGroups(user, password);
            }

            return result;
        }

        internal static bool IsLocalAccount(string username)
        {
            bool isLocalMachineAccount = username.Split('\\').Length < 2 || System.Environment.MachineName.ToLowerInvariant() == username.Split('\\')[0].ToLowerInvariant();

            return isLocalMachineAccount;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Runtime.InteropServices.SafeHandle.DangerousGetHandle", Justification = "I tried the DangerousAddRef stuff, but CA still complained. So, CA, you're going to get ignored, since there's nothing out there describing how to avoid this warning. And there's no WindowsIdentity that works with SafeTokenHandle")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode", Justification = "Currently not used, in place for future usage")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1031:DoNotCatchGeneralExceptionTypes", Justification = "Catch clauses used to provide fallbacks.")]
        internal static IList<DtoEnvironmentClaim> GetDomainGroups(string user, string password)
        {
            try
            {
                var userDomain = user.Split('\\')[0];
                var userName = user.Split('\\')[1];
                SafeTokenHandle safeTokenHandle;
                bool returnValue = NativeMethods.LogonUser(userName, userDomain, password, LogonType.LOGON32_LOGON_NETWORK, LogonProvider.LOGON32_PROVIDER_DEFAULT, out safeTokenHandle);
                if (!returnValue || safeTokenHandle == null)
                {
                    int lastError = NativeMethods.GetLastError();
                    var win32Error = new Win32Exception(lastError).Message;
                    throw new UnauthorizedAccessException(win32Error);
                }

                using (safeTokenHandle)
                using (WindowsIdentity userId = new WindowsIdentity(safeTokenHandle.DangerousGetHandle()))
                {
                    return FindClaimsWithWindowsIdentity(userId);
                }
            }
            catch (Exception ex)
            {
                var msg = "Login failed for '" + user + "': " + ex.Message;
                //if (AppSettingsFactory.Default.GetSettings()
                //    .ReadBool(SettingsKeys.Authentication_HideUsernameOnLoginFailure))
                //{
                //    msg = "Login failed: " + ex.Message;
                //}
                throw new UnauthorizedAccessException(msg, ex);
            }
        }

        internal static IList<DtoEnvironmentClaim> FindClaimsWithWindowsIdentity(WindowsIdentity userId)
        {
            if (userId == null)
            {
                throw new ArgumentException("WindowsIdentity could not be created.", nameof(userId));
            }

            var allClaims = userId.FindAll(x => true);
            var result = new List<DtoEnvironmentClaim>();
            foreach (var claim in allClaims)
            {
                if (claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid")
                {
                    result.Add(new DtoEnvironmentClaim()
                    {
                        Name = TryTranslate(claim.Value),
                        Scope = DtoClaimScope.Domain,
                        Type = DtoClaimType.Group,
                        SID = claim.Value
                    });
                }
                else if (claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid")
                {
                    result.Add(new DtoEnvironmentClaim()
                    {
                        Name = TryTranslate(claim.Value),
                        Scope = DtoClaimScope.Domain,
                        Type = DtoClaimType.User,
                        SID = claim.Value
                    });
                }
            }

            return result;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes")]
        private static string TryTranslate(string claimValue)
        {
            try
            {
                return new SecurityIdentifier(claimValue).Translate(typeof(NTAccount)).ToString();
            }
            catch (IdentityNotMappedException ex)
            {
                // don't throw
                LogDebug("Exception while translating an sid to a name: {0}", ex.Message);
            }
            catch (SystemException ex)
            {
                // don't throw
                LogDebug("Exception while translating an sid to a name: {0}", ex.Message);
                //throw;
            }

            return string.Empty;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Runtime.InteropServices.SafeHandle.DangerousGetHandle", Justification = "I tried the DangerousAddRef stuff, but CA still complained. So, CA, you're going to get ignored, since there's nothing out there describing how to avoid this warning. And there's no WindowsIdentity that works with SafeTokenHandle")]
        internal static IList<DtoEnvironmentClaim> GetMachineGroups(string user, string password)
        {
            try
            {
                string userMachine = null;
                string userName = null;

                if (user.Contains("\\"))
                {

                    userMachine = user.Split('\\')[0];
                    userName = user.Split('\\')[1];
                }
                else
                {
                    userName = user;
                }

                SafeTokenHandle safeTokenHandle;
                bool returnValue = NativeMethods.LogonUser(userName, userMachine, password, LogonType.LOGON32_LOGON_NETWORK, LogonProvider.LOGON32_PROVIDER_DEFAULT, out safeTokenHandle);
                if (!returnValue || safeTokenHandle == null)
                {
                    int lastError = NativeMethods.GetLastError();
                    var win32Error = new Win32Exception(lastError).Message;
                    throw new UnauthorizedAccessException(win32Error);
                }

                using (safeTokenHandle)
                {
                    using (var windowsIdentity = new WindowsIdentity(safeTokenHandle.DangerousGetHandle()))
                        return FindClaimsWithWindowsIdentity(windowsIdentity);
                }
            }
            catch (Exception ex)
            {
                var msg = "Login failed for '" + user + "': " + ex.Message;
                //if (AppSettingsFactory.Default.GetSettings()
                //    .ReadBool(SettingsKeys.Authentication_HideUsernameOnLoginFailure))
                //{
                //    msg = "Login failed: " + ex.Message;
                //}
                throw new UnauthorizedAccessException(msg, ex);
            }
        }
    }
    public class DtoEnvironmentClaim
    {
        /// <summary>
        /// defines a claim name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// The name in the SAM account format
        /// </summary>
        public string SamAccountName { get; set; }

        /// <summary>
        /// defines a claim SID
        /// </summary>
        public string SID { get; set; }

        /// <summary>
        /// Defines a type of the claim (user or group)
        /// </summary>
        public DtoClaimType Type { get; set; }

        /// <summary>
        /// defines a scope of the claim (domain or local machine)
        /// </summary>
        public DtoClaimScope Scope { get; set; }

        /// <summary>
        /// defines a SID of the parent claim
        /// </summary>
        public string Parent { get; set; }
    }
    public enum DtoClaimScope
    {
        /// <summary>
        /// claim scope is domain
        /// </summary>
        Domain,
        /// <summary>
        /// claim scope is local machine
        /// </summary>
        LocalMachine
    }
    public enum DtoClaimType
    {
        /// <summary>
        /// Claim is a user
        /// </summary>
        User,
        /// <summary>
        /// claim is a group
        /// </summary>
        Group,
        /// <summary>
        /// Scope defines what type of claims apply (e.g.: Process Monitor App Role or Processing Role interative/non-interactive)
        /// </summary>
        Scope
    }
}
