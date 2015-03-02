using Microsoft.WindowsAzure.Mobile.Service.Security;
using Newtonsoft.Json.Linq;
using Owin;
using Owin.Security.Providers.LinkedIn;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace mobileservicesinaweiboService
{
    public class LinkedInLoginAuthenticationProvider : LinkedInAuthenticationProvider
    {
        public override Task Authenticated(LinkedInAuthenticatedContext context)
        {
            context.Identity.AddClaim(
                new Claim(ServiceClaimTypes.ProviderAccessToken, context.AccessToken));
            return base.Authenticated(context);
        }
    }

    public class LinkedInCredentials : ProviderCredentials
    {
        public LinkedInCredentials()
            : base(LinkedInLoginProvider.ProviderName)
        {
        }

        public string AccessToken { get; set; }
    }

    #region For Linkedin ServiceBackEnd
    public class LinkedInLoginProvider : LoginProvider
    {
        internal const string ProviderName = "LinkedIn";

        public LinkedInLoginProvider(IServiceTokenHandler tokenHandler)
            : base(tokenHandler)
        {
        }

        public override string Name
        {
            get { return ProviderName; }
        }

        public override void ConfigureMiddleware(IAppBuilder appBuilder,
            Microsoft.WindowsAzure.Mobile.Service.ServiceSettingsDictionary settings)
        {
            LinkedInAuthenticationOptions options = new LinkedInAuthenticationOptions
            {
                ClientId = settings["LinkedInClientId"],
                ClientSecret = settings["LinkedInClientSecret"],
                AuthenticationType = this.Name,
                Provider = new LinkedInAuthenticationProvider()
            };
            appBuilder.UseLinkedInAuthentication(options);
        }


        public override ProviderCredentials CreateCredentials(
            ClaimsIdentity claimsIdentity)
        {
            Claim name = claimsIdentity.FindFirst(ClaimTypes.NameIdentifier);
            Claim providerAccessToken = claimsIdentity
                .FindFirst(ServiceClaimTypes.ProviderAccessToken);

            LinkedInCredentials credentials = new LinkedInCredentials
            {
                UserId = this.TokenHandler.CreateUserId(this.Name, name != null ?
                    name.Value : null),
                AccessToken = providerAccessToken != null ?
                    providerAccessToken.Value : null
            };

            return credentials;
        }

        public override ProviderCredentials ParseCredentials(JObject serialized)
        {
            return serialized.ToObject<LinkedInCredentials>();
        }
    }

    #endregion
}