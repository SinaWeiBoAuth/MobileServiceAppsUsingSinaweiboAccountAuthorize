using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Owin;
using Microsoft.Owin.Security.SinaWeibo;
using Microsoft.Owin.Security.SinaWeibo.Provider;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.WindowsAzure.Mobile.Service.Security;

namespace mobileservicesinaweiboService
{
    public class SinaWeiboLoginAuthenticationProvider :SinaWeiboAccountAuthenticationProvider //SinaWeiBoAuthenticationProvider
    {
        public override Task Authenticated(SinaWeiboAccountAuthenticatedContext context)
        {

            


            context.Identity.AddClaim(
                new Claim(ServiceClaimTypes.ProviderAccessToken, context.AccessToken));

            return base.Authenticated(context);
        }

        

    }


    public class SinaWeiboLoginProvider : LoginProvider
    {
        internal const string ProviderName = "SinaWeibo";

        public SinaWeiboLoginProvider(IServiceTokenHandler tokenHandler)
            : base(tokenHandler)
        {

        }

        public override void ConfigureMiddleware(IAppBuilder appBuilder,
            Microsoft.WindowsAzure.Mobile.Service.ServiceSettingsDictionary settings)
        {
            SinaWeiboAccountAuthenticationOptions options = new SinaWeiboAccountAuthenticationOptions
            {
                AppId = settings["SinaWeiBoClientId"],
                AppSecret = settings["SinaWeiBoClientSecret"],
                AuthenticationType = this.Name,
                Provider = new SinaWeiboAccountAuthenticationProvider()
            };
            appBuilder.UseSinaWeiboAuthentication(options);
        }

        public override ProviderCredentials CreateCredentials(ClaimsIdentity claimsIdentity)
        {
            Claim name = claimsIdentity.FindFirst(ClaimTypes.NameIdentifier);
            Claim providerAccessToken = claimsIdentity
                .FindFirst(ServiceClaimTypes.ProviderAccessToken);

            SinaWeiboCredentials credentials = new SinaWeiboCredentials
            {
                UserId = this.TokenHandler.CreateUserId(this.Name, name != null ? name.Value : null),
                AccessToken = providerAccessToken != null ? providerAccessToken.Value : null
            };

            return credentials;
        }

        public override string Name
        {
            get { return ProviderName; }
        }

        public override ProviderCredentials ParseCredentials(Newtonsoft.Json.Linq.JObject serialized)
        {
            return serialized.ToObject<SinaWeiboCredentials>();
        }


        public class SinaWeiboCredentials : ProviderCredentials
        {
            public SinaWeiboCredentials()
                : base(SinaWeiboLoginProvider.ProviderName)
            {
            }

            public string AccessToken { get; set; }
        }

    }
}