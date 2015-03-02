/*
 *  Copyright 2013 Feifan Tang. All rights reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.SinaWeibo.Provider;
using Newtonsoft.Json.Linq;
using Microsoft.Owin.Infrastructure;
using Newtonsoft.Json;

namespace Microsoft.Owin.Security.SinaWeibo
{
    internal class SinaWeiboAccountAuthenticationHandler : AuthenticationHandler<SinaWeiboAccountAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://api.weibo.com/oauth2/access_token";
        private const string UserInfoEndpoint = "https://api.weibo.com/2/users/show.json";
        private const string EmailDetailEndpoint = "https://api.weibo.com/2/account/profile/email.json";

        private readonly ILogger logger;
        private readonly HttpClient _httpClient;

        private string state_Value = string.Empty;

        public SinaWeiboAccountAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            this.logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            
            logger.WriteInformation("AuthenticateCoreAsync::::Start");

            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }

                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, logger))
                {
                    return new AuthenticationTicket(null, properties);
                }


                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>();
                body.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
                body.Add(new KeyValuePair<string, string>("code", code));
                body.Add(new KeyValuePair<string, string>("redirect_uri", redirectUri));
                body.Add(new KeyValuePair<string, string>("client_id", Options.AppId));
                body.Add(new KeyValuePair<string, string>("client_secret", Options.AppSecret));

                // Request the token
                HttpResponseMessage tokenResponse =
                    await _httpClient.PostAsync(TokenEndpoint, new FormUrlEncodedContent(body));
                tokenResponse.EnsureSuccessStatusCode();
                string oauthTokenResponse = await tokenResponse.Content.ReadAsStringAsync();

               // JObject oauth2Token = JObject.Parse(oauthTokenResponse);

                dynamic response = JsonConvert.DeserializeObject<dynamic>(oauthTokenResponse);
                string accessToken = (string)response.access_token;
                string expires = (string) response.expires_in;
                string uid = (string)response.uid;

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    logger.WriteWarning("AuthenticateCoreAsync：：：：Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                HttpResponseMessage userInfoResponse = await _httpClient.GetAsync(
                    UserInfoEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken) + "&uid=" + uid,
                    Request.CallCancelled);
                userInfoResponse.EnsureSuccessStatusCode();
                string accountString = await userInfoResponse.Content.ReadAsStringAsync();
                JObject accountInfo = JObject.Parse(accountString);

                //string email = String.Empty;
                //if (Options.RequireEmail)
                //{
                //    HttpResponseMessage emailResponse = await _httpClient.GetAsync(
                //        EmailDetailEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken),
                //        Request.CallCancelled);
                //    emailResponse.EnsureSuccessStatusCode();
                //    string emailString = await emailResponse.Content.ReadAsStringAsync();
                //    email = JObject.Parse(accountString)["email"].Value<string>();
                //}

                var context = new SinaWeiboAccountAuthenticatedContext(Context, accountInfo, string.Empty, accessToken);

                context.Identity = new ClaimsIdentity(new[]{
                    new Claim(ClaimTypes.NameIdentifier, context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:sinaweibo:id", context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:sinaweibo:name", context.Name,XmlSchemaString,Options.AuthenticationType),
                });


                if (!String.IsNullOrWhiteSpace(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }


                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                logger.WriteInformation("AuthenticateCoreAsync::::return new AuthenticationTicket(context.Identity, context.Properties);");
                logger.WriteInformation("AuthenticateCoreAsync::::End");

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                logger.WriteError(ex.Message);
            }

            logger.WriteInformation("AuthenticateCoreAsync：：：：return new AuthenticationTicket(null, properties);");
            logger.WriteInformation("AuthenticateCoreAsync：：：：END");
            return new AuthenticationTicket(null, properties);

            
            #region Old Code
            //logger.WriteInformation("AuthenticateCoreAsync::::Start");

            //AuthenticationProperties properties = null;

            //try
            //{
            //    string code = null;
            //    string state = null;

            //    IReadableStringCollection query = Request.Query;
            //    IList<string> values = query.GetValues("code");
            //    if (values != null && values.Count == 1)
            //    {
            //        code = values[0];
            //    }

            //    values = query.GetValues("state");
            //    if (values != null && values.Count == 1)
            //    {
            //        state = values[0];
            //    }

            //    properties = Options.StateDataFormat.Unprotect(state);



            //    logger.WriteInformation("AuthenticateCoreAsync：：：：properties:[" + properties + "]");
                
            //    if (properties == null)
            //    {
            //        logger.WriteInformation("AuthenticateCoreAsync：：：：return null;");
            //        logger.WriteInformation("AuthenticateCoreAsync：：：：END");
            //        return null;
            //    }

            //    // OAuth2 10.12 CSRF
            //    if (!ValidateCorrelationId(properties, logger))
            //    {
            //        logger.WriteInformation("AuthenticateCoreAsync：：：：if (!ValidateCorrelationId(properties, _logger)):return new AuthenticationTicket(null, properties);");
            //        return new AuthenticationTicket(null, properties);
            //    }

            //    var tokenRequestParameters = new List<KeyValuePair<string, string>>()
            //    {
            //        new KeyValuePair<string, string>("client_id", Options.AppId),
            //        new KeyValuePair<string, string>("client_secret", Options.AppSecret),
            //        new KeyValuePair<string, string>("redirect_uri", GenerateRedirectUri()),
            //        new KeyValuePair<string, string>("code", code),
            //        new KeyValuePair<string, string>("grant_type", "authorization_code"),
            //    };

            //    FormUrlEncodedContent requestContent = new FormUrlEncodedContent(tokenRequestParameters);

            //    HttpResponseMessage response = await _httpClient.PostAsync(TokenEndpoint, requestContent, Request.CallCancelled);
            //    response.EnsureSuccessStatusCode();
            //    string oauthTokenResponse = await response.Content.ReadAsStringAsync();

            //    JObject oauth2Token = JObject.Parse(oauthTokenResponse);
            //    string accessToken = oauth2Token["access_token"].Value<string>();

            //    logger.WriteInformation("AuthenticateCoreAsync：：：：accessToken:[" + accessToken + "]");


            //    if (string.IsNullOrWhiteSpace(accessToken))
            //    {
            //        logger.WriteWarning("AuthenticateCoreAsync：：：：Access token was not found");
            //        return new AuthenticationTicket(null, properties);
            //    }

            //    HttpResponseMessage userInfoResponse = await _httpClient.GetAsync(
            //        UserInfoEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken) + "&uid=" + oauth2Token["uid"].Value<string>(), 
            //        Request.CallCancelled);
            //    userInfoResponse.EnsureSuccessStatusCode();
            //    string accountString = await userInfoResponse.Content.ReadAsStringAsync();
            //    JObject accountInfo = JObject.Parse(accountString);

            //    string email = String.Empty;
            //    if (Options.RequireEmail)
            //    {
            //        HttpResponseMessage emailResponse = await _httpClient.GetAsync(
            //            EmailDetailEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken),
            //            Request.CallCancelled);
            //        emailResponse.EnsureSuccessStatusCode();
            //        string emailString = await emailResponse.Content.ReadAsStringAsync();
            //        email= JObject.Parse(accountString)["email"].Value<string>();
            //    }

            //    var context = new SinaWeiboAccountAuthenticatedContext(Context, accountInfo, email, accessToken);
            //    context.Identity = new ClaimsIdentity(new[]{
            //        new Claim(ClaimTypes.NameIdentifier, context.Id,XmlSchemaString,Options.AuthenticationType),
            //        new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name,XmlSchemaString,Options.AuthenticationType),
            //        new Claim("urn:sinaweibo:id", context.Id,XmlSchemaString,Options.AuthenticationType),
            //        new Claim("urn:sinaweibo:name", context.Name,XmlSchemaString,Options.AuthenticationType),
            //    });
            //    if (!String.IsNullOrWhiteSpace(context.Email))
            //    {
            //        context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
            //    }

            //    await Options.Provider.Authenticated(context);

            //    properties.RedirectUri = GenerateRedirectUri();

            //    context.Properties = properties;



            //    logger.WriteInformation("AuthenticateCoreAsync：：：：return new AuthenticationTicket(context.Identity, context.Properties);");
            //    logger.WriteInformation("AuthenticateCoreAsync：：：：END");

            //    return new AuthenticationTicket(context.Identity, context.Properties);
            //}
            //catch (Exception ex)
            //{
            //    logger.WriteError(ex.Message);
            //}

            //logger.WriteInformation("AuthenticateCoreAsync：：：：return new AuthenticationTicket(null, properties);");
            //logger.WriteInformation("AuthenticateCoreAsync：：：：END");
            //return new AuthenticationTicket(null, properties);

            #endregion 
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            logger.WriteInformation("ApplyResponseChallengeAsync::::Start");

            if (Response.StatusCode != 401)
            {
                logger.WriteInformation("ApplyResponseChallengeAsync::::if (Response.StatusCode != 401)");
                logger.WriteInformation("ApplyResponseChallengeAsync::::return Task.FromResult<object>(null);");
                logger.WriteInformation("ApplyResponseChallengeAsync::::End");
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                //string requestPrefix = Request.Scheme + "://" + Request.Host;
                //string currentQueryString = Request.QueryString.Value;
                //string currentUri = string.IsNullOrEmpty(currentQueryString)
                //    ? requestPrefix + Request.PathBase + Request.Path
                //    : requestPrefix + Request.PathBase + Request.Path + "?" + currentQueryString;

                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;


                AuthenticationProperties properties = challenge.Properties;

                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    logger.WriteInformation("ApplyResponseChallengeAsync::::properties.RedirectUri  is IsNullOrEmpty");

                    logger.WriteInformation("ApplyResponseChallengeAsync::::Set properties.RedirectUri = currentUri; currentUri:" + currentUri);

                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // comma separated
                string scope = string.Join(" ", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint =
                    "https://api.weibo.com/oauth2/authorize" +
                        "?client_id=" + Uri.EscapeDataString(Options.AppId ?? string.Empty)
                        + "&redirect_uri=" + Uri.EscapeDataString(redirectUri)
                        + "&scope=" + Uri.EscapeDataString(scope)
                        + "&state=" + Uri.EscapeDataString(state)
                        ;

                logger.WriteInformation("ApplyResponseChallengeAsync::::Response.Redirect(authorizationEndpoint);authorizationEndpoint:" + authorizationEndpoint);

                Response.Redirect(authorizationEndpoint);
            }

            logger.WriteInformation("ApplyResponseChallengeAsync::::return Task.FromResult<object>(null)");

            logger.WriteInformation("ApplyResponseChallengeAsync::::END");

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            logger.WriteInformation("InvokeAsync::::Start");
            return await InvokeReplyPathAsync();
            logger.WriteInformation("InvokeAsync::::End");

            #region old code
            //_logger.WriteInformation("InvokeAsync：：：：InvokeAsync-Start");
            //if (Options.ReturnEndpointPath != null &&
            //    String.Equals(Options.ReturnEndpointPath, Request.Path.Value, StringComparison.OrdinalIgnoreCase))
            //{

            //    _logger.WriteInformation("InvokeAsync：：：：    if (Options.ReturnEndpointPath != null && ...");

            //    _logger.WriteInformation("InvokeAsync：：：：        return await InvokeReturnPathAsync();");

            //    _logger.WriteInformation("InvokeAsync：：：：InvokeAsync-End");

            //    return await InvokeReturnPathAsync();
            //}

            //_logger.WriteInformation("InvokeAsync：：：：return false;");

            //_logger.WriteInformation("InvokeAsync：：：：InvokeAsync-End");

            //return false;
            #endregion
        }

        private async Task<bool> InvokeReplyPathAsync()
        {

            logger.WriteInformation("InvokeReplyPathAsync::::Start");

            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new SinaWeiboAccountReturnEndpointContext(Context, ticket);

                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                logger.WriteInformation("InvokeReplyPathAsync::::context.RedirectUri = ticket.Properties.RedirectUri;ticket.Properties.RedirectUri:" + ticket.Properties.RedirectUri);

                logger.WriteInformation("InvokeReplyPathAsync::::await Options.Provider.ReturnEndpoint(context);");

                await Options.Provider.ReturnEndpoint(context);


                logger.WriteInformation("context.SignInAsAuthenticationType:"+ context.SignInAsAuthenticationType);

                logger.WriteInformation("context.Identity :" + context.Identity);


                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    logger.WriteInformation("InvokeReplyPathAsync::::context.SignInAsAuthenticationType != null &&context.Identity != null");

                    ClaimsIdentity signInIdentity = context.Identity;
                    if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                    }

                    logger.WriteInformation("InvokeReturnPathAsync：：：：    Context.Authentication.SignIn(context.Properties, signInIdentity);");

                    Context.Authentication.SignIn(context.Properties, signInIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {

                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                logger.WriteInformation("InvokeReplyPathAsync::::return context.IsRequestCompleted:" + context.IsRequestCompleted);

                logger.WriteInformation("InvokeReplyPathAsync::::End");

                return context.IsRequestCompleted;
            }

            logger.WriteInformation("InvokeReplyPathAsync::::return false");

            logger.WriteInformation("InvokeReplyPathAsync::::End");

            return false;

            #region old code
            //logger.WriteInformation("InvokeReturnPathAsync：：：：Start");

            //logger.WriteInformation("InvokeReturnPathAsync：：：：  var model = await AuthenticateAsync();");


            //var model = await AuthenticateAsync();



            //if (model == null || model.Properties == null)
            //{
            //    logger.WriteInformation("InvokeReturnPathAsync：：：：     model == null ||  mode.Properties:[NULL]");
            //    logger.WriteInformation("InvokeReturnPathAsync：：：：     return false;");
            //    logger.WriteInformation("InvokeReturnPathAsync：：：：END");
            //    return false;   
            //}

            ////_logger.WriteInformation("InvokeReturnPathAsync：：：：    mode.Properties.RedirectUri:" + model.Properties.RedirectUri);

            //var context = new SinaWeiboAccountReturnEndpointContext(Context, model);


            //context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
            ////context.RedirectUri = model.Properties.RedirectUri;
            //context.RedirectUri = GenerateRedirectUri();
            //model.Properties.RedirectUri = null;



            //logger.WriteInformation("InvokeReturnPathAsync：：：：    await Options.Provider.ReturnEndpoint(context);" );
            //await Options.Provider.ReturnEndpoint(context);

            //if (context.SignInAsAuthenticationType != null && context.Identity != null)
            //{
            //    ClaimsIdentity signInIdentity = context.Identity;
            //    if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
            //    {
            //        signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
            //    }

            //    logger.WriteInformation("InvokeReturnPathAsync：：：：    Context.Authentication.SignIn(context.Properties, signInIdentity);");

            //    Context.Authentication.SignIn(context.Properties, signInIdentity);
            //}

            //if (!context.IsRequestCompleted && context.RedirectUri != null)
            //{
            //    logger.WriteInformation("InvokeReturnPathAsync：：：：    Response.Redirect(context.RedirectUri);");
            //    logger.WriteInformation("InvokeReturnPathAsync：：：：    ::::context.RedirectUri:" + context.RedirectUri);
            //    Response.Redirect(context.RedirectUri);
            //    context.RequestCompleted();
            //}

            //logger.WriteInformation("InvokeReturnPathAsync：：：：    return context.IsRequestCompleted:" + context.IsRequestCompleted);
            //logger.WriteInformation("InvokeReturnPathAsync：：：：END");
            //return context.IsRequestCompleted;
            #endregion
        }


        private string GenerateRedirectUri()
        {
            string requestPrefix = Request.Scheme + "://" + Request.Host;

            string redirectUri = requestPrefix + RequestPathBase + Options.CallbackPath; // + "?state=" + Uri.EscapeDataString(Options.StateDataFormat.Protect(state));            
            return redirectUri;
        }

    }
}
