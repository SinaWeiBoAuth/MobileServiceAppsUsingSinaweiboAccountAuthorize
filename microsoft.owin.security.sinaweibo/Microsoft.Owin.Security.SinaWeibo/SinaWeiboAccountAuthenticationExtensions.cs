﻿/*
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
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.SinaWeibo;

namespace Owin
{
    /// <summary>
    /// 授权扩展类
    /// </summary>
    public static class SinaWeiboAccountAuthenticationExtensions
    {
        /// <summary>
        /// the redirect url is "yourdomain/signin-sinaWeibo"
        /// </summary>
        /// <param name="app"></param>
        /// <param name="options"></param>
        public static void UseSinaWeiboAuthentication(this IAppBuilder app, SinaWeiboAccountAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(SinaWeiboAccountAuthenticationMiddleware), app, options);
        }
        /// <summary>
        /// the redirect url is "yourdomain/signin-sinaWeibo"
        /// </summary>
        /// <param name="app"></param>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        public static void UseSinaWeiboAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            UseSinaWeiboAuthentication(app, new SinaWeiboAccountAuthenticationOptions()
            {
                AppId = appId,
                AppSecret = appSecret,
                //SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType()
            });
        }
    }
}
