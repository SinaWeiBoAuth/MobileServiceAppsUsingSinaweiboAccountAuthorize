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
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.SinaWeibo.Provider
{
    public class SinaWeiboAccountAuthenticationProvider : ISinaWeiboAccountAuthenticationProvider
    {
        public SinaWeiboAccountAuthenticationProvider()
        {
            OnAuthenticated = (context) => Task.FromResult<Task>(null);
            OnReturnEndpoint = (context) => Task.FromResult<Task>(null);
        }

        public Func<SinaWeiboAccountAuthenticatedContext, Task> OnAuthenticated { get; set; }

        public Func<SinaWeiboAccountReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public virtual Task Authenticated(SinaWeiboAccountAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(SinaWeiboAccountReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
