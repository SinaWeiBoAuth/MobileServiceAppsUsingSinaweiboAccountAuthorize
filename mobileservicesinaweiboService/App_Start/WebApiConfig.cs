using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Web.Http;
using Microsoft.WindowsAzure.Mobile.Service;
using mobileservicesinaweiboService.DataObjects;
using mobileservicesinaweiboService.Models;

namespace mobileservicesinaweiboService
{
    public static class WebApiConfig
    {
        public static void Register()
        {
            // Use this class to set configuration options for your mobile service
            ConfigOptions options = new ConfigOptions();

            //options.LoginProviders.Add(typeof(SinaWeiboLoginProvider));

            options.LoginProviders.Add(typeof(SinaWeiboLoginProvider));


            // Use this class to set WebAPI configuration options
            HttpConfiguration config = ServiceConfig.Initialize(new ConfigBuilder(options));

            // To display errors in the browser during development, uncomment the following
            // line. Comment it out again when you deploy your service for production use.
            // config.IncludeErrorDetailPolicy = IncludeErrorDetailPolicy.Always;
            
            Database.SetInitializer(new mobileservicesinaweiboInitializer());
        }
    }

    public class mobileservicesinaweiboInitializer : ClearDatabaseSchemaIfModelChanges<mobileservicesinaweiboContext>
    {
        protected override void Seed(mobileservicesinaweiboContext context)
        {
            List<TodoItem> todoItems = new List<TodoItem>
            {
                new TodoItem { Id = Guid.NewGuid().ToString(), Text = "First item", Complete = false },
                new TodoItem { Id = Guid.NewGuid().ToString(), Text = "Second item", Complete = false },
            };

            foreach (TodoItem todoItem in todoItems)
            {
                context.Set<TodoItem>().Add(todoItem);
            }

            base.Seed(context);
        }
    }
}

