using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PROJ.Models
{
    public class SeedDB
    {
        public static async Task InitAsync(IServiceProvider serviceProvider, IConfiguration Configuration)
        {
            var RoleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var ctx = serviceProvider.GetRequiredService<AppDbContext>();
            var userManager = serviceProvider.GetRequiredService<UserManager<AppUser>>();
            ctx.Database.EnsureCreated();

            if (!ctx.Users.Any())
            {
                await RoleManager.CreateAsync(new IdentityRole("admin"));
                await RoleManager.CreateAsync(new IdentityRole("user"));

                var email = Configuration.GetSection("DefaultAdmin:Email").Value;
                var userName = Configuration.GetSection("DefaultAdmin:UserName").Value;
                AppUser user = new AppUser()
                {
                    Email = email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = userName
                };
                var password = Configuration.GetSection("DefaultAdmin:password").Value;
                var res = await userManager.CreateAsync(user, password);
                if (res.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "admin");
                }
            }
        }
    }
}
