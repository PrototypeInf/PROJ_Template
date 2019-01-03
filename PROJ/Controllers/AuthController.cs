using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using PROJ.Models;

namespace PROJ.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private UserManager<AppUser> userManager;
        private IConfiguration Configuration;

        public AuthController(
            UserManager<AppUser> userManager,
            IConfiguration configuration)
        {
            this.userManager = userManager;
            this.Configuration = configuration;
        }


        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromHeader] LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.UserName);
            if(user !=null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                var issuer = Configuration.GetSection("JwtSecurityToken:Issuer").Value;
                var audience = Configuration.GetSection("JwtSecurityToken:Audience").Value;

                int expiresHour;
                if(!int.TryParse(Configuration.GetSection("JwtSecurityToken:Expires").Value, out expiresHour))
                {
                    expiresHour = 1;
                }
                var expires = DateTime.UtcNow.AddHours(expiresHour);

                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                var userRoles = await userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }

                var secureKey = Configuration.GetSection("JwtSecurityToken:SecureKey").Value;
                var signingKey =new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secureKey));
                var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                          issuer: issuer,
                          audience: audience,
                          expires: expires,
                          claims: claims,
                          signingCredentials: signingCredentials
                    );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    roles = userRoles
                });
            }
            return Unauthorized();
        }
    }
}