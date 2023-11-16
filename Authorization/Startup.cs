using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;

namespace Authorization
{
    public class Startup
    {
        public Startup(IConfiguration configuration) => Configuration = configuration;
        public IConfiguration Configuration { get; }


        public void ConfigureServices(IServiceCollection services)
        {

            services.AddControllers();

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                options.AccessDeniedPath = "/";
                options.LogoutPath = "/";
                options.LoginPath = "/";
            });


            services.AddAuthorization(options =>
            {
                options.AddPolicy("YoneticiRoluAra", policy =>
                {
                    policy.RequireRole("Yonetici");
                });
                options.AddPolicy("ClaimPolicy", policy =>
                {
                    policy.RequireClaim("Avakado");
                });
                options.AddPolicy("ClaimValuePolicy", policy =>
                {
                    policy.RequireClaim("Avakado", "sebzedir");
                });
                options.AddPolicy("CombinedPolicy", policy =>
                {
                    policy.RequireRole("Yonetici", "User");
                });
                options.AddPolicy("CombinedPolicy2", policy =>
                {
                    policy.RequireRole("Yonetici");
                    policy.RequireRole("User");
                });

            });

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Authorization", Version = "v1" });
            });
        }


        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Authorization v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
