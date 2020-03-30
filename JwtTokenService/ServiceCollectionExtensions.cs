using Microsoft.Extensions.DependencyInjection;
using System;

namespace DannyBoyNg.Services
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddJwtTokenService(this IServiceCollection serviceCollection)
        {
            serviceCollection.AddScoped<IJwtTokenService, JwtTokenService>();
            return serviceCollection;
        }

        public static IServiceCollection AddJwtTokenService(this IServiceCollection serviceCollection, Action<JwtTokenSettings> options)
        {
            serviceCollection.AddScoped<IJwtTokenService, JwtTokenService>();
            serviceCollection.Configure(options);
            return serviceCollection;
        }
    }
}
