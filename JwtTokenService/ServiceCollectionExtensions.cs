using Microsoft.Extensions.DependencyInjection;
using System;

namespace DannyBoyNg.Services
{
    /// <summary>
    /// Contains static methods to help with Dependency Injection
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Adds the JWT token service.
        /// </summary>
        public static IServiceCollection AddJwtTokenService(this IServiceCollection serviceCollection)
        {
            serviceCollection.AddScoped<IJwtTokenService, JwtTokenService>();
            return serviceCollection;
        }

        /// <summary>
        /// Adds the JWT token service.
        /// </summary>
        /// <param name="serviceCollection">The DI container.</param>
        /// <param name="options">Options for JwtTokenService.</param>
        public static IServiceCollection AddJwtTokenService(this IServiceCollection serviceCollection, Action<JwtTokenSettings> options)
        {
            serviceCollection.AddScoped<IJwtTokenService, JwtTokenService>();
            serviceCollection.Configure(options);
            return serviceCollection;
        }
    }
}
