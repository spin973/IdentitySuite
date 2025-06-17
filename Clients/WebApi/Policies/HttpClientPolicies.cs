using Polly;

namespace WebApi.Policies;

public static class HttpClientPolicies
{
    private static readonly Random _jitterer = new();

    public static IAsyncPolicy<HttpResponseMessage> GetRetryPolicy() =>
        Policy
            .Handle<HttpRequestException>()
            .OrResult<HttpResponseMessage>(result => !result.IsSuccessStatusCode)
            .WaitAndRetryAsync(3,
                retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)) +
                                TimeSpan.FromMilliseconds(_jitterer.Next(0, 800)));

    public static IAsyncPolicy<HttpResponseMessage> GetCircuitBreakerPolicy() =>
        Policy
            .Handle<HttpRequestException>()
            .OrResult<HttpResponseMessage>(result => !result.IsSuccessStatusCode)
            .CircuitBreakerAsync(4, TimeSpan.FromMinutes(1));
}
