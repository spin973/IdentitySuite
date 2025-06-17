using BlazorClient.Shared;
using System.Net.Http.Json;

namespace BlazorClient.Client.Services;

public class WeatherServiceClient : IWeatherService
{
    private readonly HttpClient _httpClient;

    public WeatherServiceClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<WeatherForecast[]> GetForecastsAsync()
    {
        return await _httpClient.GetFromJsonAsync<WeatherForecast[]>("/api/WeatherProxy") ?? [];
    }
}
