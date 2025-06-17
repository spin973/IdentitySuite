using BlazorClient.Shared;
using System.Text.Json;

namespace BlazorClient.Services;

public class WeatherServiceServer : IWeatherService
{
    private readonly IHttpClientFactory _httpClientFactory;

    public WeatherServiceServer(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<WeatherForecast[]> GetForecastsAsync()
    {
        var client = _httpClientFactory.CreateClient("WebApiClient");
        var response = await client.GetAsync("weatherforecast");

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            return [];
        }

        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync();
        return System.Text.Json.JsonSerializer.Deserialize<WeatherForecast[]>(content) ?? [];
    }
}
