namespace BlazorClient.Shared;

public interface IWeatherService
{
    Task<WeatherForecast[]> GetForecastsAsync();
}
