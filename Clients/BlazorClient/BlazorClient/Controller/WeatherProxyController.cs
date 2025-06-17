using BlazorClient.Shared;
using Microsoft.AspNetCore.Mvc;

namespace BlazorClient.Controller;

[ApiController]
[Route("api/[controller]")]
public class WeatherProxyController : ControllerBase
{
    private readonly IWeatherService _weatherService;

    public WeatherProxyController(IWeatherService weatherService)
    {
        _weatherService = weatherService;
    }

    [HttpGet]
    public Task<WeatherForecast[]> Get()
    {
        return _weatherService.GetForecastsAsync();
    }
}
