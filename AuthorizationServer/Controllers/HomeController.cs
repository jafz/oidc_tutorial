using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationServer.Controllers
{
    public class HomeController : Controller
    {

        public HomeController()
        {
        }

        public IActionResult Index()
        {
            var adfasf = Request.HttpContext.RequestServices.GetService<IAuthenticationService>();
            return View();
        }
    }
}