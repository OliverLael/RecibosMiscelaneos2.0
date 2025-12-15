using Microsoft.AspNetCore.Mvc;

namespace RecibosMiscelaneos2._0.Controllers
{
    public class RecibosController : Controller
    {
        public IActionResult IndexRecibos()
        {
            // Verificar autenticación
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login", "Home");
            }

            return View();
        }

        public IActionResult RecibosMiscelaneos()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login", "Home");
            }

            return View();
        }

        public IActionResult EntregaMiscelaneos()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login", "Home");
            }

            return View();
        }
    }
}