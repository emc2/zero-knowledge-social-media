package net.metricspace.app;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import net.metricspace.app.forms.LoginForm;

@Controller
@RequestMapping("/")
public class AppController extends WebMvcConfigurerAdapter {

    private static final Logger logger =
        LoggerFactory.getLogger(AppController.class);

    @RequestMapping(method = RequestMethod.GET)
    public String getRoot(final Model model) {
        logger.info("Handling GET request for /");

        return "login";
    }

    @GetMapping("/login")
    public String getLogin(final LoginForm form) {
        logger.info("Handling GET request for /login");

        return "login";
    }

    @PostMapping("/login")
    public String postLogin(@Valid final LoginForm form,
                            final BindingResult binding,
                            final Model model) {
        logger.info("Handling POST request for /");
        logger.info("Binding: " + binding);

        if (binding.hasErrors()) {
            logger.info("Errors detected");

            return "login";
        } else {
            logger.info("No errors detected");
            model.addAttribute("username", form.getUsername());

            return "password";
        }
    }

    @GetMapping("/password")
    public String getPassword(final Model model) {
        logger.info("Handling GET request for /password");

        return "password";
    }

    /*
    @GetMapping("/profile")
    public String getProfile(@RequestParam(value="username")
                             final String username,
                             final Model model) {
        model.addAttribute("username", username);
        model.addAttribute("photo-id", "");
        model.addAttribute("about", "");

        return "profile";
    }

    @GetMapping("/exchange")
    public String getExchange(@RequestParam(value="id")
                              final String id,
                              final Model model) {
        model.addAttribute("content-ctext", "");

        return "exchange";
    }

    @PostMapping("/send")
    public String postSend(@RequestParam(value="id")
                           final String id,
                           @RequestParam(value="content-ctext")
                           final String content) {
    }

    @PostMapping("/grant")
    public String postGrant(@RequestParam(value="recipient-id"),
                            final String recipientId,
                            @RequestParam(value="asset-id")
                            final String assetId,
                            @RequestParam(value="grant-ctext")
                            final String grantCText,
                            final Model model) {
    }
    */
}
