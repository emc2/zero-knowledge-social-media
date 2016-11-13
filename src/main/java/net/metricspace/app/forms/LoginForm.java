package net.metricspace.app.forms;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 * Form data for the login page.
 */
public class LoginForm {

    @NotNull
    @Size(min=2, max=32)
    private String username;

    /**
     * Get the username.
     *
     * @return The username.
     */
    public String getUsername() {
        return username;
    }
}
