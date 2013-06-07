window.identityBroker = (function () {
    var queryParameters = function (name) {
        var parameters = window.location.search.substring(1).split("&");
        for (var i = 0; i < parameters.length; i++) {
            var param = parameters[i].split("=");
            if (decodeURIComponent(param[0]) == name) {
                return decodeURIComponent(param[1]);
            }
        }
    };

    var messageError = queryParameters("error");
    var messageInfo = queryParameters("info");

    var ib = {
        appKey: queryParameters("app"),
        baseUrl: "/ejs-identity",
        get loginUrl() {
            return this.baseUrl + "/api/login/" + this.appKey;
        },
        get registerUrl() {
            return this.baseUrl + "/api/register/" + this.appKey;
        }
    };

    ib.getConfig = function (success, error) {
        var req = new XMLHttpRequest();
        req.open("GET", ib.loginUrl);
        req.setRequestHeader("Accept", "application/json");
        req.onreadystatechange = function () {
            if (req.readyState == 4) {
                if (req.status == 200) {
                    var config = JSON.parse(req.responseText);
                    if (success) {
                        success(config);
                    }
                } else {
                    if (error) {
                        error(req.status);
                    }
                }
            }
        };
        req.send();
    };


    var createLogin = function(containerId) {
        var login = document.createElement("div");
        login.setAttribute("class", "ib-login");

        var container = document.getElementById(containerId);
        container.setAttribute("class", "ib-login-container");
        container.innerHTML = null;
        container.appendChild(login);

        return login;
    };

    var createHeader = function(text) {
        var div = document.createElement("div");
        div.setAttribute("class", "ib-login-header");

        var h = document.createElement("h1");
        h.textContent = text;
        div.appendChild(h);

        return div;
    };

    var createInput = function(group, name, labelText, type) {
        var div = document.createElement("div");
        div.setAttribute("class", "ib-login-" + group + "-" + name);

        var label = document.createElement("label");
        label.setAttribute("for", name);
        label.textContent = labelText;
        div.appendChild(label);

        var input = document.createElement("input");
        input.setAttribute("name", name);
        if (type) {
            input.setAttribute("type", type);
        } else {
            input.setAttribute("type", "text");
        }
        div.appendChild(input);

        return div;
    };

    var createMessage = function(message, type) {
        var div = document.createElement("div");
        div.setAttribute("class", "ib-login-message-" + type);

        if (message == "login_failed") {
            div.textContent = "Failed to login";
        } else if (message == "register_failed") {
            div.textContent = "Failed to register user";
        } else if (message = "register_created") {
            div.textContent = "Created user";
        } else {
            div.textContent = message;
        }

        return div;
    };

    ib.renderLoginForm = function (containerId) {
        var success = function (config) {
            var login = createLogin(containerId);

            login.appendChild(createHeader("Login to " + config.name));

            if (messageError) {
                login.appendChild(createMessage(messageError, "warn"));
            }

            if (messageInfo) {
                login.appendChild(createMessage(messageInfo, "info"));
            }

            var standardLogin = document.createElement("div");
            standardLogin.setAttribute("class", "ib-login-standard");
            login.appendChild(standardLogin);

            var form = document.createElement("form");
            form.setAttribute("action", ib.loginUrl);
            form.setAttribute("method", "post");
            standardLogin.appendChild(form);

            form.appendChild(createInput("standard", "username", "Username"));
            form.appendChild(createInput("standard", "password", "Password", "password"));

            var buttonsDiv = document.createElement("div");
            buttonsDiv.setAttribute("class", "ib-login-buttons");
            form.appendChild(buttonsDiv);

            var submitButton = document.createElement("button");
            submitButton.setAttribute("type", "submit");
            submitButton.textContent = "Login";
            buttonsDiv.appendChild(submitButton);

            var registerButton = document.createElement("button");
            registerButton.setAttribute("type", "button");
            registerButton.setAttribute("onclick", "location.href='" + ib.registerUrl + "'");
            registerButton.textContent = "Register";
            buttonsDiv.appendChild(registerButton);

            var socialLogin = document.createElement("div");
            socialLogin.setAttribute("class", "ib-login-social");
            login.appendChild(socialLogin);

            for (var i = 0; i < config.providerConfigs.length; i++) {
                var provider = config.providerConfigs[i];

                var providerLink = document.createElement("a");
                providerLink.setAttribute("href", provider.loginUri);
                socialLogin.appendChild(providerLink);

                var providerImage = document.createElement("img");
                providerImage.setAttribute("src", provider.icon);
                providerLink.appendChild(providerImage);
            }
        };

        var error = function() {
            var login = createLogin(containerId);

            login.appendChild(createHeader("Invalid"));
            login.appendChild(createMessage("Invalid application key", "warn"));
        };

        ib.getConfig(success, error);
    };

    ib.renderRegistrationForm = function (containerId) {
        var login = createLogin(containerId);

        var success = function (config) {
            login.appendChild(createHeader("Register with " + config.name));

            if (messageError) {
                login.appendChild(createMessage(messageError, "warn"));
            }

            var form = document.createElement("form");
            form.setAttribute("action", ib.registerUrl);
            form.setAttribute("method", "post");
            login.appendChild(form);

            form.appendChild(createInput("register", "username", "Username"));
            form.appendChild(createInput("register", "email", "Email", "email"));
            form.appendChild(createInput("register", "firstName", "First name"));
            form.appendChild(createInput("register", "lastName", "Last name"));
            form.appendChild(createInput("register", "password", "Password", "password"));

            var buttonsDiv = document.createElement("div");
            buttonsDiv.setAttribute("class", "ib-login-buttons");
            form.appendChild(buttonsDiv);

            var submitButton = document.createElement("button");
            submitButton.setAttribute("type", "submit");
            submitButton.textContent = "Register";
            buttonsDiv.appendChild(submitButton);

            var cancelButton = document.createElement("button");
            cancelButton.setAttribute("type", "button");
            cancelButton.setAttribute("onclick", "location.href='" + ib.loginUrl + "'");
            cancelButton.textContent = "Cancel";
            buttonsDiv.appendChild(cancelButton);
        };

        ib.getConfig(success);
    };

    return ib;
}());