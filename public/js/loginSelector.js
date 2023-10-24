document.addEventListener("DOMContentLoaded", function() {
    const sessionRadio = document.getElementById("session-radio");
    const jwtRadio = document.getElementById("jwt-radio");
    const loginForm = document.getElementById("log_in_form");

    sessionRadio.addEventListener("change", updateFormAction);
    jwtRadio.addEventListener("change", updateFormAction);

    function updateFormAction() {
        if (sessionRadio.checked) {
            loginForm.action = sessionRadio.value;
            
        } else if (jwtRadio.checked) {
            loginForm.action = jwtRadio.value;
        }
    }
});
