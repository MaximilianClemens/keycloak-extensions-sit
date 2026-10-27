<#--
  Kerberos as a choice on the login page (sit-auth-kerberos-ticket).

  Include from the login theme, e.g. in login.ftl right after the login </form>:
      <#include "sit-kerberos-ticket.ftl">
  The template ships in the provider jar (theme-resources/templates), no copy needed.

  Rendered only when the flow offers the execution. The page then runs the SPNEGO round trip
  against /realms/<realm>/sit-kerberos/ticket with fetch() (the browser answers the Negotiate
  challenge by itself) and, once the ticket is accepted, posts the ordinary "try another way"
  selection for the execution. Without a ticket nothing is submitted.

  Mode, set before the include (default "button"):
      <#assign sitKerberosMode = "auto">     probe on page load; log in at once if there is a
                                            ticket, otherwise show nothing
      <#assign sitKerberosMode = "button">   show the button; the probe runs on click
  Texts: sit.kerberos.button, sit.kerberos.noTicket (messages_*.properties, overridable).
-->
<#if auth?? && auth.authenticationSelections??>
  <#list auth.authenticationSelections as sel>
    <#if (sel.authenticationExecution.authenticator)! == "sit-auth-kerberos-ticket">
      <form method="post" action="${url.loginAction}" id="sit-kerberos-ticket-form" class="sit-kerberos-form"
            data-mode="${(sitKerberosMode!'button')}" hidden>
        <input type="hidden" name="authenticationExecution" value="${sel.authExecId}">
        <button type="submit" id="sit-kerberos-ticket-button"
                class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">
          ${msg("sit.kerberos.button")}
        </button>
        <div id="sit-kerberos-ticket-message" class="${properties.kcAlertClass!} ${properties.kcAlertWarningClass!}" hidden>
          ${msg("sit.kerberos.noTicket")}
        </div>
      </form>
      <script>
      (function () {
        var form = document.getElementById("sit-kerberos-ticket-form");
        var button = document.getElementById("sit-kerberos-ticket-button");
        var message = document.getElementById("sit-kerberos-ticket-message");
        if (!form || !window.fetch || !window.URL) { return; }

        // /realms/<realm>/login-actions/authenticate?...&client_id=..&tab_id=..  ->  the endpoint
        var action = new URL(form.action, window.location.href);
        var endpoint = new URL(action.pathname.replace(/\/login-actions\/.*$/, "/sit-kerberos/ticket"), action);
        endpoint.searchParams.set("client_id", action.searchParams.get("client_id") || "");
        endpoint.searchParams.set("tab_id", action.searchParams.get("tab_id") || "");

        function ticketAccepted() {
          return fetch(endpoint.toString(), {
            credentials: "same-origin", cache: "no-store", redirect: "manual",
            headers: { "Accept": "application/json" }
          }).then(function (r) { return r.ok ? r.json() : { ok: false }; })
            .then(function (j) { return !!(j && j.ok); })
            .catch(function () { return false; });
        }

        var submitting = false;
        form.addEventListener("submit", function (ev) {
          if (submitting) { return; }
          ev.preventDefault();
          button.disabled = true;
          message.hidden = true;
          ticketAccepted().then(function (ok) {
            if (ok) { submitting = true; form.submit(); }
            else { button.disabled = false; message.hidden = false; }
          });
        });

        if (form.getAttribute("data-mode") === "auto") {
          ticketAccepted().then(function (ok) {
            if (ok) { submitting = true; form.submit(); }
          });
        } else {
          form.hidden = false;
        }
      })();
      </script>
    </#if>
  </#list>
</#if>
