//! Server-rendered HTML. Every dynamic value goes through `escape_html`.

use crate::support::escape_html as e;

pub(crate) struct ConsentView<'a> {
    pub tx: &'a str,
    pub client_name: Option<&'a str>,
    pub client_id: &'a str,
    pub redirect_host: &'a str,
    pub backend_name: &'a str,
    pub resource: &'a str,
    pub scopes: &'a str,
    pub grant_lifetime: String,
    /// How long ago the authorization request was made.
    pub requested_ago: String,
    /// When the client registered (absolute and relative).
    pub client_registered: String,
    pub issuer_host: &'a str,
    /// `Some(csrf)` once the owner has proved presence with a passkey.
    pub csrf: Option<&'a str>,
}

pub(crate) struct GrantView {
    pub id: String,
    pub client: String,
    pub backend: String,
    pub created: String,
    pub expires: String,
    pub last_used: String,
}

pub(crate) fn layout(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<meta name=\"referrer\" content=\"no-referrer\">\
<title>{}</title><link rel=\"stylesheet\" href=\"/static/edge.css\">\
<script src=\"/static/edge.js\" defer></script></head>\
<body><main>{body}<p id=\"status\" role=\"status\"></p></main></body></html>\n",
        e(title)
    )
}

pub(crate) fn message(title: &str, text: &str) -> String {
    layout(title, &format!("<h1>{}</h1><p>{}</p>", e(title), e(text)))
}

pub(crate) fn consent(v: &ConsentView<'_>) -> String {
    let client = match v.client_name {
        Some(name) if !name.is_empty() => format!(
            "<strong>{}</strong> <span class=\"muted\">(name self-reported by the client; \
id {})</span>",
            e(name),
            e(v.client_id)
        ),
        _ => format!(
            "<strong>{}</strong> <span class=\"muted\">(no name given)</span>",
            e(v.client_id)
        ),
    };
    let details = format!(
        "<h1>Authorize access</h1>\
<p class=\"warning\"><strong>Approve only if you just clicked Connect in Claude yourself.</strong> \
If you did not start this, deny it: someone may be trying to get access through your account.</p>\
<dl>\
<dt>Requested</dt><dd>{}</dd>\
<dt>Client</dt><dd>{client}</dd>\
<dt>Client registered</dt><dd>{}</dd>\
<dt>Returns to</dt><dd>{}</dd>\
<dt>Backend</dt><dd><strong>{}</strong><br><code>{}</code></dd>\
<dt>Scopes</dt><dd><code>{}</code></dd>\
<dt>Lifetime</dt><dd>Access tokens last 15 minutes and are refreshed automatically; \
the grant ends after {} unless you revoke it sooner.</dd>\
</dl>\
<p class=\"note\">Requests and results pass through this edge ({}), which terminates TLS \
and can therefore see them. You can revoke this grant at any time from \
<a href=\"/owner\">/owner</a>.</p>",
        e(&v.requested_ago),
        e(&v.client_registered),
        e(v.redirect_host),
        e(v.backend_name),
        e(v.resource),
        e(v.scopes),
        e(&v.grant_lifetime),
        e(v.issuer_host),
    );
    let action = match v.csrf {
        None => format!(
            "<p>Confirm it is you with your passkey before deciding.</p>\
<button type=\"button\" data-action=\"login\" data-tx=\"{}\">Confirm with passkey</button>",
            e(v.tx)
        ),
        Some(csrf) => format!(
            "<form method=\"post\" action=\"/consent\">\
<input type=\"hidden\" name=\"tx\" value=\"{tx}\">\
<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button> \
<button type=\"submit\" name=\"decision\" value=\"deny\" class=\"secondary\">Deny</button>\
</form>",
            tx = e(v.tx),
            csrf = e(csrf)
        ),
    };
    layout("Authorize access", &format!("{details}{action}"))
}

pub(crate) fn owner_login(enrolled: bool) -> String {
    let body = if enrolled {
        "<h1>Owner sign-in</h1><p>Sign in with your passkey to manage grants.</p>\
<button type=\"button\" data-action=\"login\">Sign in with passkey</button>"
    } else {
        "<h1>Owner sign-in</h1><p>No passkey is registered yet. \
Use <a href=\"/owner/enroll\">enrollment</a> with the one-time enrollment code.</p>"
    };
    layout("Owner sign-in", body)
}

pub(crate) fn enroll(already: bool) -> String {
    let body = if already {
        "<h1>Enrollment closed</h1><p>An owner passkey already exists. \
Sign in at <a href=\"/owner\">/owner</a> to add another passkey.</p>"
            .to_string()
    } else {
        "<h1>Register owner passkey</h1>\
<p>Enter the one-time enrollment code configured for this edge.</p>\
<label for=\"enroll-code\">Enrollment code</label>\
<input id=\"enroll-code\" type=\"password\" autocomplete=\"off\" spellcheck=\"false\">\
<button type=\"button\" data-action=\"enroll\">Create passkey</button>"
            .to_string()
    };
    layout("Owner enrollment", &body)
}

pub(crate) fn owner_home(grants: &[GrantView], csrf: &str) -> String {
    let mut rows = String::new();
    for g in grants {
        rows.push_str(&format!(
            "<tr><td><code>{id}</code></td><td>{client}</td><td>{backend}</td><td>{created}</td>\
<td>{expires}</td><td>{last}</td><td><form method=\"post\" action=\"/owner/grants/revoke\">\
<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
<input type=\"hidden\" name=\"grant_id\" value=\"{id}\">\
<button type=\"submit\" class=\"secondary\">Revoke</button></form></td></tr>",
            id = e(&g.id),
            client = e(&g.client),
            backend = e(&g.backend),
            created = e(&g.created),
            expires = e(&g.expires),
            last = e(&g.last_used),
            csrf = e(csrf),
        ));
    }
    let table = if grants.is_empty() {
        "<p>No active grants.</p>".to_string()
    } else {
        format!(
            "<table><thead><tr><th>Grant</th><th>Client</th><th>Backend</th><th>Created</th>\
<th>Expires</th><th>Last used</th><th></th></tr></thead><tbody>{rows}</tbody></table>\
<form method=\"post\" action=\"/owner/grants/revoke-all\">\
<input type=\"hidden\" name=\"csrf\" value=\"{}\">\
<button type=\"submit\">Revoke all</button></form>",
            e(csrf)
        )
    };
    layout(
        "Owner",
        &format!(
            "<h1>Grants</h1>{table}<h2>Passkeys</h2>\
<button type=\"button\" data-action=\"add-passkey\">Add another passkey</button>\
<form method=\"post\" action=\"/owner/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
<button type=\"submit\" class=\"secondary\">Sign out</button></form>",
            e(csrf)
        ),
    )
}
