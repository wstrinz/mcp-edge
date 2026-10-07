//! Server-rendered HTML. Every dynamic value goes through `escape_html`.

use crate::{origin::OriginPanel, support::escape_html as e};

/// Where an origin consent stands, as far as the page is concerned.
pub(crate) enum OriginPage {
    /// Nothing sent yet, or the last attempt failed (`reason`).
    Ready {
        attempts_left: u32,
        reason: Option<String>,
    },
    /// Waiting for the owner in the app.
    Sent { pairing_code: String },
    /// A verified approval arrived; the finish form issues the code.
    Approved,
    /// Denied or no decision; the finish form returns `access_denied`.
    Ended { title: &'static str, text: String },
}

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
    /// `Some(csrf)` once the owner has proved presence with a passkey (for
    /// origin backends always, for cancel/finish).
    pub csrf: Option<&'a str>,
    /// The passkey proof is recent enough to decide or to start.
    pub fresh: bool,
    /// `Some` for `consent = "origin"` backends.
    pub origin: Option<OriginPage>,
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
<meta name=\"referrer\" content=\"same-origin\">\
<title>{}</title><link rel=\"stylesheet\" href=\"/static/edge.css\">\
<script src=\"/static/edge.js\" defer></script></head>\
<body><main>{body}<p id=\"status\" role=\"status\"></p></main></body></html>\n",
        e(title)
    )
}

pub(crate) fn message(title: &str, text: &str) -> String {
    layout(title, &format!("<h1>{}</h1><p>{}</p>", e(title), e(text)))
}

fn hidden(tx: &str, csrf: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"tx\" value=\"{}\">\
<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        e(tx),
        e(csrf)
    )
}

fn passkey_button(tx: &str) -> String {
    format!(
        "<p>Confirm it is you with your passkey before deciding.</p>\
<button type=\"button\" data-action=\"login\" data-tx=\"{}\">Confirm with passkey</button>",
        e(tx)
    )
}

/// The decision part of the consent page for an origin backend.
fn origin_action(v: &ConsentView<'_>, page: &OriginPage) -> String {
    let app = e(v.backend_name);
    let Some(csrf) = v.csrf else {
        return passkey_button(v.tx);
    };
    let fields = hidden(v.tx, csrf);
    let finish = |label: &str, auto: bool| {
        format!(
            "<form method=\"post\" action=\"/consent/finish\"{}>{fields}\
<button type=\"submit\">{}</button></form>",
            if auto { " data-autosubmit" } else { "" },
            e(label)
        )
    };
    match page {
        OriginPage::Ready {
            attempts_left,
            reason,
        } => {
            let mut out = String::new();
            if let Some(r) = reason {
                out.push_str(&format!("<p class=\"warning\">{}</p>", e(r)));
            }
            if *attempts_left == 0 {
                out.push_str("<p>No attempts are left for this request.</p>");
                out.push_str(&finish("Return to Claude", false));
                return out;
            }
            if !v.fresh {
                out.push_str(&passkey_button(v.tx));
                return out;
            }
            let label = if reason.is_some() {
                "Try again".to_string()
            } else {
                format!("Continue to {}", v.backend_name)
            };
            out.push_str(&format!(
                "<p>Next, {app} on your computer asks you to type a pairing code shown here, \
choose exactly what to share and approve it there.</p>\
<form method=\"post\" action=\"/consent/start\">{fields}\
<button type=\"submit\">{}</button></form> \
<form method=\"post\" action=\"/consent\">{fields}\
<button type=\"submit\" name=\"decision\" value=\"deny\" class=\"secondary\">Deny</button>\
</form><p class=\"muted\">Attempts left: {attempts_left}</p>",
                e(&label)
            ));
            out
        }
        OriginPage::Sent { pairing_code } => {
            let shown = if pairing_code.len() == 6 {
                format!("{}-{}", &pairing_code[..3], &pairing_code[3..])
            } else {
                pairing_code.clone()
            };
            format!(
                "<div data-poll=\"{tx}\"><h2>Approve in {app} on your computer</h2>\
<p>Open {app}. When it asks, type this pairing code, then choose what to share and \
approve:</p><p class=\"code\"><strong>{code}</strong></p>\
<p class=\"muted\">This page updates by itself. The request expires after 3 minutes.</p></div>\
<form method=\"get\" action=\"/consent\"><input type=\"hidden\" name=\"tx\" value=\"{tx}\">\
<button type=\"submit\" class=\"secondary\">Check</button></form> \
<form method=\"post\" action=\"/consent/cancel\">{fields}\
<button type=\"submit\" class=\"secondary\">Cancel</button></form>",
                tx = e(v.tx),
                code = e(&shown),
            )
        }
        OriginPage::Approved => format!(
            "<h2>Approved in {app}</h2><p>Returning to Claude.</p>{}",
            finish("Return to Claude", true)
        ),
        OriginPage::Ended { title, text } => format!(
            "<h2>{}</h2><p>{}</p>{}",
            e(title),
            e(text),
            finish("Return to Claude", false)
        ),
    }
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
    let lifetime = if v.origin.is_some() {
        format!(
            "Access tokens last 15 minutes and are refreshed automatically. You choose what to \
share and for how long in {} (at most {}).",
            v.backend_name, v.grant_lifetime
        )
    } else {
        format!(
            "Access tokens last 15 minutes and are refreshed automatically; the grant ends after \
{} unless you revoke it sooner.",
            v.grant_lifetime
        )
    };
    let export = if v.origin.is_some() {
        format!(
            "<p class=\"warning\">Data you approve in {} leaves your computer: this edge ({}) \
and the client's provider (Anthropic, for Claude) will see it in plaintext.</p>",
            e(v.backend_name),
            e(v.issuer_host)
        )
    } else {
        String::new()
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
<dt>Lifetime</dt><dd>{}</dd>\
</dl>{}\
<p class=\"note\">Requests and results pass through this edge ({}), which terminates TLS \
and can therefore see them. You can revoke this grant at any time from \
<a href=\"/owner\">/owner</a>.</p>",
        e(&v.requested_ago),
        e(&v.client_registered),
        e(v.redirect_host),
        e(v.backend_name),
        e(v.resource),
        e(v.scopes),
        e(&lifetime),
        export,
        e(v.issuer_host),
    );
    let action = match (&v.origin, v.csrf) {
        (Some(page), _) => origin_action(v, page),
        (None, None) => passkey_button(v.tx),
        (None, Some(csrf)) => format!(
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

fn origin_panel(p: &OriginPanel) -> String {
    format!(
        "<section><h3>{name} <code>{backend}</code></h3>\
<p>Paste this enrollment string into {name} (Remote access, Enroll an edge) and compare the \
fingerprint shown there:</p>\
<textarea readonly rows=\"4\" spellcheck=\"false\">{enroll}</textarea>\
<dl><dt>Fingerprint</dt><dd><strong>{fp}</strong></dd>\
<dt>Edge EndpointId</dt><dd><code>{edge}</code></dd>\
<dt>Assertion key</dt><dd><code>{akey}</code></dd>\
<dt>Issuer</dt><dd><code>{iss}</code></dd>\
<dt>Owner id (sub)</dt><dd><code>{sub}</code></dd>\
<dt>Scopes</dt><dd><code>{scopes}</code></dd>\
<dt>Configured origin</dt><dd><strong>{short}</strong><br><code>{origin}</code><br>\
<span class=\"muted\">Must equal the EndpointId {name} shows for itself.</span></dd>\
<dt>Origin status</dt><dd>{status}</dd></dl></section>",
        name = e(&p.display_name),
        backend = e(&p.backend),
        enroll = e(&p.enrollment),
        fp = e(&p.fingerprint),
        edge = e(&p.edge_id),
        akey = e(&p.assertion_key),
        iss = e(&p.issuer),
        sub = e(&p.owner_id),
        scopes = e(&p.scopes.join(" ")),
        short = e(&p.origin_short),
        origin = e(&p.origin_id),
        status = e(&p.status),
    )
}

pub(crate) fn owner_home(grants: &[GrantView], panels: &[OriginPanel], csrf: &str) -> String {
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
            "<h1>Grants</h1>{table}{origins}<h2>Passkeys</h2>\
<button type=\"button\" data-action=\"add-passkey\">Add another passkey</button>\
<form method=\"post\" action=\"/owner/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
<button type=\"submit\" class=\"secondary\">Sign out</button></form>",
            e(csrf),
            origins = if panels.is_empty() {
                String::new()
            } else {
                format!(
                    "<h2>Local apps (enrollment)</h2>{}",
                    panels.iter().map(origin_panel).collect::<String>()
                )
            },
        ),
    )
}
