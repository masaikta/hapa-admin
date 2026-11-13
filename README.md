# Hapa Admin

Settings for the public site (homesupport.co.ke) on their own subdomain, separate from Hapa Pro.
Notice banner, switched-off pages, emergency contacts, article status, and a change log. Super administrator only.

## One-time setup (Cloudflare)
1. Workers & Pages: create the worker from this repo (name `hapa-admin`), binding the D1 database `hapa-data` (already in wrangler.jsonc).
2. Add the custom domain `admin.homesupport.co.ke` to the worker.
3. Zero Trust > Access > Applications: add a self-hosted application for `admin.homesupport.co.ke` with one policy that allows only masaikta@gmail.com.
4. Copy the application's AUD tag and your Zero Trust team name into the worker's variables as `ACCESS_AUD` and `ACCESS_TEAM`.

Until step 4 is done the worker refuses every request, so a half-finished setup is never open.
