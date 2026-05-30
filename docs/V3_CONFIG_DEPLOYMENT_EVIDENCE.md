# V3 Configuration And Deployment Evidence

`OSMAP-WSTG-CONF-008` records the Slice 10 evidence lane for sensitive
extension handling plus backup and unreferenced file exposure.
`OSMAP-WSTG-CONF-009` records the Slice 10 applicability lane for legacy RIA
cross-domain policy files and cloud storage exposure.

Mapped WSTG rows:

- `WSTG-v42-CONF-03`
- `WSTG-v42-CONF-04`
- `WSTG-v42-CONF-08`
- `WSTG-v42-CONF-11`

## Public File Exposure

The public WAN OSMAP vhost is not a repository or deployment-artifact file
server. `maint/openbsd/mail.blackbagsecurity.com/nginx/templates/osmap-root.tmpl`
proxies the canonical browser path to `proxy_pass http://127.0.0.1:8080`, and
the Rust router serves only explicit browser routes. Unknown paths emit
`http_route_not_found` through the generic route-not-found branch.

There is no public static repository root, no public backup directory, and no source archive exposure in the reviewed OSMAP browser boundary.

## Sensitive Extension Handling

`OSMAP-WSTG-CONF-008` probes sensitive extension handling for repository,
configuration, key, and source-like paths including `.env`, `.toml`, `.lock`,
`.md`, `.key`, `.conf`, and `.php` filenames.

## Backup And Unreferenced File Exposure

`OSMAP-WSTG-CONF-008` also probes backup and unreferenced file exposure for
common editor backups, archive names, SQL dumps, old env files, and
source/deployment filenames using `.bak`, `.old`, `.swp`, `.sql`, `.zip`, and
`.tar.gz` style paths.

Dot-segment request targets fail in the HTTP parser with the reviewed invariant
`request target path must not contain dot segments` before route handling.

## RIA Cross-Domain Policy

RIA cross-domain policy is not applicable to the current OSMAP browser surface.
OSMAP has no Flash or Silverlight boundary; no public RIA cross-domain policy
exists in the OSMAP browser boundary. `OSMAP-WSTG-CONF-009`
probes `/crossdomain.xml` and `/clientaccesspolicy.xml` and fails if either
legacy policy file is served or contains permissive cross-domain policy
directives.

## Cloud Storage Exposure

Cloud storage testing is not applicable to the current OSMAP browser surface.
OSMAP has no cloud object storage surface, no cloud storage dependency, and no
public S3, GCS, Azure Blob, CloudFront, or object-storage bucket endpoint for
mail data. The public WAN OSMAP vhost proxies browser routes to the Rust
service rather than mounting a cloud bucket or static object-storage root.
