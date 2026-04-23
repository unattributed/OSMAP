# Reusable Webmail WSTG Shell Test Pack

This pack turns the ad hoc one-liners from the original OSMAP exposed-slice assessment into reusable Bash scripts that load target-specific values from a `.env` file.

## What is included

- `.env.example`, template configuration file
- `lib/common.sh`, shared helpers for login, cookie handling, CSRF extraction, and output directories
- `scripts/`, numbered Bash scripts grouped around the original test flow

The scripts are intended for **authorized testing only** against webmail applications you have permission to assess.

## Important note on fidelity

Most scripts are direct conversions of the commands used in the original test run. A smaller number, mainly the earliest auth and lockout probes, are **hardened functional equivalents** reconstructed from the test history and directory naming rather than byte-for-byte copies of the original shell one-liners.

That means the pack is suitable for repeatable testing and sharing with other testers, but a few early scripts are best treated as generalized versions of the original checks.

## Quick start

1. Copy `.env.example` to `.env`
2. Set at least:
   - `HOSTNAME=`
   - `EMAIL=`
3. Leave `TEST_PASSWORD` and `TEST_TOTP_CODE` blank unless you explicitly want them stored in the environment
4. Run any script you need, for example:

```bash
cd webmail-wstg-pack
cp .env.example .env
joe .env
./scripts/29_compose_surface_map.sh
```

## Shared environment variables

Required:
- `HOSTNAME`
- `EMAIL`

Common optional values:
- `SCHEME`
- `OUT_ROOT`
- `DEFAULT_MAILBOX`
- `DEFAULT_MESSAGE_UID`
- `DEFAULT_ATTACHMENT_PART`
- `DEFAULT_ARCHIVE_MAILBOX`
- `SEARCH_QUERY`
- `INVALID_EMAIL`
- `ATTACKER_URL`

Optional secret values:
- `TEST_PASSWORD`
- `TEST_TOTP_CODE`

If secret values are blank, the scripts prompt interactively.

## Script coverage

### Authentication and session
- `01_baseline_routes.sh`
- `02_auth_negative_login.sh`
- `03_auth_throttle_same_ip.sh`
- `04_auth_throttle_cooldown.sh`
- `05_lockout_scope_same_ip.sh`
- `06_real_user_lockout_threshold.sh`
- `07_valid_login_during_lockout.sh`
- `08_real_user_cooldown_window.sh`
- `09_success_login_and_session.sh`
- `10_session_fixation.sh`
- `11_auth_form_map.sh`
- `12_logout_missing_csrf.sh`
- `13_logout_valid_csrf.sh`
- `14_logout_browserlike_csrf.sh`
- `19_session_timeout_activity.sh`
- `20_idle_timeout_spotcheck.sh`
- `23_concurrent_sessions_baseline.sh`

### Input validation, injection, and request handling
- `15_search_reflected_xss_and_availability.sh`
- `16_settings_archive_html_injection.sh`
- `17_archive_hidden_field_tamper.sh`
- `18_reset_archive_mailbox.sh`
- `24_sqli_login.sh`
- `25_ldap_injection_login.sh`
- `26_xml_injection_settings.sh`
- `27_ssi_injection_settings.sh`
- `28_xpath_injection_login.sh`
- `29_compose_surface_map.sh`
- `30_send_header_injection.sh`
- `33_command_injection_attachment_filename.sh`
- `34_format_string_settings.sh`
- `35_http_response_splitting.sh`
- `36_request_smuggling_parser_check.sh`
- `37_host_header_injection.sh`
- `38_ssti_settings.sh`
- `39_ssrf_sink_discovery.sh`
- `40_mass_assignment_settings.sh`
- `41_csv_export_sink_discovery.sh`

### Transport and crypto
- `44_tls_transport_check.sh`
- `45_padding_oracle_check.sh`
- `46_unencrypted_channel_check.sh`
- `47_weak_crypto_primitives_check.sh`

### Business logic
- `48_business_invalid_archive_mailbox.sh`
- `49_business_forge_request_revoke.sh`
- `50_business_integrity_message_move.sh`
- `51_business_revoke_race.sh`
- `52_business_session_count_limit.sh`
- `53_business_workflow_circumvention_send.sh`
- `54_business_application_misuse_send_repeat.sh`
- `55_upload_unexpected_types.sh`
- `56_upload_malicious_files.sh`

### Client-side
- `57_dom_xss_sink_discovery.sh`
- `58_javascript_execution_check.sh`
- `59_html_injection_check.sh`
- `60_url_redirect_check.sh`
- `61_css_injection_check.sh`
- `62_resource_manipulation_check.sh`
- `63_cors_check.sh`
- `64_clickjacking_check.sh`
- `65_websockets_check.sh`
- `66_web_messaging_check.sh`
- `67_browser_storage_and_flash_applicability.sh`
- `68_xssi_check.sh`
- `69_reverse_tabnabbing_check.sh`
- `70_client_side_template_injection.sh`

### API reconnaissance
- `71_api_reconnaissance.sh`

## Output behavior

Each script writes its own timestamped run directory under `OUT_ROOT`, for example:

```text
$OUT_ROOT/29-compose-surface-map-20260423-190349
```

## Dependencies

Core:
- `bash`
- `curl`
- `awk`
- `grep`
- `sed`
- `python3`

Optional:
- `git`, for `testssl.sh` bootstrap
- `testssl.sh`, if already installed
- `file`, for attachment inspection

## Safety notes

- These scripts are for **permitted** testing only
- Several scripts intentionally submit malformed values to authenticated workflows
- Some tests prompt for multiple TOTP codes because they establish separate fresh sessions
- The timeout scripts can be long-running, tune values in `.env` if needed

## Suggested repo layout if you commit this pack

- Path: `tools/webmail-wstg-pack/`
- Change description: add reusable shell scripts for webmail WSTG testing with shared .env configuration
- Suggested git commit comment: `add reusable webmail wstg shell test pack`
