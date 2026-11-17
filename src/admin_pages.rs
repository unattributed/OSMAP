//! Domain projections and own presentation settings behind current admin authority.
use super::*;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminPreferences {
    pub(crate) theme: String,
    pub(crate) density: String,
    pub(crate) font_size: String,
    #[serde(default = "text_labels")]
    pub(crate) presentation_style: String,
}
fn text_labels() -> String {
    crate::appearance::PresentationStyle::default()
        .as_str()
        .into()
}

#[cfg(test)]
mod preference_compatibility_tests {
    use super::*;
    #[test]
    fn old_admin_records_and_cookie_hints_keep_text_labels() {
        let old: AdminPreferences =
            serde_json::from_str(r#"{"theme":"dark","density":"compact","font_size":"large"}"#)
                .unwrap();
        assert!(old.valid());
        assert_eq!(old.presentation_style, "text_labels");
        assert_eq!(
            AdminPreferences::parse("dark.compact.large")
                .unwrap()
                .presentation_style,
            "text_labels"
        );
        let mut icons = old;
        icons.presentation_style = "icons".into();
        assert_eq!(
            AdminPreferences::parse(&icons.value())
                .unwrap()
                .presentation_style,
            "icons"
        );
        assert!(AdminPreferences::parse("dark.compact.large.svg").is_none());
        assert!(AdminPreferences::parse("dark.compact.large.icons.extra").is_none());
    }
}
impl Default for AdminPreferences {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            density: "comfortable".into(),
            font_size: "medium".into(),
            presentation_style: text_labels(),
        }
    }
}
impl AdminPreferences {
    pub(crate) fn valid(&self) -> bool {
        crate::appearance::AppearancePreference::parse(&self.theme).is_some()
            && crate::appearance::Density::parse(&self.density).is_some()
            && crate::appearance::FontSize::parse(&self.font_size).is_some()
            && crate::appearance::PresentationStyle::parse(&self.presentation_style).is_some()
    }
    pub(crate) fn value(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.theme, self.density, self.font_size, self.presentation_style
        )
    }
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let values = value.split('.').collect::<Vec<_>>();
        if !matches!(values.len(), 3 | 4) {
            return None;
        }
        let result = Self {
            theme: values[0].into(),
            density: values[1].into(),
            font_size: values[2].into(),
            presentation_style: values
                .get(3)
                .map(|s| (*s).into())
                .unwrap_or_else(text_labels),
        };
        result.valid().then_some(result)
    }
    pub(crate) fn apply(&self, response: &mut crate::http::HttpResponse) {
        let appearance = crate::appearance::AppearanceSettings {
            theme: crate::appearance::AppearancePreference::parse(&self.theme).unwrap_or_default(),
            density: crate::appearance::Density::parse(&self.density).unwrap_or_default(),
            font_size: crate::appearance::FontSize::parse(&self.font_size).unwrap_or_default(),
            presentation_style: crate::appearance::PresentationStyle::parse(
                &self.presentation_style,
            )
            .unwrap_or_default(),
            ..Default::default()
        };
        // Internal presentation projection only. No mailbox cookie is emitted,
        // accepted from the browser, or used as administrator authority.
        let projected = format!(
            "{}; {}",
            appearance.theme.cookie(true),
            appearance.cookie(true)
        );
        crate::http_support::apply_appearance(response, Some(&projected));
    }
    pub(crate) fn apply_menus(&self, response: &mut crate::http::HttpResponse) {
        const ROOT: &[u8] = b"<!doctype html><html lang=\"en\"";
        if response.status_code == 200 && response.body.starts_with(ROOT) {
            let style = crate::appearance::PresentationStyle::parse(&self.presentation_style)
                .unwrap_or_default();
            let attribute = format!(" data-presentation-style=\"{}\"", style.as_str());
            response
                .body
                .splice(ROOT.len()..ROOT.len(), attribute.bytes());
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DomainSummary {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) active: bool,
    pub(crate) mailboxes: u64,
    pub(crate) forwards: u64,
    pub(crate) created: Option<String>,
}
fn timestamp(value: &Option<String>) -> bool {
    value
        .as_ref()
        .is_none_or(|s| s.len() <= 32 && !s.chars().any(char::is_control))
}
fn identity(login: &str, csrf: &str) -> bool {
    valid_login(login) && csrf.len() == 64 && csrf.bytes().all(|b| b.is_ascii_hexdigit())
}
pub(crate) fn overview_options(query: &str, page: u8) -> bool {
    query.len() <= 64 && !query.chars().any(char::is_control) && (1..=10).contains(&page)
}
impl DomainSummary {
    pub(crate) fn valid(&self) -> bool {
        Scope::domains(&[&self.name]).is_ok()
            && self.id == format!("{:x}", Sha256::digest(self.name.as_bytes()))
            && timestamp(&self.created)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DomainOverview {
    pub(crate) login: String,
    pub(crate) csrf: String,
    pub(crate) system: bool,
    pub(crate) query: String,
    pub(crate) page: u8,
    pub(crate) total: u16,
    pub(crate) domain_total: u16,
    pub(crate) preferences: AdminPreferences,
    pub(crate) mailbox_total: u64,
    pub(crate) forward_total: u64,
    pub(crate) rows: Vec<DomainSummary>,
}
impl DomainOverview {
    pub(crate) fn pages(&self) -> u8 {
        self.total.div_ceil(10).max(1) as u8
    }
    pub(crate) fn valid(&self) -> bool {
        identity(&self.login, &self.csrf)
            && overview_options(&self.query, self.page)
            && self.domain_total <= 100
            && self.total <= self.domain_total
            && self.preferences.valid()
            && self.page <= self.pages()
            && self.rows.len()
                == usize::from(self.total)
                    .saturating_sub(usize::from(self.page - 1) * 10)
                    .min(10)
            && self.rows.iter().all(DomainSummary::valid)
            && self.rows.iter().all(|row| {
                row.mailboxes <= self.mailbox_total && row.forwards <= self.forward_total
            })
            && self
                .rows
                .iter()
                .map(|r| &r.id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.rows.len()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DomainDetails {
    pub(crate) login: String,
    pub(crate) csrf: String,
    pub(crate) domain: DomainSummary,
    pub(crate) description: String,
    pub(crate) modified: Option<String>,
    pub(crate) mailbox_limit: i64,
    pub(crate) alias_limit: i64,
    pub(crate) mailbox_quota: i64,
    pub(crate) domain_quota: i64,
    pub(crate) backup_mx: bool,
    pub(crate) transport: String,
    pub(crate) preferences: AdminPreferences,
}
impl DomainDetails {
    pub(crate) fn valid(&self) -> bool {
        identity(&self.login, &self.csrf)
            && self.preferences.valid()
            && self.domain.valid()
            && timestamp(&self.modified)
            && self.description.chars().count() <= 255
            && self.description.len() <= 1020
            && !self
                .description
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
            && self.transport.len() <= 255
            && !self.transport.chars().any(char::is_control)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SettingsPage {
    pub(crate) login: String,
    pub(crate) csrf: String,
    pub(crate) system: bool,
    pub(crate) preferences: AdminPreferences,
}
impl SettingsPage {
    pub(crate) fn valid(&self) -> bool {
        identity(&self.login, &self.csrf) && self.preferences.valid()
    }
}
fn directory_error(error: crate::admin_directory::Error) -> Error {
    match error {
        crate::admin_directory::Error::Limit => Error::Capacity,
        crate::admin_directory::Error::Missing => Error::Missing,
        _ => Error::Unavailable,
    }
}
impl<E, T, P> Service<E, T, P>
where
    E: CommandExecutor + Clone + Send + Sync + 'static,
    T: TimeProvider + Clone,
    P: PasswordVerifier,
{
    fn catalogue(&self, summary: &Summary) -> Result<Vec<DomainSummary>, Error> {
        let rows = Adapter::new(self.authority.executor.clone())
            .catalogue(summary.system, &summary.domains)
            .map_err(directory_error)?;
        let mut ids = std::collections::BTreeSet::new();
        rows.into_iter()
            .map(|r| {
                let row = DomainSummary {
                    id: format!("{:x}", Sha256::digest(r.name.as_bytes())),
                    name: r.name,
                    active: r.active,
                    mailboxes: r.mailboxes,
                    forwards: r.forwards,
                    created: r.created,
                };
                if !row.valid()
                    || !ids.insert(row.id.clone())
                    || (!summary.system && !summary.domains.contains(&row.name))
                {
                    return Err(Error::Unavailable);
                }
                Ok(row)
            })
            .collect()
    }
    pub(crate) fn overview_from(
        &self,
        token: &Token,
        context: &AuthenticationContext,
        query: &str,
        page: u8,
    ) -> Result<DomainOverview, Error> {
        let summary = self.scope(token, context)?;
        if !overview_options(query, page) {
            return Err(Error::Invalid);
        }
        let rows = self.catalogue(&summary)?;
        let domain_total = u16::try_from(rows.len()).map_err(|_| Error::Capacity)?;
        let preferences = self.presentation_for(&summary.login);
        let mailbox_total = rows
            .iter()
            .try_fold(0u64, |sum, r| sum.checked_add(r.mailboxes))
            .ok_or(Error::Unavailable)?;
        let forward_total = rows
            .iter()
            .try_fold(0u64, |sum, r| sum.checked_add(r.forwards))
            .ok_or(Error::Unavailable)?;
        let query = query.trim();
        let rows = rows
            .into_iter()
            .filter(|r| {
                r.name
                    .to_ascii_lowercase()
                    .contains(&query.to_ascii_lowercase())
            })
            .collect::<Vec<_>>();
        let total = u16::try_from(rows.len()).map_err(|_| Error::Capacity)?;
        let page = page.min(total.div_ceil(10).max(1) as u8);
        let rows = rows
            .into_iter()
            .skip(usize::from(page - 1) * 10)
            .take(10)
            .collect();
        let result = DomainOverview {
            login: summary.login,
            csrf: summary.csrf,
            system: summary.system,
            query: query.into(),
            page,
            total,
            domain_total,
            preferences,
            mailbox_total,
            forward_total,
            rows,
        };
        if !result.valid() {
            return Err(Error::Unavailable);
        }
        Ok(result)
    }
    pub(crate) fn domain_details_from(
        &self,
        token: &Token,
        context: &AuthenticationContext,
        id: &str,
    ) -> Result<DomainDetails, Error> {
        let summary = self.scope(token, context)?;
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Invalid);
        }
        let domain = self
            .catalogue(&summary)?
            .into_iter()
            .find(|r| r.id == id)
            .ok_or(Error::Missing)?;
        let info = Adapter::new(self.authority.executor.clone())
            .domain_info(
                &Scope::domains(&[&domain.name]).map_err(|_| Error::Invalid)?,
                &domain.name,
            )
            .map_err(directory_error)?;
        if info.domain.name != domain.name
            || info.domain.active != domain.active
            || info.created != domain.created
        {
            return Err(Error::Unavailable);
        }
        let result = DomainDetails {
            preferences: self.presentation_for(&summary.login),
            login: summary.login,
            csrf: summary.csrf,
            domain,
            description: info.description,
            modified: info.modified,
            mailbox_limit: info.domain.mailboxes,
            alias_limit: info.domain.aliases,
            mailbox_quota: info.domain.maxquota,
            domain_quota: info.domain.quota,
            backup_mx: info.domain.backupmx,
            transport: info.transport,
        };
        if !result.valid() {
            return Err(Error::Unavailable);
        }
        Ok(result)
    }
    fn preferences_store(&self) -> crate::private_account_file::PrivateAccountFile {
        crate::private_account_file::PrivateAccountFile::new(
            self.authority.root.join("preferences"),
            "osmap-admin-appearance-v1",
            512,
        )
    }
    fn preferences_for(&self, login: &str) -> Result<AdminPreferences, Error> {
        let preferences = match self
            .preferences_store()
            .read(login)
            .map_err(|_| Error::Unavailable)?
        {
            Some(bytes) => serde_json::from_slice::<AdminPreferences>(&bytes)
                .map_err(|_| Error::Unavailable)?,
            None => AdminPreferences::default(),
        };
        if !preferences.valid() {
            return Err(Error::Unavailable);
        }
        Ok(preferences)
    }
    fn presentation_for(&self, login: &str) -> AdminPreferences {
        self.preferences_for(login).unwrap_or_else(|_| {
            eprintln!("ADMIN_PRESENTATION_UNAVAILABLE");
            AdminPreferences::default()
        })
    }
    pub(crate) fn settings_from(
        &self,
        token: &Token,
        context: &AuthenticationContext,
    ) -> Result<SettingsPage, Error> {
        let summary = self.scope(token, context)?;
        let preferences = match self
            .preferences_store()
            .read(&summary.login)
            .map_err(|_| Error::Unavailable)?
        {
            Some(bytes) => serde_json::from_slice::<AdminPreferences>(&bytes)
                .map_err(|_| Error::Unavailable)?,
            None => AdminPreferences::default(),
        };
        let result = SettingsPage {
            login: summary.login,
            csrf: summary.csrf,
            system: summary.system,
            preferences,
        };
        if !result.valid() {
            return Err(Error::Unavailable);
        }
        Ok(result)
    }
    pub(crate) fn save_preferences_from(
        &self,
        token: &Token,
        context: &AuthenticationContext,
        csrf: &str,
        preferences: AdminPreferences,
    ) -> Result<SettingsPage, Error> {
        let summary = self.scope(token, context)?;
        if !crate::http_support::constant_time_eq(summary.csrf.as_bytes(), csrf.as_bytes()) {
            return Err(Error::Denied);
        }
        if !preferences.valid() {
            return Err(Error::Invalid);
        }
        let held = self
            .preferences_store()
            .lock(&summary.login)
            .map_err(|_| Error::Unavailable)?;
        held.write(&serde_json::to_vec(&preferences).map_err(|_| Error::Unavailable)?)
            .map_err(|_| Error::Unavailable)?;
        Ok(SettingsPage {
            login: summary.login,
            csrf: summary.csrf,
            system: summary.system,
            preferences,
        })
    }
}
