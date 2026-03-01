use keyring::Entry;

const SERVICE: &str = "coulson";
const CF_TOKEN_ACCOUNT: &str = "cf-api-token";

pub fn store_api_token(token: &str) -> anyhow::Result<()> {
    let entry = Entry::new(SERVICE, CF_TOKEN_ACCOUNT)?;
    entry.set_password(token)?;
    Ok(())
}

pub fn get_api_token() -> anyhow::Result<Option<String>> {
    let entry = Entry::new(SERVICE, CF_TOKEN_ACCOUNT)?;
    match entry.get_password() {
        Ok(token) => Ok(Some(token)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn delete_api_token() -> anyhow::Result<()> {
    let entry = Entry::new(SERVICE, CF_TOKEN_ACCOUNT)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
