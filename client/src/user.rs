pub struct LoginInfo {
    username: String,
    password: String,
    token: Option<String>,
}

impl LoginInfo {
    pub fn new<T>(username: T, password: T, token: Option<T>) -> Self
    where
        T: Into<String>,
    {
        Self {
            username: username.into(),
            password: password.into(),
            token: token.map(|t| t.into()),
        }
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn password(&self) -> String {
        self.password.clone()
    }

    pub fn set_token(&mut self, token: impl Into<String>) {
        self.token = Some(token.into());
    }

    pub fn token(&self) -> Option<String> {
        self.token.clone()
    }
}
