#[derive(Debug, Clone)]
pub struct Config {
    pub server_url: String,
    pub server_port: u16,
    pub data_dir: String,
}

impl Config {
    pub fn init() -> Config {
        let server_url = std::env::var("SERVER_URL").expect("SERVER_URL must be set");
        let server_port = std::env::var("SERVER_PORT").unwrap_or("8000".to_string());
        let data_dir = std::env::var("DATA_DIR").unwrap_or("~/.local/share/secloud/".to_string());

        Config {
            server_url,
            server_port: server_port.parse::<u16>().unwrap(),
            data_dir,
        }
    }
}
