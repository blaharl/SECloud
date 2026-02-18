use axum::Extension;
use axum::body::Bytes;

use crate::config::AppState;
use std::io::Write;
use std::{path::Path, sync::Arc};

use rand::Rng;
use rand::distr::Alphanumeric;

pub async fn generate_filename(name_len: usize) -> Result<String, std::io::Error> {
    let mut rng = rand::rng();
    let filename: String = (0..name_len)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();
    Ok(filename)
}

pub async fn create_file<T: Into<String> + Send + Clone>(
    Extension(app_state): Extension<Arc<AppState>>,
    username: T,
    filename: Option<T>,
) -> Result<String, std::io::Error> {
    let data_dir = Path::new(&app_state.env.data_dir);
    let user_dir = data_dir.join(username.clone().into());

    std::fs::create_dir_all(&user_dir)?;

    let filename = if let Some(name) = filename {
        name.into()
    } else {
        generate_filename(64).await?
    };

    let root_file = user_dir.join(&filename);

    std::fs::File::create(root_file)?;

    Ok(filename)
}

pub async fn write_file<T: Into<String> + Send + Clone>(
    Extension(app_state): Extension<Arc<AppState>>,
    username: T,
    filename: T,
    contents: &Bytes,
) -> Result<(), std::io::Error> {
    let data_dir = Path::new(&app_state.env.data_dir);
    let user_dir = data_dir.join(username.clone().into());
    let file = user_dir.join(filename.into());

    let mut file = std::fs::File::open(file)?;
    file.write_all(contents)?;
    Ok(())
}
