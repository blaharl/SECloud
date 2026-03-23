//🐱

use crate::{encryption::AlgoInfo, error::ErrorMessage};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
enum FileType {
    Folder,
    File,
}

#[derive(Clone, Serialize, Deserialize)]
struct File {
    hashed_name: String,
    file_type: FileType,
    algo_info: AlgoInfo,
    path: PathBuf,
}

impl File {
    fn new<T>(hashed_name: T, file_type: FileType, algo_info: AlgoInfo, path: PathBuf) -> Self
    where
        T: Into<String>,
    {
        Self {
            hashed_name: hashed_name.into(),
            file_type,
            algo_info,
            path,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Folder {
    files: HashMap<String, File>,
}

impl Folder {
    fn new<T>(hashed_name: T, algo_info: AlgoInfo, path: PathBuf, parent: Option<File>) -> Self
    where
        T: Into<String>,
    {
        let mut files = HashMap::new();
        if let Some(parent) = parent {
            files.insert("..".to_string(), parent);
        }
        let curr = File::new(hashed_name, FileType::Folder, algo_info, path);
        files.insert(".".to_string(), curr);
        Self { files }
    }

    /// adds metadata of the added file to current folder,
    /// returns folder info if type of the added file is folder
    fn add_file<T>(
        &mut self,
        name: T,
        hashed_name: T,
        file_type: FileType,
        algo_info: AlgoInfo,
    ) -> Result<Option<Folder>, ErrorMessage>
    where
        T: Into<String> + Copy,
    {
        let mut new_file_path = self.curr_dir()?.path.clone();
        new_file_path.push(name.into());

        let new_file = File::new(
            hashed_name,
            file_type,
            algo_info.clone(),
            new_file_path.clone(),
        );
        self.files.insert(name.into(), new_file);

        if file_type == FileType::Folder {
            let new_folder = Folder::new(
                hashed_name,
                algo_info,
                new_file_path,
                Some(self.curr_dir()?.clone()),
            );
            Ok(Some(new_folder))
        } else {
            Ok(None)
        }
    }

    fn curr_dir(&self) -> Result<&File, ErrorMessage> {
        self.files.get(".").ok_or(ErrorMessage::IOError)
    }
    /// returns Result<(ciphertext, nonce)>
    fn encrypt(&self) -> Result<(Vec<u8>, Vec<u8>), ErrorMessage> {
        let algo_info = &self.curr_dir()?.algo_info;
        let serialized = serde_json::to_vec(&self).map_err(|_| ErrorMessage::EncryptionError)?;
        crate::encryption::encrypt(&serialized, algo_info)
    }

    fn decrypt(ciphertext: &[u8], algo_info: &AlgoInfo) -> Result<Self, ErrorMessage> {
        let serialized = crate::encryption::decrypt(ciphertext, algo_info)?;
        let folder: Self =
            serde_json::from_slice(&serialized).map_err(|_| ErrorMessage::DecryptionError)?;
        Ok(folder)
    }
}
