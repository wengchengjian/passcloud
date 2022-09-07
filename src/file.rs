use serde::de::DeserializeOwned;
use serde::Serialize;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn write_content<T>(file: &mut File, t: &T) -> Result<(), Box<dyn Error>>
where
    T: Serialize,
{
    let content = serde_json::to_string_pretty(t)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}
pub fn load_content<T>(path: &str, default: Option<T>) -> Result<T, Box<dyn Error>>
where
    T: Serialize + DeserializeOwned,
{
    let content_file_path = Path::new(path);
    if !content_file_path.exists() {
        // 创建默认配置文件
        let mut file = File::create(content_file_path)?;
        // 写入基本配置
        if let Some(t) = default {
            write_content(&mut file, &t)?;
        }
    };
    let content = fs::read_to_string(content_file_path)?;
    let res = serde_json::from_str::<T>(content.as_str())?;
    Ok(res)
}
