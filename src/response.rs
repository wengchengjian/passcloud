use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::Password;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum ResponseCode {
    Success,

    Failure,
}

pub type PullPasswords = HashMap<String, HashMap<String, Vec<Password>>>;


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerResponse<T> {
    pub code: ResponseCode,
    pub data: T,
    pub msg: String,
}
