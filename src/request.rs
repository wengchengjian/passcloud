use crate::{Authorization, Passwords};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ReqCommand {
    Push {
        auth: Authorization,
        passwords: Passwords,
    },
    Pull {
        auth: Authorization,
    },

    Stop {
        auth: Authorization,
    },

    Register {
        auth: Authorization,
    },
}
