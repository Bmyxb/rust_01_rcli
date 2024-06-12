use std::{path::PathBuf, time::Duration};

use super::verify_path;
use clap::Parser;
use enum_dispatch::enum_dispatch;

use crate::{process_jwt_sign, process_jwt_verify, CmdExector};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum JWTSubCommand {
    #[command(about = "Sign a JWT token")]
    Sign(JwtSignOpts),
    #[command(about = "Verify a JWT token")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(long)]
    pub sub: String,
    #[arg(long)]
    pub aud: String,
    #[arg(long, value_parser = humantime::parse_duration)]
    pub exp: Duration,
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(long)]
    pub token: String,
}

#[derive(Debug, Parser)]
pub struct JwtKeyGenerateOpts {
    #[arg(short, long, value_parser = verify_path)]
    pub output_path: PathBuf,
}

impl CmdExector for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let token = process_jwt_sign(self.sub, self.aud, self.exp)?;
        println!("{}", token);
        Ok(())
    }
}

impl CmdExector for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        match process_jwt_verify(self.token.as_str()) {
            Ok(v) => println!("{}", v),
            Err(e) => println!("{}", e),
        }
        Ok(())
    }
}