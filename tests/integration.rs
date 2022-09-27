#[cfg(test)]
mod integration {
    use std::{
        io::Write,
        process::{Command, Stdio}, str::FromStr,
    };

    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use tempfile::tempdir;
    use tonic_lnd::rpc::{ConnectPeerRequest, LightningAddress};

    #[tokio::test]
    async fn test() {
        let localhost = vec!["localhost".to_string()];
        let cert = rcgen::generate_simple_self_signed(localhost).unwrap();
        let ssl_dir = format!("{}/tests/compose/nginx/ssl", env!("CARGO_MANIFEST_DIR"));
        std::fs::write(format!("{}/localhost-key.pem", ssl_dir), cert.serialize_private_key_pem()).expect("unable to write file");
        std::fs::write(format!("{}/localhost.pem", ssl_dir), cert.serialize_pem().unwrap()).expect("unable to write file");
        let compose_dir = format!("{}/tests/compose", env!("CARGO_MANIFEST_DIR"));

        // name _fixture so it doesn't drop until the end of the block
        let _fixture = Fixture::new(compose_dir);

        std::thread::sleep(std::time::Duration::from_secs(2));

        // sanity check
        let bitcoin_rpc = Client::new(
            "http://localhost:43782",
            Auth::UserPass("ceiwHEbqWI83".to_string(), "DwubwWsoo3".to_string()),
        )
        .unwrap();
        assert!(&bitcoin_rpc.get_best_block_hash().is_ok());

        println!("Fail test until integration is complete");
        assert!(false);
    }

    struct Fixture {
        compose_dir: String,
    }

    impl Fixture {
        fn new(compose_dir: String) -> Self {
            println!("Running docker-compose from {}", compose_dir);
            Command::new("docker-compose")
            .arg("--project-directory")
            .arg(&compose_dir)
            .arg("up")
            .arg("-d")
            .output()
            .expect("failed to docker-compose ... up");

            Fixture {
                compose_dir,
            }
        }
    }

    impl Drop for Fixture {
        /// This runs on panic to clean up the test
        fn drop(&mut self) {
            println!("Running `docker-compose down -v` to clean up");
            Command::new("docker-compose")
            .arg("--project-directory")
            .arg(self.compose_dir.as_str())
            .arg("down")
            .output()
            .expect("failed to docker-compose ... down");
        }
    }
}
