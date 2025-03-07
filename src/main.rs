use anyhow::Context;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

fn handle_connection(
    mut stream: TcpStream,
    key_pair: Arc<webutils::KeyPair>,
) -> anyhow::Result<()> {
    // EXCHANGE KEYS WITH CLIENT

    let client_public_key = webutils::exchange_keys(&key_pair.public_key, &mut stream)?;

    // CONFIRM KEYS WERE SUCCESSFULLY SWAPPED

    webutils::synchronize(&client_public_key, &key_pair.private_key, &mut stream)
        .with_context(|| "Failed to synchronize with client")?;

    // EXECUTE MAIN SERVER LOOP

    println!("SERVER-CLIENT SYNC SUCCEEDED");

    loop {
        webutils::send_sync_message(
            &client_public_key,
            &key_pair.private_key,
            &mut stream,
            b"HEARTBEAT",
        )
        .with_context(|| "Failed to synchronize heartbeat")?;
        println!(
            "HEARTBEAT SYNCHRONIZED [Time since epoch: {:.2?}]",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?
        );

        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

fn main() -> anyhow::Result<()> {
    // RETRIEVE SERVER INFORMATION FROM ENVIRONMENT VARIABLES

    let ip_addr = std::env::var("SERVER_IP").with_context(|| "Missing server IP address envvar")?;
    let ip_port = std::env::var("SERVER_PORT").with_context(|| "Missing server port envvar")?;

    // BIND THE SERVER TO THE GIVEN IP ADDRESS AND PORT

    let listener = TcpListener::bind(format!("{ip_addr}:{ip_port}"))
        .with_context(|| format!("Failed to bind to {ip_addr}:{ip_port}"))?;

    // GENERATE THE RSA KEY PAIR FOR MESSAGE ENCRYPTION

    let key_pair =
        Arc::new(webutils::generate_key_pair().with_context(|| "Failed to generate key pair")?);

    // LOOP THROUGH INCOMING CONNECTIONS

    for stream in listener.incoming() {
        // HANDLE THE STREAM IF IT WAS RECEIVED CORRECTLY, OR LOG THE ERRORS

        match stream {
            Ok(stream) => {
                // SPAWN A THREAD FOR EACH CONNECTION

                // Create a cloned key pair to safely pass to the thread
                let key_pair = key_pair.clone();

                std::thread::spawn(move || {
                    // HAND OFF CONNECTION HANDLING TO A NEW FUNCTION AND HANDLE ERROR LOGGING

                    match handle_connection(stream, key_pair) {
                        Ok(_) => {}
                        Err(e) => eprintln!("{e}"),
                    }
                });
            }
            Err(e) => eprintln!("{e}"),
        }
    }

    Ok(())
}
