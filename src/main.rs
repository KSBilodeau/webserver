use anyhow::bail;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

fn handle_connection(
    mut stream: TcpStream,
    key_pair: Arc<webutils::KeyPair>,
) -> anyhow::Result<()> {
    // EXCHANGE KEYS WITH CLIENT

    let client_public_key = webutils::exchange_keys(&key_pair.public_key, &mut stream)?;

    // CONFIRM KEYS WERE SUCCESSFULLY SWAPPED

    let ack = webutils::send_message(
        &client_public_key,
        &key_pair.private_key,
        &mut stream,
        b"ACK",
    )?;

    if ack != "ACK" {
        bail!("ACKNOWLEDGEMENT FAILED")
    }

    // EXECUTE MAIN SERVER LOOP

    println!("ACKNOWLEDGEMENT SUCCEEDED");

    loop {
        std::hint::spin_loop();
    }
}

fn main() -> anyhow::Result<()> {
    // RETRIEVE SERVER INFORMATION FROM ENVIRONMENT VARIABLES

    let Ok(ip_addr) = std::env::var("SERVER_IP") else {
        bail!("Missing server IP address envvar")
    };

    let Ok(ip_port) = std::env::var("SERVER_PORT") else {
        bail!("Missing server port envvar")
    };

    // BIND THE SERVER TO THE GIVEN IP ADDRESS AND PORT

    let Ok(listener) = TcpListener::bind(format!("{ip_addr}:{ip_port}")) else {
        bail!("Failed to bind to {ip_addr}:{ip_port}")
    };

    // GENERATE THE RSA KEY PAIR FOR MESSAGE ENCRYPTION

    let key_pair = Arc::new(webutils::generate_key_pair()?);

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
