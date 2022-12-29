// examples/ping.rs

use futures::channel::oneshot;
use ping_rs::IcmpEchoSender;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: ping <destination>");
        std::process::exit(1);
    }

    let destination = args[1].parse().unwrap();

    let (tx, rx) = oneshot::channel();

    match IcmpEchoSender::new(tx, destination, None, None, None) {
        Ok(s) => match s.send() {
            Ok(_) => {
                if let Ok(reply) = rx.await {
                    println!(
                        "Reply from {}: status = {:?}, time = {:?}",
                        reply.destination(),
                        reply.status(),
                        reply.round_trip_time()
                    );
                }
            }
            Err(e) => {
                eprintln!("Error in send: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Error in new: {}", e);
            std::process::exit(1);
        }
    }
}
