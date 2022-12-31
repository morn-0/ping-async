// examples/ping.rs

use std::io;
use std::net::IpAddr;

use async_ping::IcmpEchoRequestor;
use futures::{channel::oneshot, StreamExt};

use tokio::time;
use tokio_stream::wrappers::IntervalStream;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: ping <destination>");
        std::process::exit(1);
    }

    let destination = args[1].parse().unwrap();

    let interval = IntervalStream::new(time::interval(time::Duration::from_secs(1)));
    interval
        .take(4)
        .for_each(|_| async {
            let _ = ping(destination).await;
        })
        .await;
}

async fn ping(dest: IpAddr) -> io::Result<()> {
    let (tx, rx) = oneshot::channel();

    match IcmpEchoRequestor::new(tx, dest, None, None, None) {
        Ok(s) => match s.send() {
            Ok(_) => match rx.await {
                Ok(reply) => {
                    println!(
                        "Reply from {}: status = {:?}, time = {:?}",
                        reply.destination(),
                        reply.status(),
                        reply.round_trip_time()
                    );
                    Ok(())
                }
                Err(e) => {
                    eprintln!("Error in rx: {}", e);
                    Ok(())
                }
            },
            Err(e) => {
                eprintln!("Error in send: {}", e);
                Err(e)
            }
        },
        Err(e) => {
            eprintln!("Error in new: {}", e);
            Err(e)
        }
    }
}
