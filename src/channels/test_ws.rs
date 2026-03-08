use tokio_tungstenite::connect_async;
use url::Url;
use futures_util::StreamExt;

#[tokio::main]
async fn main() {
    let url = Url::parse("ws://127.0.0.1:8080/v1/receive/+15551234567").unwrap();
    match connect_async(url).await {
        Ok((mut stream, _)) => {
            println!("Connected!");
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}
