#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustscope::run().await
}
