use argh::FromArgs;

#[derive(FromArgs)]
#[argh(description = "A simple Hello World CLI application.")]
struct Args {
    #[argh(option, description = "name to greet")]
    name: String,
}

fn main() {
    let args: Args = argh::from_env();
    println!("Hello, {}!", args.name);
}