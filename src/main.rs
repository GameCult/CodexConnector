use std::path::PathBuf;

fn main() {
    let mut args = std::env::args_os().skip(1);
    let config = match (args.next(), args.next(), args.next()) {
        (Some(flag), Some(path), None) if flag == "--config" => PathBuf::from(path),
        _ => {
            eprintln!("usage: codex-connector --config PATH.cc");
            std::process::exit(2);
        }
    };
    if let Err(error) = codex_connector::serve(&config) {
        eprintln!("codex-connector stopped: {error}");
        std::process::exit(1);
    }
}
