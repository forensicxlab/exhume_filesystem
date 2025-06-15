use clap::{Arg, ArgAction, Command, value_parser};
use clap_num::maybe_hex;
use exhume_body::Body;
use exhume_filesystem::Filesystem;
use exhume_filesystem::detected_fs::detect_filesystem;
use exhume_filesystem::filesystem::DirectoryCommon;
use exhume_filesystem::filesystem::FileCommon;
use log::{debug, error, info};
use serde_json::{Value, json};

fn main() {
    let matches = Command::new("exhume_filesystem")
        .version("0.2.3")
        .author("ForensicXlab")
        .about("Exhume in a standardized and normalized way files & directories from a given filesystem.")
        .arg(
            Arg::new("body")
                .short('b')
                .long("body")
                .value_parser(value_parser!(String))
                .required(true)
                .help("The path to the body to exhume."),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(value_parser!(String))
                .required(false)
                .help("The format of the file, either 'raw' or 'ewf'."),
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .long("offset")
                .value_parser(maybe_hex::<u64>)
                .required(true)
                .help("The filesystem starts address (decimal or hex)."),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_parser(maybe_hex::<u64>)
                .required(true)
                .help("The size of the filesystem in sectors (decimal or hex)."),
        )

        .arg(
            Arg::new("record")
                .short('r')
                .long("record")
                .value_parser(maybe_hex::<usize>)
                .help("Display the metadata about a specific file record using its record identifier."),
        )

        .arg(
            Arg::new("enum")
                .short('e')
                .long("enum")
                .conflicts_with("dump")
                .conflicts_with("list")
                .conflicts_with("record")
                .conflicts_with("json")
                .action(ArgAction::SetTrue)
                .help("Enumerate all file records"),
        )
        .arg(
            Arg::new("list")
                .long("list")
                .action(ArgAction::SetTrue)
                .requires("record")
                .help("If --record is specified and if it is a directory, list the entries inside."),
        )
        .arg(
            Arg::new("dump")
                .long("dump")
                .action(ArgAction::SetTrue)
                .requires("record")
                .help("If --record is specified, dump the content to a file named 'file_<N>.bin'."),
        )

        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Output the result in a JSON format."),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info")
                .help("Set the log verbosity level"),
        )
        .get_matches();

    // Initialize logger.
    let log_level_str = matches.get_one::<String>("log_level").unwrap();
    let level_filter = match log_level_str.as_str() {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    env_logger::Builder::new().filter_level(level_filter).init();

    let file_path = matches.get_one::<String>("body").unwrap();
    let auto = String::from("auto");
    let format = matches.get_one::<String>("format").unwrap_or(&auto);
    let offset = matches.get_one::<u64>("offset").unwrap();
    let size = matches.get_one::<u64>("size").unwrap();

    let file_id = matches.get_one::<usize>("record").copied().unwrap_or(0);
    let list = matches.get_flag("list");
    let enumerate = matches.get_flag("enum");
    let dump = matches.get_flag("dump");
    let json_output = matches.get_flag("json");

    let body = Body::new(file_path.to_owned(), format);
    debug!("Created Body from '{}'", file_path);

    let partition_size = *size * body.get_sector_size() as u64;

    let mut filesystem = match detect_filesystem(&body, *offset, partition_size) {
        Ok(fs) => fs,
        Err(e) => {
            error!("Could not detect the provided filesystem: {e:?}");
            return;
        }
    };

    if file_id > 0 {
        let file = match filesystem.get_file(file_id as u64) {
            Ok(file) => file,
            Err(err) => {
                error!("Could not fetch the requested file: {:?}", err);
                return;
            }
        };

        if list {
            if file.is_dir() {
                match filesystem.list_dir(&file) {
                    Ok(entries) => {
                        if json_output {
                            let arr: Vec<Value> = entries.iter().map(|de| de.to_json()).collect();
                            let dir_json = json!(arr);
                            println!("{}", serde_json::to_string_pretty(&dir_json).unwrap());
                        } else {
                            info!("Directory listing for file record {}:", file_id);
                            for entry in entries {
                                println!("[{}] - {}", entry.file_id(), entry.name());
                            }
                        }
                    }
                    Err(err) => {
                        error!(
                            "Failed to list directory for file record {}: {}",
                            file_id, err
                        );
                    }
                }
            } else {
                error!(
                    "Requested to list the directory entries for a file but {} is not a directory.",
                    file_id
                );
            }
        } else {
            if json_output {
                match serde_json::to_string_pretty(&file.to_json()) {
                    Ok(json_str) => {
                        info!("File record {} metadata:", file_id);
                        println!("{}", json_str)
                    }
                    Err(e) => error!("Error serializing inode {} to JSON: {}", file_id, e),
                }
            } else {
                println!("{}", file.to_string());
            }
        }

        if dump {
            filesystem.dump(&file);
        }
    }

    if enumerate {
        match filesystem.enumerate() {
            Ok(_) => {}
            Err(err) => {
                error!("Could not enumerate the files: {:?}", err);
                return;
            }
        }
    }
}
