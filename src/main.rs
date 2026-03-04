use clap::*;
use clap_num::maybe_hex;
use exhume_body::Body;
use exhume_filesystem::Filesystem;
use exhume_filesystem::detected_fs::{detect_filesystem, DetectedFs, KeyMaterial};
use exhume_filesystem::filesystem::DirectoryCommon;
use exhume_filesystem::filesystem::FileCommon;
use exhume_filesystem::folder_impl::FolderFS;
use log::{debug, error, info};
use serde_json::{Value, json};
use std::path::Path;

fn main() {
    let matches = Command::new("exhume_filesystem")
        .version(crate_version!())
        .author(crate_authors!())
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
                .required(false) // Not required for folders
                .help("The filesystem starts address (decimal or hex)."),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_parser(maybe_hex::<u64>)
                .required(false) // Not required for folders
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
            Arg::new("fvek")
                .long("fvek")
                .value_parser(value_parser!(String))
                .help("Full Volume Encryption Key (FVEK) for BitLocker, in hex format"),
        )
        .arg(
            Arg::new("enum")
                .short('e')
                .long("enum")
                .conflicts_with("dump")
                .conflicts_with("list")
                .conflicts_with("record")
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
            Arg::new("print")
                .long("print")
                .action(ArgAction::SetTrue)
                .requires("record")
                .help("If --record is specified, print the content of the record to STDOUT."),
        )

        .arg(
            Arg::new("metadata")
                .long("metadata")
                .action(ArgAction::SetTrue)
                .help("Print the filsystem metadata (JSON)."),
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

    // Check if path is a directory
    let path = Path::new(file_path);
    let is_directory = path.is_dir();

    let offset = matches.get_one::<u64>("offset");
    let size = matches.get_one::<u64>("size");

    // Validation for non-directory inputs
    if !is_directory
        && (offset.is_none() || size.is_none()) {
            // Need a way to enforce required args conditionally?
            // Clap doesn't support conditional requirements easily.
            // We just error out here.
            error!("Offset and Size arguments are required for disk images.");
            return;
        }

    let file_id = matches.get_one::<usize>("record").copied().unwrap_or(0);
    let list = matches.get_flag("list");
    let enumerate = matches.get_flag("enum");
    let metadata = matches.get_flag("metadata");
    let print = matches.get_flag("print");
    let dump = matches.get_flag("dump");
    let json_output = matches.get_flag("json");

    let mut keys = None;
    if let Some(fvek_hex) = matches.get_one::<String>("fvek") {
        if let Ok(fvek_bytes) = hex::decode(fvek_hex) {
            keys = Some(KeyMaterial {
                bitlocker_fvek: Some(fvek_bytes),
            });
        } else {
            error!("Provided FVEK is not a valid hex string.");
            return;
        }
    }

    let mut filesystem: DetectedFs<exhume_filesystem::detected_fs::ImageStream> = if is_directory {
        let fs = FolderFS::new(path.to_path_buf());
        DetectedFs::Folder(fs)
    } else {
        let offset_val = *offset.unwrap();
        let size_val = *size.unwrap();

        let body = Body::new(file_path.to_owned(), format);
        debug!("Created Body from '{}'", file_path);

        let partition_size = size_val * body.get_sector_size() as u64;

        match detect_filesystem(&body, offset_val, partition_size, keys) {
            Ok(fs) => fs,
            Err(e) => {
                error!("Could not detect the provided filesystem: {e:?}");
                return;
            }
        }
    };

    if metadata {
        if json_output {
            match serde_json::to_string_pretty(&filesystem.get_metadata().unwrap()) {
                Ok(json_str) => {
                    println!("{}", json_str)
                }
                Err(e) => error!("Error serializing inode {} to JSON: {}", file_id, e),
            }
        } else {
            println!("{}", &filesystem.get_metadata_pretty().unwrap());
        }
    }

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
        } else if json_output {
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

        if dump {
            filesystem.dump_to_fs(&file);
        }

        if print {
            match filesystem.read_file_prefix(&file, 8192) {
                Ok(prefix) => println!("Successfully read prefix of length {}", prefix.len()),
                Err(e) => println!("Error reading prefix: {}", e),
            }
        }
    }

    if enumerate {
        if json_output {
            let mut files = Vec::new();
            let collected = filesystem.walk_fs(&mut |event| match event {
                exhume_filesystem::filesystem::WalkEvent::File(f) => files.push(f),
                exhume_filesystem::filesystem::WalkEvent::Status(msg) => info!("{}", msg),
            });
            match collected {
                Ok(_) => {
                    println!("{}", serde_json::to_string_pretty(&files).unwrap());
                }
                Err(err) => {
                    error!("Failed JSON enumeration: {:?}", err);
                }
            }
        } else if let Err(err) = filesystem.walk_fs(&mut |event| match event {
            exhume_filesystem::filesystem::WalkEvent::File(file) => {
                if let Some(custom_display) = file.display {
                    println!("{}", custom_display);
                } else {
                    println!(
                        "[{}] - {} {} {} {} {} {}",
                        file.identifier,
                        file.permissions
                            .clone()
                            .unwrap_or_else(|| "??????????".to_string()),
                        exhume_apfs::fmt_apfs_ns_utc(
                            file.modified.unwrap_or(0) * 1_000_000_000
                        ),
                        file.owner.clone().unwrap_or_else(|| "-".to_string()),
                        file.group.clone().unwrap_or_else(|| "-".to_string()),
                        file.size,
                        file.absolute_path
                    );
                }
            }
            exhume_filesystem::filesystem::WalkEvent::Status(msg) => info!("{}", msg),
        }) {
            error!("Could not enumerate the files: {:?}", err);
        }
    }
}
