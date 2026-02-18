use clap::*;
use clap_num::maybe_hex;
use exhume_body::Body;
use exhume_filesystem::File;
use exhume_filesystem::Filesystem;
use exhume_filesystem::detected_fs::{DetectedFs, detect_filesystem};
use exhume_filesystem::filesystem::DirectoryCommon;
use exhume_filesystem::filesystem::FileCommon;
use log::{debug, error, info};
use serde_json::{Value, json};
use std::collections::{HashSet, VecDeque};
use std::error::Error;

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
    let offset = matches.get_one::<u64>("offset").unwrap();
    let size = matches.get_one::<u64>("size").unwrap();

    let file_id = matches.get_one::<usize>("record").copied().unwrap_or(0);
    let list = matches.get_flag("list");
    let enumerate = matches.get_flag("enum");
    let metadata = matches.get_flag("metadata");
    let print = matches.get_flag("print");
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
            filesystem.dump_to_fs(&file);
        }

        if print {
            filesystem.dump_to_std(&file);
        }
    }

    if enumerate {
        if json_output {
            let collected = match &mut filesystem {
                DetectedFs::Apfs(fs) => fs.enumerate_all_files(),
                _ => enumerate_collect(&mut filesystem),
            };
            match collected {
                Ok(files) => {
                    println!("{}", serde_json::to_string_pretty(&files).unwrap());
                }
                Err(err) => {
                    error!("Failed JSON enumeration: {:?}", err);
                }
            }
        } else {
            if let Err(err) = filesystem.enumerate() {
                error!("Could not enumerate the files: {:?}", err);
            }
        }
    }
}

fn enumerate_collect<F: Filesystem>(fs: &mut F) -> Result<Vec<File>, Box<dyn Error>> {
    let mut out: Vec<File> = Vec::new();
    let mut visited = HashSet::<u64>::new();
    let mut queue = VecDeque::<(u64, String)>::new();

    let sep = fs.path_separator();
    let root_id = fs.get_root_file_id();
    let root_path = sep.clone();

    queue.push_back((root_id, root_path.clone()));

    while let Some((id, path)) = queue.pop_front() {
        if !visited.insert(id) {
            continue;
        }

        let file_rec = match fs.get_file(id) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let file_obj = fs.record_to_file(&file_rec, id, &path);
        out.push(file_obj.clone());

        if file_rec.is_dir() {
            let entries = match fs.list_dir(&file_rec) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for de in entries {
                let child_id = de.file_id();
                let name = de.name();
                let child_path = if path == sep {
                    format!("{}{}", sep, name)
                } else {
                    format!("{}{}{}", path, sep, name)
                };
                queue.push_back((child_id, child_path));
            }
        }
    }

    Ok(out)
}
