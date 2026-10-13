use exhume_filesystem::{Filesystem, folder_impl::FolderFS};
use std::{fs, io::Read};

#[test]
fn verified_handles_are_public_and_have_independent_file_positions() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("evidence.bin"), b"abcdef").unwrap();
    let mut filesystem = FolderFS::new(directory.path().to_path_buf());
    let root = filesystem.get_file(filesystem.get_root_file_id()).unwrap();
    let entry = filesystem.list_dir(&root).unwrap().remove(0);
    let file = filesystem.resolve_child(&root, &entry).unwrap();

    let mut first = filesystem.open_verified_regular(&file).unwrap();
    let mut second = filesystem.open_verified_regular(&file).unwrap();
    let mut bytes = [0; 2];
    first.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"ab");
    second.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"ab");
    first.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"cd");
    assert!(filesystem.open_verified_regular(&root).is_err());
}

#[test]
fn verified_handle_rejects_a_replaced_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("evidence.bin");
    fs::write(&path, b"original").unwrap();
    let mut filesystem = FolderFS::new(directory.path().to_path_buf());
    let root = filesystem.get_file(filesystem.get_root_file_id()).unwrap();
    let entry = filesystem.list_dir(&root).unwrap().remove(0);
    let file = filesystem.resolve_child(&root, &entry).unwrap();

    // Keep the original inode allocated so a replacement cannot reuse its ID.
    fs::rename(&path, directory.path().join("original.bin")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    assert!(filesystem.open_verified_regular(&file).is_err());
}
