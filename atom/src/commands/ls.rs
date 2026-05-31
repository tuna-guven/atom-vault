use crate::vfs::VaultMetadata;

pub fn handle_ls(metadata: &VaultMetadata) {
    println!("--- Volatile VFS File Allocation Table ---");
    if metadata.file_table.is_empty() {
        println!("Vault is empty.");
    } else {
        for file in &metadata.file_table {
            println!("File: {:<20} Chunks: {}", file.vfs_name, file.chunks.len());
        }
    }
}