use crate::vfs::VaultMetadata;

pub fn handle_ls(metadata: &VaultMetadata) {
    println!("--- Volatile VFS File Allocation Table ---");
    if metadata.file_table.is_empty() {
        println!("Vault is empty.");
    } else {
        for file in &metadata.file_table {
            let sanitized_name: String = file.vfs_name
                .chars()
                .map(|c| {
                    if c.is_ascii_control() {
                        '?' 
                    } else {
                        c
                    }
                })
                .collect();

            println!("File: {:<20} Chunks: {}", sanitized_name, file.chunks.len());        }
    }
}