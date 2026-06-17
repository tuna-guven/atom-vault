use gtk4 as gtk;
use gtk::prelude::*;
use gtk::{
    Application, ApplicationWindow, Box as GtkBox, Button, FileChooserAction,
    FileChooserNative, Label, ListBox, Orientation, PasswordEntry,
    ResponseType, ScrolledWindow, Entry, GestureClick, Window,
};
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zeroize::Zeroizing;

// Shared vault session state
pub struct VaultSession {
    pub file: File,
    pub metadata: crate::vfs::VaultMetadata,
    pub unlocked_vault: crate::crypto::UnlockedVault,
    pub current_offset: u64,
}

pub fn run_gui() -> Result<(), Box<dyn std::error::Error>> {
    let app = Application::builder()
        .application_id("org.atom.Vault")
        .build();

    app.connect_activate(build_login_ui);
    app.run();

    Ok(())
}

fn build_login_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("Atom Vault - Login")
        .default_width(450)
        .default_height(300)
        .build();

    let vbox = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(16)
        .margin_top(32)
        .margin_bottom(32)
        .margin_start(32)
        .margin_end(32)
        .build();

    let title = Label::builder()
        .label("<span size='xx-large' weight='bold'>Atom Vault</span>")
        .use_markup(true)
        .build();

    let selected_path: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));

    let select_btn = Button::builder().label("Select .aegis Vault").build();
    let pass_entry = PasswordEntry::builder().placeholder_text("Master Password").build();
    let unlock_btn = Button::builder().label("Unlock Vault").css_classes(["suggested-action"]).build();
    let status_label = Label::builder().label("Please select a vault to begin.").build();

    // File selection
    let path_clone = Rc::clone(&selected_path);
    let btn_clone = select_btn.clone();
    let status_clone = status_label.clone();
    let window_weak = window.downgrade();

    select_btn.connect_clicked(move |_| {
        let chooser = FileChooserNative::new(
            Some("Open .aegis Vault"),
            window_weak.upgrade().as_ref().map(|w| w.upcast_ref::<gtk::Window>()),
            FileChooserAction::Open,
            Some("_Open"),
            Some("_Cancel"),
        );

        let path_alloc = Rc::clone(&path_clone);
        let btn_alloc = btn_clone.clone();
        let status_alloc = status_clone.clone();

        chooser.connect_response(move |dialog, response| {
            if response == ResponseType::Accept {
                if let Some(file) = dialog.file() {
                    if let Some(path) = file.path() {
                        btn_alloc.set_label(&format!("Selected: {:?}", path.file_name().unwrap_or_default()));
                        *path_alloc.borrow_mut() = Some(path);
                        status_alloc.set_label("Vault selected. Enter master password.");
                    }
                }
            }
            dialog.destroy();
        });

        chooser.show();
    });

    // Vault unlock
    let path_clone2 = Rc::clone(&selected_path);
    let status_clone2 = status_label.clone();
    let pass_entry_clone = pass_entry.clone();
    let window_clone = window.clone();
    
    unlock_btn.connect_clicked(move |_| {
        let path_opt = path_clone2.borrow();
        let secure_password = Zeroizing::new(pass_entry_clone.text().to_string());
        
        pass_entry_clone.set_text(""); // Clear password field

        if let Some(path) = &*path_opt {
            if secure_password.is_empty() {
                status_clone2.set_label("Error: Password cannot be empty!");
                return;
            }

            status_clone2.set_label("Decrypting...");

            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(mut file) => {
                    match crate::storage::load_vault_metadata(&mut file, &secure_password) {
                        Ok((metadata, unlocked_vault, current_offset)) => {
                            let session = Rc::new(RefCell::new(VaultSession {
                                file,
                                metadata,
                                unlocked_vault,
                                current_offset,
                            }));

                            build_vault_explorer(&window_clone, session);
                        }
                        Err(_) => {
                            status_clone2.set_label("Error: Invalid password or corrupted vault.");
                        }
                    }
                }
                Err(e) => {
                    status_clone2.set_label(&format!("Error: Could not open file: {}", e));
                }
            }
        } else {
            status_clone2.set_label("Error: Please select a vault first!");
        }
    });

    vbox.append(&title);
    vbox.append(&select_btn);
    vbox.append(&pass_entry);
    vbox.append(&unlock_btn);
    vbox.append(&status_label);

    window.set_child(Some(&vbox));
    window.present();
}

// --- SECURE VAULT EXPLORER VIEW ---
fn build_vault_explorer(window: &ApplicationWindow, session: Rc<RefCell<VaultSession>>) {
    window.set_title(Some("Atom Vault - Secure Explorer"));
    window.set_default_width(650);
    window.set_default_height(500);

    let vbox = GtkBox::builder().orientation(Orientation::Vertical).spacing(8).build();

    let toolbar = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(12).margin_bottom(12).margin_start(12).margin_end(12)
        .build();

    let title = Label::builder()
        .label("<span size='large' weight='bold'>Encrypted File System</span>")
        .use_markup(true).hexpand(true).xalign(0.0).build();

    let import_btn = Button::builder().label("Import File").css_classes(["suggested-action"]).build();
    let export_btn = Button::builder().label("Export File").build();
    let lock_btn = Button::builder().label("Lock & Exit").css_classes(["destructive-action"]).build();

    toolbar.append(&title);
    toolbar.append(&import_btn);
    toolbar.append(&export_btn);
    toolbar.append(&lock_btn);

    let action_status_label = Label::builder().use_markup(true).margin_start(12).margin_end(12).xalign(0.0).build();

    let list_box = ListBox::builder().selection_mode(gtk::SelectionMode::Single).margin_start(12).margin_end(12).build();
    let scrolled_window = ScrolledWindow::builder().vexpand(true).child(&list_box).build();

    vbox.append(&toolbar);
    vbox.append(&action_status_label);
    vbox.append(&scrolled_window);

    // Initial render
    refresh_file_list(&list_box, Rc::clone(&session), window.clone(), action_status_label.clone());

    // --- EVENT HANDLER: Import Action ---
    let import_session = Rc::clone(&session);
    let import_window_weak = window.downgrade();
    let import_list_box = list_box.clone();
    let import_dialog_window = window.clone();
    let import_status = action_status_label.clone();

    import_btn.connect_clicked(move |_| {
        let chooser = FileChooserNative::new(
            Some("Select File to Encrypt & Import"),
            import_window_weak.upgrade().as_ref().map(|w| w.upcast_ref::<gtk::Window>()),
            FileChooserAction::Open,
            Some("_Import"), Some("_Cancel"),
        );

        let session_alloc = Rc::clone(&import_session);
        let list_box_alloc = import_list_box.clone();
        let dialog_window_alloc = import_dialog_window.clone();
        let status_alloc = import_status.clone();

        chooser.connect_response(move |dialog, response| {
            if response == ResponseType::Accept {
                if let Some(file) = dialog.file() {
                    if let Some(path) = file.path() {
                        let from_disk = path.to_string_lossy().to_string();
                        let vfs_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                        
                        let mut sess = session_alloc.borrow_mut();
                        let VaultSession { ref mut file, ref mut metadata, ref unlocked_vault, ref mut current_offset } = *sess;

                        if let Err(e) = crate::commands::import::handle_import(
                            from_disk, vfs_name.clone(), file, metadata, unlocked_vault, current_offset
                        ) {
                            eprintln!("[GUI Error] {}", e);
                            status_alloc.set_label(&format!("<span foreground='red'>Import Error: {}</span>", e));
                        } else {
                            let _ = file.sync_all();
                            drop(sess); 
                            
                            refresh_file_list(&list_box_alloc, Rc::clone(&session_alloc), dialog_window_alloc.clone(), status_alloc.clone());
                            status_alloc.set_label(&format!("<span foreground='green'>Success: {} imported.</span>", vfs_name));
                        }
                    }
                }
            }
            dialog.destroy();
        });
        chooser.show();
    });

    // --- EVENT HANDLER: Direct Export Action (Atom Staging) ---
    let export_session = Rc::clone(&session);
    let export_list_box = list_box.clone();
    let export_status = action_status_label.clone();

    export_btn.connect_clicked(move |_| {
        let session_alloc = Rc::clone(&export_session);

        if let Some(row) = export_list_box.selected_row() {
            let index = row.index() as usize;
            let raw_vfs_name = { session_alloc.borrow().metadata.file_table[index].vfs_name.clone() };

            // Anti-Traversal Shield
            let safe_vfs_name = Path::new(&raw_vfs_name).file_name().unwrap_or_default().to_string_lossy().to_string();
            if safe_vfs_name.is_empty() { return; }

            let staging_dir = PathBuf::from("atom_staging");
            let _ = std::fs::create_dir_all(&staging_dir);
            let target_path_str = staging_dir.join(&safe_vfs_name).to_string_lossy().to_string();

            let mut sess = session_alloc.borrow_mut();
            let VaultSession { ref mut file, ref metadata, ref unlocked_vault, .. } = *sess;

            match crate::commands::export::handle_export(raw_vfs_name, target_path_str, metadata, file, unlocked_vault) {
                Ok(_) => export_status.set_label(&format!("<span foreground='green'>Success: Extracted to atom_staging/{}</span>", safe_vfs_name)),
                Err(e) => export_status.set_label(&format!("<span foreground='red'>Export failed: {}</span>", e)),
            }
        } else {
            export_status.set_label("<span foreground='orange'>Warning: Please select a file from the list first.</span>");
        }
    });

    // --- EVENT HANDLER: Lock and Exit ---
    let lock_window = window.clone();
    lock_btn.connect_clicked(move |_| { lock_window.close(); });

    window.set_child(Some(&vbox));
}

// --- UI HELPER: Dynamic List Renderer (WITH RENAME, OPEN & DELETE HOOKS) ---
fn refresh_file_list(
    list_box: &ListBox, 
    session: Rc<RefCell<VaultSession>>, 
    window: ApplicationWindow, 
    status_label: Label
) {
    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }

    let metadata = &session.borrow().metadata;

    if metadata.file_table.is_empty() {
        let empty_label = Label::builder().label("Vault is empty. Click 'Import File' to add.").margin_top(20).build();
        list_box.append(&empty_label);
        return;
    }

    for file_index in &metadata.file_table {
        let row_box = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(8)
            .margin_top(6).margin_bottom(6).margin_start(12).margin_end(12)
            .build();

        let row_label = Label::builder()
            .label(&format!("📄 {}", file_index.vfs_name))
            .xalign(0.0)
            .hexpand(true) 
            .build();

        let open_btn = Button::builder().label("Open").css_classes(["flat"]).build();
        let delete_btn = Button::builder().label("Delete").css_classes(["destructive-action"]).build();

        // --- 1. OPEN ACTION (Lock-Free Async Sandbox Hook) ---
        let session_open = Rc::clone(&session);
        let status_open = status_label.clone();
        let vfs_name_open = file_index.vfs_name.clone();

        open_btn.connect_clicked(move |_| {
            status_open.set_label(&format!("Opening {} securely in Sandbox...", vfs_name_open));
            
            let mut sess = session_open.borrow_mut();
            let VaultSession { ref mut file, ref metadata, ref unlocked_vault, .. } = *sess;

            if let Some(target_file_index) = metadata.file_table.iter().find(|f| f.vfs_name == vfs_name_open) {
                
                // Thread-Safe ve Lock-Free Bayrak Yaratımı
                let done_flag = Arc::new(AtomicBool::new(false));
                let done_flag_thread = Arc::clone(&done_flag);
                
                if let Err(e) = crate::commands::view::execute(
                    file,
                    target_file_index,
                    unlocked_vault,
                    move || {
                        // İşlem bittiğinde arka plandan sinyali çak
                        done_flag_thread.store(true, Ordering::SeqCst);
                    }
                ) {
                    eprintln!("[GUI Error] View failed: {}", e);
                    status_open.set_label(&format!("<span foreground='red'>Open failed: {}</span>", e));
                } else {
                    // Ana arayüz donmadan 100ms'de bir bayrağı kontrol et
                    let status_open_async = status_open.clone();
                    let vfs_name_open_clone = vfs_name_open.clone();
                    
                    gtk::glib::timeout_add_local(
                        std::time::Duration::from_millis(100), 
                        move || {
                            if done_flag.load(Ordering::SeqCst) {
                                status_open_async.set_label(&format!("<span foreground='green'>Closed securely: {}</span>", vfs_name_open_clone));
                                gtk::glib::ControlFlow::Break
                            } else {
                                gtk::glib::ControlFlow::Continue
                            }
                        }
                    );
                }
            } else {
                status_open.set_label("<span foreground='red'>Error: File index not found!</span>");
            }
        });

        // --- 2. RENAME ACTION (Double Click Gesture) ---
        let gesture = GestureClick::new();
        gesture.set_button(1); 
        
        let session_rename = Rc::clone(&session);
        let window_clone = window.clone();
        let list_box_clone = list_box.clone();
        let status_rename = status_label.clone();
        let old_name = file_index.vfs_name.clone();

        gesture.connect_pressed(move |_, n_press, _, _| {
            if n_press == 2 {
                let dialog = Window::builder()
                    .transient_for(&window_clone)
                    .modal(true)
                    .title("Rename File")
                    .default_width(300)
                    .destroy_with_parent(true)
                    .build();

                let dialog_vbox = GtkBox::builder().orientation(Orientation::Vertical).spacing(12).margin_top(16).margin_bottom(16).margin_start(16).margin_end(16).build();
                let entry = Entry::builder().text(&old_name).build();
                let save_btn = Button::builder().label("Save New Name").css_classes(["suggested-action"]).build();

                dialog_vbox.append(&Label::builder().label("Enter new file name:").xalign(0.0).build());
                dialog_vbox.append(&entry);
                dialog_vbox.append(&save_btn);
                dialog.set_child(Some(&dialog_vbox));

                let dialog_clone = dialog.clone();
                let session_save = Rc::clone(&session_rename);
                let old_name_save = old_name.clone();
                let status_save = status_rename.clone();
                let list_box_save = list_box_clone.clone();
                let window_save = window_clone.clone();

                save_btn.connect_clicked(move |_| {
                    let new_name = entry.text().to_string();
                    
                    if new_name.is_empty() || new_name.contains('/') || new_name.contains('\\') || new_name.contains('\0') {
                        status_save.set_label("<span foreground='red'>Rename Error: Invalid characters.</span>");
                        dialog_clone.close();
                        return;
                    }

                    let mut sess = session_save.borrow_mut();
                    
                    if sess.metadata.file_table.iter().any(|f| f.vfs_name == new_name) {
                        status_save.set_label("<span foreground='red'>Rename Error: Name already exists.</span>");
                        dialog_clone.close();
                        return;
                    }

                    if let Some(file_idx) = sess.metadata.file_table.iter_mut().find(|f| f.vfs_name == old_name_save) {
                        file_idx.vfs_name = new_name.clone();
                    }

                    let _ = sess.file.sync_all(); 

                    status_save.set_label(&format!("<span foreground='green'>Renamed to: {}</span>", new_name));
                    dialog_clone.close();
                    
                    drop(sess);
                    refresh_file_list(&list_box_save, Rc::clone(&session_save), window_save.clone(), status_save.clone());
                });

                dialog.present();
            }
        });

        // --- 3. SECURE DELETE ACTION ---
        let session_delete = Rc::clone(&session);
        let status_delete = status_label.clone();
        let list_box_delete = list_box.clone();
        let window_delete = window.clone();
        let vfs_name_delete = file_index.vfs_name.clone();

        delete_btn.connect_clicked(move |_| {
            let mut sess = session_delete.borrow_mut();
            let VaultSession { ref mut file, ref mut metadata, ref unlocked_vault, ref mut current_offset } = *sess;

            match crate::commands::rm::handle_rm( 
                vfs_name_delete.clone(),
                metadata,
                file,
                unlocked_vault,
                current_offset,
            ) {
                Ok(_) => {
                    status_delete.set_label(&format!("<span foreground='green'>Permanently Shredded: {}</span>", vfs_name_delete));
                    drop(sess); 
                    refresh_file_list(&list_box_delete, Rc::clone(&session_delete), window_delete.clone(), status_delete.clone());
                }
                Err(e) => {
                    eprintln!("[GUI Error] Delete failed: {}", e);
                    status_delete.set_label(&format!("<span foreground='red'>Delete failed: {}</span>", e));
                }
            }
        });

        row_box.add_controller(gesture);
        row_box.append(&row_label);
        row_box.append(&open_btn);
        row_box.append(&delete_btn);
        
        list_box.append(&row_box);
    }
}