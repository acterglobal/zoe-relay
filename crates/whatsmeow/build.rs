use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=whatsmeow.go");
    println!("cargo:rerun-if-changed=go.mod");
    println!("cargo:rerun-if-changed=go.sum");

    // Only build Go library when using real FFI
    if env::var("CARGO_FEATURE_E2E_REAL_FFI").is_ok() || cfg!(not(test)) {
        setup_ffi();
    }
}

fn setup_ffi() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let static_lib_path = PathBuf::from(&manifest_dir).join("libwhatsmeow.a");
    let shared_lib_path = PathBuf::from(&manifest_dir).join("libwhatsmeow.so");
    let header_path = PathBuf::from(&manifest_dir).join("libwhatsmeow.h");

    // Prefer static library, fall back to shared
    let (_lib_path, link_type) = if static_lib_path.exists() {
        (static_lib_path, "static")
    } else if shared_lib_path.exists() {
        (shared_lib_path, "dylib")
    } else {
        println!("cargo:warning=Go library not found. Run one of:");
        println!(
            "cargo:warning=  Static: go build -buildmode=c-archive -o libwhatsmeow.a whatsmeow.go"
        );
        println!(
            "cargo:warning=  Shared: go build -buildmode=c-shared -o libwhatsmeow.so whatsmeow.go"
        );
        return;
    };

    // Check if header exists
    if !header_path.exists() {
        println!(
            "cargo:warning=Header file not found: {}",
            header_path.display()
        );
        return;
    }

    // Tell Cargo to link the library
    println!("cargo:rustc-link-search=native={manifest_dir}");
    println!("cargo:rustc-link-lib={}=whatsmeow", link_type);

    // For static linking, we need to link Go runtime dependencies
    if link_type == "static" {
        println!("cargo:rustc-link-lib=static=pthread");
        println!("cargo:rustc-link-lib=static=dl");
        println!("cargo:rustc-link-lib=static=m");
        // Link libgcc and other Go runtime dependencies
        println!("cargo:rustc-link-lib=dylib=gcc_s");
    }

    // Link system libraries
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-link-lib=dylib=pthread");
            println!("cargo:rustc-link-lib=dylib=dl");
            println!("cargo:rustc-link-lib=dylib=m");
        }
        "macos" => {
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-link-lib=framework=Security");
        }
        "windows" => {
            println!("cargo:rustc-link-lib=dylib=ws2_32");
            println!("cargo:rustc-link-lib=dylib=userenv");
        }
        _ => {}
    }

    // Generate bindings using bindgen with proper filtering
    let bindings = bindgen::Builder::default()
        .header(header_path.to_str().unwrap())
        // Only include our Go functions, not system headers
        .allowlist_function("whatsmeow_.*")
        .allowlist_function("go_free")
        .allowlist_type("GoUintptr")
        .allowlist_type("GoSlice")
        .allowlist_type("GoString")
        // Exclude problematic system constants and types
        .blocklist_item("_.*")
        .blocklist_item("__.*")
        .blocklist_item("IPPORT_.*")
        .blocklist_item("FP_.*")
        // Use core/std types where possible
        .use_core()
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
