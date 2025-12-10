// build.rs - GPU detection and CUDA build support
// This script detects available GPU hardware and enables appropriate feature flags

fn main() {
    // Check if CUDA is available
    #[cfg(target_os = "windows")]
    {
        let cuda_path = std::env::var("CUDA_PATH").ok();

        if cuda_path.is_some() {
            println!("cargo:rustc-cfg=feature=\"cuda_available\"");
            println!("cargo:warning=CUDA toolkit detected - GPU acceleration available");
        } else {
            println!("cargo:warning=CUDA toolkit not found - building with CPU-only support");
            println!("cargo:warning=Install NVIDIA CUDA Toolkit to enable GPU acceleration");
        }
    }

    #[cfg(target_os = "linux")]
    {
        let cuda_path = std::env::var("CUDA_PATH").ok();

        if cuda_path.is_some() {
            println!("cargo:rustc-cfg=feature=\"cuda_available\"");
            println!("cargo:warning=CUDA toolkit detected - GPU acceleration available");
        } else {
            println!("cargo:warning=CUDA toolkit not found - building with CPU-only support");
        }
    }

    // Emit cargo instructions for conditional compilation
    println!("cargo:rustc-env=CELEREUM_BUILD_TIME={}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());
}
