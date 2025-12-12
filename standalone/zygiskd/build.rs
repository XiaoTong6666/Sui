// standalone/zygiskd/build.rs

fn main() {
    // 这些值是 Rust 代码在编译时需要的，我们在这里直接定义
    println!("cargo:rustc-env=MIN_APATCH_VERSION=10000");
    println!("cargo:rustc-env=MIN_KSU_VERSION=10940");
    println!("cargo:rustc-env=MAX_KSU_VERSION=20000");
    println!("cargo:rustc-env=MIN_MAGISK_VERSION=26100");

    // ZKSU_VERSION 比较特殊，我们可以从 Gradle 传进来，也可以在这里硬编码
    // 为了保持和 Gradle 的版本同步，我们继续让 Gradle 传
    // 所以，保留 ZKSU_VERSION 在 Gradle 的 environment 设置里
    match std::env::var("ZKSU_VERSION") {
        Ok(v) => println!("cargo:rustc-env=ZKSU_VERSION={}", v),
        Err(_) => println!("cargo:rustc-env=ZKSU_VERSION=unknown"), // 提供一个默认值
    }
}