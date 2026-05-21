fn main() {
    let dst = cmake::Config::new("../../")
        .define("UNICORN_ARCH", "arm")
        .define("UNICORN_BUILD_SHARED", "OFF")
        .define("UNICORN_STATIC_MSVCRT", "OFF")
        .cflag("-DFUZZWARE_FUZZING_STUBS")
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=unicorn");
    println!("cargo:rustc-link-lib=static=arm-softmmu");
    println!("cargo:rustc-link-lib=static=armeb-softmmu");
}
