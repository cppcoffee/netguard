use std::backtrace::Backtrace;
use std::panic::PanicInfo;

use log::error;

pub fn set_panic_hook() {
    std::panic::set_hook(Box::new(|panic| {
        log_panic(panic);
    }));
}

pub fn log_panic(panic: &PanicInfo) {
    let backtrace = Backtrace::force_capture();
    let backtrace_str = format!("{:?}", backtrace);

    eprintln!("{}", panic);
    eprintln!("{}", backtrace);

    if let Some(location) = panic.location() {
        error!(
            backtrace = &backtrace_str,
            "panic.file" = location.file(),
            // TODO: use u32
            "panic.line" = location.line(),
            "panic.column" = location.column();
            "{}",
            panic,
        );
    } else {
        error!(backtrace = backtrace_str; "{}", panic);
    }
}
