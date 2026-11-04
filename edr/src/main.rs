use std::io;

use libc::{CLONE_NEWPID, FSOPEN_CLOEXEC, RB_POWER_OFF, SYS_fsconfig, SYS_fsopen, fchdir, fsconfig_command, reboot, syscall, unshare};

fn main() {
    println!("Hello, world!");
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);
    unsafe { setup() };
    unsafe { unshare(CLONE_NEWPID) };
    unsafe { reboot(RB_POWER_OFF) };
}
unsafe fn setup() {
    unsafe {
        syscall(SYS_fsopen, c"tmpfs".as_ptr(), FSOPEN_CLOEXEC);
        syscall(SYS_fsconfig,
    }
}
