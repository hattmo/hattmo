use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, OwnedFd},
};

use libc::{RB_POWER_OFF, fchdir, mkdirat, reboot};

use crate::fsopen::{FsConfig, MountAttrs};

fn main() {
    println!("Hello, world!");
    let mut buf = String::new();
    unsafe { setup().unwrap() };

    let args = std::env::args().collect::<Vec<_>>().join("\n");
    println!("{args}");

    let vars = std::env::vars()
        .map(|(k, v)| format!("{k} = {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    println!("{vars}");

    let _ = io::stdin().read_line(&mut buf);
    unsafe { reboot(RB_POWER_OFF) };
}
unsafe fn setup() -> Result<(), &'static str> {
    let mut fs = fsopen::FS::new("tmpfs")?;
    fs.configure([FsConfig::flag("rw")?])?;
    let newrootfd = fs.create([])?;

    let procfs = fsopen::FS::new("proc")?.create([MountAttrs::NoSuid])?;

    let oldrootfd: OwnedFd = File::open("/").unwrap().into();

    unsafe {
        fchdir(newrootfd.as_raw_fd());
        mkdirat(newrootfd.as_raw_fd(), c"/proc/".as_ptr(), 0700)
            .ne(&-1)
            .ok_or("failed to mkdir")?;

        Ok(())
    }
}

mod fsopen {
    use std::{
        ffi::CString,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
    };

    use libc::{
        FSCONFIG_CMD_CREATE, FSCONFIG_SET_FLAG, FSMOUNT_CLOEXEC, FSOPEN_CLOEXEC, MOUNT_ATTR_NOSUID,
        SYS_fsconfig, SYS_fsmount, SYS_fsopen, syscall,
    };

    const NULL: *const isize = std::ptr::null::<isize>();

    pub struct FS {
        fsfd: OwnedFd,
    }

    pub struct FsConfig {
        ty: FsConfigType,
    }

    enum FsConfigType {
        SetFlag(CString),
    }

    pub enum MountAttrs {
        NoSuid,
    }

    impl MountAttrs {
        fn val(self) -> u64 {
            match self {
                MountAttrs::NoSuid => MOUNT_ATTR_NOSUID,
            }
        }
    }

    impl FsConfig {
        pub fn flag(flag: &str) -> Result<Self, &'static str> {
            Ok(Self {
                ty: FsConfigType::SetFlag(CString::new(flag).or(Err("Invalid Flag"))?),
            })
        }
    }

    impl FS {
        pub fn new(fs_type: &str) -> Result<Self, &'static str> {
            let fs_type = CString::new(fs_type).or(Err("invalid type"))?;
            let fd = unsafe { syscall(SYS_fsopen, fs_type.as_ptr(), FSOPEN_CLOEXEC) };
            if fd == -1 {
                println!("Failed to open tmpfs")
            }
            Ok(FS {
                fsfd: unsafe { OwnedFd::from_raw_fd(fd.try_into().or(Err("Invalid fd"))?) },
            })
        }
        pub fn configure(
            &mut self,
            options: impl IntoIterator<Item = FsConfig>,
        ) -> Result<&mut Self, &'static str> {
            for option in options.into_iter() {
                match &option.ty {
                    FsConfigType::SetFlag(flag) => {
                        unsafe {
                            syscall(
                                SYS_fsconfig,
                                self.fsfd.as_raw_fd(),
                                FSCONFIG_SET_FLAG,
                                flag.as_ptr(),
                                NULL,
                                0,
                            )
                            .ne(&-1)
                            .ok_or("Failed to set flag")?;
                        };
                    }
                }
            }
            Ok(self)
        }
        pub fn create(
            self,
            attrs: impl IntoIterator<Item = MountAttrs>,
        ) -> Result<OwnedFd, &'static str> {
            let Self { fsfd } = self;
            unsafe {
                syscall(
                    SYS_fsconfig,
                    fsfd.as_raw_fd(),
                    FSCONFIG_CMD_CREATE,
                    NULL,
                    NULL,
                    0,
                )
            }
            .ne(&-1)
            .ok_or("Failed to create")?;
            let mut flags = 0;
            for attr in attrs {
                flags |= attr.val();
            }

            let root_mntfd =
                unsafe { syscall(SYS_fsmount, fsfd.as_raw_fd(), FSMOUNT_CLOEXEC, flags) } as i32;
            if root_mntfd == -1 {
                return Err("Failed to mount tmpfs");
            }
            Ok(unsafe { OwnedFd::from_raw_fd(root_mntfd) })
        }
    }
}
