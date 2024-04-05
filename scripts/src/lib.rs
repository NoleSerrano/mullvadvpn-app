pub mod utils {
    use chrono::Local;
    use log::error;
    use std::collections::{HashMap, HashSet};
    use std::ffi::{OsStr, OsString};
    use std::fs::{File, OpenOptions};
    use std::io::{self, prelude::*, BufReader};
    use winapi::um::winbase::QueryFullProcessImageNameA;
    // use std::sync::RwLockReadGuard;
    use std::os::windows::ffi::OsStringExt;
    use talpid_types::split_tunnel::ExcludedProcess;

    use winapi::shared::minwindef::{DWORD, MAX_PATH};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };
    use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    pub fn read_exclude_these_file_to_set(file_path: &str) -> HashSet<OsString> {
        let file = match File::open(file_path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Failed to open file: {}", err);
                return HashSet::new();
            }
        };

        let reader = BufReader::new(file);
        reader
            .lines()
            .filter_map(Result::ok)
            .map(|line| {
                let cleaned_line = line.trim_matches('"').replace("\\\\", "\\");
                OsString::from(cleaned_line)
            })
            .collect()
    }

    pub fn read_paths_from_file(file_path: &str) -> io::Result<Vec<OsString>> {
        let file = File::open(file_path)?;
        let buf_reader = io::BufReader::new(file);
        let paths = buf_reader
            .lines()
            .filter_map(|line| line.ok())
            .map(|line| line.trim_matches('"').replace("\\\\", "\\"))
            .map(OsString::from)
            .collect();
        Ok(paths)
    }

    pub fn get_all_apps_list() -> Vec<OsString> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                panic!("Failed to create snapshot");
            }

            let mut entry: PROCESSENTRY32 = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
            let mut unique_apps = HashSet::new();

            if Process32First(snapshot, &mut entry) == 1 {
                loop {
                    let process_handle = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        0,
                        entry.th32ProcessID,
                    );
                    if !process_handle.is_null() {
                        let mut exe_name: [i8; MAX_PATH] = [0; MAX_PATH];
                        let mut size = MAX_PATH as DWORD;
                        if QueryFullProcessImageNameA(
                            process_handle,
                            0,
                            exe_name.as_mut_ptr(),
                            &mut size,
                        ) != 0
                        {
                            let exe_name_os = OsString::from_wide(
                                &exe_name
                                    .iter()
                                    .map(|&c| c as u16)
                                    .take_while(|&c| c != 0)
                                    .collect::<Vec<u16>>(),
                            );
                            unique_apps.insert(exe_name_os);
                        }
                        CloseHandle(process_handle);
                    }

                    if Process32Next(snapshot, &mut entry) != 1 {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);

            unique_apps.into_iter().collect()
        }
    }

    pub fn log_os_strings_to_file(paths: Vec<OsString>, file_path: &str) {
        let mut log_file = match OpenOptions::new().create(true).append(true).open(file_path) {
            Ok(file) => file,
            Err(err) => {
                error!("Failed to open log file: {}", err);
                return;
            }
        };

        let current_datetime = Local::now().format("[%Y-%m-%d %H:%M:%S]").to_string();

        if let Err(err) = writeln!(log_file, "{}", current_datetime) {
            error!("Failed to write to log file: {}", err);
            return;
        }

        for path in paths {
            if let Err(err) = writeln!(log_file, "{}", path.to_string_lossy()) {
                error!("Failed to write to log file: {}", err);
            }
        }

        // Add an empty line for separation between entries
        if let Err(err) = writeln!(log_file, "") {
            error!("Failed to write to log file: {}", err);
        }
    }

    pub fn log_paths_to_file<T>(paths: &[T], file_path: &str)
    where
        T: AsRef<OsStr>,
    {
        let mut log_file = match OpenOptions::new().create(true).append(true).open(file_path) {
            Ok(file) => file,
            Err(err) => {
                error!("Failed to open log file: {}", err);
                return;
            }
        };

        let current_datetime = Local::now().format("[%Y-%m-%d %H:%M:%S]").to_string();

        if let Err(err) = writeln!(log_file, "{}", current_datetime) {
            error!("Failed to write to log file: {}", err);
            return;
        }

        for path in paths.iter() {
            if let Err(err) = writeln!(log_file, "Path: {:?}", path.as_ref().to_string_lossy()) {
                error!("Failed to write to log file: {}", err);
            }
        }

        // Add an empty line for separation between entries
        if let Err(err) = writeln!(log_file, "") {
            error!("Failed to write to log file: {}", err);
        }
    }

    pub fn log_excluded_processes(processes: HashMap<usize, ExcludedProcess>, file_path: &str) {
        let mut log_file = match OpenOptions::new().create(true).append(true).open(file_path) {
            Ok(file) => file,
            Err(err) => {
                error!("Failed to open log file: {}", err);
                return;
            }
        };

        let current_datetime = Local::now().format("[%Y-%m-%d %H:%M:%S]").to_string();

        if let Err(err) = writeln!(log_file, "{}", current_datetime) {
            error!("Failed to write to log file: {}", err);
            return;
        }

        for (pid, process) in processes.iter() {
            let image_path = process.image.display(); // This converts the PathBuf to a displayable path
            if let Err(err) = writeln!(
                log_file,
                "PID: {}, Path: {}, Reason: {}",
                pid, image_path, process.inherited
            ) {
                error!("Failed to write to log file: {}", err);
            }
        }

        if let Err(err) = writeln!(log_file, "") {
            error!("Failed to write to log file: {}", err);
        }
    }

    pub fn log_excluded_process_list(processes: Vec<ExcludedProcess>, file_path: &str) {
        let mut log_file = match OpenOptions::new().create(true).append(true).open(file_path) {
            Ok(file) => file,
            Err(err) => {
                error!("Failed to open log file: {}", err);
                return;
            }
        };

        let current_datetime = Local::now().format("[%Y-%m-%d %H:%M:%S]").to_string();

        if let Err(err) = writeln!(log_file, "{}", current_datetime) {
            error!("Failed to write to log file: {}", err);
            return;
        }

        for process in processes.iter() {
            let image_path = process.image.display(); // This converts the PathBuf to a displayable path
            if let Err(err) = writeln!(
                log_file,
                "PID: {}, Path: {}, Reason: {}",
                process.pid, image_path, process.inherited
            ) {
                error!("Failed to write to log file: {}", err);
            }
        }

        if let Err(err) = writeln!(log_file, "") {
            error!("Failed to write to log file: {}", err);
        }
    }

    pub fn log_excluded_processes2(processes: Vec<(u32, String, bool)>, file_path: &str) {
        let mut log_file = match OpenOptions::new().create(true).append(true).open(file_path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Failed to open log file: {}", err);
                return;
            }
        };

        let current_datetime = Local::now().format("[%Y-%m-%d %H:%M:%S]").to_string();

        if let Err(err) = writeln!(log_file, "{}", current_datetime) {
            eprintln!("Failed to write to log file: {}", err);
            return;
        }

        for (pid, image_path, inherited) in processes.iter() {
            if let Err(err) = writeln!(
                log_file,
                "PID: {}, Path: {}, Inherited: {}",
                pid, image_path, inherited
            ) {
                eprintln!("Failed to write to log file: {}", err);
            }
        }

        if let Err(err) = writeln!(log_file, "") {
            eprintln!("Failed to write to log file: {}", err);
        }
    }
}
